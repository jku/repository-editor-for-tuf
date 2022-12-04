# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

# Git + filesystem based implementation of Repository. Invoked by the CLI.

import glob
import logging
import os
import subprocess

from contextlib import suppress
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from click.exceptions import ClickException
from securesystemslib.exceptions import StorageError
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Signed,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.repository import AbortEdit, Repository
from tufrepo.librepo.keys import Keyring

logger = logging.getLogger("tufrepo")

_signed_init = {
    Root.type: Root,
    Snapshot.type: Snapshot,
    Targets.type: Targets,
    Timestamp.type: Timestamp,
}


def _git(command: List[str]):
    """Helper to run git commands in the repository git repo"""
    full_cmd = ["git"] + command
    proc = subprocess.run(full_cmd)
    return proc.returncode


def _get_filename(role: str, version: Optional[int] = None):
    """Returns versioned filename"""
    if role == "timestamp":
        return f"{role}.json"
    else:
        if version is None:
            # Find largest version number in filenames
            filenames = glob.glob(f"*.{role}.json")
            versions = [int(name.split(".", 1)[0]) for name in filenames]
            try:
                version = max(versions)
            except ValueError:
                # No files found
                version = 1

        return f"{version}.{role}.json"


class GitRepository(Repository):
    """Manages loading, saving (signing) repository metadata in files stored in git"""

    def __init__(self, keyring: Keyring):
        self._keyring = keyring

    def _sign_role(self, role: str, md: Metadata):
        try:
            for key in self._keyring[role]:
                keyid = key.public.keyid
                logger.info("Signing role %s with key %s", role, keyid[:7])
                md.sign(key.signer, append=True)
        except KeyError:
            logger.info(f"No keys for role %s found in keyring", role)

    def open(self, role:str, init: bool = False) -> Metadata:
        fname = _get_filename(role)

        if init:
            # safety check
            filenames = glob.glob(f"*.{role}.json")
            versions = [int(name.split(".", 1)[0]) for name in filenames]
            if versions:
                raise ValueError(f"cannot initialize {role} as versions already exist")

            signed_init = _signed_init.get(role, Targets)
            md = Metadata(signed_init())
        else:
            try:
                md = Metadata.from_file(fname)
            except StorageError as e:
                raise ClickException(f"Failed to open {fname}.") from e

        return md

    def close(self, role:str, md: Metadata, sign_only: bool = False):
        if not sign_only:
            # Find out expiry and need for version bump
            try:
                period = md.signed.unrecognized_fields["x-tufrepo-expiry-period"]
            except KeyError:
                raise ClickException(
                    "Expiry period not found in metadata: use 'set-expiry'"
                )

            md.signed.expires = datetime.utcnow() + timedelta(seconds=period)

            fname = _get_filename(role)
            diff_cmd = ["diff", "--exit-code", "--no-patch", "--", fname]
            if os.path.exists(fname) and _git(diff_cmd) == 0:
                md.signed.version += 1

            md.signatures.clear()

        self._sign_role(role, md)

        new_fname = _get_filename(role, md.signed.version)
        md.to_file(new_fname, JSONSerializer())
        _git(["add", "--intent-to-add", new_fname])

    @property
    def targets_infos(self) -> Dict[str, MetaFile]:
        """Build and return current state of targets metadata"""

        # NOTE: we trust the version in the filenames to be correct here
        targets_roles: Dict[str, MetaFile] = {}
        for filename in glob.glob("*.*.json"):
            ver_str, keyname = filename[: -len(".json")].split(".")
            version = int(ver_str)
            if keyname in ["root", "snapshot", "timestamp"]:
                continue
            keyname = f"{keyname}.json"

            curr_role = targets_roles.get(keyname)
            if not curr_role or version > curr_role.version:
                targets_roles[keyname] = MetaFile(version)

        return targets_roles

    @property
    def snapshot_info(self) -> MetaFile:
        """Build and return current state of snapshot metadata"""

        # NOTE: we trust the version in the filename to be correct here
        current_version = 0
        for filename in glob.glob("*.snapshot.json"):
            version, _ = filename[: -len(".json")].split(".")
            current_version = max(current_version, int(version))

        return MetaFile(current_version)

    def snapshot(self) -> bool:  # type: ignore[override]
        """Update snapshot meta information

        This command only updates the meta information in snapshot
        according to current filenames: it does not validate those files in any
        way. Run 'verify' after 'snapshot' to validate repository state.

        Deletes targets files once they are no longer part of the
        repository.

        Returns False if a new snapshot version was not needed, True otherwise.
        """

        updated, removed = super().snapshot()

        # delete targets removed from snapshot meta (if any)
        for keyname, meta in removed.items():
            with suppress(FileNotFoundError):
                os.remove(f"{meta.version}.{keyname}")

        return updated

    def timestamp(self):
        """Update timestamp meta information

        Deletes the old snapshot file once it's no longer part of the
        repository.
        """

        # NOTE: we trust the version in the filename to be correct here
        updated, removed = super().timestamp()

        # delete the snapshot removed from timestamp meta (if any)
        if removed:
            with suppress(FileNotFoundError):
                os.remove(f"{removed.version}.snapshot.json")

    def add_target(
        self,
        role,
        follow_delegations: bool,
        target_in_repo: bool,
        target_path: str,
        local_file: str,
    ) -> str:
        """Adds a file to the repository as a target

        role: name of targets role that is the starting point for the targets-role search
        follow_delegations: should delegations under role be followed to find the correct targets-role
        target_in_repo: should local_file (and hash-prefixed symlinks) be added to git as well

        Returns the name of the role the target was actually added into
        """

        targetfile = TargetFile.from_file(target_path, local_file)
        final_role = None

        # special case delegation search: if follow_delegations, then we look
        # for the first "leaf" targets role (that does not delegate further)
        while not final_role:
            targets: Targets
            with self.edit(role) as targets:
                if targets.delegations and follow_delegations:
                    # see if target path is delegated (always pick first valid delegation)
                    delegations = targets.delegations.get_roles_for_target(targetfile.path)
                    new_role, _ = next(delegations, (None, None))
                    if new_role:
                        role = new_role
                        raise AbortEdit("Skip add-target: use delegation instead")

                # role does not delegate further: add the target
                targets.targets[targetfile.path] = targetfile
                final_role = role

        # Add the actual file to git and create hash-prefixed symlinks
        if target_in_repo:
            _git(["add", "--intent-to-add", local_file])
            for h in targetfile.hashes.values():
                dir, src_file = os.path.split(local_file)
                dst = os.path.join(dir, f"{h}.{src_file}")
                if os.path.islink(dst):
                    os.remove(dst)
                os.symlink(src_file, dst)
                _git(["add", "--intent-to-add", dst])

        return final_role

    def remove_target(self, role: str, follow_delegations: bool, target_path: str) -> Optional[str]:
        """Removes a file from the repository

        role: name of targets role that is the starting point for the targets-role search
        follow_delegations: should delegations under role be followed to find the correct targets-role

        Returns the name of the role the target was actually removed from (or
        None if nothing was removed)
        """
        roles = [role]

        # Delegation search here works like the one in tuf.ngclient
        while roles:
            role = roles.pop(-1)
            targets: Targets
            with self.edit(role) as targets:
                if target_path in targets.targets:
                    del targets.targets[target_path]
                    return role

                # target file was not found in this metadata: try delegations
                if targets.delegations and follow_delegations:
                    child_roles: List[str] = []
                    for (
                        child, terminating
                    ) in targets.delegations.get_roles_for_target(target_path):
                        child_roles.append(child)
                        if terminating:
                            # prevent further delegation search
                            roles.clear()
                            break
                    roles.extend(reversed(child_roles))

                raise AbortEdit("skipping remove-target: target not found in metadata")

        # No target found
        return None
