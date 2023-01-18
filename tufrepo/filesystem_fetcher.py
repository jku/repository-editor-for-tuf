# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Provides a local filesystem implementation of FetcherInterface"""


import logging
import time

from typing import Dict

from tuf.api import exceptions
from tuf.ngclient.fetcher import FetcherInterface

# Globals
logger = logging.getLogger(__name__)

# Classess
class FilesystemFetcher(FetcherInterface):
    """A filesystem based FetcherInterface implementation

    FilesystemFetcher pretends to load files from a remote host but really
    loads them from a local directory.

    Attributes:
        remote_dirs: a Dictionary of URL prefixes to directories: this is
            used to figure out which file to return for a URL.
    """

    def __init__(self, remote_dirs: Dict[str, str]):
        self.remote_dirs: Dict[str, str] = remote_dirs

    def _fetch(self, url: str):
        for url_prefix, dir in self.remote_dirs.items():
            if url.startswith(url_prefix):
                try:
                    return open(f"{dir}/{url[len(url_prefix):]}", "rb")
                except FileNotFoundError:
                    raise exceptions.DownloadHTTPError("File not found", 404)
        raise exceptions.DownloadHTTPError(
            f"URL {url} not prefixed with a known prefix", 404
        )
