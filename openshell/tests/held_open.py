"""A file that is there and cannot be read, for one test: opened without sharing on Windows (what an editor that
locks its file does), without any permission elsewhere."""
from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest


@contextmanager
def held_open(path):
    """Until the block ends, *path* cannot be opened by anyone else."""
    path = Path(path)
    assert path.is_file(), path
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                         wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel32.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)  # read, no sharing, existing
        assert handle not in (None, wintypes.HANDLE(-1).value), ctypes.get_last_error()
        try:
            yield path
        finally:
            kernel32.CloseHandle(handle)
        return
    if os.geteuid() == 0:
        pytest.skip("the administrator reads every file")
    mode = path.stat().st_mode
    os.chmod(path, 0)
    try:
        yield path
    finally:
        os.chmod(path, mode)
