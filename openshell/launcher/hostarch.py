"""The Windows machine's own architecture, and the architecture a Windows binary is built for.

Arm64 Windows runs x64 programs under emulation, and an emulated x64 Python sees ``PROCESSOR_ARCHITECTURE=AMD64``
(and so does ``platform.machine()`` when it falls back to the environment). Neither may decide which OpenShell
build or which ``wxc-exec`` this machine needs. The machine's architecture comes from the kernel
(``IsWow64Process2``'s native machine, which names Arm64 to an emulated x64 process too), then the machine's own
``PROCESSOR_ARCHITECTURE`` in the registry, then the process environment.

Names are the installer's: ``x86_64``, ``aarch64`` (also ``x86``, ``arm``), ``""`` when unknown.
"""
from __future__ import annotations

import os
import platform as _platform
from pathlib import Path
from typing import Optional

# IMAGE_FILE_MACHINE_* values, as IsWow64Process2 reports them and as a PE file header carries them.
IMAGE_FILE_MACHINE = {0x8664: "x86_64", 0xAA64: "aarch64", 0x014C: "x86", 0x01C4: "arm"}
_NAMES = {"amd64": "x86_64", "x86_64": "x86_64", "x64": "x86_64", "em64t": "x86_64",
          "arm64": "aarch64", "aarch64": "aarch64",
          "x86": "x86", "i386": "x86", "i686": "x86", "arm": "arm"}
LABELS = {"x86_64": "x64", "aarch64": "Arm64", "x86": "32-bit x86", "arm": "32-bit Arm"}
_ENV_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"


def normalize(raw) -> str:
    """``AMD64``/``x64``/``ARM64``/... as ``x86_64``/``aarch64``/...; ``""`` for anything unknown."""
    return _NAMES.get(str(raw or "").strip().lower(), "")


def label(arch: str) -> str:
    return LABELS.get(arch, arch or "unknown")


def windows_native_arch() -> str:
    """This Windows machine's architecture, also when this Python runs emulated (x64 Python on Arm64)."""
    for source in (_wow64_native, _registry_arch, _environment_arch):
        try:
            got = source()
        except (OSError, AttributeError, TypeError, ValueError, ImportError):
            got = ""
        if got:
            return got
    return normalize(_platform.machine())


def _wow64_native() -> str:
    """``IsWow64Process2``'s native machine (Windows 10 1709+), or ``""``."""
    if os.name != "nt":
        return ""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    probe = getattr(kernel32, "IsWow64Process2", None)
    if probe is None:
        return ""
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE  # ctypes would truncate the pseudo-handle to c_int
    kernel32.GetCurrentProcess.argtypes = []
    probe.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT)]
    probe.restype = wintypes.BOOL
    process_machine, native_machine = wintypes.USHORT(0), wintypes.USHORT(0)
    if not probe(kernel32.GetCurrentProcess(), ctypes.byref(process_machine), ctypes.byref(native_machine)):
        return ""
    return IMAGE_FILE_MACHINE.get(native_machine.value, "")


def _registry_arch() -> str:
    """The machine's ``PROCESSOR_ARCHITECTURE`` (system environment in the registry; not the process's)."""
    if os.name != "nt":
        return ""
    import winreg

    flags = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _ENV_KEY, 0, flags) as key:
        return normalize(winreg.QueryValueEx(key, "PROCESSOR_ARCHITECTURE")[0])


def _environment_arch() -> str:
    return normalize(os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE"))


def pe_machine(path) -> Optional[str]:
    """The architecture a PE file (``.exe``/``.dll``) is built for, from its COFF header; None when *path* is
    not a readable PE file. An Arm64EC/Arm64X binary reports x86_64, as its header does."""
    try:
        with open(Path(path), "rb") as fh:
            head = fh.read(64)
            if len(head) < 64 or head[:2] != b"MZ":
                return None
            offset = int.from_bytes(head[0x3C:0x40], "little")
            if offset < 64 or offset > 1 << 20:
                return None
            fh.seek(offset)
            sig = fh.read(6)
    except OSError:
        return None
    if len(sig) < 6 or sig[:4] != b"PE\0\0":
        return None
    return IMAGE_FILE_MACHINE.get(int.from_bytes(sig[4:6], "little"), f"0x{int.from_bytes(sig[4:6], 'little'):04x}")
