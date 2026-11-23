"""The MXC gate in front of OpenShell's MXC driver on Windows.

OpenShell's Windows sandboxes run in MXC process containers, which OpenShell starts through ``wxc-exec``.
Before the launcher installs or starts anything, it checks that binary and this host: MXC 1.0 or newer
(a schema-1.0.0 request passes ``--dry-run``), the base-container tier, host loopback and deny paths
supported, and no DACL augmentation (MXC would otherwise enforce grants by rewriting host file permissions).
Read-only: ``--probe`` and ``--dry-run`` never create a container.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from pathlib import Path

from . import hostarch
from .driver import DriverUnavailable

# The launcher may run as a windowless logon task; a console child started without this flag opens a
# new terminal window on the user's desktop.
_NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}

# MXC's first stable config contract. wxc-exec builds before MXC 1.0 reject it ("Unsupported contract
# version"), which is how the gate tells them apart: no wxc-exec build answers --version.
SCHEMA = "1.0.0"
_MIN_VERSION = (1, 0, 0)
_GET = "MXC 1.0 or newer is required (npm @microsoft/mxc-sdk@1.0.0 ships bin/x64/wxc-exec.exe and bin/arm64/wxc-exec.exe)"


def preflight(exe: Path) -> dict:
    """Facts about *exe* and this host; raise DriverUnavailable with the reason when MXC can't be used."""
    if not _on_windows():
        raise DriverUnavailable("MXC process containers run on Windows only.")
    exe = Path(exe)
    _require_native(exe)
    version = _require_mxc1(exe)
    probe = subprocess.run([str(exe), "--probe"], capture_output=True, text=True, timeout=60, **_NO_WINDOW)
    try:
        facts = json.loads(probe.stdout)
    except ValueError as exc:
        raise DriverUnavailable(f"wxc-exec --probe gave no JSON (exit {probe.returncode}): "
                                f"{(probe.stderr or probe.stdout)[-300:]}") from exc
    probes = facts.get("probes") or {}
    problems = []
    # MXC defaults fallback.allowDaclMutation to true and, on a host that needs it, writes ACEs onto
    # the granted paths. OpenShell's request turns that off, but such a host cannot enforce the policy
    # without it, so refuse here with the reason instead of starting a sandbox MXC must refuse.
    needs_dacl = facts.get("needsDaclAugmentation")
    if needs_dacl is not False:
        problems.append("wxc-exec --probe reports needsDaclAugmentation "
                        f"{json.dumps(needs_dacl) if 'needsDaclAugmentation' in facts else 'missing'}: "
                        "on this host MXC would enforce the grants by rewriting host file permissions "
                        "(DACLs), which the launcher never allows")
    if facts.get("tier") != "base-container":
        problems.append(f"containment tier is {facts.get('tier')!r}; only base-container enforces "
                        "deny paths without rewriting host ACLs")
    for key in ("baseContainerSupportsDenyPaths", "baseContainerSupportsIngressHostLoopbackAllow"):
        if not probes.get(key):
            problems.append(f"{key} is false (Windows update needed)")
    if problems:
        raise DriverUnavailable("; ".join(problems))
    return {"exe": str(exe), "mxc_version": version, "schema": SCHEMA, "tier": facts["tier"],
            "needs_dacl_augmentation": False}


def _require_native(exe: Path) -> None:
    """Refuse a wxc-exec built for another architecture than this machine's (an x64 wxc-exec on an Arm64 PC
    would run emulated, which the sandbox was never tested with). A file that is not a readable PE image is left
    to the checks below."""
    built, machine = hostarch.pe_machine(exe), hostarch.windows_native_arch()
    if built and machine and built != machine:
        folder = {"x86_64": "x64", "aarch64": "arm64"}.get(machine, machine)
        raise DriverUnavailable(f"wxc-exec at {exe} is built for {hostarch.label(built)} but this PC is "
                                f"{hostarch.label(machine)}: use MXC's bin/{folder}/wxc-exec.exe")


def _require_mxc1(exe: Path) -> str | None:
    """Refuse a wxc-exec older than MXC 1.0; return its version string when the binary carries one.

    The PE version resource names the build (``1.0.0+<commit>``); the deciding check is a dry run of a
    schema-1.0.0 request, which validates without creating a container."""
    version = _file_version(exe)
    parsed = _parse_version(version)
    if parsed is not None and parsed < _MIN_VERSION:
        raise DriverUnavailable(f"wxc-exec at {exe} is MXC {version}, older than MXC 1.0. {_GET}.")
    b64 = base64.b64encode(json.dumps(_dry_run_config()).encode()).decode()
    r = subprocess.run([str(exe), "--config-base64", b64, "--dry-run"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60, **_NO_WINDOW)
    out = " ".join(((r.stdout or "") + " " + (r.stderr or "")).split())
    if r.returncode != 0:
        if "Unsupported contract version" in out:
            raise DriverUnavailable(f"wxc-exec at {exe}{f' (MXC {version})' if version else ''} rejects "
                                    f"MXC config version {SCHEMA}, so it predates MXC 1.0. {_GET}. "
                                    f"wxc-exec said: {out[-300:]}")
        raise DriverUnavailable(f"wxc-exec at {exe} refused a schema-{SCHEMA} process-container request "
                                f"in --dry-run (exit {r.returncode}): {out[-400:]}")
    return version


def _on_windows() -> bool:
    return os.name == "nt"


def _file_version(exe: Path) -> str | None:
    """The PE version resource of *exe* (``ProductVersion``, e.g. ``1.0.0+3cddcbc2``), or None."""
    if not _on_windows():
        return None
    try:
        import ctypes
        from ctypes import wintypes

        ver = ctypes.WinDLL("version")
        size = ver.GetFileVersionInfoSizeW(str(exe), None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(str(exe), 0, size, buf):
            return None
        ptr, length = ctypes.c_void_p(), wintypes.UINT()
        if not ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(length)) \
                or not length.value:
            return None
        lang, codepage = ctypes.cast(ptr, ctypes.POINTER(wintypes.WORD * 2)).contents
        for key in ("ProductVersion", "FileVersion"):
            query = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\{key}"
            if ver.VerQueryValueW(buf, query, ctypes.byref(ptr), ctypes.byref(length)) and length.value:
                return ctypes.wstring_at(ptr, length.value - 1).strip() or None
    except (OSError, AttributeError, ValueError):
        return None
    return None


def _parse_version(version: str | None) -> tuple[int, int, int] | None:
    m = re.match(r"\s*(\d+)\.(\d+)\.(\d+)", version or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _dry_run_config() -> dict:
    """A minimal process-container request for ``--dry-run`` (validated, never run)."""
    sysroot = os.environ.get("SYSTEMROOT") or "C:\\Windows"
    local = os.environ.get("LOCALAPPDATA") or sysroot
    return {"version": SCHEMA, "containerId": "hermes-sandbox-preflight", "containment": "processcontainer",
            "process": {"commandLine": f'"{sysroot}\\System32\\cmd.exe" /c exit 0',
                        "env": [f"SYSTEMROOT={sysroot}", f"LOCALAPPDATA={local}"], "inheritDefaultEnv": False,
                        "timeout": 1000},
            "processContainer": {"leastPrivilege": False}, "fallback": {"allowDaclMutation": False},
            "filesystem": {}, "ui": {"disable": False, "clipboard": "none", "injection": False},
            "network": {"ingress": {"default": "allow", "hostLoopback": "allow"}, "egress": {"default": "deny"}}}
