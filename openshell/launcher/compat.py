"""Host compatibility: can this computer run the sandbox at all?

Checked before the Sandbox switch can be turned on (``switch.availability``), so an incompatible host
says why on the Sandbox page instead of failing after the user clicked. The check reads and probes
only: no install, no gateway, no sandbox, nothing written. It is cached for ``CACHE_TTL`` seconds and
re-run on demand (the page's "Check again" and page open, and ``turn_on``). The drivers' own preflight
gates still run at switch-on; this check never replaces them.

Windows (MXC process containers under OpenShell's MXC driver):

* Windows 11 client on x64 or Arm64 (not Windows 10, not Windows Server), with a build of the pinned OpenShell
  for the machine's own architecture (``runtime/pins.json``; an x64 Python emulated on Arm64 still counts as Arm64).
* The build and update level from ``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion``
  (``CurrentBuild``, ``UBR``, ``DisplayVersion``, ``InstallationType``) against ``WINDOWS_LINES``: the
  sandbox reaches OpenShell's proxy and a local model over host loopback, which arrived with the
  September 2026 update (process isolation itself came in August). A build the table doesn't know and
  that is newer than 24H2 passes on to the probe.
* When wxc-exec is on this machine (the plugin's own install, or a copy the person named; see
  ``windows_programs.py``): it must be built for the machine's architecture (MXC ships
  ``bin/x64`` and ``bin/arm64``; an emulated wxc-exec is not what the sandbox was tested with), and
  ``wxc-exec --probe`` must report the base-container tier,
  ``needsDaclAugmentation: false`` and the host-loopback and deny-path capabilities
  (``probes.baseContainerSupportsIngressHostLoopbackAllow``, ``probes.baseContainerSupportsDenyPaths``).
  MXC 1.0.x reports a fallback tier (``appcontainer-dacl``) when PSEC can't serve a request; MXC main
  omits ``tier`` and ``needsDaclAugmentation`` and adds ``error`` instead. Both fail here.

Linux (OpenShell on its Docker driver, as pinned): x86_64 or aarch64 with glibc, Landlock active with
ABI v3 or newer (Linux 6.2+; the sandbox applies a hard-requirement Landlock baseline), seccomp user
notification (the sandbox's network broker), and a Docker daemon this user can reach. Unprivileged
user namespaces are not needed: Docker creates the containers, and the sandbox blocks new user
namespaces itself.

macOS: not supported yet.
"""
from __future__ import annotations

import errno
import json
import os
import platform as _platform
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

CACHE_TTL = 60.0
PROBE_TIMEOUT = 15.0
DOCKER_TIMEOUT = 8.0
_NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}

WIN11_FIRST_BUILD = 22000
FIRST_SUPPORTED_BUILD = 26100  # 24H2: older Windows 11 releases get no process isolation
# Windows 11 lines that can run the sandbox: the first UBR with host loopback (and enumerate-only
# access), which the sandbox needs to reach OpenShell's proxy. Process isolation came a month earlier
# (KB5120998: 26100/26200.9278, 28000.2804), which is not enough on its own.
WINDOWS_LINES = {
    26100: {"ubr": 9550, "update": "KB5124010"},  # 24H2
    26200: {"ubr": 9550, "update": "KB5124010"},  # 25H2
    26300: {"ubr": 9550, "update": "KB5124010"},  # 26H2
    28000: {"ubr": 3086, "update": "KB5124006"},  # 26H1
}
LANDLOCK_MIN_ABI = 3  # OpenShell v0.1.5's mandatory baseline (Linux 6.2+)
DOCKER_INSTALL_URL = "https://docs.docker.com/engine/install/"

_WU = "Settings > Windows Update"
_UPDATE_TEXT = f"Install it in {_WU}, then check again."
_LATEST_TEXT = f"Install the latest updates in {_WU} and restart, then check again."
_ARCH_LABEL = {"x86_64": "x64", "aarch64": "Arm64", "x86": "32-bit x86", "arm": "32-bit Arm"}

_lock = threading.Lock()
_cache: dict = {}


# -- entry points ---------------------------------------------------------------------------------

def check(wxc_exec=None, *, refresh: bool = False) -> dict:
    """This host's verdict, cached for ``CACHE_TTL`` seconds (``refresh`` re-runs it). Always a dict:
    ``ok``, ``platform``, ``code``, ``reason`` (one line for the page, None when ok), ``action`` (None or
    ``{text, label?, url?}``), ``detail`` (technical, for logs), ``facts`` and ``checked_at``."""
    key = (_platform_key(), str(wxc_exec) if wxc_exec else None)
    with _lock:
        hit = _cache.get(key)
        if not refresh and hit is not None and time.monotonic() - hit[0] < CACHE_TTL:
            return hit[1]
        try:
            result = _check(key[0], Path(wxc_exec) if wxc_exec else None)
        except Exception as exc:  # a check that breaks must not take the Sandbox page down with it
            result = _result(False, key[0], "check-failed", "Couldn't check this computer.",
                             {"text": "Check again."}, detail=f"{type(exc).__name__}: {exc}")
        _cache[key] = (time.monotonic(), result)
        return result


def wxc_exec_for(spec: Optional[dict], root: Optional[Path] = None) -> Optional[Path]:
    """The wxc-exec the launcher would use for *spec*, as the driver picks it (``windows_programs.chosen``):
    the person's own copy, else the plugin's install under the Hermes root *root* (default: this one) once it
    is there with its pinned sha256. None before that: this check installs nothing."""
    from . import windows_programs

    if root is None:
        from hermes_constants import get_default_hermes_root

        root = get_default_hermes_root().resolve()
    return windows_programs.chosen("wxc-exec", spec, Path(root))["file"]


def _check(platform: str, wxc_exec: Optional[Path]) -> dict:
    if platform == "windows":
        return check_windows(wxc_exec)
    if platform == "linux":
        return check_linux()
    if platform == "macos":
        return _result(False, platform, "macos", "Not supported on macOS yet.")
    return _result(False, platform, "unsupported-os", "Not supported on this system.")


def _platform_key() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


def _result(ok: bool, platform: str, code: str, reason: Optional[str] = None, action: Optional[dict] = None, *,
            detail: Optional[str] = None, facts: Optional[dict] = None) -> dict:
    return {"ok": ok, "platform": platform, "code": code, "reason": None if ok else reason,
            "action": None if ok else action, "detail": detail, "facts": facts or {}, "checked_at": time.time()}


# -- Windows --------------------------------------------------------------------------------------

def _windows_version() -> dict:
    import winreg

    flags = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0, flags) as key:
        def get(name):
            try:
                return winreg.QueryValueEx(key, name)[0]
            except OSError:
                return None

        return {"build": get("CurrentBuild") or get("CurrentBuildNumber"), "ubr": get("UBR"),
                "display_version": get("DisplayVersion") or get("ReleaseId"),
                "installation_type": get("InstallationType")}


def _windows_arch() -> str:
    """The machine's own architecture as ``PROCESSOR_ARCHITECTURE`` spells it (``AMD64``, ``ARM64``), also under an
    emulated (x64 on Arm) interpreter."""
    from . import hostarch

    arch = hostarch.windows_native_arch()
    return {"x86_64": "AMD64", "aarch64": "ARM64", "x86": "X86", "arm": "ARM"}.get(arch, arch.upper())


def _pinned_windows_arches() -> list:
    """The Windows architectures the shipped pin has an OpenShell build for (``x86_64``, ``aarch64``)."""
    from .openshell_install import windows_arches

    return windows_arches()


def _exe_arch(path: Path) -> Optional[str]:
    """The architecture *path* is built for (``x86_64``, ``aarch64``), or None when it can't be read as a PE file."""
    from . import hostarch

    return hostarch.pe_machine(path)


def _as_int(value) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def windows_label(build: Optional[int], ubr: Optional[int], display: Optional[str]) -> str:
    name = "Windows 11" if (build or 0) >= WIN11_FIRST_BUILD else "Windows 10"
    version = f" {display}" if display else ""
    number = f"{build}.{ubr}" if ubr is not None else f"{build}"
    return f"{name}{version}, build {number}"


def check_windows(wxc_exec: Optional[Path]) -> dict:
    ver = _windows_version()
    arch = str(_windows_arch() or "").upper()
    build, ubr = _as_int(ver.get("build")), _as_int(ver.get("ubr"))
    display = ver.get("display_version")
    install = str(ver.get("installation_type") or "")
    label = windows_label(build, ubr, display)
    facts = {"os": label, "build": build, "ubr": ubr, "display_version": display, "installation_type": install,
             "arch": arch, "wxc_exec": str(wxc_exec) if wxc_exec else None}

    def fail(code, reason, action=None, detail=None):
        return _result(False, "windows", code, reason, action, detail=detail, facts=facts)

    if install.lower().startswith("server") or install.lower() == "nano server":
        return fail("windows-server", "Not supported on Windows Server.")
    if arch not in ("AMD64", "X64", "X86_64", "ARM64", "AARCH64"):
        return fail("arch", "Needs a 64-bit PC (x64 or Arm).", detail=f"PROCESSOR_ARCHITECTURE {arch or 'unknown'}")
    machine = "aarch64" if arch in ("ARM64", "AARCH64") else "x86_64"
    try:
        built_for = _pinned_windows_arches()
    except (OSError, ValueError) as exc:
        built_for = []
        facts["pin_error"] = f"{type(exc).__name__}: {exc}"
    facts["openshell_builds"] = built_for
    if machine not in built_for:
        # The pinned OpenShell has no build for this architecture (x64 binaries would run emulated: untested).
        return fail("arch-arm64" if machine == "aarch64" else "arch-x64",
                    "Not supported on Arm PCs yet." if machine == "aarch64" else "Not supported on x64 PCs yet.",
                    detail=f"PROCESSOR_ARCHITECTURE {arch}; the pinned OpenShell has builds for "
                           f"{', '.join(built_for) or 'no Windows architecture'}")
    if build is None:
        return fail("windows-unknown", "Couldn't read this PC's Windows version.", {"text": "Check again."},
                    detail=f"CurrentBuild {ver.get('build')!r}")
    if build < WIN11_FIRST_BUILD:
        return fail("windows-10", "Needs Windows 11.", detail=f"This PC has {label}.")
    line = WINDOWS_LINES.get(build)
    if line is None and build < FIRST_SUPPORTED_BUILD:
        return fail("windows-feature-update", f"Needs Windows 11 24H2 or newer. This PC has {label}.",
                    {"text": f"Update in {_WU}, then check again."})
    if line is not None and (ubr or 0) < line["ubr"]:
        return fail("windows-update", f"Needs the September 2026 Windows update. This PC has {label}.",
                    {"text": _UPDATE_TEXT}, detail=f"{line['update']} or later ({build}.{line['ubr']}+)")
    facts["os_table"] = "known" if line is not None else "newer"
    if wxc_exec is None:  # Nothing to probe yet: switch-on installs wxc-exec and its preflight probes with it
        facts["probe"] = "skipped: wxc-exec not found"
        return _result(True, "windows", "ok", facts=facts)
    exe_arch = _exe_arch(wxc_exec)
    facts["wxc_exec_arch"] = exe_arch
    if exe_arch is not None and exe_arch != machine:
        want = "arm64" if machine == "aarch64" else "x64"
        return fail("wxc-exec-arch", f"wxc-exec is the {_ARCH_LABEL.get(exe_arch, exe_arch)} build. "
                                     f"This PC needs the {_ARCH_LABEL[machine]} one.",
                    {"text": f"Use bin\\{want}\\wxc-exec.exe from the MXC package, then check again."},
                    detail=f"{wxc_exec}: PE machine {exe_arch}, host {machine}")
    return _probe_verdict(_run_probe(wxc_exec), facts, label)


def _run_probe(exe: Path) -> dict:
    """``wxc-exec --probe`` (read-only: no container is created) as {code, stdout, stderr} or {error}."""
    try:
        done = subprocess.run([str(exe), "--probe"], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=PROBE_TIMEOUT, stdin=subprocess.DEVNULL, **_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return {"error": f"wxc-exec --probe did not answer within {PROBE_TIMEOUT:.0f} s"}
    except OSError as exc:
        return {"error": f"wxc-exec --probe could not run: {exc}"}
    return {"code": done.returncode, "stdout": done.stdout or "", "stderr": done.stderr or ""}


def _probe_verdict(run: dict, facts: dict, label: str) -> dict:
    def fail(code, reason, action, detail):
        return _result(False, "windows", code, reason, action, detail=detail, facts=facts)

    if "error" in run:
        return fail("probe-failed", "Couldn't check process isolation on this PC.", {"text": "Check again."},
                    run["error"])
    try:
        data = json.loads(run["stdout"])
        if not isinstance(data, dict):
            raise ValueError("not an object")
    except ValueError:
        tail = (run.get("stderr") or run.get("stdout") or "").strip()[-300:]
        return fail("probe-failed", "Couldn't check process isolation on this PC.", {"text": "Check again."},
                    f"wxc-exec --probe gave no JSON (exit {run.get('code')}): {tail}")
    probes = data.get("probes") if isinstance(data.get("probes"), dict) else {}
    facts["probe"] = {"tier": data.get("tier"), "needsDaclAugmentation": data.get("needsDaclAugmentation"),
                      "baseContainerApiPresent": probes.get("baseContainerApiPresent"),
                      "baseContainerSupportsIngressHostLoopbackAllow":
                          probes.get("baseContainerSupportsIngressHostLoopbackAllow"),
                      "baseContainerSupportsDenyPaths": probes.get("baseContainerSupportsDenyPaths"),
                      "error": data.get("error")}
    said = f"wxc-exec --probe: tier {data.get('tier')!r}, needsDaclAugmentation " \
           f"{data.get('needsDaclAugmentation')!r}" + (f", error {data['error']!r}" if data.get("error") else "")
    if probes.get("baseContainerApiPresent") is not True:
        return fail("isolation-missing", "Process isolation isn't available on this PC.", {"text": _LATEST_TEXT},
                    said + ", baseContainerApiPresent false")
    if data.get("tier") != "base-container" or data.get("needsDaclAugmentation") is not False:
        # The API is there but PSEC can't serve the request (a fallback tier, or MXC's error): the feature is off.
        return fail("isolation-off", "Process isolation is turned off on this PC.", {"text": _LATEST_TEXT}, said)
    missing = [k for k in ("baseContainerSupportsIngressHostLoopbackAllow", "baseContainerSupportsDenyPaths")
               if probes.get(k) is not True]
    if missing:
        return fail("windows-update", f"Needs the September 2026 Windows update. This PC has {label}.",
                    {"text": _UPDATE_TEXT}, f"{said}; false: {', '.join(missing)}")
    return _result(True, "windows", "ok", detail=said, facts=facts)


# -- Linux ----------------------------------------------------------------------------------------

def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _landlock_abi() -> tuple[int, int]:
    """``landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)``: (abi, 0) or (-1, errno). Creates
    no file descriptor; the syscall number is 444 on x86_64 and aarch64."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    got = libc.syscall(ctypes.c_long(444), ctypes.c_void_p(None), ctypes.c_size_t(0), ctypes.c_uint32(1))
    return (int(got), 0) if got >= 0 else (-1, ctypes.get_errno())


def _kernel_release() -> str:
    return _platform.release()


def _machine() -> str:
    return _platform.machine()


def _libc() -> str:
    return _platform.libc_ver()[0] or ""


def _docker_version(cli: str) -> dict:
    try:
        done = subprocess.run([cli, "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=DOCKER_TIMEOUT, stdin=subprocess.DEVNULL,
                              **_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return {"error": f"docker version did not answer within {DOCKER_TIMEOUT:.0f} s"}
    except OSError as exc:
        return {"error": f"docker could not run: {exc}"}
    return {"code": done.returncode, "stdout": (done.stdout or "").strip(), "stderr": (done.stderr or "").strip()}


def _kernel_at_least(release: str, want: tuple[int, int]) -> Optional[bool]:
    import re

    m = re.match(r"(\d+)\.(\d+)", release or "")
    return None if m is None else (int(m.group(1)), int(m.group(2))) >= want


def check_linux() -> dict:
    release, machine = _kernel_release(), _machine()
    facts = {"kernel": release, "arch": machine}

    def fail(code, reason, action=None, detail=None):
        return _result(False, "linux", code, reason, action, detail=detail, facts=facts)

    if machine not in ("x86_64", "aarch64", "amd64", "arm64"):
        return fail("arch", "Needs a 64-bit x86 or Arm computer.", detail=f"machine {machine}")
    libc = _libc()
    facts["libc"] = libc
    if libc != "glibc":
        return fail("libc", "Needs a Linux distribution with glibc.", detail=f"libc {libc or 'unknown'}")
    lsm = _read_text("/sys/kernel/security/lsm")
    facts["lsm"] = lsm.strip() if lsm is not None else None
    try:
        abi, err = _landlock_abi()
    except (OSError, AttributeError) as exc:
        abi, err = -1, None
        facts["landlock_probe"] = f"{type(exc).__name__}: {exc}"
    facts["landlock_abi"] = abi if abi >= 0 else None
    old_kernel = fail("linux-kernel", f"Needs Linux 6.2 or newer. This computer has Linux {release}.",
                      {"text": "Update the kernel, then check again."},
                      f"Landlock ABI {abi if abi >= 0 else 'none'}; v{LANDLOCK_MIN_ABI} or newer is required")
    landlock_off = fail("landlock-off", "Landlock is turned off in this Linux kernel.",
                        {"text": "Add landlock to the kernel's lsm= boot option, restart, then check again."},
                        f"active LSMs: {facts['lsm']}")
    if abi >= LANDLOCK_MIN_ABI:
        pass
    elif abi >= 1:
        return old_kernel
    elif err == errno.EPERM:
        return fail("landlock-blocked", "Landlock is blocked here.",
                    {"text": "Run Hermes directly on this computer, not inside a container."},
                    "landlock_create_ruleset: EPERM (a seccomp profile denies it)")
    elif err == errno.EOPNOTSUPP:
        return landlock_off
    elif _kernel_at_least(release, (6, 2)) is False:
        return old_kernel
    elif err is None:  # the syscall couldn't be made from here: go by the active LSM list
        if lsm is not None and "landlock" not in lsm.strip().split(","):
            return landlock_off
    else:  # ENOSYS on a 6.2+ kernel, or anything else
        return fail("landlock-missing", "This Linux kernel has no Landlock.",
                    {"text": "Use a kernel built with Landlock (CONFIG_SECURITY_LANDLOCK), then check again."},
                    f"landlock_create_ruleset errno {err}")
    actions = _read_text("/proc/sys/kernel/seccomp/actions_avail")
    facts["seccomp_actions"] = actions.strip() if actions is not None else None
    if actions is None or "user_notif" not in actions.split():
        return fail("seccomp", "This Linux kernel can't hand system calls to the sandbox's broker.",
                    {"text": "Use a kernel with seccomp user notification (CONFIG_SECCOMP_FILTER), then check again."},
                    f"seccomp actions_avail: {facts['seccomp_actions']}")
    cli = shutil.which("docker")
    facts["docker"] = cli
    if cli is None:
        return fail("docker-missing", "Needs Docker.",
                    {"text": "Install Docker Engine, then check again.", "label": "Install Docker",
                     "url": DOCKER_INSTALL_URL})
    run = _docker_version(cli)
    if run.get("code") == 0 and run.get("stdout"):
        facts["docker_server"] = run["stdout"]
        return _result(True, "linux", "ok", facts=facts)
    said = run.get("error") or f"docker version exit {run.get('code')}: {(run.get('stderr') or '')[-300:]}"
    if "permission denied" in said.lower():
        return fail("docker-permission", "This user can't use Docker.",
                    {"text": "Add this user to the docker group, sign in again, then check again."}, said)
    return fail("docker-unreachable", "Docker isn't running.", {"text": "Start Docker, then check again."}, said)
