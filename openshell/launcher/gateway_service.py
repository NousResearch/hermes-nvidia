"""This Hermes root's private OpenShell gateway, run as a per-user login service.

One gateway serves every sandboxed profile of a Hermes root. The launcher (``OpenShellDriver``
preflight and start) calls ``ensure_gateway`` before it creates a sandbox; the profile login service's
removal calls ``release_if_unused``, which removes the gateway once no profile is switched on.

Host-only state, under ``<root>/openshell/runtime/gateway/`` (owner-only on POSIX; under the user's
private LOCALAPPDATA on Windows; never granted to a sandbox):

    gateway.json      name, port, the runtime id and config hash the service runs (``active``)
    pki/              generated CA, server and client certificates and the sandbox JWT key
                      (``openshell-gateway generate-certs``); keys are 0600
    gateway.toml      loopback bind, mTLS user auth required, the Docker driver (Linux: bind mounts
                      and driver config on, runtime images pinned by digest, never pulled) or the MXC
                      driver (Windows: user auth on, a supervisor state and log dir, no debug)
    state/            the gateway's database (XDG_STATE_HOME)
    cli/              the CLI registration the launcher uses (XDG_CONFIG_HOME: metadata + client cert)
    service/          bootstrap.py + gateway-service.json, which the login service runs
    logs/, ocsf/      gateway log (rotated by the bootstrap) and gateway OCSF JSONL

The login service (``login_service`` managers: Task Scheduler, systemd --user, LaunchAgent) runs this
install's Python on the bootstrap, which refuses binaries whose sha256 no longer matches the pinned
identity and execs the gateway. Without ``gateway-service.json`` it starts nothing, so a registration
a crash left behind never brings a removed gateway back.

Upgrades: when the pinned runtime (or the generated config) changes, the new runtime is installed
beside the old one and the gateway is restarted on it only when no sandbox runs on it; until then
launchers keep using the running version (``upgrade_pending``).
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Optional

from . import openshell_install as inst
from .driver import DriverUnavailable

GATEWAY_DIRNAME = "gateway"
GATEWAY_FILE = "gateway.json"
SERVICE_FILE = "gateway-service.json"
BOOTSTRAP_FILE = "bootstrap.py"
PORT_ENV = "HERMES_OPENSHELL_GATEWAY_PORT"
HEALTH_TIMEOUT = 90.0
STATE_ROOT_SKIP = (inst.RUNTIME_DIRNAME,)  # <root>/openshell children that are not profiles
# Supervisor tuning the MXC gateway passes on to every sandbox's supervisor (both default to 10 s).
SUPERVISOR_ENV = {"OPENSHELL_POLICY_POLL_INTERVAL_SECS": "2", "OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS": "2"}
# OpenShell sends anonymous usage telemetry to its publisher unless this says otherwise (its README, "Telemetry").
# The plugin always turns it off: the gateway is the program that sends, and it hands the value on to every sandbox's
# supervisor. Each environment the plugin builds for an OpenShell program sets it last, after inherited OPENSHELL_*
# values are dropped, so neither the user's shell nor a caller's extras can turn it back on.
TELEMETRY_OFF = {"OPENSHELL_TELEMETRY_ENABLED": "false"}

BOOTSTRAP = '''\
"""Starts this Hermes root's private OpenShell gateway for the OS login service (written by the
openshell plugin). Reads gateway-service.json beside this file; without it the gateway was removed and
nothing starts. Refuses to start binaries whose sha256 no longer matches the installed identity."""
import hashlib, json, os, subprocess, sys

here = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(here, "gateway-service.json"), encoding="utf-8") as fh:
        cfg = json.load(fh)
except FileNotFoundError:
    sys.exit(0)
log = cfg["log"]
os.makedirs(os.path.dirname(log), exist_ok=True)
try:
    if os.path.getsize(log) > 5_000_000:
        os.replace(log, log + ".1")
except OSError:
    pass
out = open(log, "ab", buffering=0)


def note(msg):
    out.write(("[hermes-gateway-bootstrap] " + msg + "\\n").encode("utf-8", "replace"))


for path, want in (cfg.get("verify") or {}).items():
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
    except OSError as exc:
        note("refusing to start: cannot read %s: %s" % (path, exc))
        sys.exit(3)
    if digest.hexdigest() != want:
        note("refusing to start: %s does not match its pinned sha256" % path)
        sys.exit(3)
env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("OPENSHELL_", "XDG_", "HERMES_"))}
env.update(cfg.get("env") or {})
argv = cfg["argv"]
os.chdir(cfg["cwd"])
note("starting %s" % " ".join(argv))
if os.name == "nt":
    # Task Scheduler's End stops this process, not what it started: hold the gateway (and the
    # supervisors and sandboxes it starts) in a kill-on-close job, so they end with this bootstrap.
    import ctypes
    from ctypes import wintypes

    class _Basic(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

    class _Extended(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _Basic), ("IoInfo", ctypes.c_ulonglong * 6),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    job = k32.CreateJobObjectW(None, None)
    info = _Extended()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not job or not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        note("refusing to start: cannot create a kill-on-close job (%d)" % ctypes.get_last_error())
        sys.exit(4)
    proc = subprocess.Popen(argv, env=env, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            creationflags=0x08000000)
    if not k32.AssignProcessToJobObject(job, int(proc._handle)):
        note("refusing to run: cannot hold the gateway in a job (%d)" % ctypes.get_last_error())
        proc.kill()
        sys.exit(4)
    sys.exit(proc.wait())
os.dup2(out.fileno(), 1)
os.dup2(out.fileno(), 2)
os.execve(argv[0], argv, env)
'''


# -- paths and small helpers --------------------------------------------------------------------

def gateway_dir(root: Path) -> Path:
    return inst.runtime_dir(root) / GATEWAY_DIRNAME


def gateway_log(root: Path) -> Path:
    """The gateway's own output, which its login service writes (``_definition``): where a refused connection of
    any sandbox shows as it happens."""
    return gateway_dir(root) / "logs" / "gateway.log"


def gateway_name(root: Path) -> str:
    from .login_service import _root_tag

    return f"hermes-{_root_tag(Path(root))}"


def _read_json(path: Path) -> Optional[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _toml_str(value) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def _locked(root: Path, timeout: float = 600.0):
    """One gateway change at a time per Hermes root (two launchers starting at login, say)."""
    base = inst.runtime_dir(root)
    base.mkdir(parents=True, exist_ok=True)
    path = base / ".gateway.lock"
    fh = open(path, "a+b")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise DriverUnavailable(f"another process holds {path} (an OpenShell gateway change)")
                time.sleep(0.2)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        fh.close()


def cli_env(gw: Path, name: str, extra: Optional[dict] = None) -> dict:
    """The CLI's environment for this gateway: its own config home; nothing from the user's own
    OpenShell or Hermes settings."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("OPENSHELL_", "HERMES_", "XDG_"))}
    env.update({"XDG_CONFIG_HOME": str(gw / "cli"), "XDG_STATE_HOME": str(gw / "cli-state"),
                "XDG_DATA_HOME": str(gw / "cli-data"), "OPENSHELL_SYSTEM_GATEWAY_DIR": str(gw / "cli-system"),
                "OPENSHELL_GATEWAY": name, "NO_COLOR": "1"})
    if extra:
        env.update(extra)
    env.update(TELEMETRY_OFF)
    return env


def _run_cli(cli: Path, gw: Path, name: str, *args, run=subprocess.run, timeout: float = 60.0,
             extra: Optional[dict] = None) -> tuple[int, str]:
    try:
        done = run([str(cli), *args], env=cli_env(gw, name, extra), capture_output=True, text=True,
                   encoding="utf-8", errors="replace", timeout=timeout, stdin=subprocess.DEVNULL,
                   **({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return done.returncode, ((done.stdout or "") + ("\n" + done.stderr if done.stderr else "")).strip()


# -- PKI, config, registration ------------------------------------------------------------------

PKI_FILES = ("ca.crt", "server/tls.crt", "server/tls.key", "client/tls.crt", "client/tls.key",
             "jwt/signing.pem", "jwt/public.pem", "jwt/kid")


def ensure_pki(gw: Path, gateway_bin: Path, *, run=subprocess.run) -> Path:
    """Generated once per gateway: CA, server (SANs 127.0.0.1, localhost, host.openshell.internal),
    client, sandbox JWT key. Owner-only permissions on POSIX."""
    pki = gw / "pki"
    if all((pki / f).is_file() for f in PKI_FILES):
        _restrict_pki(pki)
        return pki
    if pki.exists():
        shutil.rmtree(pki)
    # generate-certs also registers the new client certificate and key for the CLI: it copies them (and the CA)
    # into $XDG_CONFIG_HOME/openshell/gateways/openshell/mtls. With the user's environment that is their own
    # OpenShell config (~/.config/openshell on Linux), where it would replace the client key of their own gateway
    # named "openshell" and leave this gateway's key outside the host-only state. Give it a throwaway config home
    # inside the gateway folder and remove it; the launcher's own registration is ensure_registration's.
    scratch = gw / "pki-cli-scratch"
    shutil.rmtree(scratch, ignore_errors=True)
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("OPENSHELL_", "XDG_"))}
    env.update({"XDG_CONFIG_HOME": str(scratch / "config"), "XDG_STATE_HOME": str(scratch / "state"),
                "XDG_DATA_HOME": str(scratch / "data"), "OPENSHELL_SYSTEM_GATEWAY_DIR": str(scratch / "system"),
                **TELEMETRY_OFF})
    try:
        done = run([str(gateway_bin), "generate-certs", "--output-dir", str(pki), "--server-san", "127.0.0.1",
                    "--server-san", "localhost", "--server-san", "host.openshell.internal"],
                   capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL, env=env,
                   **({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    missing = [f for f in PKI_FILES if not (pki / f).is_file()]
    if done.returncode != 0 or missing:
        raise DriverUnavailable(f"generating the gateway's certificates failed ({done.returncode}; missing {missing}): "
                                f"{(done.stderr or done.stdout or '').strip()[-300:]}")
    _restrict_pki(pki)
    return pki


def _restrict_pki(pki: Path) -> None:
    if os.name == "nt":
        return  # under the user's private LOCALAPPDATA; host ACLs are never changed
    for dirpath, dirnames, filenames in os.walk(pki):
        os.chmod(dirpath, 0o700)
        for f in filenames:
            p = os.path.join(dirpath, f)
            os.chmod(p, 0o600 if f.endswith((".key", ".pem")) and not f.startswith("public") else 0o644)


def render_config(kind: str, *, gw: Path, name: str, port: int, root: Path, ident: dict,
                  wxc_exec: Optional[Path] = None) -> str:
    """The gateway's TOML (schema v2), loopback only, mTLS user auth required."""
    pki = gw / "pki"
    lines = ["[openshell]", "version = 2", "", "[openshell.gateway]", f"name = {_toml_str(name)}"]
    if kind == "docker":
        images = ident.get("images") or {}
        lines += [f'bind_address = "127.0.0.1:{int(port)}"', 'compute_driver = "docker"',
                  'policy_validation_failure_mode = "fail_closed"', 'config_delivery_mode = "push"', "",
                  "[openshell.gateway.mtls_auth]", "enabled = true", "",
                  "[openshell.gateway.ocsf_log]", f"path = {_toml_str(gw / 'ocsf' / 'gateway-ocsf.jsonl')}", "",
                  "[openshell.drivers.docker]", "allow_driver_config = true", "enable_bind_mounts = true",
                  f"sandbox_label = {_toml_str(name)}", 'image_pull_policy = "never"',
                  f"supervisor_image = {_toml_str(images['openshell-supervisor']['ref'])}",
                  f"sandbox_runtime_image = {_toml_str(images['openshell-sandbox']['ref'])}", "",
                  "[openshell.drivers.docker.resource_admission]", "enabled = false"]
    elif kind == "mxc":
        if wxc_exec is None:
            raise DriverUnavailable("the MXC gateway needs wxc-exec (MXC 1.0 or newer)")
        bins = inst.identity_dir(root, ident) / "bin"
        lines += ['compute_driver = "mxc"', f"guest_tls_ca = {_toml_str(pki / 'ca.crt')}", "",
                  "[openshell.gateway.tls]", f"cert_path = {_toml_str(pki / 'server' / 'tls.crt')}",
                  f"key_path = {_toml_str(pki / 'server' / 'tls.key')}",
                  f"client_ca_path = {_toml_str(pki / 'ca.crt')}", "",
                  "[openshell.gateway.mtls_auth]", "enabled = true", "",
                  "[openshell.gateway.gateway_jwt]", f"signing_key_path = {_toml_str(pki / 'jwt' / 'signing.pem')}",
                  f"public_key_path = {_toml_str(pki / 'jwt' / 'public.pem')}",
                  f"kid_path = {_toml_str(pki / 'jwt' / 'kid')}", f"gateway_id = {_toml_str(name)}", "",
                  "[openshell.gateway.ocsf_log]", f"path = {_toml_str(gw / 'ocsf' / 'gateway-ocsf.jsonl')}", "",
                  "[openshell.drivers.mxc]", "allow_driver_config = true",
                  f"wxc_exec_path = {_toml_str(wxc_exec)}",
                  f"supervisor_binary_path = {_toml_str(bins / 'openshell-supervisor.exe')}",
                  f"sandbox_binary_path = {_toml_str(bins / 'openshell-windows-sandbox.exe')}",
                  # The supervisor keeps each sandbox's host state under the gateway's own folder.
                  f"state_dir = {_toml_str(gw / 'mxc-state')}",
                  'backend = "process_container"', "pc_least_privilege = false", "pc_capabilities = []",
                  "pc_allow_local_network = true", "pc_minimal_env = false", "debug = false", "etw_audit = false"]
    else:
        raise DriverUnavailable(f"no OpenShell gateway driver {kind!r} on this platform")
    return "\n".join(lines) + "\n"


def service_spec(kind: str, *, gw: Path, port: int, root: Path, ident: dict) -> dict:
    """What the bootstrap runs: argv, environment, binaries to re-verify."""
    gateway_bin = inst.bin_path(root, ident, "openshell-gateway")
    env = {"XDG_CONFIG_HOME": str(gw / "xdg-config"), "XDG_STATE_HOME": str(gw / "state"),
           "XDG_DATA_HOME": str(gw / "data"), "OPENSHELL_SYSTEM_GATEWAY_DIR": str(gw / "cli-system")}
    argv = [str(gateway_bin), "--config", str(gw / "gateway.toml")]
    if kind == "docker":
        # Local mTLS from this gateway's own PKI (server cert, client CA, sandbox JWT key).
        env["OPENSHELL_LOCAL_TLS_DIR"] = str(gw / "pki")
    else:
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        env.update({"PATH": ";".join([sysroot + r"\System32", sysroot, sysroot + r"\System32\Wbem"]),
                    "SystemRoot": sysroot, "OPENSHELL_OCSF_JSON": "1", "OPENSHELL_OCSF_LOG_DIR": str(gw / "ocsf")})
        # Each sandbox's supervisor inherits these (the MXC driver starts it with the gateway's environment):
        # a policy update loads within ~2 s instead of the next 10 s poll, and a blocked request becomes a
        # proposal within ~2 s, so an answered card takes effect while the agent's turn still waits.
        env.update(SUPERVISOR_ENV)
        argv += ["--port", str(int(port)), "--log-level", "info"]
    # Part of the service's environment, so its hash in gateway.json changes with it: a gateway service an older
    # version of the plugin wrote is rewritten and restarted by the next ensure_gateway that finds no sandbox on it.
    env.update(TELEMETRY_OFF)
    verify = {str(inst.identity_dir(root, ident) / "bin" / n): sha for n, sha in (ident.get("binaries") or {}).items()
              if n.startswith("openshell-gateway") or n.startswith(("openshell-supervisor", "openshell-windows-sandbox"))
              or n == "libz3.dll"}
    return {"argv": argv, "env": env, "cwd": str(gw), "log": str(gw / "logs" / "gateway.log"), "verify": verify}


def ensure_registration(cli: Path, gw: Path, name: str, port: int, *, run=subprocess.run) -> Path:
    """Register the gateway with the CLI in this gateway's own config home (mTLS, local)."""
    gdir = gw / "cli" / "openshell" / "gateways" / name
    meta = _read_json(gdir / "metadata.json") or {}
    endpoint = f"https://127.0.0.1:{int(port)}"
    pki = gw / "pki"
    if meta.get("gateway_endpoint") == endpoint and meta.get("auth_mode") == "mtls" and \
            all((gdir / "mtls" / f).is_file() for f in ("ca.crt", "tls.crt", "tls.key")):
        return gdir
    if gdir.exists():
        _run_cli(cli, gw, name, "gateway", "remove", name, run=run, timeout=30)
        shutil.rmtree(gdir, ignore_errors=True)
    mtls = gdir / "mtls"
    mtls.mkdir(parents=True, exist_ok=True)
    for src, dst in (("ca.crt", "ca.crt"), ("client/tls.crt", "tls.crt"), ("client/tls.key", "tls.key")):
        shutil.copyfile(pki / src, mtls / dst)
    if os.name != "nt":
        for d in (gdir, mtls):
            d.chmod(0o700)
        (mtls / "tls.key").chmod(0o600)
    code, out = _run_cli(cli, gw, name, "gateway", "add", endpoint, "--local", "--name", name, run=run, timeout=60,
                         extra={"OPENSHELL_LOCAL_TLS_DIR": str(pki)})
    meta = _read_json(gdir / "metadata.json") or {}
    if code != 0 or meta.get("auth_mode") != "mtls":
        raise DriverUnavailable(f"registering the OpenShell gateway with its CLI failed ({code}): {out[-300:]}")
    return gdir


def health(cli: Path, gw: Path, name: str, port: int, *, run=subprocess.run) -> tuple[bool, str]:
    """Listening on loopback, and the CLI connects to it over mTLS."""
    if not port_open(port):
        return False, f"nothing listens on 127.0.0.1:{port}"
    code, out = _run_cli(cli, gw, name, "status", run=run, timeout=30)
    low = out.lower()
    ok = code == 0 and "connected" in low and "disconnected" not in low and "mtls" in low
    return ok, out[-300:]


def sandboxes(cli: Path, gw: Path, name: str, *, run=subprocess.run) -> Optional[list[str]]:
    """Sandbox names on the gateway, or None when they cannot be listed."""
    code, out = _run_cli(cli, gw, name, "sandbox", "list", run=run, timeout=60)
    if code != 0:
        return None
    names = []
    for line in out.splitlines():
        first = line.split()[0] if line.split() else ""
        if first.startswith("hermes-"):
            names.append(first)
    return names


# -- the service --------------------------------------------------------------------------------

def _definition(root: Path, runtime=None):
    from .login_service import ServiceDefinition, _root_tag

    if runtime is None:
        from .layout import current_runtime

        runtime = current_runtime()
    gw = gateway_dir(root)
    return ServiceDefinition(name=f"hermes-openshell-gateway-{_root_tag(Path(root))}", profile="",
                             python=_bootstrap_python(runtime), bootstrap=gw / "service" / BOOTSTRAP_FILE,
                             config=gw / "service" / SERVICE_FILE, cwd=gw, log=gateway_log(root),
                             env={}, args=[], description="Hermes OpenShell gateway")


def _bootstrap_python(runtime, os_name: Optional[str] = None) -> Path:
    """The interpreter the gateway's login service runs the (stdlib-only) bootstrap with. On Windows the
    base ``pythonw.exe``, not the venv's redirector: Task Scheduler's End stops only the process it
    started, and a redirector would leave the real interpreter (and the gateway) running."""
    from .login_service import background_python

    if (os_name or os.name) == "nt":
        base = getattr(runtime, "base_python", None)
        for candidate in ((Path(base) / "pythonw.exe") if base else None, (Path(base) / "python.exe") if base else None):
            if candidate is not None and candidate.is_file():
                return candidate
    return background_python(Path(runtime.python))


def service_state(root: Path, *, runtime=None, manager: Optional[Callable] = None) -> str:
    """What the login service manager says about this root's gateway service: ``running`` (also while the
    manager is starting it again), ``stopped`` or ``absent``. One question to the manager; nothing is started
    or changed (``gateway_watch`` asks when the gateway does not answer)."""
    from .login_service import manager_for

    return (manager or manager_for)(_definition(Path(root), runtime)).state()


def stop_runtime_processes(root: Path, only: Optional[Path] = None) -> list[str]:
    """Kill processes running this root's installed OpenShell binaries (``only``: one binary). Nothing
    outside ``<root>/openshell/runtime`` is touched. The fallback when a service manager's stop leaves
    the gateway (or what it started) running."""
    try:
        import psutil
    except ImportError:
        return []
    base = os.path.normcase(str(inst.runtime_dir(root).resolve())) + os.sep
    target = os.path.normcase(str(Path(only).resolve())) if only else None
    victims = []
    for p in psutil.process_iter(["pid", "exe", "name"]):
        exe = os.path.normcase(p.info.get("exe") or "")
        if exe and exe.startswith(base) and (target is None or exe == target):
            victims.append(p)
    for p in victims:
        try:
            p.kill()
        except psutil.Error:
            pass
    psutil.wait_procs(victims, timeout=10)
    return [f"{p.pid} {p.info.get('name')}" for p in victims]


def _write_service(gw: Path, spec: dict) -> None:
    folder = gw / "service"
    folder.mkdir(parents=True, exist_ok=True)
    (gw / "logs").mkdir(parents=True, exist_ok=True)
    (gw / "ocsf").mkdir(parents=True, exist_ok=True)
    (folder / BOOTSTRAP_FILE).write_text(BOOTSTRAP, encoding="utf-8")
    tmp = folder / (SERVICE_FILE + ".tmp")
    tmp.write_text(json.dumps(spec, indent=1), encoding="utf-8")
    os.replace(tmp, folder / SERVICE_FILE)


def telemetry_setting(root: Path) -> str:
    """What the gateway service starts OpenShell's own usage telemetry as: ``off`` (``TELEMETRY_OFF``), or ``on``
    for a service file an older version of the plugin wrote, until that gateway is next restarted. Read the way
    OpenShell reads the variable (unset means on)."""
    svc = _read_json(gateway_dir(root) / "service" / SERVICE_FILE) or {}
    value = str((svc.get("env") or {}).get("OPENSHELL_TELEMETRY_ENABLED", "true"))
    return "off" if value.strip().lower() in ("0", "false", "no", "off") else "on"


def _log_tail(gw: Path, lines: int = 6) -> str:
    try:
        text = (gw / "logs" / "gateway.log").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return " | ".join(l.strip()[-200:] for l in text[-lines:] if l.strip())


def kind_for(platform: Optional[str] = None) -> str:
    key = platform or inst.platform_key()
    if key == "linux":
        return "docker"
    if key == "windows":
        return "mxc"
    raise DriverUnavailable(f"no private OpenShell gateway for {key} yet (Linux and Windows only)")


def managed_defaults(root: Path, platform: Optional[str] = None) -> dict:
    """Where the managed gateway's CLI, registration and SDK are (no side effects): what
    ``config_from_spec`` uses when the spec names no gateway."""
    key = platform or inst.platform_key()
    gw = gateway_dir(root)
    state = _read_json(gw / GATEWAY_FILE) or {}
    active_id = (state.get("active") or {}).get("runtime_id")
    ident = inst.installed(root)
    if ident is None or (active_id and ident.get("id") != active_id):
        try:
            ident = {"id": active_id or inst.pinned(key)["id"], "platform": key, "sdk": key == "linux"}
        except DriverUnavailable:
            ident = {"id": "unavailable", "platform": key, "sdk": False}
    sdk = inst.identity_dir(root, ident) / "python" if key == "linux" else None
    return {"gateway": gateway_name(root), "config_home": gw / "cli", "cli": inst.bin_path(root, ident, "openshell"),
            "sdk_path": sdk, "root": Path(root)}


def ensure_gateway(root: Path, *, kind: Optional[str] = None, wxc_exec: Optional[Path] = None,
                   container_cli: Optional[str] = None, build_dir: Optional[Path] = None, runtime=None,
                   manager: Optional[Callable] = None, run=subprocess.run, fetch=None,
                   timeout: float = HEALTH_TIMEOUT, base_image: bool = True,
                   sleep: Callable[[float], None] = time.sleep) -> dict:
    """Install, configure, register, start and health-check this root's gateway; restart it on a new
    pinned runtime or config when no sandbox runs on it. Returns what the driver needs."""
    from .login_service import manager_for

    manager = manager or manager_for
    root = Path(root)
    kind = kind or kind_for()
    platform = "windows" if kind == "mxc" else "linux"
    with _locked(root):
        ident = inst.ensure_installed(root, platform=platform, build_dir=build_dir, container_cli=container_cli,
                                      fetch=fetch, run=run)
        gw = gateway_dir(root)
        inst._private_dir(gw)
        name = gateway_name(root)
        state = _read_json(gw / GATEWAY_FILE) or {}
        port = int(state.get("port") or os.environ.get(PORT_ENV) or free_port())
        gateway_bin = inst.bin_path(root, ident, "openshell-gateway")
        ensure_pki(gw, gateway_bin, run=run)
        config = render_config(kind, gw=gw, name=name, port=port, root=root, ident=ident, wxc_exec=wxc_exec)
        spec_for_service = service_spec(kind, gw=gw, port=port, root=root, ident=ident)
        desired = {"runtime_id": ident["id"], "config_sha256": hashlib.sha256(config.encode()).hexdigest(),
                   "port": port, "kind": kind,
                   # the service's environment counts too (supervisor tuning): a change restarts it when idle
                   "service_sha256": hashlib.sha256(json.dumps(spec_for_service["env"], sort_keys=True)
                                                    .encode()).hexdigest()}
        active = state.get("active")
        defn = _definition(root, runtime)
        service = manager(defn)
        upgrade_pending = False
        if active and active != desired:
            old = _active_ident(root, active)
            old_cli = inst.bin_path(root, old, "openshell") if old else None
            busy = None
            if old_cli is not None and old_cli.is_file() and health(old_cli, gw, name, int(active["port"]), run=run)[0]:
                busy = sandboxes(old_cli, gw, name, run=run)
                busy = busy if busy is not None else ["(unknown)"]
            if busy:
                upgrade_pending = True  # keep serving the running version; restart once it is idle
                return _result(root, gw, name, old, int(active["port"]), upgrade_pending=True, pending=desired,
                               sandboxes=busy, kind=kind, container_cli=container_cli, run=run, base_image=base_image)
        if active != desired:
            (gw / "gateway.toml").write_text(config, encoding="utf-8")
            _write_service(gw, service_spec(kind, gw=gw, port=port, root=root, ident=ident))
            state.update({"name": name, "port": port, "kind": kind, "active": desired,
                          "configured_at": time.time()})
            inst._write_json(gw / GATEWAY_FILE, state)
            try:
                if service.state() != "absent":
                    service.stop()
                if active and port_open(int(active.get("port") or port)):  # the old gateway outlived its service
                    old = _active_ident(root, active)
                    if old:
                        stop_runtime_processes(root, only=inst.bin_path(root, old, "openshell-gateway"))
                service.install()
                service.start()
            except Exception as exc:
                raise DriverUnavailable(f"could not start the OpenShell gateway as a login service: {exc}") from exc
        else:
            if not (gw / "service" / SERVICE_FILE).is_file():
                _write_service(gw, service_spec(kind, gw=gw, port=port, root=root, ident=ident))
            svc_state = service.state()
            if svc_state == "absent":
                service.install()
            if svc_state != "running" and not port_open(port):
                service.start()
        cli = inst.bin_path(root, ident, "openshell")
        _wait_healthy(root, gw, name, port, cli, service, timeout, run=run, sleep=sleep)
        inst.prune(root, keep={ident["id"]})
        return _result(root, gw, name, ident, port, kind=kind, container_cli=container_cli, run=run,
                       base_image=base_image)


def _active_ident(root: Path, active: dict) -> Optional[dict]:
    path = inst.runtime_dir(root) / str(active.get("runtime_id")) / inst.IDENTITY_FILE
    return _read_json(path)


def _wait_healthy(root: Path, gw: Path, name: str, port: int, cli: Path, service, timeout: float, *, run, sleep) -> None:
    start = time.monotonic()
    deadline = start + timeout
    registered = False
    detail = ""
    while time.monotonic() < deadline:
        if port_open(port):
            if not registered:
                ensure_registration(cli, gw, name, port, run=run)
                registered = True
            ok, detail = health(cli, gw, name, port, run=run)
            if ok:
                return
        elif time.monotonic() - start > 15 and service.state() != "running":
            raise DriverUnavailable(f"the OpenShell gateway service stopped before it listened on 127.0.0.1:{port}; "
                                    f"log: {_log_tail(gw)}")
        sleep(0.5)
    raise DriverUnavailable(f"the OpenShell gateway on 127.0.0.1:{port} is not healthy after {timeout:.0f}s "
                            f"({detail.strip()[-200:]}); log: {_log_tail(gw)}")


def _result(root: Path, gw: Path, name: str, ident: dict, port: int, *, kind: str, container_cli, run,
            base_image: bool, upgrade_pending: bool = False, pending=None, sandboxes=None) -> dict:
    out = {"gateway": name, "config_home": gw / "cli", "cli": inst.bin_path(root, ident, "openshell"),
           "sdk_path": inst.sdk_path(root, ident), "port": port, "endpoint": f"https://127.0.0.1:{port}",
           "runtime_id": ident["id"], "version": ident.get("version"), "kind": kind,
           "features": list(ident.get("features") or []), "upgrade_pending": upgrade_pending}
    if pending:
        out["pending"] = pending
    if sandboxes:
        out["sandboxes"] = sandboxes
    if kind == "docker" and base_image:
        from .base_image import ensure_base_image

        out["image"] = ensure_base_image(root, container_cli, run=run)["tag"]
    return out


# -- who uses it, removal -----------------------------------------------------------------------

def profiles_in_use(root: Path, *, leaving: Optional[str] = None) -> list[str]:
    """Profiles whose sandbox switch is on (a login service definition exists) or whose launcher is
    running in the foreground. ``leaving`` is the profile being switched off right now."""
    base = Path(root) / "openshell"
    users = []
    if not base.is_dir():
        return users
    for child in sorted(base.iterdir()):
        if not child.is_dir() or child.name in STATE_ROOT_SKIP or child.name == leaving:
            continue
        if (child / "service" / "service.json").is_file():
            users.append(child.name)
            continue
        state = _read_json(child / "state.json")
        if state and _launcher_alive(state):
            users.append(child.name)
    return users


def _launcher_alive(state: dict) -> bool:
    from .login_service import launcher_state_alive

    return launcher_state_alive(state)


def release_if_unused(root: Path, *, leaving: Optional[str] = None, runtime=None,
                      manager: Optional[Callable] = None, run=subprocess.run) -> dict:
    """Remove the gateway when no profile is sandboxed any more (called when a profile's login
    service is removed). The installed runtime and the base image stay as a cache."""
    root = Path(root)
    gw = gateway_dir(root)
    if not gw.exists():
        return {"removed": False, "reason": "no gateway"}
    with _locked(root):
        users = profiles_in_use(root, leaving=leaving)
        if users:
            return {"removed": False, "in_use": users}
        return _remove(root, runtime=runtime, manager=manager, run=run)


def remove_gateway(root: Path, *, force: bool = False, runtime=None, manager: Optional[Callable] = None,
                   run=subprocess.run) -> dict:
    """``hermes sandbox gateway remove``: refuses while a profile uses it unless forced."""
    root = Path(root)
    with _locked(root):
        users = profiles_in_use(root)
        if users and not force:
            raise DriverUnavailable(f"the OpenShell gateway is in use by: {', '.join(users)}; switch them off first")
        return _remove(root, runtime=runtime, manager=manager, run=run)


def _remove(root: Path, *, runtime=None, manager=None, run=subprocess.run) -> dict:
    from .login_service import manager_for

    manager = manager or manager_for
    gw = gateway_dir(root)
    state = _read_json(gw / GATEWAY_FILE) or {}
    name = state.get("name") or gateway_name(root)
    deleted = []
    ident = _active_ident(root, state.get("active") or {}) if state.get("active") else None
    cli = inst.bin_path(root, ident, "openshell") if ident else None
    port = int(state.get("port") or 0)
    if cli is not None and cli.is_file() and port and port_open(port):
        for sb in sandboxes(cli, gw, name, run=run) or []:  # a crashed launcher's leftovers
            _run_cli(cli, gw, name, "sandbox", "delete", sb, run=run, timeout=120)
            deleted.append(sb)
    (gw / "service" / SERVICE_FILE).unlink(missing_ok=True)  # off on disk first: a restart starts nothing
    service = manager(_definition(root, runtime))
    errors = []
    for step in (service.stop, service.uninstall):
        try:
            step()
        except Exception as exc:
            errors.append(str(exc))
    for _ in range(40):
        if not port or not port_open(port):
            break
        time.sleep(0.25)
    else:  # the service manager stopped its process but not the gateway: end ours (runtime binaries only)
        errors.append(f"gateway still listening after the service stopped; killed {stop_runtime_processes(root)}")
    shutil.rmtree(gw, ignore_errors=True)
    if gw.exists():  # Windows: a file still held open by an exiting process
        time.sleep(2.0)
        shutil.rmtree(gw, ignore_errors=True)
    return {"removed": not gw.exists(), "gateway": name, "service": service.kind, "sandboxes_deleted": deleted,
            "errors": errors, "kept": [str(p) for p in sorted(inst.runtime_dir(root).glob("*"))
                                       if p.name not in (".gateway.lock",)]}


def gateway_status(root: Path, *, runtime=None, manager: Optional[Callable] = None, run=subprocess.run) -> dict:
    from .login_service import manager_for

    root = Path(root)
    manager = manager or manager_for
    gw = gateway_dir(root)
    state = _read_json(gw / GATEWAY_FILE)
    ident = inst.installed(root)
    out = {"root": str(root), "runtime": ident and {k: ident.get(k) for k in ("id", "version", "platform", "arch",
                                                                              "source", "signer", "signature")},
           "pinned": None, "gateway": None, "profiles_in_use": profiles_in_use(root)}
    try:
        out["pinned"] = inst.pinned()["id"]
    except DriverUnavailable as exc:
        out["pinned"] = str(exc)
    image = _read_json(inst.runtime_dir(root) / "base-image.json")
    if image:
        out["base_image"] = image
    if state:
        active = state.get("active") or {}
        service = manager(_definition(root, runtime))
        a_ident = _active_ident(root, active)
        cli = inst.bin_path(root, a_ident, "openshell") if a_ident else None
        ok, detail = health(cli, gw, state["name"], int(state["port"]), run=run) if cli and cli.is_file() \
            else (False, "runtime missing")
        out["gateway"] = {"name": state.get("name"), "port": state.get("port"), "kind": state.get("kind"),
                          "runtime_id": active.get("runtime_id"), "service": service.kind,
                          "service_state": service.state(), "healthy": ok, "detail": detail,
                          "dir": str(gw), "openshell_telemetry": telemetry_setting(root)}
        if ok:
            out["gateway"]["sandboxes"] = sandboxes(cli, gw, state["name"], run=run)
    return out
