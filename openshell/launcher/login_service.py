"""Run one profile's sandbox launcher as a per-user login service.

The launcher (``hermes sandbox serve --service``) must outlive whatever turned the sandbox on: a
host gateway that started it would take it down when it exits after idle. So the switch registers it
with the OS's per-user service manager, which starts it now and again at every login:

* Windows: a Task Scheduler task with a logon trigger for the current user, running as that user
  with least privilege (registered from XML; no admin rights needed).
* Linux: a ``systemd --user`` unit, enabled for ``default.target``.
* macOS: a LaunchAgent in ``~/Library/LaunchAgents`` (``RunAtLoad``), loaded into ``gui/<uid>``.

Every manager runs the same command: this install's Python on a small stdlib-only bootstrap kept in
the profile's host-only state folder (``<hermes root>/openshell/<profile>/service/``, denied to the
sandbox), which reads ``service.json`` beside it for the environment, working folder and arguments,
and runs ``hermes_cli.main`` in-process. A Task Scheduler action cannot carry environment variables,
and one definition keeps the three managers alike. No ``service.json`` means the switch is off: the
bootstrap exits without starting anything, so a registration left behind by a crash never brings
the sandbox back on its own.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

SERVICE_DIRNAME = "service"
SERVICE_FILE = "service.json"
BOOTSTRAP_FILE = "bootstrap.py"
LAUNCHER_LOG = "launcher.log"
# Carried from the process that turns the switch on into the service's environment. Nothing else:
# a scheduled task starts with the login environment, not the desktop's or the gateway's.
_CARRIED_ENV = ("HERMES_RUNTIME_DIR", "HERMES_SHARED_AUTH_DIR", "HERMES_DISABLE_LAZY_INSTALLS",
                "HERMES_GATEWAY_LOCK_DIR", "OPENSHELL_BUSYBOX", "OPENSHELL_WXC_EXEC_PATH",
                "PYTHONUTF8", "PYTHONIOENCODING",
                # the managed OpenShell gateway (gateway_service.py): Windows build dir, fixed port
                "HERMES_OPENSHELL_BUILD_DIR", "HERMES_OPENSHELL_GATEWAY_PORT")

BOOTSTRAP = '''\
"""Starts one profile's sandbox launcher for the OS login service (written by the openshell plugin).
Reads service.json beside this file; without it the switch is off and nothing starts."""
import json, os, runpy, sys

here = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(here, "service.json"), encoding="utf-8") as fh:
        cfg = json.load(fh)
except FileNotFoundError:
    sys.exit(0)
log = cfg.get("log")
if log:
    try:
        if os.path.getsize(log) > 2_000_000:
            os.replace(log, log + ".1")
    except OSError:
        pass
    sys.stdout = sys.stderr = open(log, "a", encoding="utf-8", buffering=1)
if os.name == "nt":
    # pythonw has no console, so every console program the launcher starts (the OpenShell CLI, git run by
    # Hermes code, anything else) would get a new one, which Windows 11 opens as a Windows Terminal window
    # on the user's desktop. Share a console that has no window instead: a helper started with
    # CREATE_NO_WINDOW owns one, this process attaches to it, the helper exits, and children inherit it.
    import ctypes, subprocess, time
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not k32.GetConsoleCP():
        try:
            helper = subprocess.Popen([os.path.join(os.environ.get("SystemRoot", "C:/Windows"), "System32", "cmd.exe"),
                                       "/d", "/q", "/k"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, creationflags=0x08000000)
        except OSError as exc:
            print("launcher: no hidden console helper (%s)" % exc, flush=True)
        else:
            for _ in range(250):
                if k32.AttachConsole(helper.pid) or helper.poll() is not None:
                    break
                time.sleep(0.02)
            helper.stdin.close()
            try:
                helper.wait(10)
            except subprocess.TimeoutExpired:
                helper.kill()
        if not k32.GetConsoleCP():
            print("launcher: running without a hidden console; console programs may open windows", flush=True)
os.environ.update(cfg.get("env") or {})
for entry in reversed([p for p in (cfg.get("env") or {}).get("PYTHONPATH", "").split(os.pathsep) if p]):
    if entry not in sys.path:
        sys.path.insert(0, entry)
if cfg.get("cwd"):
    os.chdir(cfg["cwd"])
sys.argv = ["hermes", *cfg["args"]]
runpy.run_module("hermes_cli.main", run_name="__main__", alter_sys=True)
'''


class ServiceError(RuntimeError):
    """The OS service manager refused a step."""


Runner = Callable[..., subprocess.CompletedProcess]


def _root_tag(root: Path) -> str:
    """Eight hex digits naming the Hermes root, so two roots' services for one profile never collide."""
    return hashlib.sha256(os.path.normcase(str(root)).encode("utf-8")).hexdigest()[:8]


def service_dir(layout) -> Path:
    return layout.state_dir / SERVICE_DIRNAME


def service_file(layout) -> Path:
    return service_dir(layout) / SERVICE_FILE


def launcher_log(layout) -> Path:
    return layout.state_dir / LAUNCHER_LOG


def switched_on(layout) -> bool:
    """Whether the switch is on for this profile: the service definition exists."""
    return service_file(layout).is_file()


def process_start_ticks(pid: int) -> Optional[int]:
    """When the kernel started *pid*, in clock ticks since boot (field 22 of ``/proc/<pid>/stat``); None where
    there is no such file (Windows, macOS) or no such process. Unlike a creation time, it never moves with the
    wall clock."""
    try:
        with open(f"/proc/{int(pid)}/stat", "rb") as fh:
            return int(fh.read().rsplit(b")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def launcher_state_alive(state: Optional[dict]) -> bool:
    """Whether the process a launcher's ``state.json`` names still runs AS that launcher. A launcher that was
    killed leaves its state file behind, and Windows hands its PID to the next process soon after; a process
    created after the launcher wrote its state (``since``) is not the launcher. On Linux the creation time psutil
    reports is the boot time plus the process's start stamp, and the boot time moves when the wall clock is
    stepped or drifts (a VM), so a state file that names the start stamp itself (``start_ticks``) is judged by
    that: the same stamp is the same process."""
    if not isinstance(state, dict):
        return False
    try:
        pid = int(state.get("pid") or 0)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        import psutil
    except ImportError:  # pragma: no cover - psutil ships with Hermes
        return True
    try:
        proc = psutil.Process(pid)
        if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
            return False
        ticks = state.get("start_ticks")
        if ticks is not None:
            now = process_start_ticks(pid)
            if now is not None:
                return now == ticks
        since = state.get("since")
        return since is None or proc.create_time() <= float(since) + 2.0
    except (psutil.Error, OSError, TypeError, ValueError):
        return False


def background_python(python: Path) -> Path:
    """The interpreter a login service runs: ``pythonw.exe`` beside ``python.exe`` on Windows (no
    console window at login), else the interpreter itself."""
    if os.name == "nt" and python.name.lower() == "python.exe":
        windowed = python.with_name("pythonw.exe")
        if windowed.is_file():
            return windowed
    return python


def service_env(layout, runtime, environ: Optional[dict] = None) -> dict:
    environ = os.environ if environ is None else environ
    env = {k: environ[k] for k in _CARRIED_ENV if environ.get(k)}
    paths = [str(runtime.code_dir), *[p for p in environ.get("PYTHONPATH", "").split(os.pathsep) if p]]
    env.update({"HERMES_HOME": str(layout.home), "PYTHONPATH": os.pathsep.join(dict.fromkeys(paths)),
                "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    return env


@dataclass
class ServiceDefinition:
    """What the login service runs, as written to the host-only state folder."""

    name: str
    profile: str
    python: Path
    bootstrap: Path
    config: Path
    cwd: Path
    log: Path
    env: dict = field(default_factory=dict)
    args: list = field(default_factory=lambda: ["sandbox", "serve", "--service"])
    description: Optional[str] = None  # default: "Hermes sandbox for profile <profile>"
    # The Hermes root of a profile's launcher service: removing that service releases the root's
    # shared OpenShell gateway once no profile uses it (gateway_service.release_if_unused).
    root: Optional[Path] = None

    @property
    def argv(self) -> list[str]:
        return [str(self.python), str(self.bootstrap), str(self.config)]

    @property
    def summary(self) -> str:
        return self.description or f"Hermes sandbox for profile {self.profile}"


def define(layout, runtime, environ: Optional[dict] = None) -> ServiceDefinition:
    """The service for *layout*'s launcher, run by this install's interpreter (not written yet)."""
    folder = service_dir(layout)
    return ServiceDefinition(
        name=f"hermes-sandbox-{layout.name}-{_root_tag(layout.root)}", profile=layout.name,
        python=background_python(Path(runtime.python)), bootstrap=folder / BOOTSTRAP_FILE,
        config=folder / SERVICE_FILE, cwd=Path(runtime.code_dir), log=launcher_log(layout),
        env=service_env(layout, runtime, environ), root=Path(layout.root))


def write_definition(defn: ServiceDefinition) -> None:
    """Write the bootstrap and ``service.json`` (atomically; the json last, since it turns the switch on)."""
    defn.config.parent.mkdir(parents=True, exist_ok=True)
    defn.bootstrap.write_text(BOOTSTRAP, encoding="utf-8")
    data = {"profile": defn.profile, "env": defn.env, "cwd": str(defn.cwd), "args": list(defn.args),
            "log": str(defn.log)}
    tmp = defn.config.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    os.replace(tmp, defn.config)


def remove_definition(layout) -> None:
    """Turn the switch off on disk: without ``service.json`` the bootstrap starts nothing."""
    service_file(layout).unlink(missing_ok=True)


# -- service managers ------------------------------------------------------------------------------

class LoginService:
    """One registration with the OS's per-user service manager."""

    kind = "none"

    def __init__(self, defn: ServiceDefinition, runner: Runner = subprocess.run):
        self.defn = defn
        self._runner = runner

    def _run(self, *cmd, check: bool = True) -> subprocess.CompletedProcess:
        try:
            result = self._runner(list(cmd), capture_output=True, text=True, timeout=60,
                                  **({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}))
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ServiceError(f"{cmd[0]} failed: {exc}") from exc
        if check and result.returncode != 0:
            detail = " ".join(((result.stderr or "") + " " + (result.stdout or "")).split())
            raise ServiceError(f"{' '.join(str(c) for c in cmd[:3])} exited with {result.returncode}: {detail[-300:]}")
        return result

    def install(self) -> None:
        raise NotImplementedError

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def uninstall(self) -> None:
        raise NotImplementedError

    def state(self) -> str:
        """``running``, ``stopped`` or ``absent`` (not registered)."""
        raise NotImplementedError

    def _after_uninstall(self) -> None:
        """A profile's launcher service is gone: release the root's shared OpenShell gateway if no
        other profile uses it. Best effort; never fails the switch (the gateway stays, and the next
        switch-off or ``hermes sandbox gateway remove`` retries)."""
        if self.defn.root is None or not self.defn.profile:
            return
        try:
            from .gateway_service import release_if_unused

            release_if_unused(self.defn.root, leaving=self.defn.profile)
        except Exception as exc:  # noqa: BLE001
            try:
                with open(self.defn.log, "a", encoding="utf-8") as fh:
                    fh.write(f"hermes sandbox: could not release the OpenShell gateway: {exc}\n")
            except OSError:
                pass


def _xml(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def windows_user_id() -> str:
    domain, user = os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", "")
    if not user:
        import getpass

        user = getpass.getuser()
    return f"{domain}\\{user}" if domain else user


class WindowsTask(LoginService):
    """A Task Scheduler task: logon trigger for this user, interactive token, least privilege, no time
    limit, restarted on failure. ``schtasks /End`` kills the task's whole process tree at once (the
    launcher's Job Object then ends the sandbox), so callers ask the launcher to stop first and keep
    ``/End`` as the fallback. ``schtasks /Delete`` leaves a running instance alone, which lets the
    launcher unregister itself during its own teardown."""

    kind = "windows-task"
    FOLDER = "Hermes"

    @property
    def task_name(self) -> str:
        return f"{self.FOLDER}\\{self.defn.name}"

    def task_xml(self, user: Optional[str] = None) -> str:
        user = _xml(user or windows_user_id())
        args = subprocess.list2cmdline([str(self.defn.bootstrap), str(self.defn.config)])
        return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>{_xml(self.defn.summary)}</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{_xml(str(self.defn.python))}</Command><Arguments>{_xml(args)}</Arguments><WorkingDirectory>{_xml(str(self.defn.cwd))}</WorkingDirectory></Exec></Actions>
</Task>
"""

    def install(self) -> None:
        path = self.defn.config.parent / "task.xml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.task_xml(), encoding="utf-16")
        try:
            self._run("schtasks", "/Create", "/TN", self.task_name, "/XML", str(path), "/F")
        finally:
            path.unlink(missing_ok=True)

    def start(self) -> None:
        self._run("schtasks", "/Run", "/TN", self.task_name)

    def stop(self) -> None:
        if self.state() == "running":
            self._run("schtasks", "/End", "/TN", self.task_name)

    def uninstall(self) -> None:
        if self.state() != "absent":
            self._run("schtasks", "/Delete", "/TN", self.task_name, "/F")
        self._after_uninstall()

    def state(self) -> str:
        result = self._run("schtasks", "/Query", "/TN", self.task_name, "/FO", "CSV", "/NH", check=False)
        if result.returncode != 0:
            return "absent"
        return "running" if '"Running"' in (result.stdout or "") else "stopped"


def _systemd_quote(arg: str) -> str:
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def running_inside_unit(unit: str, runner: Runner = subprocess.run, pid: Optional[int] = None) -> bool:
    """Whether this process is systemd unit *unit*'s main process. The bootstrap runs the launcher in its own
    process, so a launcher serving as the login service is its unit's MainPID. Asked of systemd itself: reading
    the process's cgroup file instead makes Hermes's install scan rate the whole plugin 'caution' (process
    introspection), which blocks `hermes plugins install` from any source outside the catalog."""
    try:
        done = runner(["systemctl", "--user", "show", "--property=MainPID", "--value", unit],
                      capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    value = (done.stdout or "").strip()
    return done.returncode == 0 and value.isdigit() and int(value) == (os.getpid() if pid is None else pid)


class SystemdUser(LoginService):
    """A ``systemd --user`` unit, enabled for ``default.target`` (starts at login), restarted on failure."""

    kind = "systemd-user"

    def __init__(self, defn: ServiceDefinition, runner: Runner = subprocess.run, unit_dir: Optional[Path] = None):
        super().__init__(defn, runner)
        config_home = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        self.unit_dir = unit_dir or config_home / "systemd" / "user"

    @property
    def unit(self) -> str:
        return f"{self.defn.name}.service"

    @property
    def unit_path(self) -> Path:
        return self.unit_dir / self.unit

    def unit_text(self) -> str:
        exec_start = " ".join(_systemd_quote(a) for a in self.defn.argv)
        return (f"[Unit]\nDescription={self.defn.summary}\n\n"
                # WorkingDirectory takes the path as is (no quote removal; '%' starts a specifier)
                f"[Service]\nType=simple\nExecStart={exec_start}\nWorkingDirectory={str(self.defn.cwd).replace('%', '%%')}\n"
                "Restart=on-failure\nRestartSec=5\nKillMode=mixed\nTimeoutStopSec=30\n\n"
                "[Install]\nWantedBy=default.target\n")

    def install(self) -> None:
        self.unit_dir.mkdir(parents=True, exist_ok=True)
        self.unit_path.write_text(self.unit_text(), encoding="utf-8")
        self._run("systemctl", "--user", "daemon-reload")
        self._run("systemctl", "--user", "enable", self.unit)

    def start(self) -> None:
        self._run("systemctl", "--user", "start", self.unit)

    def stop(self) -> None:
        self._run("systemctl", "--user", "stop", self.unit, check=False)

    def uninstall(self) -> None:
        if self.unit_path.exists():
            # A launcher removing its own unit (the switch's off route) must not have systemd stop it
            # mid-request: disable only; the launcher exits cleanly right after, and Restart=on-failure
            # does not bring it back.
            inside = running_inside_unit(self.unit)
            self._run("systemctl", "--user", "disable", *([] if inside else ["--now"]), self.unit, check=False)
            self.unit_path.unlink(missing_ok=True)
            self._run("systemctl", "--user", "daemon-reload", check=False)
        self._after_uninstall()

    def state(self) -> str:
        if not self.unit_path.exists():
            return "absent"
        result = self._run("systemctl", "--user", "is-active", self.unit, check=False)
        return "running" if (result.stdout or "").strip() in ("active", "activating", "reloading") else "stopped"


class LaunchAgent(LoginService):
    """A LaunchAgent (``RunAtLoad``, kept alive after a crash), loaded into the user's GUI domain."""

    kind = "launch-agent"

    def __init__(self, defn: ServiceDefinition, runner: Runner = subprocess.run, agent_dir: Optional[Path] = None,
                 uid: Optional[int] = None):
        super().__init__(defn, runner)
        self.agent_dir = agent_dir or Path.home() / "Library" / "LaunchAgents"
        self.uid = os.getuid() if uid is None and hasattr(os, "getuid") else (uid or 0)

    @property
    def label(self) -> str:
        return f"com.nousresearch.{self.defn.name}"

    @property
    def plist_path(self) -> Path:
        return self.agent_dir / f"{self.label}.plist"

    @property
    def domain(self) -> str:
        return f"gui/{self.uid}"

    def plist(self) -> dict:
        return {"Label": self.label, "ProgramArguments": self.defn.argv, "WorkingDirectory": str(self.defn.cwd),
                "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False}, "ProcessType": "Background",
                "StandardOutPath": str(self.defn.log), "StandardErrorPath": str(self.defn.log)}

    def install(self) -> None:
        self.agent_dir.mkdir(parents=True, exist_ok=True)
        with open(self.plist_path, "wb") as fh:
            plistlib.dump(self.plist(), fh)

    def start(self) -> None:
        if self._run("launchctl", "print", f"{self.domain}/{self.label}", check=False).returncode != 0:
            self._run("launchctl", "bootstrap", self.domain, str(self.plist_path))
        self._run("launchctl", "kickstart", f"{self.domain}/{self.label}")

    def stop(self) -> None:
        self._run("launchctl", "bootout", f"{self.domain}/{self.label}", check=False)

    def uninstall(self) -> None:
        self.stop()
        self.plist_path.unlink(missing_ok=True)
        self._after_uninstall()

    def state(self) -> str:
        if not self.plist_path.exists():
            return "absent"
        result = self._run("launchctl", "print", f"{self.domain}/{self.label}", check=False)
        return "running" if result.returncode == 0 and "state = running" in (result.stdout or "") else "stopped"


def manager_for(defn: ServiceDefinition, runner: Runner = subprocess.run, platform: Optional[str] = None) -> LoginService:
    platform = platform or sys.platform
    if platform.startswith("win"):
        return WindowsTask(defn, runner)
    if platform == "darwin":
        return LaunchAgent(defn, runner)
    return SystemdUser(defn, runner)
