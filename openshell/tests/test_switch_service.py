"""The Sandbox switch's login service: definitions for Windows (Task Scheduler), Linux (systemd --user)
and macOS (LaunchAgent), the commands each manager runs, and the bootstrap they all start.

The managers run against a recording runner; nothing is registered with the real OS here.
"""
import json
import os
import plistlib
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import pytest

from openshell.launcher import login_service as LS
from openshell.launcher.layout import ProfileLayout


@dataclass
class FakeRuntime:
    python: Path
    code_dir: Path


class Recorder:
    """A subprocess.run stand-in: records argv, answers from a table of (prefix -> CompletedProcess)."""

    def __init__(self, answers=None):
        self.calls: list[list[str]] = []
        self.answers = answers or {}

    def __call__(self, cmd, **kwargs):
        self.calls.append([str(c) for c in cmd])
        for prefix, (code, out) in self.answers.items():
            if tuple(str(c) for c in cmd[:len(prefix)]) == prefix:
                return subprocess.CompletedProcess(cmd, code, out, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.fixture
def layout(tmp_path):
    root = tmp_path / "hermes root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    return ProfileLayout(name="work", home=home, root=root)


@pytest.fixture
def defn(layout, tmp_path):
    code = tmp_path / "code dir"
    code.mkdir()
    py = tmp_path / "venv" / "python.exe"
    return LS.define(layout, FakeRuntime(python=py, code_dir=code),
                     environ={"HERMES_RUNTIME_DIR": "R", "OPENSHELL_BUSYBOX": "B", "OPENAI_API_KEY": "sk-secret",
                              "HERMES_DASHBOARD_SESSION_TOKEN": "tok", "PYTHONPATH": "extra"})


def test_definition_lives_in_host_only_state_and_carries_no_secrets(defn, layout):
    assert defn.config == layout.state_dir / "service" / "service.json"
    assert defn.bootstrap.parent == defn.config.parent
    assert defn.env["HERMES_HOME"] == str(layout.home)
    assert defn.env["PYTHONPATH"].split(os.pathsep)[0] == str(defn.cwd)
    assert "extra" in defn.env["PYTHONPATH"].split(os.pathsep)
    assert defn.env["HERMES_RUNTIME_DIR"] == "R" and defn.env["OPENSHELL_BUSYBOX"] == "B"
    assert "OPENAI_API_KEY" not in defn.env and "HERMES_DASHBOARD_SESSION_TOKEN" not in defn.env
    assert defn.args == ["sandbox", "serve", "--service"]
    # Two roots never share a service name for the same profile.
    other = ProfileLayout(name="work", home=layout.home, root=layout.root.parent / "other")
    assert LS.define(other, FakeRuntime(Path("p"), Path("c"))).name != defn.name


def test_write_and_remove_definition_is_the_switch_on_disk(defn, layout):
    assert not LS.switched_on(layout)
    LS.write_definition(defn)
    assert LS.switched_on(layout)
    data = json.loads(defn.config.read_text(encoding="utf-8"))
    assert data["args"] == defn.args and data["env"]["HERMES_HOME"] == str(layout.home)
    assert defn.bootstrap.read_text(encoding="utf-8") == LS.BOOTSTRAP
    LS.remove_definition(layout)
    assert not LS.switched_on(layout) and defn.bootstrap.exists()


def test_bootstrap_runs_hermes_main_with_the_saved_environment(tmp_path, layout):
    """The real bootstrap, in a child interpreter, against a stand-in hermes_cli.main."""
    fake = tmp_path / "fakecore" / "hermes_cli"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("", encoding="utf-8")
    out = tmp_path / "seen.json"
    (fake / "main.py").write_text(
        "import json, os, sys\n"
        f"json.dump({{'argv': sys.argv, 'home': os.environ.get('HERMES_HOME'), 'cwd': os.getcwd()}}, "
        f"open({str(out)!r}, 'w'))\n", encoding="utf-8")
    defn = LS.define(layout, FakeRuntime(python=Path(sys.executable), code_dir=fake.parent), environ={})
    LS.write_definition(defn)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("HERMES_", "PYTHON"))}
    subprocess.run([sys.executable, str(defn.bootstrap), str(defn.config)], check=True, env=env, timeout=60)
    seen = json.loads(out.read_text(encoding="utf-8"))
    assert seen["argv"][1:] == ["sandbox", "serve", "--service"]
    assert seen["home"] == str(layout.home)
    assert os.path.normcase(seen["cwd"]) == os.path.normcase(str(fake.parent))
    assert defn.log.is_file()  # output goes to the host-only launcher log
    # Switch off: the same registration starts nothing.
    out.unlink()
    LS.remove_definition(layout)
    subprocess.run([sys.executable, str(defn.bootstrap), str(defn.config)], check=True, env=env, timeout=60)
    assert not out.exists()


def test_windows_task_is_a_least_privilege_logon_task_for_this_user(defn):
    task = LS.WindowsTask(defn, Recorder())
    root = ET.fromstring(task.task_xml(user="HOST\\user").replace('encoding="UTF-16"', ""))
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    assert root.find("t:Triggers/t:LogonTrigger/t:UserId", ns).text == "HOST\\user"
    principal = root.find("t:Principals/t:Principal", ns)
    assert principal.find("t:LogonType", ns).text == "InteractiveToken"
    assert principal.find("t:RunLevel", ns).text == "LeastPrivilege"
    assert root.find("t:Settings/t:ExecutionTimeLimit", ns).text == "PT0S"
    assert root.find("t:Settings/t:MultipleInstancesPolicy", ns).text == "IgnoreNew"
    exec_ = root.find("t:Actions/t:Exec", ns)
    assert exec_.find("t:Command", ns).text == str(defn.python)
    assert exec_.find("t:Arguments", ns).text == subprocess.list2cmdline([str(defn.bootstrap), str(defn.config)])
    assert exec_.find("t:WorkingDirectory", ns).text == str(defn.cwd)


def test_windows_task_commands(defn):
    rec = Recorder({("schtasks", "/Query"): (0, '"\\Hermes\\x","N/A","Running"\r\n')})
    task = LS.WindowsTask(defn, rec)
    task.install()
    task.start()
    assert task.state() == "running"
    task.stop()
    task.uninstall()
    verbs = [c[1] for c in rec.calls]
    assert verbs == ["/Create", "/Run", "/Query", "/Query", "/End", "/Query", "/Delete"]
    create = rec.calls[0]
    assert create[create.index("/TN") + 1] == f"Hermes\\{defn.name}" and "/XML" in create
    assert not (defn.config.parent / "task.xml").exists()  # the XML is not left behind
    absent = LS.WindowsTask(defn, Recorder({("schtasks", "/Query"): (1, "")}))
    assert absent.state() == "absent"
    absent.uninstall()  # nothing to delete: no /Delete call
    assert [c[1] for c in absent._runner.calls] == ["/Query", "/Query"]


def test_windows_service_errors_name_the_step(defn):
    task = LS.WindowsTask(defn, Recorder({("schtasks", "/Create"): (1, "ERROR: Access is denied.")}))
    with pytest.raises(LS.ServiceError, match="Access is denied"):
        task.install()


def test_systemd_user_unit_and_commands(defn, tmp_path, monkeypatch):
    rec = Recorder({("systemctl", "--user", "is-active"): (0, "active\n")})
    # Removing a unit first asks systemd whether this process is the unit's own, through a runner of its own.
    monkeypatch.setattr(LS, "running_inside_unit", lambda unit: False)
    unit = LS.SystemdUser(defn, rec, unit_dir=tmp_path / "units")
    unit.install()
    text = unit.unit_path.read_text(encoding="utf-8")
    assert "WantedBy=default.target" in text and "Restart=on-failure" in text
    assert f'ExecStart="{str(defn.python)}" ' .replace("\\", "\\\\") in text
    unit.start()
    assert unit.state() == "running"
    unit.stop()
    unit.uninstall()
    assert not unit.unit_path.exists()
    assert rec.calls == [
        ["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", unit.unit],
        ["systemctl", "--user", "start", unit.unit], ["systemctl", "--user", "is-active", unit.unit],
        ["systemctl", "--user", "stop", unit.unit], ["systemctl", "--user", "disable", "--now", unit.unit],
        ["systemctl", "--user", "daemon-reload"]]
    assert LS.SystemdUser(defn, rec, unit_dir=tmp_path / "none").state() == "absent"


def test_launch_agent_plist_and_commands(defn, tmp_path):
    rec = Recorder({("launchctl", "print"): (0, "state = running\n")})
    agent = LS.LaunchAgent(defn, rec, agent_dir=tmp_path / "agents", uid=501)
    agent.install()
    with open(agent.plist_path, "rb") as fh:
        plist = plistlib.load(fh)
    assert plist["ProgramArguments"] == defn.argv and plist["RunAtLoad"] is True
    assert plist["KeepAlive"] == {"SuccessfulExit": False}
    assert plist["StandardErrorPath"] == str(defn.log)
    agent.start()  # already loaded: kickstart only
    assert agent.state() == "running"
    agent.uninstall()
    assert not agent.plist_path.exists()
    assert ["launchctl", "kickstart", f"gui/501/{agent.label}"] in rec.calls
    assert ["launchctl", "bootout", f"gui/501/{agent.label}"] in rec.calls
    fresh = Recorder({("launchctl", "print"): (113, "")})
    LS.LaunchAgent(defn, fresh, agent_dir=tmp_path / "agents2", uid=501).start()
    assert fresh.calls[1][:2] == ["launchctl", "bootstrap"]


def test_manager_for_each_platform(defn):
    assert isinstance(LS.manager_for(defn, platform="win32"), LS.WindowsTask)
    assert isinstance(LS.manager_for(defn, platform="linux"), LS.SystemdUser)
    assert isinstance(LS.manager_for(defn, platform="darwin"), LS.LaunchAgent)


def test_background_python_prefers_pythonw_on_windows(tmp_path):
    py = tmp_path / "python.exe"
    py.write_text("")
    if os.name == "nt":
        assert LS.background_python(py) == py
        (tmp_path / "pythonw.exe").write_text("")
        assert LS.background_python(py) == tmp_path / "pythonw.exe"
    else:
        assert LS.background_python(py) == py
