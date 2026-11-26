"""A test run never reaches the computer's service manager (``no_service_manager``, wired in ``conftest.py``).

Every manager of the login service runs its program through a runner, ``subprocess.run`` unless it is given another.
A test that leaves that default in place is stopped before the program starts, whichever system runs the tests.
Only the first test here asks for a program at all; the others hand the guard the announcement that comes before
a start.
"""
import re
import subprocess

import pytest

import no_service_manager
from openshell.launcher import login_service as LS
from test_switch_service import Recorder, defn, layout  # noqa: F401  (a service definition in a temporary root)

STOPPED = no_service_manager.ReachedServiceManager


def test_a_manager_with_the_default_runner_stops_the_test_before_its_program_runs(defn, service_manager_guard):  # noqa: F811
    with pytest.raises(STOPPED) as stop:
        LS.manager_for(defn, platform="win32").state()
    assert "a test reached the computer's service manager: `schtasks /Query /TN " in str(stop.value)
    assert str(stop.value).endswith("was about to run; give the test a runner or a manager of its own")
    assert len(service_manager_guard.calls) == 1 and service_manager_guard.calls[0].startswith("schtasks /Query /TN ")
    assert service_manager_guard.report().startswith("the test reached the computer's service manager (schtasks ")
    service_manager_guard.calls.clear()  # this test made the call on purpose


def _every_command(defn, tmp_path, monkeypatch):  # noqa: F811
    """Each command the three managers run, noted by a runner of the test's own: nothing is started."""
    inside = LS.running_inside_unit
    monkeypatch.setattr(LS, "running_inside_unit", lambda unit: False)
    noted = Recorder({("schtasks", "/Query"): (0, '"task","N/A","Running"'),
                      ("systemctl", "--user", "is-active"): (0, "active"), ("launchctl", "print"): (113, "")})
    for manager in (LS.WindowsTask(defn, noted), LS.SystemdUser(defn, noted, unit_dir=tmp_path / "units"),
                    LS.LaunchAgent(defn, noted, agent_dir=tmp_path / "agents", uid=501)):
        for step in ("install", "start", "state", "stop", "uninstall"):
            getattr(manager, step)()
    inside("hermes-sandbox-work-0.service", noted)
    return noted.calls


def test_every_command_of_the_three_managers_is_refused_as_either_system_announces_it(
        defn, tmp_path, monkeypatch, service_manager_guard):  # noqa: F811
    commands = _every_command(defn, tmp_path, monkeypatch)
    assert {command[0] for command in commands} == {"schtasks", "systemctl", "launchctl"} and len(commands) > 15
    assert service_manager_guard.calls == []  # a manager with a runner of its own is none of the guard's business
    for command in commands:
        # a list with the program first, and (Windows) one command line
        for announced in ((command[0], command, None, None), (None, subprocess.list2cmdline(command), None, None)):
            with pytest.raises(STOPPED, match=re.escape(f"`{command[0]} {command[1]}")):
                no_service_manager.refuse_event("subprocess.Popen", announced)
    assert len(service_manager_guard.calls) == 2 * len(commands)
    service_manager_guard.calls.clear()


def test_the_console_helper_and_the_other_ways_to_start_a_program_are_refused(service_manager_guard):
    assert no_service_manager.hooked()
    helper = ["C:\\Windows\\System32\\cmd.exe", "/d", "/q", "/k"]  # the bootstrap's hidden console helper
    for event, announced in (("subprocess.Popen", (helper[0], helper, None, None)),
                             ("subprocess.Popen", (None, subprocess.list2cmdline(helper), None, None)),
                             ("subprocess.Popen", (None, '"C:\\Windows\\System32\\SCHTASKS.EXE" /Delete /TN x /F', None, None)),
                             ("subprocess.Popen", ("/usr/bin/loginctl", ["loginctl", "enable-linger"], None, None)),
                             ("os.system", ("systemctl --user daemon-reload",)),
                             ("os.posix_spawn", ("/bin/systemctl", ["systemctl", "--user", "stop", "x.service"], {})),
                             ("os.exec", ("/bin/launchctl", ["launchctl", "bootout", "gui/501/x"], {})),
                             ("os.spawn", (0, "/bin/launchctl", ["launchctl", "print", "gui/501/x"], {}))):
        with pytest.raises(STOPPED):
            no_service_manager.refuse_event(event, announced)
    assert service_manager_guard.calls[:3] == ["cmd /d /q /k", "cmd /d /q /k", "schtasks /Delete /TN x /F"]
    assert len(service_manager_guard.calls) == 8
    service_manager_guard.calls.clear()


def test_every_other_program_passes(service_manager_guard):
    for announced in ((None, "cmd.exe /c echo done", None, None), ("python", ["python", "-c", "pass"], None, None),
                      (None, ["sh", "-c", "systemctl --user stop x.service"], None, None), (None, [], None, None),
                      (None, "x" * 200_000, None, None), ("C:\\tools\\not-schtasks.exe", ["not-schtasks"], None, None)):
        no_service_manager.refuse_event("subprocess.Popen", announced)  # not the service manager's: nothing is said
    no_service_manager.refuse_event("open", ("schtasks", "r", 0))  # another event
    no_service_manager.refuse_event("os.system", ())  # a call of another shape
    assert service_manager_guard.calls == []
