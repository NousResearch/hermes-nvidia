"""Launcher hardening that rides with the Sandbox switch:

* the sandbox is denied core's run-elsewhere marker folder (it must not clear its own marker);
* approval frames the sandbox sends lose ``kind`` and access targets (only launcher cards carry them);
* ``serve`` saves the spec only after the driver's preflight passes;
* the launcher follows only a venv redirector parent, never whoever started it (a gateway that idles out).
"""
import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

import openshell.launcher_cli as CLI
from openshell.launcher import cards as C
from openshell.launcher import layout as L
from openshell.launcher.driver import DriverUnavailable, SandboxDriver
from openshell.launcher.spec import load_spec, save_spec
from openshell.launcher.supervisor import Supervisor


class NullDriver(SandboxDriver):
    name = "null"
    uses_host_shell = False

    def preflight(self):
        return {}

    def start(self, request):
        pass

    def exit_code(self):
        return -1

    def stop(self, timeout=20.0):
        pass

    def policy(self):
        return {}


def _runtime(tmp: Path) -> L.Runtime:
    for d in ("code", "env", "base"):
        (tmp / d).mkdir(parents=True, exist_ok=True)
    return L.Runtime(python=tmp / "env" / "python.exe", code_dir=tmp / "code", env_dir=tmp / "env",
                     base_python=tmp / "base", store=None)


@pytest.mark.parametrize("named", [True, False])
def test_the_sandbox_is_denied_the_run_elsewhere_markers(tmp_path, named):
    root = tmp_path / "root"
    home = root / "profiles" / "work" if named else root
    home.mkdir(parents=True)
    layout = L.ProfileLayout(name="work" if named else "default", home=home, root=root)
    save_spec(layout, {**load_spec(layout), "folders": []})
    sup = Supervisor(layout, _runtime(tmp_path), load_spec(layout), NullDriver(), outer_port=1)
    request, _ = sup._launch_request()
    markers = root / "profiles_run_elsewhere"
    assert markers in request.grants.denied and markers.is_dir()
    assert home / "plugins" in request.grants.readonly  # unchanged: plugin code stays read-only
    assert markers not in request.grants.readwrite and markers not in request.grants.readonly


# -- approval frames from the sandbox ---------------------------------------------------------------

class _Conn:
    n = 1

    def __init__(self):
        self.sent = []
        self.sessions, self.running, self.pending_lists = [], set(), {}

    def saw(self, sid):
        pass

    async def to_client(self, data):
        self.sent.append(data)


def _from_sandbox(cards, obj, conn=None):
    return asyncio.run(cards._from_sandbox(conn or _Conn(), obj))


@pytest.mark.parametrize("enabled", [True, False])
def test_sandbox_sent_approvals_lose_access_wording(enabled):
    cards = C.Cards(cards=enabled)
    frame = {"jsonrpc": "2.0", "id": "srq-1", "method": "approval", "params": {
        "session_id": "s", "request_id": "r1", "command": "rm notes.txt", "description": "Allow read & write to C:\\",
        "choices": ["once", "deny"], "kind": "access", "path": "C:\\", "access": "rw", "host": "evil.example",
        "port": 443}}
    out = _from_sandbox(cards, frame)
    assert isinstance(out, dict)
    params = out["params"]
    assert params["command"] == "rm notes.txt" and params["request_id"] == "r1" and params["choices"] == ["once", "deny"]
    for key in ("kind", "path", "access", "host", "port"):
        assert key not in params
    assert cards.stripped == 1
    plain = {"jsonrpc": "2.0", "id": "srq-2", "method": "approval", "params": {"command": "ls", "request_id": "r2"}}
    assert _from_sandbox(cards, plain) is True  # nothing to strip: forwarded byte-for-byte


def test_pending_approval_lists_from_the_sandbox_are_stripped_too():
    cards = C.Cards(cards=False)
    conn = _Conn()
    conn.pending_lists[7] = "s"
    reply = {"jsonrpc": "2.0", "id": 7, "result": {"approvals": [
        {"request_id": "r1", "command": "x", "kind": "network", "host": "a.example"}, {"request_id": "r2", "command": "y"}]}}
    out = _from_sandbox(cards, reply, conn)
    assert out["result"]["approvals"] == [{"request_id": "r1", "command": "x"}, {"request_id": "r2", "command": "y"}]


def test_forged_launcher_card_ids_are_still_dropped():
    cards = C.Cards(cards=False)
    forged = {"jsonrpc": "2.0", "id": "x", "method": "approval",
              "params": {"request_id": C.REQUEST_PREFIX + "abc", "kind": "access"}}
    assert _from_sandbox(cards, forged) is False


def test_cards_off_raise_nothing():
    cards = C.Cards(cards=False)
    status, payload = asyncio.run(cards.raise_access("C:\\x", "read_write", key=cards._chat_of("s"), origin="route"))
    assert status == 409
    cards._maybe_card_for_denial("s", {"args": {"path": "C:\\x"}, "result": "Permission denied"})
    assert cards.open == {}


# -- serve: the spec is saved only after preflight --------------------------------------------------

def test_a_refused_driver_path_is_not_saved(monkeypatch, tmp_path):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    layout = L.ProfileLayout(name="work", home=home, root=root)
    save_spec(layout, {**load_spec(layout), "folders": [], "port": 47000})
    before = layout.spec_path.read_bytes()
    monkeypatch.setattr("openshell.launcher.layout.current_profile", lambda: layout)

    class Refusing(NullDriver):
        def preflight(self):
            raise DriverUnavailable("wxc-exec at C:\\old\\wxc-exec.exe is MXC 0.9, older than MXC 1.0.")

    monkeypatch.setattr(CLI, "make_driver", lambda spec: Refusing())
    bad = tmp_path / "wxc-exec.exe"
    bad.write_text("")
    args = types.SimpleNamespace(folder=None, port=None, wxc_exec=str(bad), busybox=None,
                                 openshell_gateway=None, openshell_image=None, egress="allow", rotate_token=False,
                                 service=False)
    assert CLI._cmd_serve(args) == 1
    assert layout.spec_path.read_bytes() == before


def test_openshell_is_the_only_driver_a_spec_or_the_cli_can_select():
    import argparse

    with pytest.raises(DriverUnavailable, match="unknown sandbox driver 'wxc-exec'"):
        CLI.make_driver({"driver": "wxc-exec"})
    parser = argparse.ArgumentParser()
    CLI._setup(parser)
    with pytest.raises(SystemExit):
        parser.parse_args(["serve", "--driver", "wxc-exec"])
    assert parser.parse_args(["serve", "--wxc-exec", "C:/mxc/wxc-exec.exe"]).wxc_exec == "C:/mxc/wxc-exec.exe"


def test_service_mode_starts_nothing_while_the_switch_is_off(monkeypatch, tmp_path, capsys):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    layout = L.ProfileLayout(name="work", home=home, root=root)
    monkeypatch.setattr("openshell.launcher.layout.current_profile", lambda: layout)
    monkeypatch.setattr(CLI, "make_driver", lambda spec: pytest.fail("no driver while the switch is off"))
    args = types.SimpleNamespace(folder=None, port=None, wxc_exec=None, busybox=None,
                                 openshell_gateway=None, openshell_image=None, egress=None, rotate_token=False,
                                 service=True)
    assert CLI._cmd_serve(args) == 0
    assert "switch is off" in capsys.readouterr().out
    assert not layout.spec_path.exists()


# -- which parent the launcher follows --------------------------------------------------------------

class _Proc:
    def __init__(self, exe, parent=None):
        self._exe, self._parent = exe, parent

    def exe(self):
        return self._exe

    def parent(self):
        return self._parent


def _fake_psutil(monkeypatch, me):
    fake = types.SimpleNamespace(Process=lambda: me, Error=Exception)
    monkeypatch.setitem(sys.modules, "psutil", fake)


def test_follows_a_venv_redirector_parent(monkeypatch):
    venv = sys.executable
    redirector = _Proc(venv)
    _fake_psutil(monkeypatch, _Proc(str(Path(venv).parent / "base-python.exe"), redirector))
    assert CLI._redirector_parent() is redirector


@pytest.mark.parametrize("parent_exe", ["C:\\Program Files\\Hermes\\hermes.exe", "C:\\Windows\\System32\\svchost.exe"])
def test_does_not_follow_a_gateway_or_service_manager(monkeypatch, parent_exe):
    _fake_psutil(monkeypatch, _Proc(sys.executable, _Proc(parent_exe)))
    assert CLI._redirector_parent() is None


# -- a launcher's state file outliving it ------------------------------------------------------------

def test_a_reused_pid_is_not_the_launcher_its_state_file_names(tmp_path):
    # A killed launcher leaves state.json; Windows soon hands its PID to another process. That process was
    # created after the launcher wrote its state, so it is not the launcher, and switching on must not refuse
    # with "A sandbox is already running for this profile".
    import os
    import time

    from openshell.launcher import switch as SW
    from openshell.launcher.login_service import launcher_state_alive

    class Layout:
        state_path = tmp_path / "state.json"

    me = {"pid": os.getpid(), "profile": "work", "port": 1, "url": "http://127.0.0.1:1", "driver": "x"}
    Layout.state_path.write_text(json.dumps({**me, "since": time.time()}), encoding="utf-8")
    assert SW.running_launcher(Layout) is not None  # the process that wrote it, still running
    Layout.state_path.write_text(json.dumps({**me, "since": 1_000_000.0}), encoding="utf-8")
    assert SW.running_launcher(Layout) is None  # same PID, but a process created long after: reused
    assert launcher_state_alive({"pid": os.getpid()})  # older state files without `since` keep working
    assert not launcher_state_alive({"pid": 0}) and not launcher_state_alive(None)


def test_a_moving_wall_clock_does_not_hide_a_running_launcher(tmp_path, monkeypatch):
    # Linux: psutil derives a process's creation time from the boot time in /proc/stat, and that moves when the
    # wall clock is stepped or drifts (seen in a WSL2 VM: +10 s in three minutes). A launcher that is still running
    # must stay recognised: its state file names the kernel's own start stamp of its PID, which never moves.
    import os
    import time

    import psutil

    from openshell.launcher import login_service as LS

    ticks = LS.process_start_ticks(os.getpid())
    me = {"pid": os.getpid(), "since": time.time()}
    if ticks is None:  # no /proc/<pid>/stat here (Windows, macOS): the creation-time rule stays the only one
        assert LS.launcher_state_alive(me) and not LS.launcher_state_alive({**me, "since": 1_000_000.0})
        return
    assert isinstance(ticks, int) and ticks == LS.process_start_ticks(os.getpid())
    assert LS.process_start_ticks(0) is None and LS.process_start_ticks(2 ** 22 + 12345) is None
    real = psutil.Process.create_time
    # what psutil reads once the boot time has moved: a creation time 30 s after the launcher wrote its state
    monkeypatch.setattr(psutil.Process, "create_time", lambda self: me["since"] + 30.0)
    assert not LS.launcher_state_alive(me)                         # an older state file: the old rule, fooled
    assert LS.launcher_state_alive({**me, "start_ticks": ticks})   # with the stamp: still this launcher
    monkeypatch.setattr(psutil.Process, "create_time", real)
    assert not LS.launcher_state_alive({**me, "start_ticks": ticks + 1})  # same PID, another process: reused
    assert LS.launcher_state_alive({**me, "start_ticks": None})          # written where no stamp exists


def test_the_launcher_writes_its_start_stamp_into_its_state_file(tmp_path):
    import os
    import types

    from openshell.launcher import login_service as LS
    from openshell.launcher.supervisor import Supervisor

    sup = types.SimpleNamespace(layout=types.SimpleNamespace(name="work", state_path=tmp_path / "state.json"),
                                outer_port=1, driver=types.SimpleNamespace(name="x"))
    Supervisor.write_state(sup)
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert state["pid"] == os.getpid() and "since" in state
    assert state["start_ticks"] == LS.process_start_ticks(os.getpid())
    assert LS.launcher_state_alive(state)
