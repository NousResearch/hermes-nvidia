"""A switch-on that is cut off: the command or the process that turns a sandbox on ends after the launcher's
service is registered and before the profile is marked.

The launcher keeps a sandbox only for a profile that is marked or whose switch-on is still under way. For any
other it marks the profile first, ends the sandbox, removes its service and clears the marker last, when it is
started (a login, a restart) and while its sandbox runs. The home is put back without asking only for a switch-on
that never reached its mark (its record is still there); a profile that was switched on and whose marker is gone
keeps what its sandbox changed, and the next switch-on lists that and asks. ``hermes sandbox on`` takes itself
back when the command is told to end, and an undo that is interrupted in its turn still runs every step.

The launcher runs here as its login service runs it, over the stand-in sandbox of the settings tests; the service
manager and core's marker are the switch tests' stand-ins.
"""
import asyncio
import json
import os
import signal
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

import test_handback as TH
import test_settings_routes as SR
from openshell import launcher_cli as CLI
from openshell.launcher import handback as H
from openshell.launcher import layout as L
from openshell.launcher import login_service as LS
from openshell.launcher import pins as P
from openshell.launcher import supervisor as S
from openshell.launcher import switch as SW
from openshell.launcher.spec import load_spec
from test_review_before_on import _answer, page  # noqa: F401  (the page's switch-on route)
from test_switch_flow import FakeDriver, FakeService, _on, env  # noqa: F401  (the switch fixture)

SERVICE = dict(folder=None, port=None, wxc_exec=None, busybox=None, openshell_gateway=None, openshell_image=None,
               egress=None, rotate_token=False, service=True)
PLANTED, SCRIPT, ROW = "scripts/planted.sh", b"#!/bin/sh\nid\n", "file:scripts/planted.sh"


class Sandbox(SR.FakeDriver):
    """The stand-in sandbox. It notes in the fixture's log when it stops; *answers* False is a sandbox whose
    backend is not up yet; *on_start* runs once the sandbox was asked to start."""

    def __init__(self, log, on_start=lambda: None, answers=True):
        super().__init__()
        self.log, self.on_start, self.answers = log, on_start, answers

    def start(self, request):
        if self.answers:
            super().start(request)
        else:
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), SR._Health)  # some other port: nothing is ready
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            self.requests.append(request)
        self.on_start()

    def stop(self, timeout=20.0):
        if self.server is not None:
            self.log.append("sandbox stopped")
        super().stop(timeout)


@pytest.fixture
def host(env, tmp_path, monkeypatch):  # noqa: F811
    """The fixture's profile as the launcher's own process finds it: its service manager is the fixture's."""
    monkeypatch.setattr(L, "current_profile", lambda: env["layout"])
    monkeypatch.setattr(L, "current_runtime", lambda: SR._runtime(tmp_path))
    monkeypatch.setattr(SW, "manager_for", env["manager"])
    monkeypatch.setattr(S.Supervisor, "_busybox", lambda self: None)  # no shell in the stand-in sandbox
    monkeypatch.setattr(S, "WATCH_INTERVAL", 0.02)
    return env


def _half_on(env):  # noqa: F811
    """A switch-on that got as far as a registered service and a sandbox that runs: nothing is marked yet."""
    started = SW._start(env["layout"], runtime=env["runtime"], manager=env["manager"], environ={},
                        make_driver=lambda spec: FakeDriver(), sleep=lambda s: None)
    assert LS.switched_on(env["layout"]) and env["services"][0].running and not env["markers"].marked
    return started


def _its_process_ends(layout):
    """The process that was turning the sandbox on is gone: the number its record names belongs to another."""
    record = {"pid": os.getpid(), "since": time.time(), "start_ticks": -1}
    if LS.process_start_ticks(os.getpid()) is None:  # no start stamp here: the process is told apart by its age
        record["since"] = 0.0
    (layout.state_dir / SW.START_RECORD).write_text(json.dumps(record), encoding="utf-8")


def _the_sandbox_writes(layout):
    """What a sandbox leaves among the files that run on this computer: a script that was not there at switch-on."""
    TH.put(layout.home / PLANTED, SCRIPT)


def _switched_on(env):  # noqa: F811
    """A switch-on that finished: the profile is marked, and the record of its start is gone."""
    SW._finish(_half_on(env))
    assert "work" in env["markers"].marked and not (env["layout"].state_dir / SW.START_RECORD).exists()


def _the_marker_goes(env):  # noqa: F811
    """The profile's marker is gone (its file was removed) although its switch-on finished."""
    env["markers"].marked.discard("work")


def _rows(layout):
    return [row["id"] for row in H.diff(layout.home, layout.state_dir)["rows"]]


def _login_start(monkeypatch, driver):
    """``hermes sandbox serve --service`` up to the point where the launcher would run. Returns the exit status
    and the launches."""
    launches = []

    async def launcher(lay, spec, drv, token, service=False, own_pin=False):
        launches.append(service)
        return 0

    monkeypatch.setattr(CLI, "make_driver", lambda spec: driver)
    monkeypatch.setattr(CLI, "_serve", launcher)
    return CLI._cmd_serve(SimpleNamespace(**SERVICE)), launches


def _nothing_is_left(env):  # noqa: F811
    layout = env["layout"]
    return (not LS.switched_on(layout) and "uninstall" in env["log"] and not env["markers"].marked
            and not (layout.state_dir / SW.START_RECORD).exists() and not P.present(layout)
            and not H.is_open(layout.state_dir))


# -- the launcher is started (a login, a restart by the service manager) ------------------------------------------

def test_a_login_start_runs_no_sandbox_for_a_switch_on_that_was_cut_off(host, monkeypatch, capsys):
    env, layout = host, host["layout"]  # noqa: F811
    _half_on(env)
    _the_sandbox_writes(layout)
    _its_process_ends(layout)
    env["services"][0].running = False  # the computer was restarted: the service manager starts the launcher
    env["log"].clear()
    left = []
    driver = SimpleNamespace(preflight=dict, capabilities=dict, drop_leftover=lambda name: left.append(name) or True)
    code, launches = _login_start(monkeypatch, driver)
    assert code == 0 and launches == []
    assert "the switch-on of profile 'work' did not finish; not starting." in capsys.readouterr().out
    log = env["log"]
    # Hermes on this computer is kept from the profile while a sandbox the last launcher left is ended
    assert left == ["work"] and log[0] == "mark" and log[-1] == "clear" and log.index("uninstall") < log.index("clear")
    assert "stop" not in log  # the launcher never stops its own service: that would end it half way
    # that switch-on never reached its mark: what its sandbox wrote in those minutes is put back, nothing is asked
    assert _nothing_is_left(env) and not (layout.home / PLANTED).exists()
    assert _login_start(monkeypatch, driver) == (0, [])  # and what is left of the registration starts nothing


def test_a_login_start_goes_on_for_a_switch_on_under_way_and_for_a_marked_profile(host, monkeypatch):
    env = host  # noqa: F811
    started = _half_on(env)  # the record names this process, which runs
    assert _login_start(monkeypatch, SR.FakeDriver()) == (0, [True])
    SW._finish(started)  # marked, and the record is gone
    assert not (env["layout"].state_dir / SW.START_RECORD).exists()
    assert _login_start(monkeypatch, SR.FakeDriver()) == (0, [True])
    assert LS.switched_on(env["layout"]) and "work" in env["markers"].marked and "uninstall" not in env["log"]


def test_a_login_start_that_cannot_end_the_sandbox_left_running_keeps_the_profile_marked(host, monkeypatch):
    env, layout = host, host["layout"]  # noqa: F811
    _half_on(env)
    _its_process_ends(layout)

    def drop_leftover(name):
        raise RuntimeError("the gateway did not answer")

    driver = SimpleNamespace(preflight=dict, capabilities=dict, drop_leftover=drop_leftover)
    code, launches = _login_start(monkeypatch, driver)
    assert code == 0 and launches == []
    # as after a switch-off that failed: still marked and still registered, and `sandbox off` finishes the job
    assert "work" in env["markers"].marked and LS.switched_on(layout) and P.present(layout)
    assert "uninstall" not in env["log"] and "clear" not in env["log"]


# -- the launcher runs ----------------------------------------------------------------------------------------

def _launcher(env, driver, scenario=None, *, service=True, seconds=30.0):  # noqa: F811
    """Run the profile's launcher over *driver* until it ends by itself; with *scenario*, until that returns (the
    launcher is then stopped as its stop route stops it). Returns the launcher's exit status, or None when it
    was still running after *seconds*."""
    layout = env["layout"]
    token = layout.token_path.read_text(encoding="utf-8").strip()

    async def main():
        launcher = asyncio.ensure_future(CLI._serve(layout, load_spec(layout), driver, token, service=service))
        if scenario is not None:
            await scenario(launcher)
            launcher.cancel()
        try:
            return await asyncio.wait_for(launcher, seconds)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return None

    return asyncio.run(main())


async def _for(done, seconds=10.0):
    end = time.monotonic() + seconds
    while not done() and time.monotonic() < end:
        await asyncio.sleep(0.01)
    return done()


@pytest.mark.parametrize("answers", [True, False], ids=["the sandbox runs", "the sandbox is starting"])
def test_a_launcher_marks_the_profile_then_ends_its_sandbox_when_the_switch_on_is_cut_off(host, answers):
    env, layout = host, host["layout"]  # noqa: F811
    _half_on(env)
    env["log"].clear()
    driver = Sandbox(env["log"], on_start=lambda: (_the_sandbox_writes(layout), _its_process_ends(layout)),
                     answers=answers)
    began = time.monotonic()
    assert _launcher(env, driver) == 0  # it ends by itself, and a start under way is not waited out
    assert time.monotonic() - began < 25.0
    log = env["log"]
    assert log.index("mark") < log.index("sandbox stopped") < log.index("uninstall") < log.index("clear")
    assert log[-1] == "clear" and "stop" not in log and len(driver.requests) == 1
    assert _nothing_is_left(env) and driver.server is None and not (layout.home / PLANTED).exists()


@pytest.mark.parametrize("case", ["a switch-on under way", "a marked profile", "a foreground serve"])
def test_a_launcher_keeps_its_sandbox_while_someone_owns_it(host, case):
    env, layout = host, host["layout"]  # noqa: F811
    started = _half_on(env)
    if case == "a marked profile":
        SW._finish(started)
    elif case == "a foreground serve":  # it never marks, and no switch-on stands behind it
        (layout.state_dir / SW.START_RECORD).unlink()
    env["log"].clear()
    driver = Sandbox(env["log"])
    seen = {}

    async def scenario(launcher):
        seen["up"] = await _for(lambda: bool(driver.requests) and driver.server is not None)
        await asyncio.sleep(0.5)  # many looks of the launcher's watch
        seen.update(done=launcher.done(), log=list(env["log"]), running=driver.server is not None)

    _launcher(env, driver, scenario, service=case != "a foreground serve")
    assert seen["up"] and seen["running"] and not seen["done"]
    assert not {"sandbox stopped", "uninstall", "clear"} & set(seen["log"]) and LS.switched_on(layout)
    assert ("mark" in seen["log"]) is False and P.present(layout)


def test_a_start_record_counts_while_its_process_runs(host):
    env, layout = host, host["layout"]  # noqa: F811
    _half_on(env)
    assert SW.start_in_flight(layout) and not SW.cut_off(layout)
    _its_process_ends(layout)
    assert not SW.start_in_flight(layout) and SW.cut_off(layout)
    env["markers"].marked.add("work")
    assert not SW.cut_off(layout)  # a marked profile's sandbox has its owner


def _record_written(layout, seconds_ago):
    """The record of this process's own switch-on, as if it was written *seconds_ago* by the wall clock."""
    path = layout.state_dir / SW.START_RECORD
    record = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps({**record, "since": time.time() - seconds_ago}), encoding="utf-8")


def test_a_clock_set_forward_past_the_longest_switch_on_ends_it(host):
    env, layout = host, host["layout"]  # noqa: F811
    _half_on(env)
    runs = lambda record: True  # noqa: E731  (the process runs: only the record's age is in question)
    _record_written(layout, SW.START_LIMIT - 30.0)
    assert SW.start_in_flight(layout, runs) and not SW.cut_off(layout, runs)
    _record_written(layout, SW.START_LIMIT + 30.0)  # a switch-on that hangs, or a clock that jumped ahead
    assert not SW.start_in_flight(layout, runs) and SW.cut_off(layout, runs)


def test_a_clock_set_back_during_a_switch_on_leaves_it_under_way(host):
    env, layout = host, host["layout"]  # noqa: F811
    _half_on(env)
    _record_written(layout, -3600.0)  # written "an hour from now": the clock went back since
    assert SW.start_in_flight(layout) and not SW.cut_off(layout)
    _record_written(layout, -10 * 365 * 86400.0)
    assert SW.start_in_flight(layout) and not SW.cut_off(layout)


# -- a profile that was switched on and whose marker is gone: nothing is put back without a list ------------------

def _the_next_switch_on_asks(env, request, capsys, caller):  # noqa: F811
    """The next switch-on, from the terminal or from the page, stops with the list of what the sandbox changed."""
    layout = env["layout"]
    env["log"].clear()
    capsys.readouterr()
    if caller == "the terminal":
        run, _ = request.getfixturevalue("on_command")
        assert run() == 3
        said = capsys.readouterr()
        assert "Changed in the sandbox (profile work)" in said.out and PLANTED in said.out
        assert said.err == "hermes sandbox: 1 change needs an answer. Run again with --revert or --keep.\n"
    else:
        answer = _answer(request.getfixturevalue("page").switch_on({"wait": 5}))
        assert answer == (409, {"detail": "1 change needs an answer.", "code": "handback_needs_answer", "unanswered": 1})
    # nothing started, and nothing was changed: the answer is the user's
    assert "install" not in env["log"] and "mark" not in env["log"]
    assert (layout.home / PLANTED).read_bytes() == SCRIPT and H.is_open(layout.state_dir)


@pytest.mark.parametrize("caller", ["the terminal", "the page"])
def test_a_login_start_for_a_profile_whose_marker_is_gone_leaves_the_home_for_the_next_switch_on(
        host, monkeypatch, capsys, request, caller):
    env, layout = host, host["layout"]  # noqa: F811
    _switched_on(env)
    _the_sandbox_writes(layout)  # in the hours or days the sandbox ran
    _the_marker_goes(env)
    env["services"][0].running = False  # the launcher is started again: a restart, the next login
    env["log"].clear()
    left = []
    driver = SimpleNamespace(preflight=dict, capabilities=dict, drop_leftover=lambda name: left.append(name) or True)
    assert _login_start(monkeypatch, driver) == (0, [])
    # nobody has seen a list of what that sandbox changed: the home stays as it is, and the record of it stays open
    assert (layout.home / PLANTED).exists() and H.is_open(layout.state_dir)
    assert (layout.home / PLANTED).read_bytes() == SCRIPT and _rows(layout) == [ROW]
    log = env["log"]
    assert left == ["work"] and log[0] == "mark" and log[-1] == "clear" and "stop" not in log
    assert log.index("uninstall") < log.index("clear")
    assert not LS.switched_on(layout) and not env["markers"].marked and not P.present(layout)
    out = capsys.readouterr().out
    assert "hermes sandbox: profile 'work' is not marked as run elsewhere; not starting." in out
    assert "hermes sandbox: the sandbox of profile 'work' is off. The next switch-on lists what it changed." in out
    _the_next_switch_on_asks(env, request, capsys, caller)


def test_a_launcher_whose_profiles_marker_goes_ends_its_sandbox_and_leaves_the_home_for_the_next_switch_on(
        host, capsys, request):
    env, layout = host, host["layout"]  # noqa: F811
    _switched_on(env)
    env["log"].clear()
    driver = Sandbox(env["log"])
    ended = {}

    async def scenario(launcher):
        assert await _for(lambda: bool(driver.requests) and driver.server is not None)
        await asyncio.sleep(0.2)  # the sandbox runs, marked, through many looks of the launcher
        ended["early"] = launcher.done() or "sandbox stopped" in env["log"]
        _the_sandbox_writes(layout)
        _the_marker_goes(env)
        done, _ = await asyncio.wait({launcher}, timeout=25.0)
        ended["by itself"] = bool(done)

    assert _launcher(env, driver, scenario) == 0 and ended == {"early": False, "by itself": True}
    assert (layout.home / PLANTED).exists() and H.is_open(layout.state_dir)
    assert (layout.home / PLANTED).read_bytes() == SCRIPT and _rows(layout) == [ROW]
    log = env["log"]
    assert log.index("mark") < log.index("sandbox stopped") < log.index("uninstall") < log.index("clear")
    assert log[-1] == "clear" and "stop" not in log and driver.server is None
    assert not LS.switched_on(layout) and not env["markers"].marked and not P.present(layout)
    said = capsys.readouterr().err
    assert "hermes sandbox: profile 'work' is not marked as run elsewhere; ending its sandbox." in said
    assert "hermes sandbox: the sandbox of profile 'work' is off. The next switch-on lists what it changed." in said
    _the_next_switch_on_asks(env, request, capsys, "the terminal")

# -- a record the switch-on could not remove: another program held the file ----------------------------------------

@pytest.fixture
def held_record(monkeypatch):
    """Another program (a scanner, an indexer) holds the record of the start: removing it fails ``held["left"]``
    more times (``float("inf")``: every time). ``held["tries"]`` counts the tries, whoever makes them."""
    held = {"left": 0, "tries": 0}
    unlink = Path.unlink

    def refused(self, *args, **kwargs):
        if self.name == SW.START_RECORD:
            held["tries"] += 1
            if held["left"]:
                held["left"] -= 1
                raise PermissionError(13, "The process cannot access the file because it is being used by another process")
        return unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refused)
    return held


def _turn_on(env, pauses):  # noqa: F811
    return SW.turn_on(env["layout"], runtime=env["runtime"], manager=env["manager"], environ={},
                      make_driver=lambda spec: FakeDriver(), sleep=pauses.append)


def test_a_record_that_is_held_for_a_moment_is_removed_when_the_switch_on_finishes(env, held_record):  # noqa: F811
    held_record["left"] = 2
    pauses = []
    result = _turn_on(env, pauses)
    assert result["undo_ticket"] == "undo-ticket" and "work" in env["markers"].marked
    assert not (env["layout"].state_dir / SW.START_RECORD).exists()  # the third try removed it
    assert held_record["tries"] == 3 and pauses == [SW.FORGET_PAUSE] * 2


def test_a_record_that_stays_held_does_not_hold_the_switch_on(env, held_record):  # noqa: F811
    held_record["left"] = float("inf")
    pauses = []
    result = _turn_on(env, pauses)
    # the switch-on is not kept waiting: it is on, marked and answered within a fraction of a second
    assert result["undo_ticket"] == "undo-ticket" and env["log"][-1] == "mark" and "work" in env["markers"].marked
    assert (env["layout"].state_dir / SW.START_RECORD).exists()
    assert held_record["tries"] > 1 and len(pauses) == held_record["tries"] - 1  # it tried again, a few times
    assert held_record["tries"] == SW.FORGET_TRIES and pauses == [SW.FORGET_PAUSE] * (SW.FORGET_TRIES - 1)
    assert sum(pauses) < 0.5


def _finished_with_its_record_held(env, held_record):  # noqa: F811
    """A switch-on that reached its mark and could not remove its record. Returns the record's path."""
    started = _half_on(env)
    held_record["left"] = float("inf")
    SW._finish(started)
    record = env["layout"].state_dir / SW.START_RECORD
    assert "work" in env["markers"].marked and record.exists()
    return record


def test_the_launcher_removes_a_record_its_finished_switch_on_left_and_a_lost_marker_then_asks(host, held_record, capsys):
    env, layout = host, host["layout"]  # noqa: F811
    record = _finished_with_its_record_held(env, held_record)
    env["log"].clear()
    driver = Sandbox(env["log"])
    seen = {}

    async def scenario(launcher):
        assert await _for(lambda: bool(driver.requests) and driver.server is not None)
        await asyncio.sleep(0.2)  # many looks: the process that switched on still runs, and the record is its own
        seen["kept while its process runs"] = record.exists()
        _its_process_ends(layout)  # the command that switched on has ended; the file is still held
        await asyncio.sleep(0.2)
        seen["there while it is held"] = record.exists() and not launcher.done()
        held_record["left"] = 0  # the other program lets go
        seen["removed at a later look"] = await _for(lambda: not record.exists(), 5.0)
        seen["the sandbox goes on"] = not launcher.done() and "sandbox stopped" not in env["log"]
        _the_sandbox_writes(layout)
        _the_marker_goes(env)
        done, _ = await asyncio.wait({launcher}, timeout=25.0)
        seen["ended when the marker went"] = bool(done)

    assert _launcher(env, driver, scenario) == 0
    assert seen == {"kept while its process runs": True, "there while it is held": True,
                    "removed at a later look": True, "the sandbox goes on": True, "ended when the marker went": True}
    # that switch-on reached its mark: nothing is put back without a list
    assert (layout.home / PLANTED).exists() and H.is_open(layout.state_dir)
    assert (layout.home / PLANTED).read_bytes() == SCRIPT and _rows(layout) == [ROW]
    said = capsys.readouterr().err
    assert "hermes sandbox: profile 'work' is not marked as run elsewhere; ending its sandbox." in said
    assert "hermes sandbox: the sandbox of profile 'work' is off. The next switch-on lists what it changed." in said


@pytest.mark.parametrize("marked", [True, False], ids=["the profile is marked", "the profile is not marked"])
def test_the_launcher_never_touches_the_record_of_a_switch_on_under_way(host, held_record, marked):
    env, layout = host, host["layout"]  # noqa: F811
    if marked:  # between the mark and the removal of the record, or with the record held: this process runs
        record = _finished_with_its_record_held(env, held_record)
        held_record["left"] = 0
    else:
        _half_on(env)
        record = layout.state_dir / SW.START_RECORD
    written, tries = record.read_bytes(), held_record["tries"]
    env["log"].clear()
    driver = Sandbox(env["log"])
    seen = {}

    async def scenario(launcher):
        seen["up"] = await _for(lambda: bool(driver.requests) and driver.server is not None)
        await asyncio.sleep(0.3)  # many looks of the launcher's watch
        seen["running"] = not launcher.done() and driver.server is not None
        seen["log"] = list(env["log"])

    _launcher(env, driver, scenario)
    assert seen == {"up": True, "running": True, "log": []}  # nothing stopped, removed or marked meanwhile
    assert record.read_bytes() == written and held_record["tries"] == tries  # there, and nobody tried to remove it


def test_a_page_request_for_a_marked_profile_removes_a_record_of_an_ended_process_and_undoes_nothing(
        host, held_record, page):  # noqa: F811
    env, layout = host, host["layout"]  # noqa: F811
    record = _finished_with_its_record_held(env, held_record)
    held_record["left"] = 0
    _its_process_ends(layout)  # the process that switched on is gone, and no launcher has looked since
    home, pinned = TH.tree_bytes(layout.home), P.load(layout)
    env["log"].clear()
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as refused:
        page.switch_on({"wait": 5})
    assert (refused.value.status_code, refused.value.detail) == (
        409, "The sandbox is still switched on for this profile, but it isn't running. "
             "Run `hermes -p work sandbox off`, then turn it on again.")
    # the switch-on that reached its mark is not taken back: only the record goes
    assert not record.exists() and env["log"] == [] and "work" in env["markers"].marked
    assert LS.switched_on(layout) and P.load(layout) == pinned and H.is_open(layout.state_dir)
    assert TH.tree_bytes(layout.home) == home


# -- the switch-on itself -------------------------------------------------------------------------------------

def test_a_second_interrupt_does_not_leave_the_undo_half_way(env, monkeypatch):  # noqa: F811
    layout = env["layout"]

    def interrupted(port, token, method, route, body=None, timeout=5.0):
        env["log"].append(f"{method} {route}")
        if route == "status":
            raise KeyboardInterrupt  # Ctrl+C while the sandbox starts
        return 0, None

    def stop(self):
        self.log.append("stop")
        raise KeyboardInterrupt  # and again while the switch-on takes itself back

    monkeypatch.setattr(SW, "launcher_call", interrupted)
    monkeypatch.setattr(FakeService, "stop", stop)
    with pytest.raises(KeyboardInterrupt):
        _on(env)
    log = env["log"]
    assert "stop" in log and "uninstall" in log and log.index("stop") < log.index("uninstall") and "mark" not in log
    assert not LS.switched_on(layout) and not env["services"][0].registered and not env["markers"].marked
    assert not (layout.state_dir / SW.START_RECORD).exists() and not P.present(layout)


def test_a_switch_on_waits_for_a_launcher_that_is_ending_a_start_nobody_finished(env, monkeypatch):  # noqa: F811
    layout = env["layout"]
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    # a launcher of this profile runs; it has marked the profile and is ending its sandbox
    layout.state_path.write_text(json.dumps({"pid": os.getpid(), "port": 47998, "since": time.time(),
                                             "start_ticks": LS.process_start_ticks(os.getpid())}), encoding="utf-8")
    env["markers"].marked.add("work")
    ending = {"switching_off": True}
    real = SW.launcher_call

    def call(port, token, method, route, body=None, timeout=5.0):
        if route == "status" and ending:
            return 200, {"state": "stopping", **ending}
        return real(port, token, method, route, body, timeout)

    def sleep(seconds):
        if ending:  # it is done: the marker is cleared, and the launcher has ended
            ending.clear()
            env["markers"].marked.discard("work")
            layout.state_path.unlink()

    monkeypatch.setattr(SW, "launcher_call", call)
    result = SW.turn_on(layout, runtime=env["runtime"], manager=env["manager"], environ={},
                        make_driver=lambda spec: FakeDriver(), sleep=sleep)
    assert result["undo_ticket"] == "undo-ticket" and env["log"][-1] == "mark" and "work" in env["markers"].marked


# -- `hermes sandbox on` is told to end -------------------------------------------------------------------------

ENDINGS = [name for name in ("SIGTERM", "SIGHUP", "SIGBREAK", "SIGINT") if hasattr(signal, name)]


@pytest.fixture
def on_command(env, monkeypatch):  # noqa: F811
    """``hermes -p work sandbox on`` for the fixture's profile. While it runs, a signal the command does not
    handle itself is only noted (it must not end the test run). Returns ``(run, seen)``: ``run`` gives the exit
    status, or ``"interrupt"`` when the interrupt left the command; ``seen["unhandled"]`` are the signals the
    command left alone, ``seen["restored"]`` whether it put back the handlers it found."""
    layout = env["layout"]
    monkeypatch.setattr(L, "current_profile", lambda: layout)
    on = SW.turn_on
    monkeypatch.setattr(SW, "turn_on", lambda layout_, **kw: on(
        layout_, environ={}, sleep=lambda s: None, make_driver=lambda spec: FakeDriver(), runtime=env["runtime"],
        manager=env["manager"], **kw))
    seen = {"unhandled": [], "restored": None}

    def note(number, frame):
        seen["unhandled"].append(number)

    def run():
        numbers = [getattr(signal, name) for name in ENDINGS]
        before = {number: signal.signal(number, note) for number in numbers}
        try:
            return CLI._cmd_on(SimpleNamespace(handback_answer=None, move_keys=False))
        except KeyboardInterrupt:
            return "interrupt"
        finally:
            seen["restored"] = all(signal.getsignal(number) is note for number in numbers)
            for number, handler in before.items():
                signal.signal(number, handler if handler is not None else signal.SIG_DFL)

    return run, seen


def _signal_while_the_sandbox_starts(env, monkeypatch, name, then=None):  # noqa: F811
    """The command gets signal *name* at its first look at the launcher, and *then* (another signal) when the
    undo stops the service."""
    real = SW.launcher_call
    sent = []

    def call(port, token, method, route, body=None, timeout=5.0):
        if route == "status" and not sent:
            sent.append(name)
            signal.raise_signal(getattr(signal, name))
        return real(port, token, method, route, body, timeout)

    monkeypatch.setattr(SW, "launcher_call", call)
    if then is not None:
        stop = FakeService.stop

        def interrupted_stop(self):
            signal.raise_signal(getattr(signal, then))
            stop(self)

        monkeypatch.setattr(FakeService, "stop", interrupted_stop)


@pytest.mark.parametrize("name", ENDINGS)
def test_sandbox_on_takes_itself_back_when_the_command_is_told_to_end(env, on_command, monkeypatch, capsys, name):  # noqa: F811
    run, seen = on_command
    _signal_while_the_sandbox_starts(env, monkeypatch, name)
    assert run() == 128 + getattr(signal, name) and seen == {"unhandled": [], "restored": True}
    out = capsys.readouterr()
    assert out.out == "" and out.err == "hermes sandbox: Interrupted. The sandbox was not turned on.\n"
    log, layout = env["log"], env["layout"]
    assert log.index("start") < log.index("stop") < log.index("uninstall") and "mark" not in log
    assert not LS.switched_on(layout) and env["services"][0].state() == "absent" and not env["markers"].marked
    assert not (layout.state_dir / SW.START_RECORD).exists() and not P.present(layout)
    assert H.is_open(layout.state_dir) is False


def test_a_signal_that_comes_while_sandbox_on_takes_itself_back_does_not_cut_that_short(env, on_command, monkeypatch):  # noqa: F811
    run, seen = on_command
    _signal_while_the_sandbox_starts(env, monkeypatch, "SIGTERM", then="SIGINT")
    assert run() == 128 + signal.SIGTERM and seen == {"unhandled": [], "restored": True}
    log, layout = env["log"], env["layout"]
    assert log.index("stop") < log.index("uninstall") and "mark" not in log
    assert not LS.switched_on(layout) and env["services"][0].state() == "absent" and not P.present(layout)


def test_sandbox_on_that_ran_to_its_end_leaves_the_signals_as_they_were(env, on_command, capsys):  # noqa: F811
    run, seen = on_command
    assert run() == 0 and json.loads(capsys.readouterr().out)["state"] == "running"
    assert "work" in env["markers"].marked and seen == {"unhandled": [], "restored": True}
