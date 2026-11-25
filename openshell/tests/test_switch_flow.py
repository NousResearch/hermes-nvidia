"""The Sandbox switch's order: turn_on starts and waits before it marks, undoes everything on failure,
and saves the spec only after the driver's preflight; the launcher's switch/off takes a ticket or the
outer token and clears the marker last. Core's marker module is replaced by an in-memory stand-in
(the core under test may predate it).
"""
import asyncio
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from openshell.launcher import host_routes as HR
from openshell.launcher import login_service as LS
from openshell.launcher import switch as SW
from openshell.launcher.driver import DriverUnavailable
from openshell.launcher.layout import ProfileLayout
from openshell.launcher.proxy import MAX_HEAD, Proxy, Upstream

OUTER = "outer-" + "o" * 40


class FakeMarkers:
    """hermes_cli.profiles_run_elsewhere, reduced to what the switch calls."""

    def __init__(self, log):
        self.marked: set[str] = set()
        self.log = log

    def run_elsewhere(self, profile, *, root=None):
        return object() if profile in self.marked else None

    def mark_profile_run_elsewhere(self, profile, plugin, *, root=None):
        assert plugin == "openshell"
        self.log.append("mark")
        self.marked.add(profile)

    def clear_profile_run_elsewhere(self, profile, plugin, *, root=None):
        self.log.append("clear")
        had = profile in self.marked
        self.marked.discard(profile)
        return had


class FakeService(LS.LoginService):
    kind = "fake"

    def __init__(self, defn, log):
        super().__init__(defn)
        self.log, self.registered, self.running = log, False, False

    def install(self):
        self.log.append("install")
        self.registered = True

    def start(self):
        self.log.append("start")
        self.running = True

    def stop(self):
        self.log.append("stop")
        self.running = False

    def uninstall(self):
        self.log.append("uninstall")
        self.registered = False

    def state(self):
        return "running" if self.running else ("stopped" if self.registered else "absent")


class FakeDriver:
    def __init__(self, refuse=None):
        self.refuse = refuse

    def preflight(self):
        if self.refuse:
            raise DriverUnavailable(self.refuse)
        return {}


@dataclass
class FakeRuntime:
    python: Path
    code_dir: Path


@pytest.fixture
def env(tmp_path, monkeypatch):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    layout = ProfileLayout(name="work", home=home, root=root)
    log: list[str] = []
    markers = FakeMarkers(log)
    monkeypatch.setattr(SW, "marker_api", lambda: markers)
    services: list[FakeService] = []

    def manager(defn):
        services.append(FakeService(defn, log))
        return services[-1]

    calls = []
    launcher = {"state": "running", "ticket": "undo-ticket"}

    def fake_call(port, token, method, route, body=None, timeout=5.0):
        calls.append((method, route, token))
        log.append(f"{method} {route}")
        if route == "status":
            return 200, {"state": launcher["state"], "error": launcher.get("error")}
        if route == "switch/ticket":
            return (200, {"ticket": launcher["ticket"]}) if launcher["ticket"] else (500, None)
        if route == "stop":
            return 200, {"ok": True}
        return 404, None

    monkeypatch.setattr(SW, "launcher_call", fake_call)
    return dict(layout=layout, log=log, markers=markers, services=services, manager=manager, calls=calls,
                launcher=launcher, runtime=FakeRuntime(Path("py.exe"), tmp_path))


def _on(env, driver=None, **kw):
    return SW.turn_on(env["layout"], runtime=env["runtime"], manager=env["manager"], environ={},
                      make_driver=lambda spec: driver or FakeDriver(), sleep=lambda s: None, **kw)


def test_turn_on_starts_waits_then_marks(env):
    result = _on(env)
    log = env["log"]
    assert log.index("install") < log.index("start") < log.index("GET status") < log.index("mark")
    # the mark is the LAST step: the desktop asked first and applies its override the
    # moment this returns, so the host refuses the profile only for that apply
    assert log.index("POST switch/ticket") < log.index("mark") and log[-1] == "mark"
    assert result["url"].startswith("http://127.0.0.1:") and result["undo_ticket"] == "undo-ticket"
    assert result["token"] == env["layout"].token_path.read_text(encoding="utf-8").strip()
    assert LS.switched_on(env["layout"]) and "work" in env["markers"].marked
    assert env["layout"].spec_path.is_file()


def test_refused_driver_saves_nothing_and_registers_nothing(env):
    with pytest.raises(SW.SwitchError) as err:
        _on(env, driver=FakeDriver(refuse="wxc-exec at C:\\bad is older than MXC 1.0"))
    assert err.value.status == 422 and "older than MXC 1.0" in str(err.value)
    assert not env["layout"].spec_path.exists()
    assert env["services"] == [] and env["log"] == []


def test_a_sandbox_that_fails_to_start_is_undone_and_never_marked(env):
    env["launcher"].update(state="failed", error="sandbox exited with 1\ntraceback...")
    with pytest.raises(SW.SwitchError, match="sandbox exited with 1"):
        _on(env)
    assert "mark" not in env["log"]
    assert not LS.switched_on(env["layout"])
    assert env["services"][0].state() == "absent"


def test_no_undo_ticket_means_never_marked(env):
    env["launcher"]["ticket"] = None
    with pytest.raises(SW.SwitchError, match="undo ticket"):
        _on(env)
    assert "mark" not in env["log"] and not env["markers"].marked
    assert not LS.switched_on(env["layout"]) and env["services"][0].state() == "absent"


def test_a_failure_after_the_mark_clears_it(env, monkeypatch):
    def host_drop(layout):
        raise KeyboardInterrupt  # anything after the mark (here: interrupted while telling the host gateway)

    monkeypatch.setattr(SW, "host_drop", host_drop)
    with pytest.raises(KeyboardInterrupt):
        _on(env)
    log = env["log"]
    assert log.index("mark") < log.index("clear") and not env["markers"].marked
    assert log.index("uninstall") < log.index("clear")  # the marker goes last
    assert not LS.switched_on(env["layout"])


def test_turn_on_refuses_marked_or_default_or_markerless_hosts(env, monkeypatch):
    env["markers"].marked.add("work")
    with pytest.raises(SW.SwitchError, match="still switched on for this profile.*sandbox off"):
        _on(env)
    default = ProfileLayout(name="default", home=env["layout"].root, root=env["layout"].root)
    assert SW.availability(default)["available"] is False
    monkeypatch.setattr(SW, "marker_api", lambda: None)
    assert SW.availability(env["layout"]) == {"available": False, "reason": "Needs a newer version of Hermes."}


@pytest.mark.parametrize("platform, too_old", [("windows", True), ("linux", False)])
def test_a_hermes_that_does_not_read_the_named_state_folder_is_too_old_on_windows(env, monkeypatch, platform, too_old):
    """On Windows Hermes in the sandbox is named an install-state folder of its own. A Hermes that does not read
    the name ends at start, so the switch says it is too old before it starts anything. A Linux sandbox is named
    no folder and needs nothing."""
    from openshell.launcher import compat as C

    monkeypatch.setattr(C, "_platform_key", lambda: platform)
    monkeypatch.setattr(SW, "state_folder_api", lambda: None, raising=False)
    answer = SW.availability(env["layout"], check_host=False)
    assert answer == ({"available": False, "reason": "Needs a newer version of Hermes."} if too_old
                      else {"available": True, "reason": None})
    if too_old:
        with pytest.raises(SW.SwitchError, match="Needs a newer version of Hermes"):
            _on(env)


def test_a_hermes_that_reads_the_named_state_folder_can_switch_on_windows(env, monkeypatch):
    from openshell.launcher import compat as C

    monkeypatch.setattr(C, "_platform_key", lambda: "windows")
    monkeypatch.setattr(SW, "state_folder_api", lambda: (lambda: None), raising=False)
    assert SW.availability(env["layout"], check_host=False) == {"available": True, "reason": None}


def test_tickets_are_single_use_and_expire():
    now = [0.0]
    tickets = SW.Tickets(ttl=10, clock=lambda: now[0])
    t = tickets.mint()
    assert not tickets.redeem("forged") and not tickets.redeem(None)
    assert tickets.redeem(t) and not tickets.redeem(t)
    t2 = tickets.mint()
    now[0] = 11
    assert not tickets.redeem(t2)


# -- the launcher's switch routes, through the real proxy ------------------------------------------

class FakeSup:
    def __init__(self, layout, log):
        self.layout, self.log = layout, log
        self.outer_port = 47999
        self.runtime = FakeRuntime(Path("py.exe"), layout.root)

    async def stop(self):
        self.log.append("sandbox stopped")

    def status(self):
        return {"profile": "work", "sandboxed": True, "state": "running"}

    def owns_profile(self, name):
        return name in ("", "work", "current")


def _routes(env, monkeypatch, stopped):
    log = env["log"]
    monkeypatch.setattr(HR, "unregister", lambda layout, runtime: log.append("unregistered"))
    monkeypatch.setattr(HR, "clear_marker", lambda layout: (log.append("clear"), True)[1])
    return HR.HostRoutes(FakeSup(env["layout"], log), lambda: stopped.append(True))


def _serve(routes, scenario):
    async def main():
        proxy = Proxy(outer_token=OUTER, upstream=lambda: Upstream("127.0.0.1", 9, "inner"), unavailable=dict,
                      own_profile=lambda n: True, host_route=routes.match, public_paths=frozenset())
        server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0, limit=MAX_HEAD)
        try:
            return await scenario(server.sockets[0].getsockname()[1])
        finally:
            server.close()
    return asyncio.run(main())


async def _request(port, method, path, body=b"", headers=()):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    lines = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{port}", f"Content-Length: {len(body)}", *headers]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
    await writer.drain()
    out = await asyncio.wait_for(reader.read(), 5)
    writer.close()
    return out


def test_switch_off_needs_a_ticket_or_the_token_and_unmarks_last(env, monkeypatch):
    stopped = []
    routes = _routes(env, monkeypatch, stopped)
    token = f"X-Hermes-Session-Token: {OUTER}"

    async def scenario(port):
        p = "/api/plugins/openshell/switch"
        # The ticket route itself needs the outer token (the sandbox has none).
        assert (await _request(port, "POST", f"{p}/ticket", b"{}")).startswith(b"HTTP/1.1 401")
        forged = await _request(port, "POST", f"{p}/off", b'{"ticket": "forged"}', ["Content-Type: text/plain"])
        assert forged.startswith(b"HTTP/1.1 403") and b"Access-Control-Allow-Origin: *" in forged
        assert env["log"] == []
        minted = await _request(port, "POST", f"{p}/ticket", b"{}", [token])
        assert minted.startswith(b"HTTP/1.1 200")
        ticket = minted.split(b'"ticket": "')[1].split(b'"')[0].decode()
        off = await _request(port, "POST", f"{p}/off", f'{{"ticket": "{ticket}"}}'.encode(),
                             ["Content-Type: text/plain", "Origin: null"])
        assert off.startswith(b"HTTP/1.1 200") and b'"marker_cleared": true' in off
        again = await _request(port, "POST", f"{p}/off", f'{{"ticket": "{ticket}"}}'.encode())
        assert again.startswith(b"HTTP/1.1 403")  # single use
        pre = await _request(port, "OPTIONS", f"{p}/off")
        assert pre.startswith(b"HTTP/1.1 204") and b"Access-Control-Allow-Origin: *" in pre

    _serve(routes, scenario)
    assert env["log"] == ["sandbox stopped", "unregistered", "clear"]
    asyncio.run(asyncio.sleep(0.3))


def test_switch_off_keeps_the_marker_when_teardown_fails(env, monkeypatch):
    stopped = []
    routes = _routes(env, monkeypatch, stopped)

    def boom(layout, runtime):
        raise LS.ServiceError("schtasks /Delete exited with 1")

    monkeypatch.setattr(HR, "unregister", boom)

    async def scenario(port):
        out = await _request(port, "POST", "/api/plugins/openshell/switch/off", b"{}",
                             [f"X-Hermes-Session-Token: {OUTER}"])
        assert out.startswith(b"HTTP/1.1 500") and b"didn't turn off" in out

    _serve(routes, scenario)
    assert "clear" not in env["log"] and stopped == []


def test_status_reports_the_switch(env, monkeypatch):
    routes = _routes(env, monkeypatch, [])

    async def scenario(port):
        return await _request(port, "GET", "/api/plugins/openshell/status", headers=[f"X-Hermes-Session-Token: {OUTER}"])

    out = _serve(routes, scenario)
    assert b'"switch": {"available": true' in out and b'"on": true' in out


# -- a switch-on asked for in short requests (the page's route: no request waits for the whole start) ------

def _ask(env, starts, wait=0.0, driver=None, **kw):
    """One request of the page for the fixture's profile: the final answer, or ``pending`` after *wait* seconds."""
    kw.setdefault("sleep", lambda s: time.sleep(0.002))
    return SW.turn_on_within(env["layout"], wait, starts=starts, runtime=env["runtime"], manager=env["manager"],
                             environ={}, make_driver=lambda spec: driver or FakeDriver(), **kw)


def _until(done, seconds=5.0):
    """Wait (a few milliseconds at a time) until *done* answers true; says whether it did."""
    end = time.monotonic() + seconds
    while True:
        if done():
            return True
        if time.monotonic() >= end:
            return False
        time.sleep(0.005)


def _nobody_asks_any_more(env, now):
    """The clock of a ``Starts`` moves far ahead: the start in flight ends by itself, and is undone."""
    now[0] += 3600.0
    assert _until(lambda: "uninstall" in env["log"])


def _the_sandbox_comes_up(env):
    """The fixture's launcher reports its sandbox running, and the start in flight has seen it: it asks the
    launcher no more."""
    env["launcher"]["state"] = "running"
    asked = -1
    while asked != env["log"].count("GET status"):
        asked = env["log"].count("GET status")
        time.sleep(0.1)


def _runs_once_asked(env, times=3):
    """The fixture's launcher reports its sandbox starting until it has been asked *times* times."""
    env["launcher"]["state"] = "starting"

    def watch():
        _until(lambda: env["log"].count("GET status") >= times)
        env["launcher"]["state"] = "running"

    threading.Thread(target=watch, daemon=True).start()


def test_a_start_slower_than_one_request_answers_pending_and_a_later_request_gets_the_answer(env):
    starts = SW.Starts(tick=0.01)
    env["launcher"]["state"] = "starting"
    first = _ask(env, starts)
    assert first["pending"] is True and not {"url", "token", "undo_ticket"} & set(first)
    assert _until(lambda: env["services"] and env["services"][0].running)  # the start goes on between requests
    assert _ask(env, starts)["pending"] is True
    env["launcher"]["state"] = "running"
    final = _ask(env, starts, wait=5.0)
    assert not final.get("pending")
    assert set(final) == {"profile", "plugin", "url", "token", "undo_ticket", "service", "status", "handback"}
    assert final["url"].startswith("http://127.0.0.1:") and final["undo_ticket"] == "undo-ticket"
    assert final["token"] == env["layout"].token_path.read_text(encoding="utf-8").strip()
    log = env["log"]
    assert log.count("install") == log.count("start") == log.count("mark") == 1 and len(env["services"]) == 1
    assert LS.switched_on(env["layout"]) and "work" in env["markers"].marked


def test_the_profile_is_marked_only_with_the_final_answer(env):
    starts = SW.Starts(tick=0.01)
    env["launcher"]["state"] = "starting"
    assert _ask(env, starts)["pending"] is True
    _the_sandbox_comes_up(env)  # and no request has come for the answer yet
    assert "mark" not in env["log"] and "POST switch/ticket" not in env["log"] and not env["markers"].marked
    final = _ask(env, starts, wait=5.0)
    log = env["log"]
    # the mark is still the LAST step, in the request whose answer the page turns into the desktop's route
    assert log.index("POST switch/ticket") < log.index("mark") and log[-1] == "mark"
    assert final["undo_ticket"] == "undo-ticket" and "work" in env["markers"].marked


@pytest.mark.parametrize("sandbox_runs", [True, False])
def test_a_start_nobody_comes_back_for_is_undone_and_never_marked(env, sandbox_runs):
    now = [1000.0]
    starts = SW.Starts(clock=lambda: now[0], tick=0.01)
    env["launcher"]["state"] = "starting"
    assert _ask(env, starts)["pending"] is True
    assert _until(lambda: env["services"] and env["services"][0].running)
    if sandbox_runs:
        _the_sandbox_comes_up(env)
    now[0] += 10.0  # a page that is slow to ask again is still waited for
    time.sleep(0.1)
    assert env["services"][0].running and LS.switched_on(env["layout"])
    now[0] += 60.0  # the window was closed: nobody asks any more
    assert _until(lambda: env["services"][0].state() == "absent")
    assert _until(lambda: not LS.switched_on(env["layout"]))
    log = env["log"]
    assert "mark" not in log and "POST switch/ticket" not in log and not env["markers"].marked
    assert log.index("POST stop") < log.index("stop") < log.index("uninstall")
    # nothing is left of it: the next request starts again, and gets its answer
    env["launcher"]["state"] = "running"
    assert _until(lambda: not _ask(env, starts, wait=5.0).get("pending"))
    assert log.count("install") == 2 and log[-1] == "mark" and "work" in env["markers"].marked


def test_two_requests_for_one_profile_share_one_start(env):
    starts = SW.Starts(tick=0.01)
    env["launcher"]["state"] = "starting"
    assert _ask(env, starts)["pending"] is True and _ask(env, starts)["pending"] is True
    answers, inside = [], threading.Event()

    def another_window():
        inside.set()
        answers.append(_ask(env, starts, wait=5.0))

    waiting = threading.Thread(target=another_window, daemon=True)
    waiting.start()
    assert inside.wait(5.0)
    time.sleep(0.2)  # it is waiting in its request when the sandbox comes up
    env["launcher"]["state"] = "running"
    answers.append(_ask(env, starts, wait=5.0))
    waiting.join(5.0)
    assert len(answers) == 2 and answers[0] == answers[1] and answers[0]["undo_ticket"] == "undo-ticket"
    log = env["log"]
    assert len(env["services"]) == 1
    assert log.count("install") == log.count("start") == log.count("POST switch/ticket") == log.count("mark") == 1


def test_what_is_refused_before_anything_starts_is_refused_in_the_first_answer(env):
    starts = SW.Starts(tick=0.01)
    with pytest.raises(SW.SwitchError) as err:
        _ask(env, starts, wait=5.0, driver=FakeDriver(refuse="wxc-exec at C:\\bad is older than MXC 1.0"))
    assert err.value.status == 422 and "older than MXC 1.0" in str(err.value)
    assert not env["layout"].spec_path.exists() and env["services"] == [] and env["log"] == []
    env["markers"].marked.add("work")
    with pytest.raises(SW.SwitchError, match="still switched on for this profile.*sandbox off") as err:
        _ask(env, starts, wait=5.0)
    assert err.value.status == 409 and env["services"] == []


def test_a_start_that_fails_after_a_pending_answer_reports_as_a_blocking_one_does(env):
    starts = SW.Starts(tick=0.01)
    env["launcher"]["state"] = "starting"
    assert _ask(env, starts)["pending"] is True
    env["launcher"].update(state="failed", error="sandbox exited with 1\ntraceback...")
    with pytest.raises(SW.SwitchError) as err:
        _until(lambda: not _ask(env, starts, wait=5.0).get("pending"))
    assert str(err.value) == "The sandbox didn't start: sandbox exited with 1" and err.value.status == 502
    assert "mark" not in env["log"] and not LS.switched_on(env["layout"]) and env["services"][0].state() == "absent"
    # told once: the request after it starts again
    env["launcher"].update(state="running", error=None)
    assert _until(lambda: not _ask(env, starts, wait=5.0).get("pending"))
    assert len(env["services"]) == 2 and "work" in env["markers"].marked


def test_a_start_that_runs_out_of_time_says_so_in_a_later_answer(env):
    starts = SW.Starts(tick=0.01)
    env["launcher"]["state"] = "starting"
    assert _ask(env, starts, timeout=0.2)["pending"] is True
    with pytest.raises(SW.SwitchError, match=r"^The sandbox didn't start within \d+ seconds\.$") as err:
        _until(lambda: not _ask(env, starts, wait=5.0).get("pending"))
    assert err.value.status == 504
    assert "mark" not in env["log"] and not LS.switched_on(env["layout"]) and env["services"][0].state() == "absent"


def test_no_request_waits_longer_than_it_asked_to(env):
    now = [0.0]
    starts = SW.Starts(clock=lambda: now[0], tick=0.01)
    env["launcher"]["state"] = "starting"
    began = time.monotonic()
    assert _ask(env, starts, wait=0.3)["pending"] is True
    assert 0.25 <= time.monotonic() - began < 2.0
    assert SW.REQUEST_WAIT_MAX <= 25.0  # however long a request asks for
    _nobody_asks_any_more(env, now)


def test_a_start_whose_process_is_gone_is_undone_by_the_next_request_which_says_so(env):
    """The process that serves the page's route can be replaced while a start is in flight (Hermes restarts it):
    the launcher's service is then installed and running, and nobody remembers the start."""
    never = threading.Event()
    gone = SW.Starts(tick=0.01)
    env["launcher"]["state"] = "starting"
    assert _ask(env, gone, sleep=lambda s: never.wait())["pending"] is True  # (it never gets further)
    assert _until(lambda: LS.switched_on(env["layout"]) and env["services"] and env["services"][0].running)
    starts = SW.Starts(tick=0.01, alive=lambda record: False)  # the process after it: the first has ended
    with pytest.raises(SW.SwitchError) as err:
        _until(lambda: not _ask(env, starts, wait=5.0).get("pending"))
    assert err.value.status == 409 and str(err.value) == "The sandbox didn't finish starting. Turn it on again."
    log = env["log"]
    assert not LS.switched_on(env["layout"]) and "POST stop" in log and log.count("uninstall") == 1
    assert "mark" not in log and not env["markers"].marked
    # the profile is clean: turning on again works
    env["launcher"]["state"] = "running"
    assert _until(lambda: not _ask(env, starts, wait=5.0).get("pending"))
    assert log[-1] == "mark" and "work" in env["markers"].marked


def test_a_start_that_another_running_process_holds_is_left_alone(env):
    never = threading.Event()
    other = SW.Starts(tick=0.01)
    env["launcher"]["state"] = "starting"
    assert _ask(env, other, sleep=lambda s: never.wait())["pending"] is True
    assert _until(lambda: LS.switched_on(env["layout"]) and env["services"] and env["services"][0].running)
    now = [0.0]
    starts = SW.Starts(clock=lambda: now[0], tick=0.01, alive=lambda record: True)
    env["log"].clear()
    try:
        _ask(env, starts, wait=0.3)
    except SW.SwitchError:
        pass  # refused or not, as a second blocking switch-on would be
    assert LS.switched_on(env["layout"]) and env["services"][0].running
    assert "uninstall" not in env["log"] and "POST stop" not in env["log"]
    _nobody_asks_any_more(env, now)


def test_a_blocking_turn_on_still_waits_for_the_sandbox_itself(env):
    _runs_once_asked(env)
    result = _on(env)
    assert not result.get("pending") and result["url"].startswith("http://127.0.0.1:")
    assert env["log"][-1] == "mark" and env["log"].count("GET status") >= 3
