"""The Sandbox switch's order: turn_on starts and waits before it marks, undoes everything on failure,
and saves the spec only after the driver's preflight; the launcher's switch/off takes a ticket or the
outer token and clears the marker last. Core's marker module is replaced by an in-memory stand-in
(the core under test may predate it).
"""
import asyncio
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
