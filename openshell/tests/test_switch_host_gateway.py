"""Switch order around the host gateway: after marking, a running host gateway drops the profile at
once; after clearing (and only after), it serves it again at once. The launcher's ``switch/off``
stops the sandbox, unregisters, clears the marker, THEN asks the host to serve the profile; a
teardown failure asks nothing. Core's marker and gateway control socket are in-memory stand-ins.
"""
import asyncio
import sys
import types

import pytest

from openshell.launcher import host_routes as HR
from openshell.launcher import switch as SW

from test_switch_flow import OUTER, _on, _request, _routes, _serve, env  # noqa: F401  (fixture; rootdir-less import)


@pytest.fixture
def gateway_calls(monkeypatch, env):  # noqa: F811
    log = env["log"]
    control = types.ModuleType("gateway.control_socket")
    control.request_unserve_profile = lambda root, name: log.append(f"host drop {name}") or {"ok": True}
    control.request_serve_profile_hot = lambda root, name: log.append(f"host serve {name}") or {"ok": True}
    package = types.ModuleType("gateway")
    package.control_socket = control
    monkeypatch.setitem(sys.modules, "gateway", package)
    monkeypatch.setitem(sys.modules, "gateway.control_socket", control)
    return log


def test_turn_on_drops_the_profile_from_the_host_right_after_marking(env, gateway_calls):  # noqa: F811
    _on(env)
    log = env["log"]
    # the undo ticket first, then the mark and the drop as the very last steps
    assert log.index("POST switch/ticket") < log.index("mark") < log.index("host drop work")
    assert log[-2:] == ["mark", "host drop work"]


def test_an_undone_turn_on_hands_the_profile_back_only_after_clearing(env, gateway_calls, monkeypatch):  # noqa: F811
    env["launcher"]["ticket"] = None  # fails before the mark: nothing to clear, nothing handed back
    with pytest.raises(SW.SwitchError):
        _on(env)
    assert not any(e in ("mark", "clear") or e.startswith("host ") for e in env["log"])
    env["log"].clear()
    env["launcher"]["ticket"] = "undo-ticket"
    real_drop = SW.host_drop

    def drop_then_fail(layout):
        real_drop(layout)
        raise KeyboardInterrupt  # interrupted after the mark

    monkeypatch.setattr(SW, "host_drop", drop_then_fail)
    with pytest.raises(KeyboardInterrupt):
        _on(env)
    log = env["log"]
    assert log.index("mark") < log.index("clear") < log.index("host serve work")


def test_launcher_switch_off_serves_on_the_host_only_after_the_marker_is_cleared(env, monkeypatch,  # noqa: F811
                                                                                  gateway_calls):
    stopped = []
    routes = _routes(env, monkeypatch, stopped)

    async def scenario(port):
        out = await _request(port, "POST", "/api/plugins/openshell/switch/off", b"{}",
                             [f"X-Hermes-Session-Token: {OUTER}"])
        assert out.startswith(b"HTTP/1.1 200")

    _serve(routes, scenario)
    assert env["log"] == ["sandbox stopped", "unregistered", "clear", "host serve work"]
    asyncio.run(asyncio.sleep(0.3))


def test_a_failed_teardown_never_hands_the_profile_to_the_host(env, monkeypatch, gateway_calls):  # noqa: F811
    routes = _routes(env, monkeypatch, [])

    def boom(layout, runtime):
        raise RuntimeError("schtasks /Delete exited with 1")

    monkeypatch.setattr(HR, "unregister", boom)

    async def scenario(port):
        out = await _request(port, "POST", "/api/plugins/openshell/switch/off", b"{}",
                             [f"X-Hermes-Session-Token: {OUTER}"])
        assert out.startswith(b"HTTP/1.1 500")

    _serve(routes, scenario)
    assert "clear" not in env["log"] and not any(e.startswith("host serve") for e in env["log"])


def test_no_host_gateway_or_old_core_is_fine(env, monkeypatch):  # noqa: F811
    monkeypatch.setitem(sys.modules, "gateway.control_socket", None)  # import fails
    assert SW.host_serve(env["layout"]) is None and SW.host_drop(env["layout"]) is None
