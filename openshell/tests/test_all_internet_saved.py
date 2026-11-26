"""A saved setting that allows all internet access, on a sandbox whose driver has no rule for it.

Such a setting cannot be made any more (the page offers no such choice and ``serve --egress allow`` is refused),
but a ``spec.yaml`` can still hold it: written by an earlier build, or by hand. The sandbox then starts as
Blocked, with the destinations that are listed: ``hermes sandbox on``, the page's switch and ``serve`` set the
saved value to blocked before anything is pinned or registered, and say so once, in their answer and on the
page's Internet access row of the launcher they start.
"""
import asyncio
from types import SimpleNamespace

import pytest

import test_settings_routes as SR
from openshell import launcher_cli as CLI
from openshell.launcher import switch as SW
from openshell.launcher.spec import load_spec, save_spec
from test_desktop_switch_js import run  # noqa: F401  (the Node run of the page, once per module)
from test_pins import _serve_args, layout, serve  # noqa: F401  (`hermes sandbox serve` up to the launcher)
from test_switch_flow import env  # noqa: F401  (the switch fixture)
from test_switch_on_cut_off import Sandbox, _for, _launcher, host  # noqa: F401  (the launcher, run for real)

SAID = "This sandbox has no rule for all internet access. It was set to Blocked."
SITE = {"host": "pypi.org", "port": 443}
ASK = SW.launcher_call  # the real call, before the switch fixture puts its stand-in there


class NoRule(SR.FakeDriver):
    """A driver without a rule for all internet access, as the OpenShell drivers are."""

    capabilities_info = {**SR.FakeDriver.capabilities_info, "egress_allow_all": False}


def _saved_all_internet(lay):
    save_spec(lay, {**load_spec(lay), "folders": [], "network": {"egress": "allow", "allow": [SITE]}})
    assert load_spec(lay)["network"]["egress"] == "allow"


def _network(lay):
    network = load_spec(lay)["network"]
    return network["egress"], network["allow"]


def test_serve_starts_a_saved_all_internet_setting_as_blocked_and_says_so_once(layout, serve, monkeypatch, capsys):  # noqa: F811
    _saved_all_internet(layout)
    monkeypatch.setattr(CLI, "make_driver", lambda spec: NoRule())
    assert CLI._cmd_serve(_serve_args()) == 0
    assert len(serve) == 1  # the sandbox starts
    assert _network(layout) == ("deny", [SITE])  # blocked is saved, and the listed destination is kept
    assert capsys.readouterr().err.count(SAID) == 1
    assert CLI._cmd_serve(_serve_args()) == 0
    assert len(serve) == 2 and SAID not in capsys.readouterr().err  # the next start has nothing to say


def test_a_driver_that_has_the_rule_starts_with_the_saved_setting(layout, serve, capsys):  # noqa: F811
    _saved_all_internet(layout)
    assert CLI._cmd_serve(_serve_args()) == 0  # (the fixture's driver does not say it lacks the rule)
    assert len(serve) == 1 and _network(layout) == ("allow", [SITE]) and SAID not in capsys.readouterr().err


def test_a_switch_on_starts_a_saved_all_internet_setting_as_blocked_and_says_so_once(host):  # noqa: F811
    env, lay = host, host["layout"]  # noqa: F811
    _saved_all_internet(lay)
    seen = []

    def make_driver(spec):
        seen.append(spec["network"]["egress"])
        return SimpleNamespace(preflight=dict, capabilities=lambda: dict(NoRule.capabilities_info))

    result = SW.turn_on(lay, runtime=env["runtime"], manager=env["manager"], environ={}, make_driver=make_driver,
                        sleep=lambda s: None)
    assert result["note"] == SAID and "work" in env["markers"].marked  # it is on, and the answer says what changed
    assert seen == ["allow"] and _network(lay) == ("deny", [SITE])
    token, port = result["token"], int(result["url"].rsplit(":", 1)[1])

    def row_says():
        """Run the launcher this switch-on registered, and ask its status as the page does."""
        driver, said = Sandbox(env["log"]), []

        async def scenario(launcher):
            assert await _for(lambda: bool(driver.requests) and driver.server is not None)
            code, status = await asyncio.to_thread(ASK, port, token, "GET", "status")
            assert code == 200
            said.append((status["internet_set_blocked"], driver.requests[0].network["egress"]))

        _launcher(env, driver, scenario)
        return said

    assert row_says() == [(True, "deny")]  # the sandbox started with blocked, and its launcher says so
    assert row_says() == [(False, "deny")]  # once: the launcher after it (a restart, the next login) does not


def test_a_switch_on_with_a_blocked_setting_says_nothing_about_it(host):  # noqa: F811
    env, lay = host, host["layout"]  # noqa: F811
    save_spec(lay, {**load_spec(lay), "folders": [], "network": {"egress": "deny", "allow": [SITE]}})
    result = SW.turn_on(lay, runtime=env["runtime"], manager=env["manager"], environ={}, sleep=lambda s: None,
                        make_driver=lambda spec: SimpleNamespace(preflight=dict, capabilities=lambda: dict(
                            NoRule.capabilities_info)))
    assert "note" not in result and _network(lay) == ("deny", [SITE])


def test_the_internet_access_row_says_that_the_setting_was_set_to_blocked(run):  # noqa: F811
    found = run["internet"]
    assert "error" not in found, found.get("error")
    row = found["noRuleSetBlocked"]
    assert row["shown"] == "Blocked" and row["choices"] == []  # nothing to choose, as for any such sandbox
    assert row["note"] == SAID
    assert row["asked"] == [] and row["sent"] == []
    assert found["noRule"]["note"] == "Only allowed destinations are reachable."  # a launcher that says nothing
