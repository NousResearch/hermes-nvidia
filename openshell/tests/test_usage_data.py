"""The launcher's one built-in destination: where Hermes sends the usage data a profile shares with Nous
(launcher/usage_data.py).

The rule is in the sandbox's network policy exactly while the profile's own config.yaml has both answers on
(``telemetry.shared_metrics.enabled`` and ``.send``), for one fixed host that is never read from the config; it is
bound to Hermes's interpreter like the page's destinations, is no grant of the user's, follows an answer given
while the sandbox runs, and shows on the Sandbox page with its reason. Fake gateways throughout: nothing here
talks to a network.
"""
import asyncio
import json
import logging
import os
import urllib.parse
from pathlib import Path

import pytest

import test_cards as TC
import test_openshell_driver as LD
import test_openshell_windows as WD
from openshell.launcher import cards as C
from openshell.launcher import openshell_driver as OD
from openshell.launcher import supervisor as S
from openshell.launcher import usage_data as U
from openshell.launcher.host_routes import HostRoutes
from openshell.launcher.settings_view import config_payload
from openshell.launcher.spec import load_spec, network_policy
from test_cards import harness  # noqa: F401  (the cards fixture)

HOST = "telemetry.nousresearch.com"
RULE = "hermes_builtin_usage_data"
REASON = "Usage data this profile shares with Nous"
ROW = {"host": HOST, "port": 443, "reason": REASON, "rule": RULE}
OTHER = "https://collector.example.net/v1/telemetry"
_tick = [0]


def answers(home, enabled=None, send=None, endpoint=None) -> None:
    """Write the two answers (and an endpoint) into the profile's config.yaml, keeping what else it holds. None
    leaves a key out, as a profile that was never asked has it."""
    path = Path(home) / "config.yaml"
    text = (path.read_text(encoding="utf-8") if path.exists() else "").split("telemetry:", 1)[0]
    block = "".join(f"    {key}: {json.dumps(value)}\n"
                    for key, value in (("enabled", enabled), ("send", send), ("endpoint", endpoint)) if value is not None)
    path.write_text(text + ("telemetry:\n  shared_metrics:\n" + block if block else ""), encoding="utf-8")
    _tick[0] += 1  # a later write never looks like the earlier one, however fast the test runs
    stamp = path.stat().st_mtime_ns + _tick[0] * 1_000_000
    os.utime(path, ns=(stamp, stamp))


def section(enabled=None, send=None, endpoint=None) -> dict:
    keys = {k: v for k, v in (("enabled", enabled), ("send", send), ("endpoint", endpoint)) if v is not None}
    return {"telemetry": {"shared_metrics": keys}}


ON = {"enabled": True, "send": True}
# What the profile's config can say, and whether the destination is open: (name, answers, open)
CASES = [
    ("never asked", {}, False),
    ("off", {"enabled": False, "send": False}, False),
    ("collect only", {"enabled": True, "send": False}, False),
    ("send without collecting", {"enabled": False, "send": True}, False),
    ("on", ON, True),
    ("on, Hermes's own endpoint spelled out", {**ON, "endpoint": "https://telemetry.nousresearch.com/v1/telemetry"}, True),
    ("on, blank endpoint", {**ON, "endpoint": "  "}, True),
    ("on, another host", {**ON, "endpoint": OTHER}, False),
    ("on, our host without TLS", {**ON, "endpoint": "http://telemetry.nousresearch.com/v1/telemetry"}, False),
    ("on, our host on another port", {**ON, "endpoint": "https://telemetry.nousresearch.com:8443/v1/telemetry"}, False),
    ("on, our host as a login name", {**ON, "endpoint": "https://telemetry.nousresearch.com@collector.example.net/x"}, False),
    ("on, our host as a prefix", {**ON, "endpoint": "https://telemetry.nousresearch.com.example.net/v1/telemetry"}, False),
    ("on, a local test endpoint", {**ON, "endpoint": "http://127.0.0.1:8787/v1/telemetry"}, False),
    ("answers as text", {"enabled": "true", "send": "true"}, False),
    ("answers as numbers", {"enabled": 1, "send": 1}, False),
]
IDS = [case[0] for case in CASES]
# The driver tests start a sandbox per case: the answers a user can give, and a config that names another endpoint.
DRIVER_CASES = [case for case in CASES if case[0] in ("never asked", "off", "collect only", "on", "on, another host")]
DRIVER_IDS = [case[0] for case in DRIVER_CASES]


# -- reading the profile's answers ------------------------------------------------------------------------

def test_the_destination_is_one_fixed_host_named_in_the_plugin():
    assert (U.HOST, U.PORT, U.RULE_NAME, U.REASON) == (HOST, 443, RULE, REASON)
    assert U.RULE_NAME.startswith(U.BUILTIN_PREFIX) and U.BUILTIN_PREFIX.startswith(OD.RULE_PREFIX)
    assert not U.RULE_NAME.startswith(OD.RULE_PREFIX + "site_")  # never mistaken for a destination of the user's
    config = pytest.importorskip("hermes_cli.observability.shared_metrics_send_config")
    theirs = urllib.parse.urlsplit(config.DEFAULT_ENDPOINT)
    assert (theirs.scheme, theirs.hostname, theirs.port or 443) == ("https", U.HOST, U.PORT)  # where Hermes sends


@pytest.mark.parametrize("name, keys, is_open", CASES, ids=IDS)
def test_the_destination_is_open_only_while_both_answers_are_on_and_the_endpoint_is_hermes_own(tmp_path, name, keys,
                                                                                               is_open):
    assert U.answers(section(**keys))[0] is is_open
    answers(tmp_path, **keys)
    assert U.shared(tmp_path) is is_open
    assert U.destinations(tmp_path) == ([ROW] if is_open else [])
    rules = U.rules({"hermes_site_pypi_org_443": {"name": "hermes_site_pypi_org_443"}}, tmp_path, ["/store/python3"])
    assert (RULE in rules) is is_open and "hermes_site_pypi_org_443" in rules
    if is_open:
        assert rules[RULE] == {"name": RULE, "endpoints": [{"host": HOST, "port": 443}],
                               "binaries": [{"path": "/store/python3"}]}
    text = json.dumps(rules)
    assert (HOST in text) is is_open
    assert "example.net" not in text and "127.0.0.1" not in text and "8443" not in text  # never what the config named


@pytest.mark.parametrize("name, keys, is_open", CASES, ids=IDS)
def test_the_launcher_never_opens_it_when_hermes_itself_would_not_send_there(name, keys, is_open):
    """Against Hermes's own reading of the same config: open implies Hermes sends, and sends to this host."""
    config = pytest.importorskip("hermes_cli.observability.shared_metrics_send_config")
    theirs = config.resolve_send_config(section(**keys))
    if is_open:
        assert theirs.send is True and urllib.parse.urlsplit(theirs.endpoint).hostname == HOST
    elif theirs.send:  # Hermes would send and the launcher opens nothing: only ever because the endpoint is another one
        assert U.answers(section(**keys))[1] == keys["endpoint"].strip()


def test_odd_configs_share_nothing(tmp_path):
    for config in (None, [], "x", {"telemetry": None}, {"telemetry": {"shared_metrics": "on"}}):
        assert U.answers(config) == (False, None)
    # an endpoint that is not text is Hermes's own, as Hermes reads it
    assert U.answers({"telemetry": {"shared_metrics": {**ON, "endpoint": 7}}}) == (True, None)
    assert U.shared(None) is False and U.shared(tmp_path / "missing") is False
    (tmp_path / "config.yaml").write_text("telemetry: [unclosed\n", encoding="utf-8")
    assert U.shared(tmp_path) is False and U.rules({}, tmp_path, ["/py"]) == {}


def test_the_rule_needs_an_interpreter_to_bind_to_and_replaces_whatever_holds_its_name(tmp_path):
    answers(tmp_path, **ON)
    assert U.rules({}, tmp_path, []) == {} and U.rules({}, tmp_path, [""]) == {}  # never a rule for every program
    planted = {RULE: {"name": RULE, "endpoints": [{"host": "collector.example.net", "port": 443}],
                      "binaries": [{"path": "**"}]},
               "hermes_builtin_other": {"name": "hermes_builtin_other", "endpoints": [{"host": "x.example.net", "port": 1}]}}
    rules = U.rules(planted, tmp_path, ["/py"])
    assert list(rules) == [RULE] and rules[RULE]["endpoints"] == [{"host": HOST, "port": 443}]
    assert rules[RULE]["binaries"] == [{"path": "/py"}]
    answers(tmp_path, enabled=True, send=False)
    assert U.rules(planted, tmp_path, ["/py"]) == {}
    assert planted[RULE]["binaries"] == [{"path": "**"}]  # the caller's rules are not edited in place


def test_another_endpoint_opens_nothing_and_is_logged_once(tmp_path, caplog):
    answers(tmp_path, **ON, endpoint="https://user:secret@collector.example.net:8443/v1/t?key=abc")
    with caplog.at_level(logging.WARNING, logger="openshell.usage_data"):
        for _ in range(4):
            assert U.rules({}, tmp_path, ["/py"]) == {} and U.destinations(tmp_path) == [] and not U.shared(tmp_path)
        os.utime(tmp_path / "config.yaml", ns=(1, 1))  # the file is read again: still one line for this endpoint
        assert U.rules({}, tmp_path, ["/py"]) == {}
    lines = [r.getMessage() for r in caplog.records if r.name == "openshell.usage_data"]
    assert len(lines) == 1 and "collector.example.net:8443" in lines[0] and HOST in lines[0]
    assert "secret" not in lines[0] and "abc" not in lines[0]  # where it points, never a login or a query
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="openshell.usage_data"):
        answers(tmp_path, enabled=False, send=False, endpoint=OTHER)  # sharing off: nothing to say
        assert not U.shared(tmp_path)
        answers(tmp_path, **ON)
        assert U.shared(tmp_path)
    assert [r for r in caplog.records if r.name == "openshell.usage_data"] == []


# -- the Linux driver ---------------------------------------------------------------------------------------

def _linux_policies(api):
    return api.revisions["hermes-work"][-1]["policy"]["network_policies"]


@pytest.mark.parametrize("name, keys, is_open", DRIVER_CASES, ids=DRIVER_IDS)
def test_linux_the_sandbox_starts_with_the_rule_only_while_the_profile_shares(tmp_path, monkeypatch, name, keys, is_open):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch, network={
        "egress": "deny", "allow": [{"host": "pypi.org", "port": 443}]})
    answers(layout.home, **keys)

    async def scenario():
        await sup.start()
        try:
            rules = _linux_policies(api)
            assert (RULE in rules) is is_open and sup.driver.usage_data_open is is_open
            assert {e.get("host") for r in rules.values() for e in r["endpoints"]} <= {"pypi.org", HOST}
            if is_open:
                # bound to Hermes's interpreter exactly as the page's own destinations are, and nothing wider
                assert rules[RULE]["binaries"] == rules["hermes_site_pypi_org_443"]["binaries"] \
                    == [{"path": b} for b in sup.driver._binaries]
                assert list(sup.driver._binaries) == [str(sup.driver._runtime.real_python)]  # the resolved interpreter
                assert rules[RULE]["endpoints"] == [{"host": HOST, "port": 443}]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_linux_the_rule_follows_the_answer_at_every_network_update_and_is_never_a_grant(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    routes = HostRoutes(sup, lambda: None)
    put = routes.match("PUT", "/api/plugins/openshell/network")
    get = routes.match("GET", "/api/plugins/openshell/config")
    rollback = routes.match("POST", "/api/plugins/openshell/policy/rollback")

    async def edit(allow):
        status, payload, _ = await put(LD._req(), json.dumps({"egress": "deny", "allow": allow}).encode())
        assert status == 200
        return payload

    def saved():
        return json.dumps(load_spec(layout)["network"])

    async def scenario():
        await sup.start()
        try:
            assert RULE not in _linux_policies(api) and (await get(LD._req(), b""))[1]["builtin"] == []
            answers(layout.home, **ON)  # the user says yes while the sandbox runs
            payload = await edit([{"host": "pypi.org", "port": 443}])
            assert set(_linux_policies(api)) == {"hermes_site_pypi_org_443", RULE}
            assert payload["builtin"] == [ROW] and payload["network"]["allow"] == [{"host": "pypi.org", "port": 443}]
            assert sup.status()["applied"]["network"]["allow"] == [{"host": "pypi.org", "port": 443}]
            assert not sup.status()["restart_required"] and not sup.status()["pending"]["network"]
            # the user removes every destination of their own: the built-in one stays, and is in no saved spec
            await edit([])
            assert set(_linux_policies(api)) == {RULE} and HOST not in saved() and RULE not in saved()
            # read back from the gateway it is neither a destination nor a grant
            assert sup.driver.current_network() == {"egress": "deny", "allow": []}
            # an approved request makes the live policy the saved one: the built-in rule is not adopted with it
            api.block("hermes-work", "draft1", "example.com", 443, "/usr/bin/curl")
            approve = routes.match("POST", "/api/plugins/openshell/proposals/draft1/approve")
            status, payload, _ = await approve(LD._req(), b"{}")
            assert status == 200 and set(payload["network"]["approved"]) == {"allow_example_com_443"}
            assert set(_linux_policies(api)) == {RULE, "allow_example_com_443"}
            assert HOST not in saved() and RULE not in saved()
            # restoring a revision from before the answer keeps today's answer
            status, payload, _ = await rollback(LD._req(), b'{"version": 1}')
            assert status == 200 and set(_linux_policies(api)) == {RULE} and HOST not in saved()
            # sharing turned off: the next update leaves it out, and a restored revision that held it does not bring it back
            answers(layout.home, enabled=False, send=False)
            await edit([{"host": "pypi.org", "port": 443}])
            assert set(_linux_policies(api)) == {"hermes_site_pypi_org_443"} and sup.driver.usage_data_open is False
            with_rule = next(r["version"] for r in api.revisions["hermes-work"] if RULE in r["policy"]["network_policies"])
            status, payload, _ = await rollback(LD._req(), json.dumps({"version": with_rule}).encode())
            assert status == 200 and RULE not in _linux_policies(api)
            # a restart decides again
            answers(layout.home, **ON)
            await sup.restart()
            assert RULE in [c for c in api.calls if c[0] == "create"][-1][2]["policy"]["network_policies"]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_reading_a_policy_back_leaves_the_built_in_rule_out():
    def rule(name, host, path):
        return {"name": name, "endpoints": [{"host": host, "port": 443}], "binaries": [{"path": path}]}

    policy = {"network_policies": {RULE: rule(RULE, HOST, "/py"),
                                   "hermes_site_pypi_org_443": rule("hermes_site_pypi_org_443", "pypi.org", "/py"),
                                   "allowed_host_example_com": rule("allowed_host_example_com", "example.com", "**")}}
    network = OD.network_from_policy(policy, ["/py"])
    assert network["allow"] == [{"host": "pypi.org", "port": 443}] and set(network["approved"]) == {"allowed_host_example_com"}


# -- the Windows driver -------------------------------------------------------------------------------------

def _windows(tmp_path, monkeypatch, tunnels=True, network=None):
    layout, runtime, cfg, bb = WD._tree(tmp_path)
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"TEST_MODEL_KEY": WD.SECRET, "OTHER_TOKEN": WD.DECOY})
    fake = WD.FakeCli()
    driver = WD._driver(cfg, fake, tmp_path, tls_tunnels=tunnels)
    sup = WD._supervisor(layout, runtime, driver, bb, network=network)
    return sup, fake, driver, layout


@pytest.mark.parametrize("name, keys, is_open", DRIVER_CASES, ids=DRIVER_IDS)
def test_windows_the_sandbox_starts_with_the_rule_only_while_the_profile_shares(tmp_path, monkeypatch, name, keys, is_open):
    sup, fake, driver, layout = _windows(tmp_path, monkeypatch, network={
        "egress": "deny", "allow": [{"host": "pypi.org", "port": 443}]})
    answers(layout.home, **keys)

    async def scenario():
        await sup.start()
        try:
            rules = fake.revisions["hermes-default"][0]["policy"]["network_policies"]
            assert (RULE in rules) is is_open and driver.usage_data_open is is_open
            assert {e["host"] for r in rules.values() for e in r["endpoints"]} <= {"pypi.org", HOST}
            if is_open:
                # the backend's own interpreter in native form, and a TLS tunnel to the site: as the page's destinations
                assert rules[RULE]["binaries"] == rules["hermes_site_pypi_org_443"]["binaries"] \
                    == [{"path": b} for b in driver._binaries]
                assert len(driver._binaries) == 1 and WD._native_form(driver._binaries[0])
                assert Path(driver._binaries[0]).parts[-2:] == ("python-3.14", "python.exe")  # the store's, not the venv's
                assert rules[RULE]["endpoints"] == [{"host": HOST, "port": 443, "tls": "skip"}]
                assert rules["hermes_site_pypi_org_443"]["endpoints"] == [{"host": "pypi.org", "port": 443, "tls": "skip"}]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_windows_a_runtime_without_tunnels_gets_the_rule_without_one(tmp_path, monkeypatch):
    sup, fake, driver, layout = _windows(tmp_path, monkeypatch, tunnels=False)
    answers(layout.home, **ON)

    async def scenario():
        await sup.start()
        try:
            rules = fake.revisions["hermes-default"][0]["policy"]["network_policies"]
            assert rules[RULE]["endpoints"] == [{"host": HOST, "port": 443}]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_windows_the_rule_follows_the_answer_at_every_network_update_and_is_never_a_grant(tmp_path, monkeypatch):
    sup, fake, driver, layout = _windows(tmp_path, monkeypatch)

    def live():
        return fake.revisions["hermes-default"][-1]["policy"].get("network_policies") or {}

    async def scenario():
        await sup.start()
        try:
            assert RULE not in live() and driver.usage_data_open is False
            answers(layout.home, **ON)
            await sup.apply_network({"egress": "deny", "allow": [{"host": "pypi.org", "port": 443}]})
            assert set(live()) == {"hermes_site_pypi_org_443", RULE} and driver.usage_data_open is True
            assert live()[RULE]["endpoints"] == [{"host": HOST, "port": 443, "tls": "skip"}]
            assert live()[RULE]["binaries"] == [{"path": b} for b in driver._binaries]
            assert driver.current_network() == {"egress": "deny", "allow": [{"host": "pypi.org", "port": 443}]}
            await sup.apply_network({"egress": "deny", "allow": []})
            assert set(live()) == {RULE}
            driver.approve("60c3fdd8-1b45-40ff-8605-d2b3fb08bf8a")  # the gateway merges its own rule in
            assert set(live()) == {RULE, "allow_example_com_443"}
            assert set(driver.current_network()["approved"]) == {"allow_example_com_443"}
            back = driver.rollback(1)  # a revision from before the answer: today's answer stays
            assert back["restored"] == 1 and set(live()) == {RULE}
            answers(layout.home, **ON, endpoint=OTHER)
            await sup.apply_network({"egress": "deny", "allow": []})
            assert live() == {} and driver.usage_data_open is False
            with_rule = next(r["version"] for r in fake.revisions["hermes-default"]
                             if RULE in (r["policy"].get("network_policies") or {}))
            driver.rollback(with_rule)  # a revision that held it: not brought back
            assert RULE not in live() and "example.net" not in json.dumps(fake.revisions["hermes-default"])
        finally:
            await sup.stop()

    asyncio.run(scenario())


# -- an answer given while the sandbox runs -----------------------------------------------------------------

class _Sup(TC.FakeSup):
    """A supervisor whose driver decides the built-in rule at each update, as the OpenShell drivers do."""

    async def apply_network(self, network):
        self.driver.usage_data_open = U.shared(self.layout.home)
        return await super().apply_network(network)


def _watching(harness, driver=None):  # noqa: F811
    harness["sup"] = sup = _Sup(harness["layout"], driver or harness["driver"], harness["sup"]._grants)
    sup.driver.usage_data_open = False  # the sandbox started while the profile shared nothing
    return sup, [1000.0]


def _noted(cards):
    return [e["shared"] for e in cards._records if e.get("event") == "usage data"]


def test_an_answer_given_while_the_sandbox_runs_loads_one_policy_update_once_it_has_stood(harness):  # noqa: F811
    sup, now = _watching(harness)

    async def main():
        cards, conn = await TC._setup(harness, clock=lambda: now[0])
        cards._watch_usage_data()
        await TC._settle(10)
        assert sup.applies == []  # nothing changed: no update
        answers(harness["home"], **ON)
        cards._watch_usage_data()
        now[0] += C.USAGE_DATA_HOLD - 1
        cards._watch_usage_data()
        await TC._settle(10)
        assert sup.applies == []  # seen, not yet standing
        now[0] += 1
        cards._watch_usage_data()
        await TC._settle()
        assert sup.applies == [[]] and sup.driver.usage_data_open is True  # one update, no grant in it
        assert _noted(cards) == [True]
        for _ in range(5):
            now[0] += C.USAGE_DATA_HOLD
            cards._watch_usage_data()
        await TC._settle(10)
        assert sup.applies == [[]]  # in place: nothing more
        assert TC._cards(conn) == [] and TC._continuations(conn) == []  # no card, no message to the agent
        answers(harness["home"], enabled=False, send=False)  # and off again
        cards._watch_usage_data()
        now[0] += C.USAGE_DATA_HOLD
        cards._watch_usage_data()
        await TC._settle()
        assert sup.applies == [[], []] and sup.driver.usage_data_open is False
        assert _noted(cards) == [True, False]
        await cards.stop()

    asyncio.run(main())


def test_a_config_flipped_back_and_forth_loads_nothing(harness):  # noqa: F811
    sup, now = _watching(harness)

    async def main():
        cards, conn = await TC._setup(harness, clock=lambda: now[0])
        for _ in range(6):
            answers(harness["home"], **ON)
            cards._watch_usage_data()
            now[0] += C.USAGE_DATA_HOLD - 1
            cards._watch_usage_data()
            answers(harness["home"], enabled=False, send=False)
            now[0] += C.USAGE_DATA_HOLD
            cards._watch_usage_data()
        await TC._settle(10)
        assert sup.applies == [] and not cards._net_dirty and _noted(cards) == []
        await cards.stop()

    asyncio.run(main())


def test_on_a_build_whose_reload_cuts_connections_the_update_waits_for_the_turn_to_end(harness):  # noqa: F811
    sup, now = _watching(harness, driver=TC.InterruptingDriver())

    async def main():
        cards, conn = await TC._setup(harness, clock=lambda: now[0])
        await TC._turn_start(cards, conn)
        answers(harness["home"], **ON)
        cards._watch_usage_data()
        now[0] += C.USAGE_DATA_HOLD
        cards._watch_usage_data()
        await TC._settle()
        assert sup.applies == [] and cards._net_dirty  # the model's reply would be cut off
        await TC._turn_end(cards, conn)
        assert sup.applies == [[]] and sup.driver.usage_data_open is True
        assert TC._continuations(conn) == []  # nothing for the agent to continue with
        await cards.stop()

    asyncio.run(main())


def test_the_watch_leaves_a_stopped_sandbox_and_a_driver_without_the_rule_alone(harness):  # noqa: F811
    sup, now = _watching(harness)

    async def main():
        cards, conn = await TC._setup(harness, clock=lambda: now[0])
        answers(harness["home"], **ON)

        def watch_twice():
            cards._watch_usage_data()
            now[0] += C.USAGE_DATA_HOLD
            cards._watch_usage_data()

        sup.state = "restarting"  # the next start decides
        watch_twice()
        sup.state, sup.driver.usage_data_open = "running", None  # a driver that built no rules, or adds none
        watch_twice()
        sup.driver.usage_data_open = False
        cards._net_dirty = True  # an update is already waiting: it carries the answer
        watch_twice()
        cards._net_dirty = False
        await TC._settle(10)
        assert sup.applies == [] and cards._usage_data_since is None and _noted(cards) == []
        watch_twice()
        await TC._settle()
        assert sup.applies == [[]] and _noted(cards) == [True]
        await cards.stop()

    asyncio.run(main())


class _RestartOnly(TC.FakeDriver):
    """A driver whose network changes wait for a restart."""
    capabilities_info = {**TC.FakeDriver.capabilities_info, "network_live": False}


def test_a_driver_that_changes_the_network_only_at_a_restart_gets_no_live_update(harness):  # noqa: F811
    sup, now = _watching(harness, driver=_RestartOnly())

    async def main():
        cards, conn = await TC._setup(harness, clock=lambda: now[0])
        answers(harness["home"], **ON)
        cards._watch_usage_data()
        now[0] += C.USAGE_DATA_HOLD
        cards._watch_usage_data()
        await TC._settle(10)
        assert sup.applies == [] and not cards._net_dirty and _noted(cards) == []  # the next start decides
        await cards.stop()

    asyncio.run(main())


def test_the_watch_runs_in_the_launchers_loop_and_reaches_the_real_driver(tmp_path, monkeypatch):
    """The launcher's own loop, the real supervisor and the Linux driver: the answer reaches the gateway, once,
    and nothing about it shows as a grant."""
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    monkeypatch.setattr(C, "USAGE_DATA_HOLD", 0.05)

    async def scenario():
        await sup.start()
        cards = C.Cards(sup, layout, cards=True, settle=0.0, poll_interval=0.02, batch_window=0.01, request_poll=3600,
                        bg_wait=0.0)
        cards.start()
        try:
            await asyncio.sleep(0.3)
            assert RULE not in _linux_policies(api) and len(api.revisions["hermes-work"]) == 1
            answers(layout.home, **ON)
            for _ in range(200):
                if RULE in _linux_policies(api):
                    break
                await asyncio.sleep(0.05)
            assert RULE in _linux_policies(api) and sup.driver.usage_data_open is True
            count = len(api.revisions["hermes-work"])
            await asyncio.sleep(0.4)
            assert len(api.revisions["hermes-work"]) == count  # one update for one answer
            assert HOST not in json.dumps(load_spec(layout)["network"]) and cards.grants_view()["grants"] == []
            assert (await cards.remove_grant(f"network:always:{HOST}"))[0] == 404  # nothing under "Allowed from chat"
            assert (await cards.remove_grant(f"network:allow:{HOST}"))[0] == 404
            assert RULE in _linux_policies(api) and cards.open == {}
        finally:
            await cards.stop()
            await sup.stop()

    asyncio.run(scenario())


# -- the Sandbox page ---------------------------------------------------------------------------------------

def test_the_sandbox_page_lists_the_destination_with_its_reason_while_the_profile_shares(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    caps = sup.driver.capabilities()

    def page():
        return config_payload(layout, load_spec(layout), caps, sandboxed=True, restart_required=False,
                              resolve=lambda host: [])

    assert page()["builtin"] == []
    answers(layout.home, enabled=True, send=False)
    assert page()["builtin"] == []
    answers(layout.home, **ON)
    payload = page()
    assert payload["builtin"] == [{"host": HOST, "port": 443, "reason": REASON, "rule": RULE}]
    assert payload["network"] == network_policy(load_spec(layout))  # the user's own list is untouched by it
    assert HOST not in json.dumps(payload["network"])
    assert REASON[0].isupper() and not REASON.endswith(".") and REASON == REASON.strip()  # the page's register
    answers(layout.home, **ON, endpoint=OTHER)
    assert page()["builtin"] == []
