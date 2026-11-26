"""A model server on this computer that takes no key, with the sandbox on.

A key's provider opens its model's address. A model entry without a key has no provider, so the launcher opens the
pinned address with a rule of its own: one port of this computer for Hermes's interpreter, decided at every start,
network update and restored revision, never saved, and never widened by what the sandbox writes into its config.
The Sandbox page's row for a model's address says what the sandbox reaches. Fake gateways throughout: nothing here
talks to a network.
"""
import asyncio
import json
import time

import pytest

import test_openshell_driver as LD
import test_openshell_windows as WD
from openshell.launcher import openshell_driver as OD
from openshell.launcher import pins
from openshell.launcher import settings_view as SV
from openshell.launcher import supervisor as S
from openshell.launcher.spec import load_spec, save_spec

ALIAS = "host.openshell.internal"
URL = "http://127.0.0.1:18530/v1"
RULE = "hermes_builtin_model_18530"
PYPI = {"host": "pypi.org", "port": 443}
SITE = OD.rule_name("site", "pypi.org", 443)
KEYLESS = "model:\n  default: m\n  provider: custom\n  base_url: http://127.0.0.1:18530/v1\n"
KEYED = KEYLESS + "  key_env: LOCAL_KEY\n"
VALUE = "sk-local-" + "k" * 24


def entry(label, url, **extra):
    return {"label": label, "provider": "custom", "base_url": url, "url": url, "key_env": "", "api_key_env": "", **extra}


def pin(**extra):
    return {"present": True, "allowed": [], "models": [entry("Model", URL, **extra)]}


def opened(routes):
    return [(route["host"], route["port"]) for route in routes]


NO_KEY = [("no key named", pin(), {}),
          ("a key named and not set", pin(key_env="LOCAL_KEY"), {}),
          ("a key named and empty", pin(key_env="LOCAL_KEY"), {"LOCAL_KEY": ""})]


# -- which addresses get the rule ---------------------------------------------------------------------------

@pytest.mark.parametrize("name, route_pin, secrets", NO_KEY, ids=[case[0] for case in NO_KEY])
def test_a_pinned_model_on_this_computer_without_a_key_gets_one_rule_for_its_port(name, route_pin, secrets):
    found = OD.discover_routes(None, secrets, route_pin)
    assert found.routes == []  # no key, so no provider opens the address
    models = OD.local_models(route_pin, opened(found.routes))
    assert [(m["label"], m["host"], m["port"]) for m in models] == [("Model", ALIAS, 18530)]
    rules = OD.model_rules({SITE: {"name": SITE}}, models, ["/store/python3"])
    assert set(rules) == {SITE, RULE}
    assert rules[RULE] == {"name": RULE, "endpoints": [{"host": ALIAS, "port": 18530}],
                           "binaries": [{"path": "/store/python3"}]}


def test_a_model_with_a_key_keeps_its_provider_and_gets_no_rule():
    route_pin = pin(key_env="LOCAL_KEY")
    found = OD.discover_routes(None, {"LOCAL_KEY": VALUE}, route_pin)
    assert opened(found.routes) == [(ALIAS, 18530)]
    assert OD.local_models(route_pin, opened(found.routes)) == []
    assert OD.model_rules({SITE: {"name": SITE}}, [], ["/store/python3"]) == {SITE: {"name": SITE}}


def test_only_pinned_addresses_on_this_computer_get_a_rule():
    route_pin = {"present": True, "allowed": [], "models": [
        entry("Model", "http://localhost:11434/v1"),
        entry("Fallback model", "http://[::1]:8081/v1"),
        entry("Auxiliary model (vision)", "http://127.0.0.1:11434/v1"),  # the model's own port: one rule
        entry("Saved endpoint office", "http://models.example.net:8000/v1"),  # another computer
        entry("Fallback model", "http://192.168.1.20:8000/v1"),  # another computer on the local network
        entry("Fallback model", ""), "not an entry"]}
    assert [(m["label"], m["host"], m["port"]) for m in OD.local_models(route_pin)] == [
        ("Model", ALIAS, 11434), ("Fallback model", ALIAS, 8081)]
    assert [m["port"] for m in OD.local_models(route_pin, [(ALIAS, 11434)])] == [8081]  # a provider opens the first
    assert OD.local_models({"present": False, "models": [], "allowed": []}) == [] and OD.local_models(None) == []


def test_the_rule_needs_an_interpreter_and_replaces_whatever_holds_its_name():
    models = OD.local_models(pin())
    assert OD.model_rules({}, models, []) == {} and OD.model_rules({}, models, [""]) == {}  # never for every program
    planted = {RULE: {"name": RULE, "endpoints": [{"host": "collector.example.net", "port": 443}],
                      "binaries": [{"path": "**"}]},
               "hermes_builtin_model_22": {"name": "hermes_builtin_model_22",
                                           "endpoints": [{"host": ALIAS, "port": 22}], "binaries": [{"path": "**"}]}}
    rules = OD.model_rules(planted, models, ["/py"])
    assert list(rules) == [RULE] and rules[RULE]["endpoints"] == [{"host": ALIAS, "port": 18530}]
    assert rules[RULE]["binaries"] == [{"path": "/py"}]
    assert OD.model_rules(planted, [], ["/py"]) == {}
    assert planted[RULE]["binaries"] == [{"path": "**"}]  # the caller's rules are not edited in place


def test_the_rule_is_neither_a_destination_nor_a_grant_and_keeps_the_proxys_own_tls_handling():
    def rule(name, host, port, path):
        return {"name": name, "endpoints": [{"host": host, "port": port}], "binaries": [{"path": path}]}

    rules = {RULE: rule(RULE, ALIAS, 18530, "/py"), SITE: rule(SITE, "pypi.org", 443, "/py")}
    assert OD.network_from_policy({"network_policies": rules}, ["/py"]) == {"egress": "deny", "allow": [PYPI]}
    tunnels = OD.passthrough(rules, [])
    assert tunnels[SITE]["endpoints"] == [{"host": "pypi.org", "port": 443, "tls": "skip"}]
    assert tunnels[RULE]["endpoints"] == [{"host": ALIAS, "port": 18530}]  # as a key's provider endpoint is reached


# -- the Linux driver ---------------------------------------------------------------------------------------

def _linux(tmp_path, monkeypatch, model, secrets=None, network=None):
    layout = LD._layout(tmp_path)
    (layout.home / "config.yaml").write_text(model, encoding="utf-8")
    spec = load_spec(layout)
    spec.update(driver="openshell", folders=LD._folders(tmp_path), network=network or {"egress": "deny", "allow": []})
    save_spec(layout, spec)
    pins.take(layout)
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: dict(secrets or {}))
    api, rec = LD.FakeApi(), LD.Recorder()
    driver = OD.OpenShellDriver(LD._cfg(tmp_path), api=api, run=rec.run, popen=rec.popen)
    return S.Supervisor(layout, LD._runtime(tmp_path), load_spec(layout), driver, outer_port=1), api, layout


def _linux_rules(api):
    return api.revisions["hermes-work"][-1]["policy"]["network_policies"]


def _created(api):
    return [call for call in api.calls if call[0] == "create"][-1][2]["policy"]["network_policies"]


def test_linux_a_model_without_a_key_is_reachable_through_a_rule_for_its_pinned_port(tmp_path, monkeypatch):
    sup, api, layout = _linux(tmp_path, monkeypatch, KEYLESS, network={"egress": "deny", "allow": [PYPI]})

    async def scenario():
        await sup.start()
        try:
            rules = _linux_rules(api)
            assert sup.driver.registered_providers() == []
            assert set(rules) == {RULE, SITE}
            assert rules[RULE] == {"name": RULE, "endpoints": [{"host": ALIAS, "port": 18530}],
                                   "binaries": [{"path": b} for b in sup.driver._binaries]}
            assert list(sup.driver._binaries) == [str(sup.driver._runtime.real_python)]  # Hermes's interpreter only
            # the user's edits neither remove nor save it, and a restored revision keeps it
            await sup.apply_network({"egress": "deny", "allow": []})
            assert set(_linux_rules(api)) == {RULE}
            assert sup.driver.current_network() == {"egress": "deny", "allow": []}
            sup.driver.rollback(1)
            assert RULE in _linux_rules(api)
            # the sandbox writes another port into its config: the pin decides, so nothing new is opened
            (layout.home / "config.yaml").write_text(KEYLESS.replace("18530", "18999"), encoding="utf-8")
            await sup.restart()
            assert {name for name in _created(api) if name.startswith("hermes_builtin_")} == {RULE}
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_linux_a_model_with_a_key_is_opened_by_its_provider_alone(tmp_path, monkeypatch):
    sup, api, layout = _linux(tmp_path, monkeypatch, KEYED, secrets={"LOCAL_KEY": VALUE})

    async def scenario():
        await sup.start()
        try:
            assert [row["endpoints"] for row in sup.driver.registered_providers()] == [[f"{ALIAS}:18530"]]
            assert _linux_rules(api) == {}
        finally:
            await sup.stop()

    asyncio.run(scenario())


# -- the Windows driver -------------------------------------------------------------------------------------

def _windows(tmp_path, monkeypatch, model=None, secrets=None, tunnels=True):
    layout, runtime, cfg, bb = WD._tree(tmp_path)
    if model is not None:
        (layout.home / "config.yaml").write_text(model + "terminal:\n  backend: local\n", encoding="utf-8")
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: dict(secrets or {}))
    fake = WD.FakeCli()
    driver = WD._driver(cfg, fake, tmp_path, tls_tunnels=tunnels)
    return WD._supervisor(layout, runtime, driver, bb), fake, driver, layout


def _windows_rules(fake):
    return fake.revisions["hermes-default"][-1]["policy"].get("network_policies") or {}


@pytest.mark.parametrize("tunnels", [True, False], ids=["tls tunnels", "no tls tunnels"])
def test_windows_a_model_without_a_key_is_reachable_through_a_rule_for_its_pinned_port(tmp_path, monkeypatch, tunnels):
    sup, fake, driver, layout = _windows(tmp_path, monkeypatch, KEYLESS, tunnels=tunnels)

    async def scenario():
        await sup.start()
        try:
            rules = _windows_rules(fake)
            assert driver.registered_providers() == []
            assert set(rules) == {RULE}
            assert rules[RULE] == {"name": RULE, "endpoints": [{"host": ALIAS, "port": 18530}],
                                   "binaries": [{"path": b} for b in driver._binaries]}
            assert len(driver._binaries) == 1 and WD._native_form(driver._binaries[0])
            # the address Hermes is given inside is the one the rule opens
            assert driver.policy()["model_overrides"] == {"model": {"base_url": f"http://{ALIAS}:18530/v1"}}
            await sup.apply_network({"egress": "deny", "allow": [PYPI]})
            assert set(_windows_rules(fake)) == {RULE, SITE}
            assert driver.current_network() == {"egress": "deny", "allow": [PYPI]}
            await sup.apply_network({"egress": "deny", "allow": []})
            driver.rollback(2)  # the revision that held the site: the rule stays as the pin has it
            assert RULE in _windows_rules(fake)
            assert _windows_rules(fake)[RULE]["endpoints"] == [{"host": ALIAS, "port": 18530}]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_windows_a_model_with_a_key_is_opened_by_its_provider_alone(tmp_path, monkeypatch):
    sup, fake, driver, layout = _windows(tmp_path, monkeypatch, secrets={"TEST_MODEL_KEY": WD.SECRET})

    async def scenario():
        await sup.start()
        try:
            assert [row["endpoints"] for row in driver.registered_providers()] == [[f"{ALIAS}:8080"]]
            assert _windows_rules(fake) == {}
        finally:
            await sup.stop()

    asyncio.run(scenario())


# -- what the Sandbox page is told --------------------------------------------------------------------------

CAPS = {"driver": "openshell", "model_endpoints": "provider", "host_loopback": "closed"}
DENY = {"egress": "deny", "allow": []}
ELSEWHERE = "http://models.example.net:8000/v1"


def _unresolved(host):
    raise AssertionError(f"{host} was looked up")  # a model's name is never resolved for these drivers


def test_a_model_address_is_allowed_only_where_something_opens_it():
    assert SV.endpoint_reach(URL, DENY, CAPS, _unresolved) == ("allowed", "model")
    assert SV.endpoint_reach(URL, DENY, CAPS, _unresolved, pinned=False) == ("blocked", None)
    assert SV.endpoint_reach("https://api.example.com/v1", DENY, CAPS, _unresolved) == ("allowed", "provider")
    # a server on another computer that takes no key is reachable only as a destination of the user's
    assert SV.endpoint_reach(ELSEWHERE, DENY, CAPS, _unresolved, keyless=True) == ("blocked", None)
    listed = {"egress": "deny", "allow": [{"host": "models.example.net", "port": 8000}]}
    assert SV.endpoint_reach(ELSEWHERE, listed, CAPS, _unresolved, keyless=True) == ("allowed", "rule")


def _rows(layout, **kw):
    return [(row["label"], row["reach"], row["via"]) for row in SV.model_endpoints(layout, DENY, CAPS, _unresolved, **kw)]


def test_the_network_rows_follow_what_the_sandbox_opens(tmp_path):
    layout = LD._layout(tmp_path)
    config = layout.home / "config.yaml"
    config.write_text(KEYLESS, encoding="utf-8")
    assert _rows(layout) == [("Model", "allowed", "model")]  # before the switch: the switch-on pins this address
    pins.take(layout)
    assert _rows(layout, sandboxed=True) == [("Model", "allowed", "model")]
    # another port written while the sandbox is on is not the pinned one
    config.write_text(KEYLESS.replace("18530", "18999"), encoding="utf-8")
    assert _rows(layout, sandboxed=True) == [("Model", "blocked", None)]
    config.write_text(f"model:\n  provider: custom\n  base_url: {ELSEWHERE}\n", encoding="utf-8")
    assert _rows(layout) == [("Model", "blocked", None)]
    config.write_text(f"model:\n  provider: custom\n  base_url: {ELSEWHERE}\n  key_env: LOCAL_KEY\n", encoding="utf-8")
    assert _rows(layout) == [("Model", "allowed", "provider")]


# -- addresses a sandbox can have written into config.yaml ------------------------------------------------------

LONG = 200_000
ODD = [("unclosed brackets", "http://" + "[" * LONG),
       ("a port of digits without end", "http://127.0.0.1:" + "9" * LONG + "/v1"),
       ("labels without end", "http://" + "a." * (LONG // 2) + "example/v1"),
       ("this computer and a path without end", "http://127.0.0.1:18530/" + "v1/" * (LONG // 3)),
       ("separators only", "http://" + "@:/?#%[]" * (LONG // 8)),
       ("one unclosed bracket", "http://[::1")]


@pytest.mark.parametrize("name, url", ODD, ids=[case[0] for case in ODD])
def test_text_that_is_no_address_opens_nothing_and_is_read_in_bounded_time(name, url):
    started = time.monotonic()
    many = [entry("Model", url)] * (OD.MAX_LOCAL_MODELS - 1)
    assert OD.local_models({"present": True, "allowed": [], "models": [*many, entry("Fallback model", URL)]}) == [
        {"label": "Fallback model", "host": ALIAS, "port": 18530, "url": URL}]
    # only the first entries are read, however many a config lists
    assert OD.local_models({"present": True, "allowed": [], "models": [entry("Model", url)] * LONG + [entry("x", URL)]}) == []
    keyed = {"present": True, "allowed": [], "models": [entry("Model", url, key_env="LOCAL_KEY")]}
    assert OD.discover_routes(None, {"LOCAL_KEY": VALUE}, keyed).routes == []  # a key is bound to no such text
    for keyless in (True, False):
        reach = SV.endpoint_reach(url, DENY, CAPS, _unresolved, keyless=keyless)
        assert reach == (("blocked", None) if keyless or len(url) > OD.MAX_MODEL_URL else ("allowed", "provider"))
    assert time.monotonic() - started < 5


def test_the_network_rows_of_a_config_the_sandbox_wrote_are_bounded(tmp_path):
    layout = LD._layout(tmp_path)
    fallbacks = [{"provider": "custom", "base_url": f"http://127.0.0.1:{20000 + n}/v1"} for n in range(300)]
    (layout.home / "config.yaml").write_text(json.dumps(
        {"model": {"provider": "custom", "base_url": ODD[3][1]}, "fallback_providers": fallbacks}), encoding="utf-8")
    pins.take(layout)
    started = time.monotonic()
    rows = SV.model_endpoints(layout, DENY, CAPS, _unresolved, sandboxed=True)
    assert time.monotonic() - started < 5
    assert len(rows) == SV.MAX_MODEL_ROWS and (rows[0]["label"], rows[0]["reach"]) == ("Model", "blocked")
    # the launcher opens the first pinned ports only, and the page says "Allowed" for exactly those
    opened = {m["port"] for m in OD.local_models(pins.route_pin(layout))}
    assert len(opened) == OD.MAX_LOCAL_MODELS - 1
    assert {int(row["url"].split(":")[2].split("/")[0]) for row in rows[1:] if row["reach"] == "allowed"} == opened
