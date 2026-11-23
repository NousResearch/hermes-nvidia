"""Credentials with a declared placement: which keys the sandbox gets, where each travels on the wire, and the
credential sink both OpenShell drivers offer (declare, value-only update, quiet).

The Linux driver runs through the real supervisor against the fake gateway API of ``test_openshell_driver``, the
Windows driver against the fake CLI of ``test_openshell_windows``. Every key here is made up.
"""
import asyncio
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import test_openshell_driver as LD
import test_openshell_windows as WD
from openshell.launcher import credential_sink as CS
from openshell.launcher import layout as L
from openshell.launcher import openshell_driver as OD
from openshell.launcher import pins as P
from openshell.launcher import supervisor as S
from openshell.launcher.cards import Cards
from openshell.launcher.driver import DriverUnavailable, NotSupported
from openshell.launcher.host_routes import HostRoutes

GW = "host.openshell.internal"
KEYS = {name: f"{name.lower()}-" + "k" * 24 for name in
        ("MODEL_KEY", "FALLBACK_KEY", "OLD_FALLBACK_KEY", "AUX_KEY", "SAVED_KEY", "UNUSED_TOKEN")}
CONFIG = """model:
  provider: custom
  default: test-model
  base_url: http://127.0.0.1:18500/v1
  key_env: MODEL_KEY
fallback_providers:
- provider: custom
  model: test-claude
  base_url: http://host.openshell.internal:18601/anthropic
  key_env: FALLBACK_KEY
fallback_model:
  provider: custom
  model: test-old
  base_url: http://host.openshell.internal:18602/v1
  api_key_env: OLD_FALLBACK_KEY
  api_mode: anthropic_messages
auxiliary:
  title_generation:
    provider: gemini
    model: test-gemini
    base_url: http://host.openshell.internal:18603/generativelanguage.googleapis.com/v1beta
    key_env: AUX_KEY
  compression:
    provider: auto
providers:
  mine:
    name: mine
    base_url: http://host.openshell.internal:18604/v1
    key_env: SAVED_KEY
"""


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


@pytest.fixture
def layout(tmp_path):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    _write(home / "config.yaml", CONFIG)
    _write(home / ".env", "".join(f"{k}={v}\n" for k, v in KEYS.items()))
    return L.ProfileLayout(name="work", home=home, root=root)


def _by_env(routes):
    return {r["env"]: r for r in routes}


def _where(route):
    return route["host"], route["port"], route["placement"], route["name"]


# -- discovery ------------------------------------------------------------------------------------------------

def test_every_model_route_of_the_profile_is_read_from_the_pin_with_its_place_on_the_wire(layout):
    P.take(layout)
    found = OD.discover_routes(layout.home, P.secrets(layout), P.route_pin(layout))
    routes = _by_env(found.routes)
    assert _where(routes["MODEL_KEY"]) == (GW, 18500, "bearer", None) and routes["MODEL_KEY"]["loopback_rewrite"]
    assert routes["MODEL_KEY"]["label"] == "Model"
    # a fallback model that speaks Anthropic Messages takes its key in x-api-key
    assert _where(routes["FALLBACK_KEY"]) == (GW, 18601, "header", "x-api-key")
    assert routes["FALLBACK_KEY"]["label"] == "Fallback model"
    # the request shape an entry names itself is kept with it and decides too
    assert _where(routes["OLD_FALLBACK_KEY"]) == (GW, 18602, "header", "x-api-key")
    # an auxiliary task with a provider of its own, on Google AI Studio's own API
    assert _where(routes["AUX_KEY"]) == (GW, 18603, "header", "x-goog-api-key")
    # the same address under another provider's name: Hermes speaks OpenAI's protocol there, with a bearer token
    native = "http://host.openshell.internal:18603/generativelanguage.googleapis.com/v1beta"
    assert OD.wire_placement({"provider": "custom"}, native, "k") == ("bearer", None, False)
    assert OD.wire_placement({"provider": "google"}, native, "k") == ("header", "x-goog-api-key", False)
    names = pytest.importorskip("agent.auxiliary_client")._GEMINI_NATIVE_PROVIDER_NAMES
    assert set(OD._GEMINI_NAMES) == set(names)  # the names Hermes itself goes by
    assert routes["AUX_KEY"]["label"] == "Auxiliary model (title_generation)"
    assert _where(routes["SAVED_KEY"]) == (GW, 18604, "bearer", None) and routes["SAVED_KEY"]["label"] == "Saved endpoint mine"
    assert found.changed == [] and found.withheld == ["UNUSED_TOKEN"] and found.notes == []
    assert all(r["source"] == "configured" for r in found.routes)


def test_the_pin_decides_whatever_the_home_says_now(layout):
    P.take(layout)
    before = OD.discover_routes(layout.home, P.secrets(layout), P.route_pin(layout)).routes
    # what a sandboxed agent can write: its model at an address of its choosing, with a key it has no route for
    _write(layout.home / "config.yaml", "model:\n  provider: custom\n  base_url: https://elsewhere.example/v1\n"
                                        "  key_env: UNUSED_TOKEN\n")
    found = OD.discover_routes(layout.home, P.secrets(layout), P.route_pin(layout))
    assert found.routes == before  # every pinned pair, and nothing the home added
    assert found.changed == [{"label": "Model", "host": "elsewhere.example", "port": 443, "env": "UNUSED_TOKEN"}]
    assert found.withheld == ["UNUSED_TOKEN"]
    # without a pin none of the profile's own pairs is bound: no model entry vouches for itself
    assert OD.discover_routes(layout.home, P.secrets(layout), None).routes == []


def test_a_key_with_a_registered_address_is_handed_in_whether_or_not_a_model_uses_it():
    pytest.importorskip("hermes_cli.auth")
    secrets = {"DEEPSEEK_API_KEY": "sk-" + "d" * 30, "ANTHROPIC_API_KEY": "sk-ant-api03-" + "a" * 30,
               "GEMINI_API_KEY": "AIza" + "g" * 30, "OPENROUTER_API_KEY": "sk-or-" + "o" * 30,
               "MINIMAX_API_KEY": "mm-" + "m" * 30, "LM_API_KEY": "lm-" + "l" * 20, "SOME_OTHER_TOKEN": "x" * 20}
    found = OD.discover_routes(None, secrets, None)
    routes = _by_env(found.routes)
    assert _where(routes["DEEPSEEK_API_KEY"]) == ("api.deepseek.com", 443, "bearer", None)
    assert _where(routes["ANTHROPIC_API_KEY"]) == ("api.anthropic.com", 443, "header", "x-api-key")
    assert _where(routes["GEMINI_API_KEY"]) == ("generativelanguage.googleapis.com", 443, "header", "x-goog-api-key")
    assert _where(routes["OPENROUTER_API_KEY"]) == ("openrouter.ai", 443, "bearer", None)
    # Anthropic Messages at a host that asks for a bearer token
    assert _where(routes["MINIMAX_API_KEY"]) == ("api.minimax.io", 443, "bearer", None)
    assert all(r["source"] == "provider" and not r["token"] for r in found.routes)
    # a model server on this computer is bound only when a model entry names it; a name nobody registers stays out
    assert found.withheld == ["LM_API_KEY", "SOME_OTHER_TOKEN"] and found.changed == []


def test_only_a_provider_that_takes_a_key_lends_its_address_to_one(monkeypatch):
    auth = pytest.importorskip("hermes_cli.auth")
    rows = {"keyed": SimpleNamespace(name="Keyed", auth_type="api_key", api_key_env_vars=("KEYED_API_KEY",),
                                     inference_base_url="https://api.keyed.example/v1"),
            "signed-in": SimpleNamespace(name="Signed in", auth_type="oauth_device_code", api_key_env_vars=("SIGNED_IN_TOKEN",),
                                         inference_base_url="https://api.signed-in.example/v1"),
            "nowhere": SimpleNamespace(name="Nowhere", auth_type="api_key", api_key_env_vars=("NOWHERE_API_KEY",),
                                       inference_base_url="")}
    monkeypatch.setattr(auth, "PROVIDER_REGISTRY", rows)
    monkeypatch.setattr(auth, "BUILTIN_PROVIDER_IDS", frozenset(rows), raising=False)
    secrets = {"KEYED_API_KEY": "k" * 24, "SIGNED_IN_TOKEN": "s" * 24, "NOWHERE_API_KEY": "n" * 24}
    found = OD.discover_routes(None, secrets, None)
    assert [(r["env"], r["host"], r["port"], r["label"]) for r in found.routes] == [("KEYED_API_KEY", "api.keyed.example", 443, "Keyed")]
    assert found.withheld == ["NOWHERE_API_KEY", "SIGNED_IN_TOKEN"]


def test_an_anthropic_sign_in_token_is_a_bearer_token_and_an_api_key_is_not():
    pytest.importorskip("agent.anthropic_adapter")
    token, key = "sk-ant-oat01-" + "t" * 40, "sk-ant-api03-" + "a" * 40
    for env in ("ANTHROPIC_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"):
        (route,) = OD.discover_routes(None, {env: token}, None).routes
        assert _where(route) == ("api.anthropic.com", 443, "bearer", None) and route["token"] is True
    (route,) = OD.discover_routes(None, {"ANTHROPIC_TOKEN": key}, None).routes
    assert _where(route) == ("api.anthropic.com", 443, "header", "x-api-key") and route["token"] is False
    assert OD.wire_placement({"provider": "custom"}, "https://relay.example/anthropic", token) == ("header", "x-api-key", False)
    assert OD.wire_placement({"provider": "custom", "api_mode": "anthropic_messages"}, "https://relay.example/v1", key)[:2] \
        == ("header", "x-api-key")
    assert OD.wire_placement({"provider": "custom"}, "https://relay.example/v1", key) == ("bearer", None, False)
    assert OD.wire_placement({"provider": "gemini"}, "https://generativelanguage.googleapis.com/v1beta/openai", key)[0] == "bearer"


def test_web_search_keys_go_to_their_own_service_and_no_further():
    secrets = {"TAVILY_API_KEY": "tvly-" + "t" * 20, "BRAVE_SEARCH_API_KEY": "BSA" + "b" * 20,
               "PERPLEXITY_API_KEY": "pplx-" + "p" * 20, "KEENABLE_API_KEY": "kn-" + "k" * 20, "EXA_API_KEY": "exa-" + "e" * 20}
    found = OD.discover_routes(None, secrets, {"tools": ["web_search", "web_extract"]})
    routes = _by_env(found.routes)
    assert _where(routes["TAVILY_API_KEY"]) == ("api.tavily.com", 443, "bearer", None)
    assert _where(routes["BRAVE_SEARCH_API_KEY"]) == ("api.search.brave.com", 443, "header", "x-subscription-token")
    assert _where(routes["PERPLEXITY_API_KEY"]) == ("api.perplexity.ai", 443, "bearer", None)
    assert _where(routes["KEENABLE_API_KEY"]) == ("api.keenable.ai", 443, "bearer", None)
    assert all(r["source"] == "web" for r in found.routes)
    assert found.withheld == ["EXA_API_KEY"]  # sent by its vendor's client library: not established, not handed in


def test_one_key_at_two_addresses_is_one_provider_and_no_two_address_sets_share_a_name(layout):
    _write(layout.home / "config.yaml", CONFIG.replace("key_env: FALLBACK_KEY", "key_env: MODEL_KEY")
           .replace(":18601/anthropic", ":18601/v1"))
    P.take(layout)
    routes = OD.discover_routes(layout.home, P.secrets(layout), P.route_pin(layout)).routes
    decls = dict((env, decl) for decl, env in OD.key_declarations(routes))
    both = decls["MODEL_KEY"]
    assert both.id == "env:MODEL_KEY" and both.endpoints == (CS.Endpoint(GW, 18500), CS.Endpoint(GW, 18601))
    profile = OD.credential_profile("p", [(both, "MODEL_KEY")], ("/py",), stable=True)
    assert [(e["host"], e["port"]) for e in profile["endpoints"]] == [(GW, 18500), (GW, 18601)]
    assert [c["env_vars"] for c in profile["credentials"]] == [["MODEL_KEY"]]
    one = CS.CredentialDecl(id="env:MODEL_KEY", label="x", endpoints=(CS.Endpoint(GW, 18500),))
    other = CS.CredentialDecl(id="env:MODEL_KEY", label="x", endpoints=(CS.Endpoint(GW, 18601),))
    names = {OD.provider_id("hermes-work", [(d, "MODEL_KEY")], True) for d in (both, one, other)}
    assert len(names) == 3 and all(n.startswith("hermes-work-model-key-") and len(n) <= 63 for n in names)
    # the same credential, another place on the wire or another kind of placeholder: another name too
    header = CS.CredentialDecl(id="env:MODEL_KEY", label="x", endpoints=one.endpoints, placement="header", name="x-api-key")
    assert OD.provider_id("hermes-work", [(header, "MODEL_KEY")], True) not in names
    assert OD.provider_id("hermes-work", [(one, "MODEL_KEY")], False) not in names
    assert OD.provider_id("hermes-work", [(one, "MODEL_KEY")], True) == OD.provider_id("hermes-work", [(one, "MODEL_KEY")], True)


def test_one_key_has_one_place_on_the_wire(layout):
    # the same key as a bearer token at one address and in x-api-key at the next: the second is left out, and said
    _write(layout.home / "config.yaml", CONFIG.replace("key_env: FALLBACK_KEY", "key_env: MODEL_KEY"))
    P.take(layout)
    found = OD.discover_routes(layout.home, P.secrets(layout), P.route_pin(layout))
    assert [(r["host"], r["port"]) for r in found.routes if r["env"] == "MODEL_KEY"] == [(GW, 18500)]
    (note,) = found.notes
    assert "MODEL_KEY" in note and "18601" in note and "x-api-key" in note and "bearer token" in note


# -- profiles -------------------------------------------------------------------------------------------------

def _decl(placement="bearer", name=None, endpoints=None, cid="env:SOME_KEY", expires=False):
    return CS.CredentialDecl(id=cid, label="Some key", endpoints=endpoints or (CS.Endpoint("api.example.com", 443),),
                             placement=placement, name=name, expires=expires)


def test_a_profile_says_the_one_place_its_credential_travels_in():
    def cred(decl, stable=False):
        (entry,) = OD.credential_profile("p", [(decl, "SOME_KEY")], ("/py",), stable)["credentials"]
        return {k: v for k, v in entry.items() if k not in ("name", "description", "env_vars", "required")}

    assert cred(_decl()) == {"auth_style": "bearer", "header_name": "authorization"}
    assert cred(_decl("header", "X-Api-Key")) == {"auth_style": "header", "header_name": "x-api-key"}
    assert cred(_decl("query", "key")) == {"auth_style": "query", "query_param": "key"}
    assert cred(_decl("path", "/bot{credential}/send")) == {"auth_style": "path", "path_template": "/bot{credential}/send"}
    assert cred(_decl("basic")) == {"auth_style": "basic"}
    assert cred(_decl(), stable=True) == {"auth_style": "bearer", "header_name": "authorization", "stable_placeholder": True}
    profile = OD.credential_profile("hermes-work-some-key-0", [(_decl(), "SOME_KEY")], ("/py",))
    assert profile["id"] == "hermes-work-some-key-0" and profile["binaries"] == ["/py"]
    assert profile["endpoints"] == [{"host": "api.example.com", "port": 443, "protocol": "rest", "access": "read-write",
                                     "enforcement": "enforce"}]
    assert profile["credentials"][0]["env_vars"] == ["SOME_KEY"] and profile["credentials"][0]["required"] is True


def test_a_websocket_address_and_a_path_get_their_own_endpoint_shape():
    decl = _decl(endpoints=(CS.Endpoint("api.example.com", 443, "/v1/realtime", "websocket"), CS.Endpoint("api.example.com", 443)))
    ws, rest = OD.credential_profile("p", [(decl, "SOME_KEY")], ("/py",))["endpoints"]
    assert ws == {"host": "api.example.com", "port": 443, "protocol": "websocket", "access": "full",
                  "enforcement": "enforce", "path": "/v1/realtime"}
    assert rest["protocol"] == "rest" and "path" not in rest


def test_the_values_of_one_request_signature_share_a_provider():
    where = (CS.Endpoint("bedrock-runtime.eu-west-1.amazonaws.com", 443),)
    decls = [(_decl("sigv4", "bedrock", where, f"env:{env}"), env) for env in OD.SIGV4_ENV]
    decls.insert(1, (_decl(), "SOME_KEY"))
    signing, plain = sorted(OD.provider_groups(decls), key=len, reverse=True)
    assert [env for _decl_, env in signing] == list(OD.SIGV4_ENV) and [env for _d, env in plain] == ["SOME_KEY"]
    profile = OD.credential_profile("p", signing, ("/py",))
    assert [(c["env_vars"], c["required"], "auth_style" in c) for c in profile["credentials"]] == [
        (["AWS_ACCESS_KEY_ID"], True, False), (["AWS_SECRET_ACCESS_KEY"], True, False), (["AWS_SESSION_TOKEN"], False, False)]
    (endpoint,) = profile["endpoints"]
    assert (endpoint["credential_signing"], endpoint["signing_service"], endpoint["signing_region"]) == ("sigv4", "bedrock", "eu-west-1")
    elsewhere = _decl("sigv4", "execute-api/us-west-2", (CS.Endpoint("gateway.example.com", 443),), "env:AWS_ACCESS_KEY_ID")
    (endpoint,) = OD.credential_profile("p", [(elsewhere, "AWS_ACCESS_KEY_ID")], ("/py",))["endpoints"]
    assert (endpoint["signing_service"], endpoint["signing_region"]) == ("execute-api", "us-west-2")


def test_a_credential_openshell_could_not_be_told_about_is_refused_with_the_reason():
    assert OD.credential_env(_decl()) == "SOME_KEY"
    assert OD.credential_env(_decl(cid="nous:agent_key")) == "HERMES_CRED_NOUS_AGENT_KEY"
    assert OD.credential_env(_decl(cid="env:not a name")) == "HERMES_CRED_ENV_NOT_A_NAME"
    OD.check_declaration(_decl())
    for bad, word in ((_decl("cookie"), "placement"), (_decl("header"), "name"), (_decl("query"), "name"),
                      (_decl("path", "/no/slot"), "{credential}"), (_decl("sigv4", "bedrock"), "AWS_ACCESS_KEY_ID"),
                      (_decl(endpoints=(CS.Endpoint("api.example.com", 443, None, "grpc"),)), "address"),
                      (_decl(endpoints=(CS.Endpoint("", 443),)), "address"),
                      (_decl(endpoints=(CS.Endpoint("api.example.com", 0),)), "address")):
        with pytest.raises(ValueError, match="(?i)" + word.replace("{", r"\{").replace("}", r"\}")):
            OD.check_declaration(bad)
    with pytest.raises(ValueError, match="no address"):
        OD.check_declaration(CS.CredentialDecl(id="x", label="x", endpoints=()))


# -- the sink on the Linux driver -----------------------------------------------------------------------------

NOUS = CS.CredentialDecl(id="nous:agent_key", label="Nous Portal", expires=True,
                         endpoints=(CS.Endpoint("inference-api.nousresearch.com", 443), CS.Endpoint("portal.nousresearch.com", 443)))


def _profiles(layout):
    return {p["id"]: p for p in (json.loads(f.read_text(encoding="utf-8")) for f in layout.state_dir.glob("provider-profile-*.json"))}


def test_a_declared_credential_is_registered_at_start_with_a_stable_placeholder_and_its_expiry(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    driver, expiry = sup.driver, time.time() + 900
    assert driver.declare(NOUS, "first-token", expiry) == "HERMES_CRED_NOUS_AGENT_KEY"

    async def scenario():
        await sup.start()
        try:
            (_, _, spec), = [c for c in api.calls if c[0] == "create"]
            nous, llama = sorted(api.providers)
            assert spec["providers"] == [nous, llama] and nous.startswith("hermes-work-hermes-cred-nous-agent-key-")
            assert api.providers[nous]["credentials"] == {"HERMES_CRED_NOUS_AGENT_KEY": "first-token"}
            assert api.providers[nous]["expires"] == {"HERMES_CRED_NOUS_AGENT_KEY": expiry}
            assert "expires" not in api.providers[llama]  # a key has no expiry
            profiles = _profiles(layout)
            assert profiles[nous]["credentials"][0]["stable_placeholder"] is True
            assert [e["host"] for e in profiles[nous]["endpoints"]] == ["inference-api.nousresearch.com", "portal.nousresearch.com"]
            # a key the Keys page can replace while the sandbox runs keeps its placeholder too
            assert profiles[llama]["credentials"][0]["stable_placeholder"] is True
            rows = {p["name"]: p for p in sup.policy()["enforced"]["providers"]}
            assert rows[nous]["stable"] and rows[nous]["state"] == "READY" and rows[nous]["placement"] == "bearer"
            assert rows[nous]["endpoints"] == ["inference-api.nousresearch.com:443", "portal.nousresearch.com:443"]
            assert "first-token" not in json.dumps(sup.policy()["enforced"]) + json.dumps(profiles)
            for argv, _env in rec.argvs:
                assert "first-token" not in " ".join(argv)
            # a value-only update: the same provider, the new value and its expiry, nothing created
            later = expiry + 900
            driver.update("nous:agent_key", "second-token", later)
            assert api.calls[-1] == ("provider update", nous, ["HERMES_CRED_NOUS_AGENT_KEY"],
                                     {"HERMES_CRED_NOUS_AGENT_KEY": later}, [])
            assert api.providers[nous]["credentials"] == {"HERMES_CRED_NOUS_AGENT_KEY": "second-token"}
            driver.update("nous:agent_key", "third-token", None)  # no expiry any more: the one it had is taken off
            assert api.calls[-1] == ("provider update", nous, ["HERMES_CRED_NOUS_AGENT_KEY"], {}, ["HERMES_CRED_NOUS_AGENT_KEY"])
            driver.update("env:LLAMA_API_KEY", "sk-new", None)
            assert api.calls[-1] == ("provider update", llama, ["LLAMA_API_KEY"], {}, [])
            with pytest.raises(NotSupported, match="no credential"):
                driver.update("nous:other", "x", None)
            # a restart registers what was declared again, with the newest value
            api.providers.clear()
            await sup.restart()
            assert sorted(api.providers) == [nous, llama]
            assert api.providers[nous]["credentials"] == {"HERMES_CRED_NOUS_AGENT_KEY": "third-token"}
            # Same names: nothing to forget. The only deletes are the names an earlier version gave its
            # providers (one per key of the profile), tried once at the first start.
            assert [c[1] for c in api.calls if c[0] == "provider delete"] == ["hermes-work-decoy-token",
                                                                              "hermes-work-llama-api-key"]
        finally:
            await sup.stop()
        driver.update("nous:agent_key", "after-stop", None)  # no sandbox: kept for the next start, no gateway call
        assert api.calls[-1][0] != "provider update"

    asyncio.run(scenario())


def test_a_provider_this_sandbox_no_longer_uses_is_deleted_from_the_gateway(tmp_path, monkeypatch):
    sup, api, _rec, layout = LD._supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        (first,) = api.providers
        await sup.stop()
        # the user set the model up at another address and switched the sandbox on again
        _write(layout.home / "config.yaml", "model:\n  provider: custom\n  base_url: http://127.0.0.1:18777/v1\n  key_env: LLAMA_API_KEY\n")
        P.take(layout)
        await sup.start()
        try:
            (second,) = [n for n in api.providers if n != first] or [None]
            assert second and second != first and ("provider delete", first) in api.calls
            assert json.loads((layout.state_dir / "providers.json").read_text(encoding="utf-8")) == [second]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_gateway_without_stable_placeholders_refuses_a_sign_in_and_keeps_keys_for_a_restart(tmp_path, monkeypatch):
    sup, api, _rec, layout = LD._supervisor(tmp_path, monkeypatch)
    api.stable_placeholders = False

    async def keys_only():
        await sup.start()
        try:
            (llama,) = api.providers
            assert "stable_placeholder" not in _profiles(layout)[llama]["credentials"][0]
            assert any("stable placeholders" in n for n in sup.policy()["enforced"]["provider_notes"])
            with pytest.raises(NotSupported, match="not a stable one"):
                sup.driver.update("env:LLAMA_API_KEY", "sk-new", None)
            sup.driver.turns_idle = lambda: True  # no reply runs: only the placeholder's kind stands in the way
            assert sup.driver.keys_saved({"LLAMA_API_KEY": "sk-new", "DECOY_TOKEN": LD.DECOY}, P.route_pin(layout)) is False
            assert not any(c[0] == "provider update" for c in api.calls)
        finally:
            await sup.stop()

    asyncio.run(keys_only())
    sup.driver.declare(NOUS, "token", time.time() + 900)

    async def with_a_sign_in():
        with pytest.raises(DriverUnavailable, match="does not support stable placeholders.*Nous Portal"):
            await sup.start()

    asyncio.run(with_a_sign_in())
    assert len([c for c in api.calls if c[0] == "create"]) == 1  # no sandbox was created for the second start


def test_the_values_of_a_request_signature_are_registered_by_name_and_replaced_without_a_placeholder(tmp_path, monkeypatch):
    sup, api, _rec, layout = LD._supervisor(tmp_path, monkeypatch)
    where = (CS.Endpoint("bedrock-runtime.eu-west-1.amazonaws.com", 443),)
    for env in OD.SIGV4_ENV:
        # temporary keys, which a sign-in keeps current
        assert sup.driver.declare(_decl("sigv4", "bedrock", where, f"env:{env}", True), f"value-of-{env.lower()}", time.time() + 900) == env

    async def scenario():
        await sup.start()
        try:
            profiles = _profiles(layout)
            signing = next(p for p in profiles.values() if len(p["credentials"]) == 3)
            # the signer reads these values by their names: no placeholder of theirs travels in a request
            assert not any("stable_placeholder" in c for c in signing["credentials"])
            assert api.providers[signing["id"]]["credentials"] == {env: f"value-of-{env.lower()}" for env in OD.SIGV4_ENV}
            key = next(p for p in profiles.values() if len(p["credentials"]) == 1)
            assert key["credentials"][0]["stable_placeholder"] is True
            # a new value is one provider update; the next signature is made with it
            sup.driver.update("env:AWS_SECRET_ACCESS_KEY", "another", time.time() + 1800)
            assert api.calls[-1][:3] == ("provider update", signing["id"], ["AWS_SECRET_ACCESS_KEY"])
            assert api.providers[signing["id"]]["credentials"]["AWS_SECRET_ACCESS_KEY"] == "another"
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_sandbox_that_withholds_a_stable_credential_fails_the_start_with_the_reason(tmp_path, monkeypatch):
    sup, api, _rec, _layout = LD._supervisor(tmp_path, monkeypatch)

    class Withheld(dict):
        def get(self, key, default=None):
            return ("WITHHELD", "UNSUPPORTED_SUPERVISOR")

    api.provider_states = Withheld()

    async def scenario():
        with pytest.raises(DriverUnavailable, match="does not support stable placeholders.*withheld.*LLAMA_API_KEY"):
            await sup.start()
        assert ("delete", "hermes-work") in api.calls  # the sandbox that came up is taken down again

    asyncio.run(scenario())


def test_quiet_follows_the_launchers_turns_and_says_no_without_a_signal(tmp_path, monkeypatch):
    sup, _api, _rec, layout = LD._supervisor(tmp_path, monkeypatch)
    driver = sup.driver
    assert driver.quiet() is True  # no sandbox: nothing can be streaming
    cards = Cards(sup, layout, layout.state_dir / "cards.jsonl", cards=True)

    async def scenario():
        await sup.start()
        try:
            assert driver.quiet() is False  # a sandbox runs and nobody told the driver about its turns
            driver.turns_idle = cards.quiet
            assert driver.quiet() is True
            cards._turn_started("live-1")
            assert driver.quiet() is False
            cards._turn_ended("live-1")
            assert driver.quiet() is True
            cards._conns.append(SimpleNamespace(running={"live-2"}))  # a turn only its connection knows of
            assert driver.quiet() is False
            cards._conns.clear()
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_sandbox_takes_thirty_two_providers_and_the_rest_is_said(tmp_path, monkeypatch):
    sup, api, _rec, layout = LD._supervisor(tmp_path, monkeypatch)
    many = {f"EXTRA_{i:02d}_KEY": f"value-{i:02d}-" + "v" * 16 for i in range(40)}
    extra = "".join(f"- provider: custom\n  base_url: http://host.openshell.internal:{19000 + i}/v1\n  key_env: EXTRA_{i:02d}_KEY\n"
                    for i in range(40))
    _write(layout.home / "config.yaml", (layout.home / "config.yaml").read_text(encoding="utf-8") + "fallback_providers:\n" + extra)
    P.take(layout)
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"LLAMA_API_KEY": LD.SECRET, **many})

    async def scenario():
        await sup.start()
        try:
            view = sup.policy()["enforced"]
            assert len(api.providers) == len(view["providers"]) == OD.MAX_SANDBOX_PROVIDERS == 32
            assert view["keys_withheld"] == [f"EXTRA_{i:02d}_KEY" for i in range(31, 40)]  # the model's key comes first
            assert len([n for n in view["provider_notes"] if "takes 32 providers" in n]) == 9
        finally:
            await sup.stop()

    asyncio.run(scenario())


# -- a key saved on the Keys page -----------------------------------------------------------------------------

def test_a_saved_key_reaches_the_running_sandbox_without_a_restart_when_no_reply_runs(tmp_path, monkeypatch):
    sup, api, _rec, layout = LD._supervisor(tmp_path, monkeypatch)
    routes = HostRoutes(sup, lambda: None)
    idle = [True]
    sup.driver.turns_idle = lambda: idle[0]
    secrets = {"LLAMA_API_KEY": LD.SECRET, "DECOY_TOKEN": LD.DECOY}
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: dict(secrets))

    async def scenario():
        await sup.start()
        try:
            (llama,) = api.providers
            written = (200, {"ok": True, "sandbox_restart_required": True}, {"X-Hermes-Sandbox-Restart-Required": "1"})
            # the same keys: nothing to do, nothing waits for a restart
            sup.keys_changed = True
            assert await routes._key_live(written) == (200, {"ok": True, "sandbox_restart_required": False}, {})
            assert sup.keys_changed is False and api.calls[-1][0] != "provider update"
            # a new value while a reply runs: the restart is still asked for, the gateway is not touched
            secrets["LLAMA_API_KEY"], idle[0], sup.keys_changed = "sk-replaced", False, True
            assert await routes._key_live(written) == written and sup.keys_changed is True
            assert api.providers[llama]["credentials"] == {"LLAMA_API_KEY": LD.SECRET}
            # the same once no reply runs: a value-only update, and the answer no longer asks for a restart
            idle[0] = True
            assert await routes._key_live(written) == (200, {"ok": True, "sandbox_restart_required": False}, {})
            assert api.calls[-1] == ("provider update", llama, ["LLAMA_API_KEY"], {}, [])
            assert api.providers[llama]["credentials"] == {"LLAMA_API_KEY": "sk-replaced"} and sup.keys_changed is False
            assert sup.status()["pending"]["keys"] is False
            # a key the sandbox did not start with (here: one with a registered address) needs the restart
            pytest.importorskip("hermes_cli.auth")
            secrets["DEEPSEEK_API_KEY"], sup.keys_changed = "sk-" + "d" * 30, True
            assert await routes._key_live(written) == written and sup.keys_changed is True
            assert sup.driver.keys_saved(dict(secrets), P.route_pin(layout)) is False
            # and so does a key that was taken away
            assert sup.driver.keys_saved({"DECOY_TOKEN": LD.DECOY}, P.route_pin(layout)) is False
            # a write that failed is passed on as it is
            assert await routes._key_live((422, {"detail": "no"}, {})) == (422, {"detail": "no"}, {})
            # an update that fails leaves the restart asked for, and the save itself stands
            real, sup.keys_changed = sup.driver.keys_saved, True

            def away(*_args):
                raise RuntimeError("the gateway is away")

            sup.driver.keys_saved = away
            assert sup.keys_saved() is False and sup.keys_changed is True
            sup.driver.keys_saved = real
        finally:
            await sup.stop()
        asked = []
        sup.driver.keys_saved = lambda *args: asked.append(args) or True
        assert sup.keys_saved() is False and asked == []  # nothing runs: the driver is not asked

    asyncio.run(scenario())


# -- the sink on the Windows driver ---------------------------------------------------------------------------

def _windows(tmp_path, monkeypatch):
    layout, runtime, cfg, bb = WD._tree(tmp_path)
    P.take(layout)
    fake = WD.FakeCli()
    driver = WD._driver(cfg, fake, tmp_path)
    sup = WD._supervisor(layout, runtime, driver, bb)
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"TEST_MODEL_KEY": WD.SECRET, "OTHER_TOKEN": WD.DECOY})
    return sup, fake, driver, layout


def test_the_windows_driver_updates_a_value_through_the_cli_and_never_in_an_argument(tmp_path, monkeypatch):
    sup, fake, driver, layout = _windows(tmp_path, monkeypatch)
    expiry = 1900000000.5
    assert driver.declare(NOUS, "first-token", expiry) == "HERMES_CRED_NOUS_AGENT_KEY"

    async def scenario():
        await sup.start()
        try:
            nous = next(n for n in fake.providers if "nous" in n)
            model = next(n for n in fake.providers if "test-model-key" in n)
            assert fake.providers[nous] == {"HERMES_CRED_NOUS_AGENT_KEY": "first-token"}
            assert fake.expiries[nous] == {"HERMES_CRED_NOUS_AGENT_KEY": "1900000000500"}  # milliseconds
            assert fake.profiles[nous]["credentials"][0]["stable_placeholder"] is True
            assert fake.profiles[model]["credentials"][0]["stable_placeholder"] is True
            create = next(a for a, _e in fake.calls if a[1:3] == ["sandbox", "create"])
            assert sorted(create[i + 1] for i, a in enumerate(create) if a == "--provider") == sorted([nous, model])
            assert {p["name"]: p["state"] for p in driver.policy()["providers"]} == {nous: "READY", model: "READY"}
            before = len(fake.calls)
            driver.update("nous:agent_key", "second-token", expiry + 60)
            (argv, env), = fake.calls[before:]
            assert argv[1:] == ["provider", "update", nous, "--credential", "HERMES_CRED_NOUS_AGENT_KEY",
                                "--credential-expires-at", "HERMES_CRED_NOUS_AGENT_KEY=1900000060500"]
            assert env["HERMES_CRED_NOUS_AGENT_KEY"] == "second-token" and fake.providers[nous] == {"HERMES_CRED_NOUS_AGENT_KEY": "second-token"}
            driver.update("nous:agent_key", "third-token", None)
            assert fake.calls[-1][0][-2:] == ["--credential-expires-at", "HERMES_CRED_NOUS_AGENT_KEY=0"]  # a zero clears it
            for argv, _env in fake.calls:
                assert not any(t in " ".join(argv) for t in ("first-token", "second-token", "third-token", WD.SECRET))
            assert driver.quiet() is False
            driver.turns_idle = lambda: True
            assert driver.quiet() is True
            # the Keys page: a new value of the model's key, while no reply runs
            assert driver.keys_saved({"TEST_MODEL_KEY": "sk-replaced", "OTHER_TOKEN": WD.DECOY}, P.route_pin(layout)) is True
            assert fake.providers[model] == {"TEST_MODEL_KEY": "sk-replaced"}
            assert fake.calls[-1][0][1:] == ["provider", "update", model, "--credential", "TEST_MODEL_KEY"]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_windows_driver_says_why_when_stable_placeholders_are_not_supported(tmp_path, monkeypatch):
    sup, fake, driver, _layout = _windows(tmp_path, monkeypatch)
    fake.refuses_stable = True

    async def gateway():
        with pytest.raises(DriverUnavailable, match="gateway does not support stable placeholders"):
            await sup.start()
        assert not [a for a, _e in fake.calls if a[1:3] == ["sandbox", "create"]]

    asyncio.run(gateway())
    fake.refuses_stable = False

    class Withheld(dict):
        def get(self, key, default=None):
            return ("WITHHELD", "UNSUPPORTED_SUPERVISOR")

    fake.provider_states = Withheld()

    async def supervisor():
        with pytest.raises(DriverUnavailable, match="sandbox does not support stable placeholders"):
            await sup.start()

    asyncio.run(supervisor())


def test_every_address_of_a_provider_keeps_its_tls_termination_on_windows(tmp_path, monkeypatch):
    _sup, _fake, driver, _layout = _windows(tmp_path, monkeypatch)
    driver.tls_tunnels = True
    driver._providers = [{"endpoint": "a.example:443", "endpoints": ["a.example:443", "b.example:8443"]}, {"endpoint": "c.example:443"}]
    assert driver._provider_endpoints() == [("a.example", 443), ("b.example", 8443), ("c.example", 443)]


def test_the_keys_route_passes_on_whether_a_restart_is_still_needed():
    from openshell.launcher import host_routes as HR

    assert HR._key_result((200, {"ok": True, "key": "X", "sandbox_restart_required": False}, {})) == \
        (200, {"ok": True, "sandbox_restart_required": False}, {})
    assert HR._key_result((200, {"ok": True, "key": "X"}, {"h": "1"})) == (200, {"ok": True, "sandbox_restart_required": True}, {"h": "1"})
    assert HR._key_result((422, {"detail": "no"}, {})) == (422, {"detail": "no"}, {})


def test_two_credentials_cannot_take_the_same_variable_and_an_unknown_one_is_refused(tmp_path, monkeypatch):
    sup, _api, _rec, _layout = LD._supervisor(tmp_path, monkeypatch)
    driver = sup.driver
    assert driver.declare(_decl(cid="env:SOME_KEY"), "one") == "SOME_KEY"
    assert driver.declare(_decl(cid="env:SOME_KEY", placement="header", name="x-api-key"), "two") == "SOME_KEY"  # the same credential again
    assert driver.declare(_decl(cid="some key"), "three") == "HERMES_CRED_SOME_KEY"
    with pytest.raises(ValueError, match="already holds"):
        driver.declare(_decl(cid="some-key"), "four")
    with pytest.raises(NotSupported, match="was declared"):
        driver.update("env:NEVER_DECLARED", "five")
    driver.update("env:SOME_KEY", "six")  # no sandbox runs: kept for the next start
    assert driver._decls["env:SOME_KEY"]["value"] == "six"


def test_the_contract_file_is_the_one_both_sides_build_to():
    text = Path(CS.__file__).read_bytes()
    assert b"\r" not in text.replace(b"\r\n", b"\n") and text.count(b"class ") == 3
    assert CS.PLACEMENTS == ("bearer", "header", "query", "path", "basic", "sigv4") and CS.PROTOCOLS == ("rest", "websocket")
    assert [f for f in CS.CredentialDecl.__dataclass_fields__] == ["id", "label", "endpoints", "placement", "name", "expires"]
    for method in ("declare", "update", "quiet"):
        assert callable(getattr(OD.OpenShellDriver, method)) and callable(getattr(CS.CredentialSink, method))
    assert os.path.basename(CS.__file__) == "credential_sink.py"
