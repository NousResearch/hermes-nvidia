"""The launcher's pins (launcher/pins.py): host-only copies of a profile's keys, of its own secret-source
definition and of its model entries, taken when the sandbox is switched on.

The sandbox writes most of its profile home, so nothing the launcher hands out is read from there afterwards:
keys and the secret sources come from the pin; a key is bound to an endpoint only when the pair is the pinned
one, the key's own provider's registered address, or one the user allowed through the launcher's host route; any
other pair is withheld and reported. A restart never pins. At switch-off an env file the sandbox created or
replaced is put back, then the pins are deleted. A sandbox switched on before pins existed gets none later.
"""
import asyncio
import hashlib
import json
import os
import stat
from types import SimpleNamespace

import pytest

import test_openshell_driver as LD
import test_openshell_windows as WD
import test_settings_routes as SR
from openshell import launcher_cli as CLI
from openshell.launcher import host_routes as HR
from openshell.launcher import layout as L
from openshell.launcher import login_service as LS
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_windows as W
from openshell.launcher import pins as P
from openshell.launcher import supervisor as S
from openshell.launcher import switch as SW
from openshell.launcher.spec import load_spec, save_spec
from test_switch_flow import _on, env  # noqa: F401  (the switch fixture)

KEY, OTHER = "sk-" + "k" * 40, "sk-" + "o" * 40
MODEL = "model:\n  provider: custom\n  base_url: http://127.0.0.1:18500/v1\n  key_env: MODEL_API_KEY\n"
# What a sandboxed agent can write into its own config.yaml: another key, at an endpoint of its choosing.
MOVED = "model:\n  provider: custom\n  base_url: http://127.0.0.1:18923/v1\n  key_env: OTHER_API_KEY\n# changed\n"
ENV = f"MODEL_API_KEY={KEY}\nOTHER_API_KEY={OTHER}\n"
MOVED_ROW = {"label": "Model", "host": "127.0.0.1", "port": 18923, "env": "OTHER_API_KEY"}
AUTHED = SimpleNamespace(authenticated=True)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


@pytest.fixture
def layout(tmp_path):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    _write(home / "config.yaml", MODEL)
    _write(home / ".env", ENV)
    return L.ProfileLayout(name="work", home=home, root=root)


def _decide(layout, secrets=None):
    return OD.route_decisions(layout.home, secrets if secrets is not None else P.secrets(layout), P.route_pin(layout))


def _pairs(routes):
    return [(r["env"], r["host"], r["port"]) for r in routes]


# -- take -----------------------------------------------------------------------------------------------------

def test_take_copies_the_env_files_and_records_the_secret_sources_and_the_model_entries(layout):
    _write(layout.home / ".op.env", "OP_SERVICE_ACCOUNT_TOKEN=ops-token\n")
    _write(layout.home / "config.yaml", MODEL + "secrets:\n  command:\n    enabled: true\n    command: print-keys\n")
    doc = P.take(layout)
    folder = P.pin_dir(layout)
    assert folder == layout.state_dir / "pins"  # the launcher's state folder: no sandbox is granted it
    assert (folder / ".env").read_bytes() == ENV.encode()
    assert (folder / ".op.env").read_bytes() == b"OP_SERVICE_ACCOUNT_TOKEN=ops-token\n"
    assert doc == P.load(layout) == json.loads((folder / "pins.json").read_text(encoding="utf-8"))
    assert doc["files"][".env"] == {"sha256": hashlib.sha256(ENV.encode()).hexdigest(), "link": None}
    assert doc["secrets"] == {"command": {"enabled": True, "command": "print-keys"}}
    assert doc["models"] == [{"label": "Model", "provider": "custom", "base_url": "http://127.0.0.1:18500/v1",
                              "key_env": "MODEL_API_KEY", "api_key_env": "", "url": "http://127.0.0.1:18500/v1",
                              "api_mode": "", "model": ""}]
    assert doc["allowed"] == [] and P.present(layout)
    if os.name != "nt":  # owner-only where the file mode says so
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
        assert {stat.S_IMODE((folder / n).stat().st_mode) for n in (".env", ".op.env", "pins.json")} == {0o600}


def test_take_records_a_missing_env_file_as_missing(layout):
    (layout.home / ".env").unlink()
    doc = P.take(layout)
    assert doc["files"] == {".env": None, ".op.env": None}
    # (config.yaml: the copy's own, for the sign-ins; it holds the model routes and no key)
    assert sorted(p.name for p in P.pin_dir(layout).iterdir()) == ["config.yaml", "pins.json"]
    assert P.secrets(layout) == {}


def test_turn_on_pins_after_the_spec_is_saved_and_before_anything_starts(env, monkeypatch):  # noqa: F811
    layout, log = env["layout"], env["log"]
    _write(layout.home / ".env", ENV)
    seen = {}
    real_take, real_write = P.take, SW.write_definition

    def take(lay):
        seen["spec_saved"], seen["defined"] = lay.spec_path.is_file(), LS.switched_on(lay)
        log.append("pin")
        return real_take(lay)

    def write_definition(defn):
        seen["pinned_before_definition"] = P.present(layout)
        return real_write(defn)

    monkeypatch.setattr(P, "take", take)
    monkeypatch.setattr(SW, "write_definition", write_definition)
    _on(env)
    assert seen == {"spec_saved": True, "defined": False, "pinned_before_definition": True}
    assert log.index("pin") < log.index("install") < log.index("start") < log.index("mark")
    assert P.secrets(layout) == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER}


def test_a_refused_driver_pins_nothing_and_a_failed_switch_on_removes_the_pin(env):  # noqa: F811
    from test_switch_flow import FakeDriver

    layout = env["layout"]
    _write(layout.home / ".env", ENV)
    with pytest.raises(SW.SwitchError):
        _on(env, driver=FakeDriver(refuse="no runtime"))
    assert not P.pin_dir(layout).exists()
    env["launcher"].update(state="failed", error="sandbox exited with 1")
    with pytest.raises(SW.SwitchError, match="sandbox exited with 1"):
        _on(env)
    assert not P.pin_dir(layout).exists() and (layout.home / ".env").read_bytes() == ENV.encode()


# -- a restart never pins -----------------------------------------------------------------------------------

def test_a_restart_does_not_pin_again_from_a_home_the_sandbox_has_had(layout, tmp_path):
    P.take(layout)
    pinned = (P.pin_dir(layout) / "pins.json").read_bytes()
    sup = SR._supervisor(tmp_path, layout)

    async def scenario():
        await sup.start()
        _write(layout.home / "config.yaml", MOVED)  # the sandbox rewrites its model entry and plants an env file
        _write(layout.home / ".op.env", "PLANTED=by-the-sandbox\n")
        await sup.restart()
        request = sup.driver.requests[-1]
        await sup.stop()
        return request

    request = asyncio.run(scenario())
    assert (P.pin_dir(layout) / "pins.json").read_bytes() == pinned
    assert not (P.pin_dir(layout) / ".op.env").exists()
    assert request.secrets == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER}
    assert [m["base_url"] for m in request.pins["models"]] == ["http://127.0.0.1:18500/v1"] and request.pins["present"]


def _serve_args(**kw):
    base = dict(folder=None, port=None, wxc_exec=None, busybox=None, openshell_gateway=None, openshell_image=None,
                egress=None, rotate_token=False, service=False)
    return SimpleNamespace(**{**base, **kw})


@pytest.fixture
def serve(layout, monkeypatch):
    """``hermes sandbox serve`` up to the point where the launcher would run: the pin calls and what it is told."""
    calls = []

    async def fake_serve(lay, spec, driver, token, service=False, own_pin=False):
        calls.append({"service": service, "own_pin": own_pin, "pinned": P.present(lay)})
        return 0

    monkeypatch.setattr(L, "current_profile", lambda: layout)
    monkeypatch.setattr(CLI, "make_driver", lambda spec: SR.FakeDriver())
    monkeypatch.setattr(CLI, "_serve", fake_serve)
    spec = load_spec(layout)
    spec["folders"] = []
    save_spec(layout, spec)
    return calls


def test_the_login_service_start_never_pins(layout, serve, monkeypatch):
    monkeypatch.setattr(LS, "switched_on", lambda lay: True)  # the switch is on: this is a restart at login
    SW.mark(layout)  # and its profile is marked: a login service runs a sandbox for no other
    monkeypatch.setattr(P, "take", lambda lay: pytest.fail("a restart must not pin"))
    assert CLI._cmd_serve(_serve_args(service=True)) == 0
    assert serve == [{"service": True, "own_pin": False, "pinned": False}]
    # a foreground serve beside a switched-on sandbox is not the one that pinned either
    assert CLI._cmd_serve(_serve_args()) == 0
    assert serve[-1] == {"service": False, "own_pin": False, "pinned": False}


def test_a_foreground_serve_started_by_hand_is_its_own_switch_on(layout, serve):
    assert CLI._cmd_serve(_serve_args()) == 0
    assert serve == [{"service": False, "own_pin": True, "pinned": True}]
    assert P.secrets(layout) == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER}


class NoAllInternetDriver(SR.FakeDriver):
    """A driver without a rule for all internet access, as the OpenShell drivers are."""

    capabilities_info = {**SR.FakeDriver.capabilities_info, "egress_allow_all": False}


def test_serve_refuses_all_internet_access_where_the_driver_has_no_rule_for_it(layout, serve, monkeypatch, capsys):
    monkeypatch.setattr(CLI, "make_driver", lambda spec: NoAllInternetDriver())
    assert CLI._cmd_serve(_serve_args(egress="allow")) == 1
    assert "This sandbox has no rule for all internet access; add the websites it needs." in capsys.readouterr().err
    assert serve == [] and load_spec(layout)["network"]["egress"] == "deny"  # nothing started, nothing saved
    monkeypatch.setattr(CLI, "make_driver", lambda spec: SR.FakeDriver())  # a driver that has the rule takes it
    assert CLI._cmd_serve(_serve_args(egress="allow")) == 0
    assert len(serve) == 1 and load_spec(layout)["network"]["egress"] == "allow"


# -- keys and secret sources come from the pin ---------------------------------------------------------------

def test_the_launchers_keys_are_the_pinned_ones_whatever_the_home_says_now(layout, monkeypatch):
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    P.take(layout)
    _write(layout.home / ".env", "MODEL_API_KEY=replaced-inside\nNEW_KEY=planted\n")  # Windows: replaced by rename
    _write(layout.home / ".op.env", "PLANTED=by-the-sandbox\n")  # Linux: created, it was absent
    before = dict(os.environ)
    assert P.secrets(layout) == S._profile_secrets(layout) == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER}
    assert dict(os.environ) == before  # resolved into a private dict: the process environment is not written


class _Report:
    def __init__(self, names):
        self.provenance = {n: object() for n in names}


def test_the_pinned_secret_sources_resolve_and_the_homes_definition_is_ignored(layout, monkeypatch):
    from agent.secret_sources import registry
    from hermes_cli import env_loader

    monkeypatch.setenv("HOST_ONLY_SETTING", "from-the-users-shell")
    # As a Hermes that still loads the home's files at start leaves this process: a variable from an env file the
    # sandbox planted, and the value the home's secret source (by now the sandbox's definition) supplied.
    monkeypatch.setenv("PLANTED", "by-the-sandbox")
    monkeypatch.setenv("SOURCE_API_KEY", "from-the-definition-written-inside")
    monkeypatch.setattr(env_loader, "launch_dotenv_keys", lambda: frozenset({"PLANTED"}))
    monkeypatch.setattr(env_loader, "secret_source_names", lambda: ("SOURCE_API_KEY",))
    _write(layout.home / "config.yaml", MODEL + "secrets:\n  command:\n    enabled: true\n    command: users-own-helper\n")
    _write(layout.home / ".op.env", "OP_SERVICE_ACCOUNT_TOKEN=ops-token\n")
    P.take(layout)
    _write(layout.home / "config.yaml", MOVED + "secrets:\n  command:\n    enabled: true\n    command: run-this-on-the-host\n")
    _write(layout.home / ".op.env", "OP_SERVICE_ACCOUNT_TOKEN=theirs\nPLANTED=by-the-sandbox\n")
    seen = {}

    def apply_all(cfg, home_path, environ=None):
        seen.update(cfg=cfg, home=home_path, environ=dict(environ), same=environ is os.environ)
        if not environ.get("SOURCE_API_KEY"):  # as Hermes applies a source: never over a value that is there
            environ["SOURCE_API_KEY"] = "from-the-users-helper"
        environ["NOT_APPLIED"] = "left-by-a-source-that-lost"
        return _Report(["SOURCE_API_KEY"])

    monkeypatch.setattr(registry, "apply_all", apply_all)
    before = dict(os.environ)
    assert P.secrets(layout) == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER, "SOURCE_API_KEY": "from-the-users-helper"}
    assert seen["cfg"] == {"command": {"enabled": True, "command": "users-own-helper"}}  # as it was at switch-on
    assert P.pin_dir(layout) in seen["home"].parents and seen["home"].is_dir()  # sources cache beside the pin
    assert (seen["home"].parent.name, seen["home"].name) == ("profiles", "work")  # how Hermes names the profile
    assert not seen["same"] and dict(os.environ) == before
    private = seen["environ"]
    assert private["MODEL_API_KEY"] == KEY and private["HOST_ONLY_SETTING"] == "from-the-users-shell"
    assert private["OP_SERVICE_ACCOUNT_TOKEN"] == "ops-token"  # the pinned .op.env, not the home's
    assert "PLANTED" not in private and "SOURCE_API_KEY" not in private  # what Hermes loaded from the home is out


@pytest.mark.skipif(os.name == "nt", reason="Hermes's command secret source needs /bin/sh")
def test_the_users_own_helper_command_runs_from_the_pin_and_the_one_written_inside_never_runs(layout, tmp_path, monkeypatch):
    monkeypatch.delenv("HELPER_API_KEY", raising=False)
    marker = tmp_path / "ran-on-the-host"
    _write(layout.home / "config.yaml",
           MODEL + "secrets:\n  command:\n    enabled: true\n    command: \"printf 'HELPER_API_KEY=from-the-pin\\\\n'\"\n")
    P.take(layout)
    _write(layout.home / "config.yaml", MOVED + "secrets:\n  command:\n    enabled: true\n"
           f"    command: \"touch '{marker}'; printf 'HELPER_API_KEY=from-inside\\\\n'\"\n")
    assert P.secrets(layout)["HELPER_API_KEY"] == "from-the-pin"
    assert not marker.exists() and "HELPER_API_KEY" not in os.environ


def test_a_source_that_fails_leaves_the_pinned_env_keys(layout, monkeypatch):
    from agent.secret_sources import registry

    _write(layout.home / "config.yaml", MODEL + "secrets:\n  command:\n    enabled: true\n    command: x\n")
    P.take(layout)
    monkeypatch.setattr(registry, "apply_all", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("vault down")))
    assert P.secrets(layout) == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER}


# -- the three route rules ------------------------------------------------------------------------------------

def test_rule_a_a_pinned_pair_is_registered_and_a_pair_changed_inside_is_withheld_and_reported(layout):
    P.take(layout)
    routes, changed, withheld = _decide(layout)
    assert _pairs(routes) == [("MODEL_API_KEY", "host.openshell.internal", 18500)] and changed == []
    assert withheld == ["OTHER_API_KEY"]
    _write(layout.home / "config.yaml", MOVED)  # another key, another endpoint
    routes, changed, withheld = _decide(layout)
    pinned = [("MODEL_API_KEY", "host.openshell.internal", 18500)]  # read from the pin, whatever the home says now
    assert _pairs(routes) == pinned and changed == [MOVED_ROW] and withheld == ["OTHER_API_KEY"]
    # the pinned key at another endpoint, and another key at the pinned endpoint: neither is the pinned pair
    _write(layout.home / "config.yaml", MODEL.replace("18500", "18923"))
    routes, changed, _ = _decide(layout)
    assert _pairs(routes) == pinned and changed == [{"label": "Model", "host": "127.0.0.1", "port": 18923, "env": "MODEL_API_KEY"}]
    _write(layout.home / "config.yaml", MODEL.replace("MODEL_API_KEY", "OTHER_API_KEY"))
    routes, changed, _ = _decide(layout)
    assert _pairs(routes) == pinned and changed == [{"label": "Model", "host": "127.0.0.1", "port": 18500, "env": "OTHER_API_KEY"}]
    # the same pair under another label or another spelling of host loopback is still the pinned pair
    _write(layout.home / "config.yaml", "fallback_model:\n  provider: custom\n  base_url: http://LOCALHOST:18500/v1\n"
                                        "  api_key_env: MODEL_API_KEY\n")
    routes, changed, _ = _decide(layout)
    assert _pairs(routes) == [("MODEL_API_KEY", "host.openshell.internal", 18500)] and changed == []
    assert OD.credential_routes(layout.home, P.secrets(layout), P.route_pin(layout))[0] == routes


def _provider():
    """A built-in provider with a key variable and a registered address, as this Hermes registers it."""
    from hermes_cli import auth

    for name in sorted(getattr(auth, "BUILTIN_PROVIDER_IDS", None) or dict.keys(auth.PROVIDER_REGISTRY)):
        row = dict.get(auth.PROVIDER_REGISTRY, name)
        target = OD._endpoint(str(getattr(row, "inference_base_url", "") or ""))
        if getattr(row, "api_key_env_vars", None) and target and target[2] and not target[2].startswith("127."):
            return name, row.api_key_env_vars[0], target
    pytest.skip("this Hermes registers no key-based provider with an address")


def test_rule_b_a_key_at_its_own_providers_registered_address_needs_no_pin(layout):
    name, key_env, (host, port, _) = _provider()
    secrets = {key_env: KEY, "OTHER_API_KEY": OTHER}
    _write(layout.home / "config.yaml", f"model:\n  provider: {name}\n")
    routes, changed, _ = OD.route_decisions(layout.home, secrets, None)  # no pin at all
    assert _pairs(routes) == [(key_env, host, port)] and changed == []
    # another key under that provider's name, or that provider's key at another address: withheld
    _write(layout.home / "config.yaml", f"model:\n  provider: {name}\n  key_env: OTHER_API_KEY\n")
    routes, changed, withheld = OD.route_decisions(layout.home, secrets, None)
    assert _pairs(routes) == [(key_env, host, port)] and withheld == ["OTHER_API_KEY"]  # its own key, its own address
    assert [(c["env"], c["host"], c["port"]) for c in changed] == [("OTHER_API_KEY", host, port)]
    _write(layout.home / "config.yaml", f"model:\n  provider: {name}\n  base_url: https://elsewhere.example/v1\n")
    routes, changed, _ = OD.route_decisions(layout.home, secrets, None)
    assert _pairs(routes) == [(key_env, host, port)]
    assert [(c["env"], c["host"], c["port"]) for c in changed] == [(key_env, "elsewhere.example", 443)]


def test_rule_b_reads_the_built_in_row_not_one_the_profile_home_overrides(layout, monkeypatch):
    from hermes_cli import auth

    from openshell.launcher import settings_view

    name, key_env, (host, port, _) = _provider()
    secrets = {key_env: KEY}
    # the home's view of the row (a provider plugin there can override it) names another address
    monkeypatch.setattr(settings_view, "_provider_default_url", lambda provider: "https://elsewhere.example/v1")
    _write(layout.home / "config.yaml", f"model:\n  provider: {name}\n")
    routes, changed, _ = OD.route_decisions(layout.home, secrets, None)
    assert _pairs(routes) == [(key_env, host, port)]  # the registered address, never the one the home's row names
    assert [(c["env"], c["host"], c["port"]) for c in changed] == [(key_env, "elsewhere.example", 443)]
    # a row that is not built in vouches for nothing, whatever it names
    row = dict.get(auth.PROVIDER_REGISTRY, name)
    monkeypatch.setitem(auth.PROVIDER_REGISTRY, "added-later", row)
    assert OD._own_provider({"provider": name}, key_env, host, port)
    if getattr(auth, "BUILTIN_PROVIDER_IDS", None) is not None:
        assert not OD._own_provider({"provider": "added-later"}, key_env, host, port)
    assert not OD._own_provider({"provider": ""}, key_env, host, port)


def test_rule_c_a_pair_the_user_allowed_is_registered(layout):
    P.take(layout)
    _write(layout.home / "config.yaml", MOVED)
    assert _decide(layout)[1] == [MOVED_ROW]
    assert P.allow(layout, {"env": "OTHER_API_KEY", "host": OD.route_host("127.0.0.1"), "port": 18923})
    routes, changed, withheld = _decide(layout)
    assert _pairs(routes) == [("MODEL_API_KEY", "host.openshell.internal", 18500),
                              ("OTHER_API_KEY", "host.openshell.internal", 18923)] and changed == []
    assert withheld == []
    assert [(a["env"], a["host"], a["port"]) for a in P.load(layout)["allowed"]] == [("OTHER_API_KEY", "host.openshell.internal", 18923)]
    # allowing is exact: the same key at one more endpoint is withheld again
    _write(layout.home / "config.yaml", MOVED.replace("18923", "18924"))
    assert _pairs(_decide(layout)[0]) == [("MODEL_API_KEY", "host.openshell.internal", 18500)]


# -- the running launcher: status, the allow route, both drivers ---------------------------------------------

def _linux(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    monkeypatch.setattr(S, "_profile_secrets", P.secrets)  # the real one: this file is about where keys come from
    return sup, api, layout


def test_the_linux_driver_withholds_a_changed_endpoint_reports_it_and_registers_it_once_allowed(tmp_path, monkeypatch):
    sup, api, layout = _linux(tmp_path, monkeypatch)
    routes = HR.HostRoutes(sup, lambda: None)
    moved = {"label": "Model", "host": "127.0.0.1", "port": 18923, "env": "DECOY_TOKEN"}

    async def scenario():
        await sup.start()
        try:
            (llama,) = api.providers
            assert llama.startswith("hermes-work-llama-api-key-")
            assert sup.status()["endpoint_changed"] == [] and sup.status()["pinned"] is True
            _write(layout.home / "config.yaml", "model:\n  provider: custom\n  base_url: http://127.0.0.1:18923/v1\n"
                                                "  key_env: DECOY_TOKEN\n")
            api.providers.clear()
            await sup.restart()
            # the pinned pair is registered again; the pair the home names now is withheld and reported
            assert list(api.providers) == [llama] and sup.status()["endpoint_changed"] == [moved]
            assert sup.policy()["enforced"]["endpoint_changed"] == [moved]
            assert sup.policy()["enforced"]["keys_withheld"] == ["DECOY_TOKEN"]
            allow = routes.match("POST", "/api/plugins/openshell/endpoints/allow")
            status, payload, _ = await allow(AUTHED, json.dumps({"env": "DECOY_TOKEN", "host": "evil.example", "port": 443}).encode())
            assert status == 404 and P.load(layout)["allowed"] == []  # only a pair the launcher reported
            status, payload, extra = await allow(AUTHED, json.dumps({"env": "DECOY_TOKEN", "host": "127.0.0.1", "port": 18923}).encode())
            assert status == 200 and payload["sandbox_restart_required"] and payload["endpoint_changed"] == []
            assert extra == {"X-Hermes-Sandbox-Restart-Required": "1"}
            assert sup.status()["endpoint_changed"] == [] and sup.status()["pending"]["keys"] is True
            assert list(api.providers) == [llama]  # bound at the next start, not before
            await sup.restart()
            (decoy,) = [n for n in api.providers if n != llama]
            assert decoy.startswith("hermes-work-decoy-token-")
            assert api.providers[decoy]["credentials"] == {"DECOY_TOKEN": LD.DECOY}
            assert sup.status()["endpoint_changed"] == [] and sup.status()["pending"]["keys"] is False
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_windows_driver_applies_the_same_rules_and_hides_the_pin_folder(tmp_path, monkeypatch):
    layout, runtime, cfg, bb = WD._tree(tmp_path)  # a default profile: the Hermes root itself is the granted home
    P.take(layout)
    fake = WD.FakeCli()
    driver = WD._driver(cfg, fake, tmp_path)
    sup = WD._supervisor(layout, runtime, driver, bb)
    monkeypatch.setattr(S, "_profile_secrets", P.secrets)

    async def scenario():
        await sup.start()
        try:
            (model_key,) = fake.providers
            assert model_key.startswith("hermes-default-test-model-key-") and sup.status()["endpoint_changed"] == []
            denied = [str(p) for p in driver._root_denials(driver._request)]
            assert str(P.pin_dir(layout)) in denied  # named, present or not: the root is the sandbox's own folder
            _write(layout.home / "config.yaml", "model:\n  provider: custom\n  base_url: http://localhost:18923/v1\n"
                                                "  key_env: OTHER_TOKEN\nterminal:\n  backend: local\n")
            fake.providers.clear()
            await sup.restart()
            assert list(fake.providers) == [model_key]  # the pinned pair again; nothing for the pair changed inside
            assert sup.status()["endpoint_changed"] == [{"label": "Model", "host": "localhost", "port": 18923, "env": "OTHER_TOKEN"}]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_pin_folder_is_outside_every_grant_of_a_named_profile(tmp_path):
    root = tmp_path / "Hermes Root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    layout = L.ProfileLayout(name="work", home=home, root=root)
    P.take(layout)
    grants = L.profile_grants(layout, LD._runtime(tmp_path), [])
    pin = P.pin_dir(layout)
    assert not [g for g in [*grants.readwrite, *grants.readonly] if W._inside(pin, g) or W._inside(g, pin)]
    assert "pins" in W._HOST_ONLY_FILES  # and denied by name where the root itself is granted (the default profile)


@pytest.mark.skipif(os.name != "nt", reason="Windows path forms")
def test_windows_path_forms_of_the_pin_folder_and_its_env_file(tmp_path):
    root = tmp_path / "Hermes Root"
    home = root / "profiles" / "work"
    _write(home / ".env", ENV)
    layout = L.ProfileLayout(name="work", home=home, root=root)
    P.take(layout)
    pin = P.pin_dir(layout)
    # the deny list's own comparison: another letter case and forward slashes are the same folder
    for form in (str(pin).upper(), str(pin).replace("\\", "/"), str(pin) + "\\"):
        assert W._inside(form, pin) and W._inside(pin, form) and W._inside(form + "/.env", root / "openshell")
    assert W.native(str(pin).replace("\\", "/")) == str(pin)
    # the home's env file under another letter case is the same file: a replacement is seen and put back
    _write(home / ".ENV", "MODEL_API_KEY=replaced-inside\n")
    assert P.release(layout) == [".env"] and (home / ".env").read_bytes() == ENV.encode()


# -- host-route writes refresh the pin -----------------------------------------------------------------------

@pytest.fixture
def writes(layout, tmp_path, monkeypatch):
    """The launcher's key and endpoint routes with Hermes's handlers replaced by ones that write this layout's
    home (the real ones write the process's own home, which in a launcher is the profile's)."""
    from hermes_cli.web_routers import config_env

    async def set_env_var(model, profile):
        path = layout.home / ".env"
        lines = [l for l in (path.read_text(encoding="utf-8").splitlines() if path.exists() else [])
                 if not l.startswith(model.key + "=")]
        _write(path, "\n".join([*lines, f"{model.key}={model.value}"]) + "\n")
        return {"ok": True, "key": model.key}

    def upsert_custom_endpoint(model, profile):
        path = layout.home / "config.yaml"
        rest = path.read_text(encoding="utf-8").partition("fallback_model:")
        _write(path, f"model:\n  provider: custom\n  base_url: {model.base_url}\n  key_env: OTHER_API_KEY\n"
                     "# saved by the user\n" + rest[1] + rest[2])
        return {"ok": True}

    monkeypatch.setattr(config_env, "set_env_var", set_env_var)
    monkeypatch.setattr(config_env, "upsert_custom_endpoint", upsert_custom_endpoint)
    P.take(layout)
    sup = SR._supervisor(tmp_path, layout)
    return HR.HostRoutes(sup, lambda: None), sup


def _send(routes, method, path, body):
    return asyncio.run(routes.match(method, path)(AUTHED, json.dumps(body).encode()))


def test_a_key_saved_through_the_launcher_is_pinned_at_once(layout, writes):
    routes, sup = writes
    status, payload, extra = _send(routes, "PUT", "/api/plugins/openshell/keys", {"key": "NEW_API_KEY", "value": "sk-new"})
    assert status == 200 and sup.keys_changed
    assert payload == {"ok": True, "sandbox_restart_required": True, "sandbox": "after_restart"}
    assert P.secrets(layout) == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER, "NEW_API_KEY": "sk-new"}
    home = (layout.home / ".env").read_bytes()
    assert (P.pin_dir(layout) / ".env").read_bytes() == home
    assert P.load(layout)["files"][".env"]["sha256"] == hashlib.sha256(home).hexdigest()
    assert P.restore_env(layout) == []  # the home's file is the pinned one


def test_a_saved_key_the_running_sandbox_already_uses_asks_for_no_restart(layout, writes):
    routes, sup = writes
    asked = []
    sup.keys_saved = lambda: asked.append(1) or True  # the driver replaced the value behind the key's placeholder
    sup.driver.registered_providers = lambda: [{"env": "MODEL_API_KEY", "envs": ["MODEL_API_KEY"]}]
    status, payload, extra = _send(routes, "PUT", "/api/plugins/openshell/keys", {"key": "MODEL_API_KEY", "value": "sk-newer"})
    assert (status, payload) == (200, {"ok": True, "sandbox_restart_required": False, "sandbox": "in_use"}) and asked == [1]
    assert not any("restart" in name.lower() for name in extra)
    status, payload, extra = _send(routes, "PUT", "/api/env", {"key": "MODEL_API_KEY", "value": "sk-newest"})
    assert status == 200 and payload["sandbox_restart_required"] is False and asked == [1, 1]
    assert not any("restart" in name.lower() for name in extra)
    sup.keys_saved = lambda: False  # a new key, or a reply is running
    status, payload, _extra = _send(routes, "PUT", "/api/plugins/openshell/keys", {"key": "MODEL_API_KEY", "value": "sk-last"})
    assert (status, payload) == (200, {"ok": True, "sandbox_restart_required": True, "sandbox": "after_restart"})
    assert P.secrets(layout)["MODEL_API_KEY"] == "sk-last"


def test_a_key_write_first_puts_back_an_env_file_the_sandbox_replaced(layout, writes):
    routes, _ = writes
    _write(layout.home / ".env", "MODEL_API_KEY=replaced-inside\nPLANTED=1\n")
    status, _, _ = _send(routes, "PUT", "/api/env", {"key": "NEW_API_KEY", "value": "sk-new"})
    assert status == 200
    assert P.secrets(layout) == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER, "NEW_API_KEY": "sk-new"}
    assert (layout.home / ".env").read_bytes() == (ENV + "NEW_API_KEY=sk-new\n").encode()  # the user's file plus the key
    [kept] = list((layout.state_dir / "quarantine").glob("*/.env"))
    assert kept.read_bytes() == b"MODEL_API_KEY=replaced-inside\nPLANTED=1\n"  # the other file is kept, host-only


def test_an_endpoint_saved_through_the_launcher_joins_the_pin_and_a_change_made_inside_does_not(layout, writes):
    routes, _ = writes
    # the sandbox has already added an entry of its own; the user's write must not carry it into the pin
    inside = "fallback_model:\n  provider: custom\n  base_url: http://127.0.0.1:18923/v1\n  key_env: MODEL_API_KEY\n"
    _write(layout.home / "config.yaml", MODEL + inside)
    body = {"name": "Mine", "base_url": "http://127.0.0.1:18700/v1", "model": "m", "make_default": True}
    status, _, _ = _send(routes, "POST", "/api/providers/custom-endpoints", body)
    assert status == 200 and inside in (layout.home / "config.yaml").read_text(encoding="utf-8")
    assert [m["base_url"] for m in P.load(layout)["models"]] == ["http://127.0.0.1:18500/v1", "http://127.0.0.1:18700/v1"]
    routes_, changed, _ = _decide(layout)
    assert _pairs(routes_) == [("MODEL_API_KEY", "host.openshell.internal", 18500),
                               ("OTHER_API_KEY", "host.openshell.internal", 18700)]
    assert changed == [{"label": "Fallback model", "host": "127.0.0.1", "port": 18923, "env": "MODEL_API_KEY"}]
    # the sandbox edits the model entry, then the user saves a key: the key is pinned, the entry is not
    _write(layout.home / "config.yaml", MOVED)
    assert _send(routes, "PUT", "/api/env", {"key": "NEW_API_KEY", "value": "sk-new"})[0] == 200
    assert _decide(layout)[1] == [MOVED_ROW]
    assert len(P.load(layout)["models"]) == 2


# -- switch-off: the env files go back, the pins go ------------------------------------------------------------

def _off_route(layout, monkeypatch, log):
    monkeypatch.setattr(HR, "unregister", lambda lay, runtime: log.append(
        ("unregistered", (lay.home / ".env").read_bytes() if (lay.home / ".env").exists() else None, P.present(lay))))
    monkeypatch.setattr(HR, "clear_marker", lambda lay: (log.append("clear"), True)[1])
    monkeypatch.setattr(HR, "host_serve", lambda lay: None)
    sup = SimpleNamespace(layout=layout, runtime=None, switching_off=False, outer_port=1)

    async def stop():
        log.append("stopped")

    sup.stop = stop
    return HR.HostRoutes(sup, lambda: None)


def test_switch_off_restores_a_replaced_env_file_removes_a_created_one_and_deletes_the_pins(layout, monkeypatch):
    P.take(layout)
    _write(layout.home / ".env", "MODEL_API_KEY=replaced-inside\n")  # replaced (Windows)
    _write(layout.home / ".op.env", "PLANTED=by-the-sandbox\n")  # created: it was absent at switch-on
    log = []
    routes = _off_route(layout, monkeypatch, log)
    status, payload, _ = _send(routes, "POST", "/api/plugins/openshell/switch/off", {})
    assert status == 200 and payload["state"] == "off"
    # after the sandbox stopped, before the service and the marker go: the host never reads the other files
    assert log == ["stopped", ("unregistered", ENV.encode(), False), "clear"]
    assert (layout.home / ".env").read_bytes() == ENV.encode() and not (layout.home / ".op.env").exists()
    assert not P.pin_dir(layout).exists()
    kept = {p.name: p.read_bytes() for p in (layout.state_dir / "quarantine").glob("*/*")}
    assert kept == {".env": b"MODEL_API_KEY=replaced-inside\n", ".op.env": b"PLANTED=by-the-sandbox\n"}


def test_switch_off_leaves_unchanged_env_files_alone(layout, monkeypatch):
    P.take(layout)
    before = (layout.home / ".env").stat().st_mtime_ns
    log = []
    assert _send(_off_route(layout, monkeypatch, log), "POST", "/api/plugins/openshell/switch/off", {})[0] == 200
    assert (layout.home / ".env").stat().st_mtime_ns == before and (layout.home / ".env").read_bytes() == ENV.encode()
    assert not (layout.state_dir / "quarantine").exists() and not P.pin_dir(layout).exists()


def test_an_env_file_that_was_missing_and_is_now_a_link_or_a_folder_is_removed(layout, tmp_path):
    (layout.home / ".env").unlink()
    P.take(layout)
    target = tmp_path / "outside.txt"
    target.write_bytes(b"MODEL_API_KEY=x\n")
    try:
        os.symlink(target, layout.home / ".env")
    except (OSError, NotImplementedError):
        (layout.home / ".env").mkdir()
    assert P.release(layout) == [".env"]
    assert not os.path.lexists(layout.home / ".env") and target.read_bytes() == b"MODEL_API_KEY=x\n"


def test_an_env_file_replaced_by_a_link_to_the_same_bytes_is_still_put_back(layout, tmp_path):
    P.take(layout)
    target = tmp_path / "outside.env"
    target.write_bytes(ENV.encode())  # the same bytes, so only where the name points tells the two apart
    (layout.home / ".env").unlink()
    try:
        os.symlink(target, layout.home / ".env")
    except (OSError, NotImplementedError):
        pytest.skip("this host does not let the test make a link")
    assert P.release(layout) == [".env"]
    assert not os.path.islink(layout.home / ".env") and (layout.home / ".env").read_bytes() == ENV.encode()
    [kept] = list((layout.state_dir / "quarantine").glob("*/.env"))
    assert os.path.islink(kept) and target.read_bytes() == ENV.encode()  # the link is kept as a link, its target untouched


def test_sandbox_off_from_a_terminal_restores_before_it_clears_the_marker(env):  # noqa: F811
    layout, log = env["layout"], env["log"]
    _write(layout.home / ".env", ENV)
    _on(env)
    _write(layout.home / ".env", "MODEL_API_KEY=replaced-inside\n")
    real = env["markers"].clear_profile_run_elsewhere

    def clear(profile, plugin, *, root=None):
        log.append(("env at clear", (layout.home / ".env").read_bytes(), P.present(layout)))
        return real(profile, plugin, root=root)

    env["markers"].clear_profile_run_elsewhere = clear
    result = SW.turn_off_here(layout, runtime=env["runtime"], manager=env["manager"], sleep=lambda s: None)
    assert result["stopped"] == "service" and ("env at clear", ENV.encode(), False) in log


# -- a sandbox that was switched on before pins existed -------------------------------------------------------

def test_without_a_pin_none_is_taken_later_and_only_a_providers_own_address_gets_its_key(layout, tmp_path, monkeypatch):
    name, key_env, (host, port, _) = _provider()
    _write(layout.home / ".env", ENV + f"{key_env}={KEY}\n")
    _write(layout.home / "config.yaml", MODEL + f"fallback_model:\n  provider: {name}\n"
           "secrets:\n  command:\n    enabled: true\n    command: run-this-on-the-host\n")
    from agent.secret_sources import registry

    monkeypatch.setattr(registry, "apply_all", lambda *a, **k: pytest.fail("no secret source runs without a pin"))
    assert P.route_pin(layout) == {"present": False, "models": [], "allowed": []}
    secrets = P.secrets(layout)
    assert secrets == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER, key_env: KEY}  # the .env file, as before
    routes, changed, _ = _decide(layout, secrets)
    assert _pairs(routes) == [(key_env, host, port)]
    assert changed == [{"label": "Model", "host": "127.0.0.1", "port": 18500, "env": "MODEL_API_KEY"}]
    # nothing pins later: not a key write, not an endpoint write, not an allow
    assert P.update_env(layout) is False and P.add_models(layout, [], "http://127.0.0.1:18500/v1") == []
    assert P.allow(layout, {"env": "MODEL_API_KEY", "host": "host.openshell.internal", "port": 18500}) is False
    assert P.restore_env(layout) == [] and P.release(layout) == [] and not P.pin_dir(layout).exists()


def test_without_a_pin_the_status_says_so_and_the_allow_route_asks_for_off_and_on(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    P.remove(layout)  # as an older version left it: switched on, no pin
    monkeypatch.setattr(S, "_profile_secrets", P.secrets)
    routes = HR.HostRoutes(sup, lambda: None)
    row = {"label": "Model", "host": "127.0.0.1", "port": 18500, "env": "LLAMA_API_KEY"}

    async def scenario():
        await sup.start()
        try:
            status = sup.status()
            assert status["pinned"] is False and status["endpoint_changed"] == [row] and api.providers == {}
            allow = routes.match("POST", "/api/plugins/openshell/endpoints/allow")
            code, payload, _ = await allow(AUTHED, json.dumps({k: row[k] for k in ("env", "host", "port")}).encode())
            assert code == 409 and payload == {"detail": "Turn the sandbox off and on first."}
            assert not P.pin_dir(layout).exists() and sup.status()["endpoint_changed"] == [row]
        finally:
            await sup.stop()

    asyncio.run(scenario())
