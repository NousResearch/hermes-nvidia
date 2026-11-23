"""One source for the provider rows, one wording, one route each (launcher/provider_rows.py, settings_view.py,
dashboard/plugin_api.py, host_routes.py).

The Sandbox page, the switch and the terminal commands read the rows of a profile that is off from one builder,
and a refusal of the switch begins with the sentence the page shows for the same thing. While the sandbox is on
the launcher's rows carry what the page words them from, and the launcher's own sentence is the page's. Every key
and token here is made up.
"""
import asyncio
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("openshell.launcher.signins", reason="the sign-in report is not in this tree")

import page_provider_fixtures as fx  # noqa: E402
from page_provider_fixtures import INLINE_KEY, KEYS, secrets_of, shown, write_env  # noqa: E402
from signin_home import world  # noqa: E402,F401

from openshell.launcher import host_routes as HR  # noqa: E402
from openshell.launcher import provider_rows as R  # noqa: E402
from openshell.launcher import settings_view as SV  # noqa: E402
from openshell.launcher import switch as SW  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402
from openshell.launcher.proxy import parse_head  # noqa: E402

PLUGIN_DIR = Path(__file__).resolve().parent.parent
API = "/api/plugins/openshell"
ONE_KEY = "A key is written in config.yaml, where the sandbox could read it. Move it to .env first."


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    fx.offline_catalog(monkeypatch)
    SV.forget_providers()
    yield
    SV.forget_providers()


def _layout(world):  # noqa: F811
    return ProfileLayout(name="work", home=world.home, root=world.root)


def _page(world):  # noqa: F811
    SV.forget_providers()
    return SV.provider_view(_layout(world))


# -- off: one builder ---------------------------------------------------------------------------------------

def test_the_switch_and_the_terminal_read_the_rows_the_page_shows(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "default": "m"}, "fallback_model": {"provider": "copilot", "model": "x"}})
    write_env(world.home, ["OPENROUTER_API_KEY", "TAVILY_API_KEY"])
    world.sign_in("nous")
    page = _page(world)
    rows = R.host_rows(_layout(world))
    assert rows == page["providers"] and len(rows) == 4
    assert {row["id"]: row["state"] for row in rows} == {
        "key:OPENROUTER_API_KEY": "ready", "sign_in:copilot": "unavailable", "sign_in:nous": "ready",
        "key:TAVILY_API_KEY": "ready"}
    assert R.refusal(_layout(world), rows) is None and page["providers_block"] is None
    # Nothing of the profile's home was written for it, and the copy the report was asked over is gone.
    assert not list(_layout(world).state_dir.glob("provider-check*"))
    assert [secret for secret in secrets_of(world.home) if secret in shown(rows)] == []


def test_the_report_is_asked_over_a_copy_and_the_home_gets_no_file(world):  # noqa: F811
    world.config({"model": {"provider": "nous", "default": "m"}})
    world.sign_in("nous")
    before = sorted(p.relative_to(world.home).as_posix() for p in world.home.rglob("*"))
    asked = []
    report = SV.importlib.import_module("openshell.launcher.signins").report

    def recorded(home):
        asked.append(Path(home))
        return report(home)

    import openshell.launcher.signins as signins
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(signins, "report", recorded)
        rows = R.host_rows(_layout(world))
    assert [row["id"] for row in rows] == ["sign_in:nous"] and rows[0]["main"] is True
    (copy,) = asked
    assert copy.parent == _layout(world).state_dir and copy.name.startswith("provider-check-") and not copy.exists()
    assert sorted(p.relative_to(world.home).as_posix() for p in world.home.rglob("*")) == before


def test_a_refusal_begins_with_the_pages_own_sentence(world):  # noqa: F811
    layout = _layout(world)
    world.config({"model": {"provider": "openrouter", "api_key": INLINE_KEY, "default": "m"}})
    page = _page(world)
    refusal = R.refusal(layout)
    assert page["providers_block"]["reason"] == ONE_KEY and refusal["code"] == page["providers_block"]["code"] == "key_in_config"
    assert refusal["detail"] == ONE_KEY + " Key: model.api_key."
    assert [(key["path"], key["env"]) for key in refusal["keys"]] == [("model.api_key", "OPENROUTER_API_KEY")]
    assert INLINE_KEY not in json.dumps(refusal)
    world.config({"model": {"provider": "qwen-oauth", "default": "m"}})
    page, refusal = _page(world), R.refusal(layout)
    assert refusal["code"] == page["providers_block"]["code"] == "model_unavailable" and refusal["keys"] == []
    row = next(row for row in page["providers"] if row["main"])
    assert refusal["detail"] == f"{page['providers_block']['reason']} {page['providers_block']['detail']}"
    assert refusal["detail"] == (f"This profile's model uses {row['label']}, which isn't available in the sandbox. "
                                 f"{row['label']} keeps its sign-in outside this profile.")
    world.config({"model": {"provider": "openai-codex", "default": "m"}})
    page, refusal = _page(world), R.refusal(layout)
    assert refusal["code"] == page["providers_block"]["code"] == "model_needs_sign_in"
    assert refusal["detail"] == ("This profile's model uses OpenAI Codex, which needs a sign-in first. Not signed in. "
                                 "Sign in to OpenAI Codex first.")
    with pytest.raises(SW.SwitchError) as refused:
        SW.refuse_unready(layout)
    assert refused.value.status == 422 and refused.value.code == "model_needs_sign_in" and str(refused.value) == refusal["detail"]


# -- on: the launcher's rows --------------------------------------------------------------------------------

ENGINE = [
    {"id": "nous:agent_key", "provider": "nous", "label": "Nous Portal", "kind": "sign_in", "state": "works",
     "reason": "signed_in", "sentence": "the engine's words", "error": "", "expires_at": 1.0},
    {"id": "openai-codex:access_token", "provider": "openai-codex", "label": "OpenAI Codex", "kind": "sign_in",
     "state": "retrying", "reason": "retrying", "sentence": "x"},
    {"id": "xai-oauth:access_token", "provider": "xai-oauth", "label": "xAI", "kind": "sign_in", "state": "lapsed",
     "reason": "lapsed", "sentence": "x"},
    {"id": "minimax-oauth:access_token", "provider": "minimax-oauth", "label": "MiniMax", "kind": "sign_in",
     "state": "needs_sign_in", "reason": "expired", "sentence": "x", "action": "y"},
    {"provider": "anthropic", "label": "Anthropic", "kind": "sign_in", "state": "needs_sign_in", "reason": "not_signed_in"},
]
ROUTES = [
    {"provider": "nous", "label": "Nous Portal", "state": "works", "reason": "signed_in", "used_by": ["model"]},
    {"provider": "copilot", "label": "GitHub Copilot", "state": "not_available", "reason": "own_program",
     "used_by": ["fallback 1"]},
    {"provider": "openrouter", "label": "OpenRouter", "state": "key", "reason": "key", "used_by": ["auxiliary vision"]},
]


def _keys(names):
    routes = [{"label": "Fallback", "env": env, "host": host, "port": 443, "url": f"https://{host}/v1",
               "source": "provider", "token": False} for env, host in names]
    return SV.key_rows_of(routes, {env: "set" for env, _host in names}, facts=True)[0]


def test_the_launchers_rows_carry_what_the_page_words_them_from(world):  # noqa: F811
    keys = _keys([("OPENROUTER_API_KEY", "openrouter.ai"), ("OTHER_KEY", "llm.example.com")])
    changed = [{"label": "Model", "host": "evil.example", "port": 443, "env": "OTHER_KEY"}]
    rows = R.live_rows(_layout(world), ENGINE, keys, changed, ROUTES)
    by_id = {row["id"]: row for row in rows}
    assert {key: (row["state"], row.get("reason")) for key, row in by_id.items()} == {
        "sign_in:nous": ("ready", "signed_in"), "sign_in:openai-codex": ("ready", "retrying"),
        "sign_in:xai-oauth": ("expired", "lapsed"), "sign_in:minimax-oauth": ("expired", "expired"),
        "sign_in:anthropic": ("needs_sign_in", "not_signed_in"), "sign_in:copilot": ("unavailable", "own_program"),
        "key:OPENROUTER_API_KEY": ("ready", None), "key:OTHER_KEY": ("withheld", None)}
    assert rows[0]["id"] == "sign_in:nous" and rows[0]["main"] is True and rows[0]["used_by"] == ["model"]
    assert [row["id"] for row in rows if row["main"]] == ["sign_in:nous"]
    assert by_id["key:OPENROUTER_API_KEY"]["hosts"] == [{"host": "openrouter.ai", "port": 443}]
    assert by_id["key:OPENROUTER_API_KEY"]["env"] == "OPENROUTER_API_KEY" and by_id["key:OTHER_KEY"]["env"] == "OTHER_KEY"
    # 'lapsed' (late, heals by itself) against 'expired' (sign in again): two sentences, both the page's.
    assert by_id["sign_in:xai-oauth"]["detail"] == "The xAI sign-in wasn't renewed in time. The model answers again once it is."
    assert by_id["sign_in:minimax-oauth"]["detail"] == "Sign-in expired. Turn the sandbox off, sign in to MiniMax, then turn it on."
    assert by_id["sign_in:openai-codex"]["detail"] == "Couldn't reach OpenAI Codex to renew the sign-in. Trying again."
    assert by_id["key:OPENROUTER_API_KEY"]["detail"] == ("Works in the sandbox. The key stays on this computer and is used "
                                                        "only at openrouter.ai.")
    # One wording: what the page makes of these rows is what the launcher itself says (the terminal prints it).
    paged = {row["id"]: row for row in SV.page_rows(rows)}
    assert set(paged) == set(by_id)
    for ident, row in by_id.items():
        assert paged[ident] == {key: value for key, value in row.items() if key not in ("reason", "hosts", "used_by")}, ident
    assert "the engine's words" not in json.dumps(rows) and "placeholder" not in json.dumps(rows)
    assert R.live_rows(_layout(world), None, None) == []


def test_a_key_the_model_uses_is_marked_from_the_report_of_the_start(world):  # noqa: F811
    keys = _keys([("OPENROUTER_API_KEY", "openrouter.ai"), ("TAVILY_API_KEY", "api.tavily.com")])
    routes = [{"provider": "openrouter", "label": "OpenRouter", "state": "key", "reason": "key", "used_by": ["model"]}]
    rows = R.live_rows(_layout(world), [], keys, [], routes)
    assert [(row["id"], row["main"]) for row in rows] == [("key:OPENROUTER_API_KEY", True), ("key:TAVILY_API_KEY", False)]


def test_a_key_written_in_config_yaml_while_on_is_the_first_row(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "api_key": INLINE_KEY, "default": "m"}})
    rows = R.live_rows(_layout(world), ENGINE[:1], [], [], ROUTES)
    assert rows[0] == {"id": "config:model.api_key", "label": "Key in config.yaml", "kind": "key", "state": "key_in_config",
                       "detail": "Written in config.yaml, where the sandbox can read it. Turn the sandbox off, then move "
                                 "it to .env.", "main": False, "env": "OPENROUTER_API_KEY", "path": "model.api_key"}
    assert INLINE_KEY not in json.dumps(rows)


# -- the routes: one each -------------------------------------------------------------------------------------

@pytest.fixture
def api(world):  # noqa: F811
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    spec = importlib.util.spec_from_file_location("openshell_plugin_api_rows", PLUGIN_DIR / "dashboard" / "plugin_api.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._view.forget_providers()
    app = FastAPI()
    app.include_router(module.router, prefix=API)
    client = TestClient(app)
    client.module = module
    yield client
    module._view.forget_providers()


def test_the_rows_of_a_profile_that_is_off_have_one_route_and_it_answers_what_the_config_carries(api, world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "api_key": INLINE_KEY, "default": "m"}})
    write_env(world.home, ["TAVILY_API_KEY"])
    answer = api.get(f"{API}/providers")
    assert answer.status_code == 200 and set(answer.json()) == {"providers", "providers_block"}
    config = api.get(f"{API}/config").json()
    assert answer.json() == {"providers": config["providers"], "providers_block": config["providers_block"]}
    assert answer.json()["providers_block"]["code"] == "key_in_config" and INLINE_KEY not in answer.text
    # It reads now: a change is in the next answer, not ten seconds later.
    world.config({"model": {"provider": "openrouter", "default": "m"}})
    assert api.get(f"{API}/providers").json()["providers_block"] is None


def test_the_move_has_one_route(api, world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "api_key": INLINE_KEY, "default": "m"}})
    assert api.post(f"{API}/keys/move", json={}).status_code in (404, 405)
    assert (world.home / "config.yaml").read_text(encoding="utf-8").count(INLINE_KEY) == 1
    paths = sorted(route.path for route in api.module.router.routes if "move" in route.path)
    assert paths == ["/providers/move"]
    done = api.post(f"{API}/providers/move", json={"keys": ["model.api_key"]})
    assert done.status_code == 200 and done.json()["moved"] == [{"path": "model.api_key", "env": "OPENROUTER_API_KEY"}]
    assert done.json()["providers_block"] is None and INLINE_KEY not in done.text
    assert f"OPENROUTER_API_KEY={INLINE_KEY}" in (world.home / ".env").read_text(encoding="utf-8")
    assert INLINE_KEY not in (world.home / "config.yaml").read_text(encoding="utf-8")
    backups = _layout(world).state_dir / "config-key-backups"
    assert not backups.exists(), "a copy of config.yaml with the key in it was kept"


def test_the_switch_route_refuses_with_the_code_the_keys_and_the_pages_sentence(api, world, monkeypatch):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "api_key": INLINE_KEY, "default": "m"}})
    started = []
    monkeypatch.setattr(api.module._switch, "drop_leftover", lambda *a, **k: started.append("drop"))
    refused = api.post(f"{API}/switch/on", json={})
    assert refused.status_code == 422 and started == []
    assert refused.json() == {"code": "key_in_config", "detail": ONE_KEY + " Key: model.api_key.",
                              "keys": [{"path": "model.api_key", "env": "OPENROUTER_API_KEY"}]}
    world.config({"model": {"provider": "qwen-oauth", "default": "m"}})
    refused = api.post(f"{API}/switch/on", json={})
    assert refused.status_code == 422 and refused.json()["code"] == "model_unavailable" and refused.json()["keys"] == []
    assert refused.json()["detail"].startswith("This profile's model uses ") and started == []
    assert "keeps its sign-in outside this profile." in refused.json()["detail"]


class _Sup:
    def __init__(self, layout, rows):
        self.layout, self.rows, self.outer_port = layout, rows, 47999

    def status(self):
        return {"profile": "work", "sandboxed": True, "state": "running", "endpoint_changed": [],
                "providers": [dict(row) for row in self.rows]}


def test_the_launcher_answers_the_same_path_with_its_rows(world, monkeypatch):  # noqa: F811
    keys = _keys([("OPENROUTER_API_KEY", "openrouter.ai")])
    rows = R.live_rows(_layout(world), ENGINE, keys, [], ROUTES)
    routes = HR.HostRoutes(_Sup(_layout(world), rows), lambda: None)

    def call(method, path):
        handler = routes.match(method, path)
        assert handler is not None, path
        return asyncio.run(handler(parse_head(f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode()), b""))

    monkeypatch.setattr(HR, "switch_view", lambda layout, sandboxed: {"available": True, "reason": None, "on": True})
    code, answer, _ = call("GET", f"{API}/providers")
    assert code == 200 and answer["providers_block"] is None
    assert answer["providers"] == call("GET", f"{API}/status")[1]["providers"]
    assert [row["id"] for row in answer["providers"]][0] == "sign_in:nous"
    assert all(set(row) <= {"id", "label", "kind", "state", "detail", "main", "fallback", "env", "path"}
               for row in answer["providers"])
    code, refused, _ = call("POST", f"{API}/providers/move")
    assert code == 409 and refused["detail"] == "Turn the sandbox off for this profile first."
    assert call("POST", f"{API}/keys/move")[0] == 404
