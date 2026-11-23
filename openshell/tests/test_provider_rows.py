"""The provider rows and the switch's refusal (launcher/provider_rows.py, switch.py, launcher_cli.py): which of
a profile's providers work in the sandbox, and when the switch does not turn on. Every key here is made up."""
import json
from types import SimpleNamespace

import pytest

from openshell import launcher_cli as CLI
from openshell.launcher import pins as P
from openshell.launcher import provider_rows as R
from openshell.launcher import switch as SW
from openshell.launcher.layout import ProfileLayout
from test_switch_flow import _on, env  # noqa: F401  (the switch fixture)

KEY = "sk-made-up-" + "k" * 32
SIGN_INS = [
    {"id": "nous:agent_key", "provider": "nous", "label": "Nous Portal", "state": "works", "used_by": ["model"],
     "sentence": "Signed in. Kept signed in on this computer; the sandbox holds a placeholder."},
    {"id": "openai-codex:access_token", "provider": "openai-codex", "label": "OpenAI Codex", "state": "retrying",
     "sentence": "Couldn't reach OpenAI Codex to renew the sign-in. Trying again."},
    {"id": "xai-oauth:access_token", "provider": "xai-oauth", "label": "xAI", "state": "lapsed",
     "sentence": "The xAI sign-in could not be renewed in time. The model answers again once it is renewed."},
    {"id": "minimax-oauth:access_token", "provider": "minimax-oauth", "label": "MiniMax", "state": "needs_sign_in",
     "reason": "expired", "sentence": "Sign-in expired. Sign in again.",
     "action": "Turn the sandbox off, sign in to MiniMax, then turn it on again."},
    {"provider": "anthropic", "label": "Anthropic", "state": "needs_sign_in", "reason": "not_signed_in",
     "sentence": "Not signed in. Sign in to Anthropic with the sandbox off."},
    {"provider": "copilot", "label": "GitHub Copilot", "state": "not_available", "used_by": ["fallback"],
     "sentence": "Not available in the sandbox: GitHub Copilot signs in through its own program."},
]


def _layout(tmp_path, config: str, env_text: str = ""):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(config, encoding="utf-8")
    if env_text:
        (home / ".env").write_text(env_text, encoding="utf-8")
    return ProfileLayout(name="work", home=home, root=root)


def test_the_rows_while_the_sandbox_is_on(tmp_path):
    layout = _layout(tmp_path, "model:\n  provider: nous\n")
    keys = [{"id": "key:OPENROUTER_API_KEY", "label": "OpenRouter", "kind": "key", "state": "ready", "main": False,
             "detail": "", "env": "OPENROUTER_API_KEY", "hosts": [{"host": "openrouter.ai", "port": 443}]},
            {"id": "key:OTHER_KEY", "label": "Model", "kind": "key", "state": "ready", "main": True, "detail": "",
             "env": "OTHER_KEY", "hosts": [{"host": "127.0.0.1", "port": 1}]}]
    changed = [{"label": "Model", "host": "127.0.0.1", "port": 1, "env": "OTHER_KEY"}]
    rows = R.live_rows(layout, SIGN_INS, keys, changed)
    assert sorted((row["id"], row["kind"], row["state"]) for row in rows) == sorted([
        ("sign_in:nous", "sign_in", "ready"), ("sign_in:openai-codex", "sign_in", "ready"),
        ("sign_in:xai-oauth", "sign_in", "expired"), ("sign_in:minimax-oauth", "sign_in", "expired"),
        ("sign_in:anthropic", "sign_in", "needs_sign_in"), ("sign_in:copilot", "sign_in", "unavailable"),
        ("key:OPENROUTER_API_KEY", "key", "ready"), ("key:OTHER_KEY", "key", "withheld")])
    assert all({"id", "label", "kind", "state", "detail", "main"} <= set(row) for row in rows)
    by_id = {row["id"]: row for row in rows}
    assert by_id["sign_in:minimax-oauth"]["detail"] == ("Sign-in expired. Turn the sandbox off, sign in to MiniMax, "
                                                         "then turn it on.")
    assert by_id["sign_in:openai-codex"]["detail"].endswith("Trying again.")
    assert by_id["key:OPENROUTER_API_KEY"] == {
        "id": "key:OPENROUTER_API_KEY", "label": "OpenRouter", "kind": "key", "state": "ready", "main": False,
        "detail": "Works in the sandbox. The key stays on this computer and is used only at openrouter.ai.",
        "env": "OPENROUTER_API_KEY", "hosts": [{"host": "openrouter.ai", "port": 443}]}
    assert by_id["sign_in:nous"]["used_by"] == ["model"] and by_id["sign_in:nous"]["main"] is True
    assert R.live_rows(layout, None, None) == []


def test_a_key_in_the_config_is_a_row_and_refuses_the_switch(tmp_path):
    layout = _layout(tmp_path, f"model:\n  provider: openrouter\n  api_key: {KEY}\ncustom_providers:\n- name: box\n"
                               f"  base_url: http://127.0.0.1:1/v1\n  api_key: {KEY}2\n")
    rows = R.host_rows(layout)
    assert rows[0] == {"id": "config:model.api_key", "label": "Key in config.yaml", "kind": "key", "state": "key_in_config",
                       "detail": "Written in config.yaml, where the sandbox could read it.",
                       "main": False, "env": "OPENROUTER_API_KEY", "path": "model.api_key"}
    refusal = R.refusal(layout, [])
    assert refusal["code"] == "key_in_config" and [k["path"] for k in refusal["keys"]] == ["model.api_key",
                                                                                        "custom_providers.0.api_key"]
    assert refusal["detail"] == ("Keys are written in config.yaml, where the sandbox could read them. Move them to .env "
                                 "first. Keys: model.api_key and custom_providers.0.api_key.")
    assert KEY not in json.dumps(refusal) and KEY not in json.dumps(R.host_rows(layout))


def test_only_the_main_model_refuses_the_switch(tmp_path):
    layout = _layout(tmp_path, "model:\n  provider: openrouter\n")
    row = {"id": "copilot:sign_in", "label": "GitHub Copilot", "kind": "sign_in", "state": "unavailable",
           "detail": "Not available in the sandbox: GitHub Copilot signs in through its own program.", "used_by": ["model"]}
    refusal = R.refusal(layout, [row])
    assert refusal == {"code": "model_unavailable", "keys": [], "detail": (
        "This profile's model uses GitHub Copilot, which isn't available in the sandbox. GitHub Copilot signs in "
        "through its own program.")}
    assert R.refusal(layout, [{**row, "state": "needs_sign_in"}])["code"] == "model_needs_sign_in"
    assert R.refusal(layout, [{**row, "used_by": [], "main": True}])["code"] == "model_unavailable"
    for shown_only in ({**row, "used_by": ["fallback"]}, {**row, "used_by": ["auxiliary.title_generation"]},
                       {**row, "state": "ready"}, {**row, "state": "withheld"}):
        assert R.refusal(layout, [shown_only]) is None
    assert R.refusal(layout, []) is None


def test_a_profile_with_a_key_or_with_no_model_credentials_is_not_refused(tmp_path):
    with_key = _layout(tmp_path / "a", "model:\n  provider: custom\n  base_url: http://127.0.0.1:18500/v1\n"
                                       "  key_env: MODEL_API_KEY\n", f"MODEL_API_KEY={KEY}\n")
    rows = R.host_rows(with_key)
    assert [(row["id"], row["state"]) for row in rows if row["kind"] == "key"] == [("key:MODEL_API_KEY", "ready")]
    assert R.refusal(with_key) is None and KEY not in json.dumps(rows)
    nothing = _layout(tmp_path / "b", "model:\n  provider: custom\n  base_url: http://127.0.0.1:18500/v1\n")
    assert R.host_rows(nothing) == [] and R.refusal(nothing) is None
    SW.refuse_unready(nothing)


def test_the_switch_refuses_before_anything_is_changed(env, monkeypatch):  # noqa: F811
    layout = env["layout"]
    (layout.home / "config.yaml").write_text(f"model:\n  provider: openrouter\n  api_key: {KEY}\n", encoding="utf-8")
    with pytest.raises(SW.SwitchError) as refused:
        _on(env)
    assert refused.value.status == 422 and refused.value.code == "key_in_config"
    assert [k["path"] for k in refused.value.keys] == ["model.api_key"] and "model.api_key" in str(refused.value)
    assert env["log"] == [] and not P.present(layout) and not layout.spec_path.exists()
    message = CLI._with_move_hint(layout, str(refused.value), refused.value, "on")
    assert message.endswith("Run `hermes -p work sandbox on --move-keys` to move it and go on.")
    several = SW.SwitchError("x", 422)
    several.code, several.keys = "key_in_config", [{"path": "a"}, {"path": "b"}]
    assert CLI._with_move_hint(layout, "x", several, "serve") == "x Run `hermes -p work sandbox serve --move-keys` to move them and go on."
    assert CLI._with_move_hint(layout, "x", SW.SwitchError("x"), "on") == "x"
    # moved: the switch turns on
    CLI._move_keys(layout)
    assert f"OPENROUTER_API_KEY={KEY}" in (layout.home / ".env").read_text(encoding="utf-8")
    assert _on(env)["profile"] == "work"


def test_the_switch_refuses_a_main_model_that_cannot_run_in_the_sandbox(env, monkeypatch):  # noqa: F811
    row = {"id": "x:sign_in", "label": "Qwen", "kind": "sign_in", "state": "unavailable", "used_by": ["model"],
           "detail": "Not available in the sandbox: Qwen keeps its sign-in in a file outside this profile."}
    monkeypatch.setattr(R, "host_rows", lambda _layout: [row])
    with pytest.raises(SW.SwitchError, match="This profile's model uses Qwen, which isn't available in the sandbox. Qwen keeps") as refused:
        _on(env)
    assert refused.value.code == "model_unavailable" and env["log"] == [] and not P.present(env["layout"])
    monkeypatch.setattr(R, "host_rows", lambda _layout: [{**row, "used_by": ["fallback"]}])
    assert _on(env)["profile"] == "work"


def test_a_hermes_that_cannot_be_asked_refuses_nothing(env, monkeypatch):  # noqa: F811
    def broken(_layout, rows=None):
        raise RuntimeError("no answer")

    monkeypatch.setattr(R, "refusal", broken)
    assert _on(env)["profile"] == "work"


def test_the_terminal_takes_the_move_flag(monkeypatch):
    import argparse

    parser = argparse.ArgumentParser()
    CLI._setup(parser)
    assert parser.parse_args(["on", "--move-keys"]).move_keys is True
    assert parser.parse_args(["on"]).move_keys is False and parser.parse_args(["serve", "--move-keys"]).move_keys is True
    with pytest.raises(SystemExit):
        parser.parse_args(["off", "--move-keys"])
