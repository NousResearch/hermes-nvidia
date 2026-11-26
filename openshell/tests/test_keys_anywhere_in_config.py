"""A key written anywhere in config.yaml, or in a copy of it, keeps the switch off (launcher/config_keys.py,
provider_rows.py, launcher_cli.py). Every key here is made up."""
import pytest

pytest.importorskip("hermes_yaml", reason="Hermes's own YAML reader is not importable here")

import hermes_yaml  # noqa: E402

from openshell import launcher_cli as CLI  # noqa: E402
from openshell.launcher import config_keys as K  # noqa: E402
from openshell.launcher import provider_rows as R  # noqa: E402
from openshell.launcher import switch as SW  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402

KEY = "made-up-" + "k" * 24 + "-1"
CONFIG = {
    "model": {"provider": "custom", "base_url": "http://127.0.0.1:9/v1", "api_key": KEY},
    "tts": {"provider": "openai", "openai": {"api_key": KEY, "base_url": "http://127.0.0.1:9/v1"},
            "elevenlabs": {"api_key": KEY, "voice_id": "pNInz6obpgDQGcFmaJgB"}},
    "stt": {"openai": {"api_key": KEY}},
    "voice": {"live": {"api_key": KEY}},
    "mcp_servers": {"srv": {"url": "https://mcp.example/sse?token=" + KEY,
                            "headers": {"Authorization": "Bearer " + KEY},
                            "env": {"GITHUB_TOKEN": KEY, "PLAIN_NAME": "plain"}, "args": ["--api-key", KEY]}},
    "platforms": {"telegram": {"token": KEY}, "slack": {"api_key": KEY},
                  "webhook": {"extra": {"secret": KEY, "routes": {"r": {"secret": KEY}}}}},
    "dashboard": {"basic_auth": {"username": "u", "password": KEY, "secret": KEY}},
    "browser": {"cdp_url": "wss://browser.example/?token=" + KEY},
    "web": {"firecrawl": {"api_key": KEY}},
    "memory": {"honcho": {"api_key": KEY}},
    "hooks": {"on_x": [{"command": "curl -H 'Authorization: Bearer " + KEY + "' https://hooks.example"}]},
    "quick_commands": {"x": {"command": "TOKEN=" + KEY + " run"}, "y": {"command": "tool --api-key " + KEY}},
    "discord": {"webhook_url": "https://discord.com/api/webhooks/1/" + KEY},
    "terminal": {"docker_env": {"API_TOKEN": KEY}},
    "git": {"remote": "https://someone:" + KEY + "@git.example/repo.git"},
}
MOVED = {"model.api_key", "mcp_servers.srv.headers.Authorization", "mcp_servers.srv.env.GITHUB_TOKEN"}
BY_HAND = {
    "tts.openai.api_key", "tts.elevenlabs.api_key", "stt.openai.api_key", "voice.live.api_key", "mcp_servers.srv.url",
    "mcp_servers.srv.args.1", "platforms.telegram.token", "platforms.slack.api_key", "platforms.webhook.extra.secret",
    "platforms.webhook.extra.routes.r.secret", "dashboard.basic_auth.password", "dashboard.basic_auth.secret",
    "browser.cdp_url", "web.firecrawl.api_key", "memory.honcho.api_key", "hooks.on_x.0.command",
    "quick_commands.x.command", "quick_commands.y.command", "discord.webhook_url", "terminal.docker_env.API_TOKEN",
    "git.remote"}


def _layout(tmp_path, config: dict) -> ProfileLayout:
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(hermes_yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return ProfileLayout(name="work", home=home, root=root)


@pytest.mark.parametrize("place", sorted(MOVED | BY_HAND))
def test_a_key_is_found_wherever_it_is_written(place):
    assert place in {item["path"] for item in K.inline_keys(CONFIG)}


def test_every_key_is_found_once_and_no_row_carries_its_value():
    found = K.inline_keys(CONFIG)
    assert sorted(item["path"] for item in found) == sorted(MOVED | BY_HAND)
    assert KEY not in repr(found)


def test_a_key_of_a_model_or_an_mcp_server_moves_and_any_other_is_named_for_a_move_by_hand():
    rows = {item["path"]: item for item in K.inline_keys(CONFIG)}
    assert {path for path, row in rows.items() if row["env"]} == MOVED
    assert all(not rows[path].get("by_hand") for path in MOVED)
    for path in BY_HAND:
        assert rows[path]["env"] == "" and rows[path]["by_hand"] is True and rows[path]["variable"]
    assert rows["tts.openai.api_key"]["variable"] == "TTS_OPENAI_API_KEY"
    names = [row["env"] or row["variable"] for row in rows.values()]
    assert len(names) == len(set(names)), "two keys share a variable"


@pytest.mark.parametrize("config", [
    {"tts": {"elevenlabs": {"voice_id": "pNInz6obpgDQGcFmaJgB"},
             "mistral": {"voice_id": "c69964a6-ab8b-4f8a-9465-ec0925096ec8"}}},
    {"tts": {"openai": {"api_key": "${VOICE_TOOLS_OPENAI_KEY}"}}, "platforms": {"telegram": {"token": ""}}},
    {"mcp_servers": {"srv": {"url": "https://mcp.example/sse?token=${MCP_TOKEN}", "args": ["--api-key", "${MCP_KEY}"],
                             "env": {"PLAIN_NAME": "plain", "LOG_LEVEL": "debug"}}}},
    {"hooks": {"on_x": [{"command": "curl -H 'Authorization: Bearer ${HOOK_TOKEN}' https://hooks.example"}]},
     "quick_commands": {"x": {"command": "TOKEN=$HOOK_TOKEN run --max-token 20000000"}}},
    {"agent": {"note": "Use bearer authentication and the --token option when the server asks for a token."}},
    {"browser": {"cdp_url": "ws://127.0.0.1:9222/devtools/browser"},
     "model": {"base_url": "http://host:8080/v1/path@x"}},
    {"terminal": {"docker_shared_container_key": "team-a", "backend": "local"}, "display": {"token_count": "on"}},
    {"secrets": {"onepassword": {"enabled": True, "env": {"OPENAI_API_KEY": "op://vault/openai/key"},
                                 "service_account_token_env": "OP_SERVICE_ACCOUNT_TOKEN"}}},
])
def test_a_plain_value_or_a_reference_is_not_a_key(config):
    assert K.inline_keys(config) == []


def test_hermes_default_settings_hold_no_key():
    from hermes_cli.config_defaults import DEFAULT_CONFIG

    assert K.inline_keys(DEFAULT_CONFIG) == []


def test_the_move_takes_the_keys_it_moves_and_leaves_the_others_where_they_are(tmp_path):
    layout = _layout(tmp_path, {"model": {"provider": "custom", "base_url": "http://127.0.0.1:9/v1", "api_key": KEY},
                                "tts": {"openai": {"api_key": KEY + "t"}}})
    assert K.move_to_env(layout.home) == ["model.api_key"]
    after = hermes_yaml.safe_load((layout.home / "config.yaml").read_text(encoding="utf-8"))
    assert after["tts"]["openai"]["api_key"] == KEY + "t" and after["model"]["api_key"].startswith("${")
    assert KEY + "t" not in (layout.home / ".env").read_text(encoding="utf-8")
    assert [item["path"] for item in K.inline_keys(after)] == ["tts.openai.api_key"]
    assert K.move_to_env(layout.home, [{"path": "tts.openai.api_key"}]) == []


def test_the_switch_stays_off_for_a_speech_key_and_says_where_it_goes(tmp_path):
    layout = _layout(tmp_path, {"model": {"provider": "custom", "base_url": "http://127.0.0.1:9/v1"},
                                "tts": {"provider": "openai", "openai": {"api_key": KEY}}})
    refusal = R.refusal(layout)
    assert refusal["code"] == "key_in_config" and [key["path"] for key in refusal["keys"]] == ["tts.openai.api_key"]
    assert refusal["detail"] == (
        "A key is written in config.yaml, where the sandbox could read it. Move it to .env first. Key: "
        "tts.openai.api_key (move it by hand: TTS_OPENAI_API_KEY in .env, ${TTS_OPENAI_API_KEY} in config.yaml).")
    with pytest.raises(SW.SwitchError) as refused:
        SW.refuse_unready(layout)
    assert refused.value.status == 422 and refused.value.code == "key_in_config" and KEY not in str(refused.value)
    # the flag that moves keys is named only for a key it moves
    assert CLI._with_move_hint(layout, "x", refused.value, "on") == "x"
    both = SW.SwitchError("x", 422)
    both.code, both.keys = "key_in_config", [{"path": "model.api_key", "env": "MODEL_API_KEY"}, *refusal["keys"]]
    hinted = CLI._with_move_hint(layout, "x", both, "on")
    assert hinted == "x Run `hermes -p work sandbox on --move-keys` to move it and go on."


def test_a_copy_of_the_config_with_a_key_in_it_keeps_the_switch_off(tmp_path):
    clean = {"model": {"provider": "custom", "base_url": "http://127.0.0.1:9/v1"}}
    layout = _layout(tmp_path, clean)
    assert R.refusal(layout) is None
    with_key = hermes_yaml.safe_dump({**clean, "model": {**clean["model"], "api_key": KEY}}, sort_keys=False)
    (layout.home / "config.yaml.bak").write_text(with_key, encoding="utf-8")
    refusal = R.refusal(layout)
    assert refusal == {"code": "key_in_config_copy", "keys": [], "detail": (
        "config.yaml.bak in the profile folder is a copy of config.yaml with a key in it (model.api_key), and the "
        "sandbox could read it. Delete it or move it out of the profile folder first.")}
    with pytest.raises(SW.SwitchError) as refused:
        SW.refuse_unready(layout)
    assert refused.value.status == 422 and CLI._with_move_hint(layout, "x", refused.value, "on") == "x"
    (layout.home / "Config.YAML~").write_text(with_key, encoding="utf-8")
    assert R.refusal(layout)["detail"].startswith("Config.YAML~ and config.yaml.bak in the profile folder are copies")
    for name in ("config.yaml.bak", "Config.YAML~"):
        (layout.home / name).unlink()
    assert R.refusal(layout) is None


def test_which_files_are_read_as_a_copy_of_the_config(tmp_path):
    layout = _layout(tmp_path, {"model": {"provider": "custom", "base_url": "http://127.0.0.1:9/v1"}})
    with_key = hermes_yaml.safe_dump({"model": {"api_key": KEY}})
    for name in ("config.yaml.save", "config.yaml.orig", "config.yaml~", "config.yaml.bak-my-note", "#config.yaml#",
                 "config.yaml.bak-20261125T101500Z", "notes.yaml", "config.yml", "my-config.yaml"):
        (layout.home / name).write_text(with_key, encoding="utf-8")
    (layout.home / ".config.yaml.swp").write_bytes(b"b0VIM 9.1\x00\x00\x10\x00" + with_key.encode() + b"\xff\xfe")
    (layout.home / "config.yaml.d").mkdir()
    assert K.config_copies(layout.home) == sorted(["#config.yaml#", ".config.yaml.swp", "config.yaml.bak-my-note",
                                                   "config.yaml.orig", "config.yaml.save", "config.yaml~"])
    # what Hermes's own writers leave is hidden from the sandbox; an editor's swap file cannot be read as a config
    # document, so nothing shows that it holds no key
    assert [(item["file"], item["unread"]) for item in K.keys_in_copies(layout.home)] == [
        ("#config.yaml#", False), (".config.yaml.swp", True), ("config.yaml.bak-my-note", False),
        ("config.yaml.orig", False), ("config.yaml.save", False), ("config.yaml~", False)]
    assert K.keys_in_copies(tmp_path / "gone") == []
    for name in K.config_copies(layout.home):
        (layout.home / name).unlink()
    (layout.home / "config.yaml.old").write_text("model:\n  provider: custom\n", encoding="utf-8")
    (layout.home / "config.yaml.empty").write_text("", encoding="utf-8")
    assert K.keys_in_copies(layout.home) == [] and R.refusal(layout) is None
    (layout.home / ".config.yaml.swp").write_bytes(b"b0VIM 9.1\x00\xff\xfe")
    assert R.refusal(layout)["detail"] == (
        ".config.yaml.swp in the profile folder is a copy of config.yaml that can't be checked for keys, and the "
        "sandbox could read it. Delete it or move it out of the profile folder first.")
