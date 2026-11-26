"""Which settings count as keys written in config.yaml (launcher/config_keys.py). A name that can only be a
credential's keeps the switch off for any value; a name that is a key of some kind (of a keyboard, of a sort, of
a cache) does so only for a value that looks like a credential. Every key here is made up."""
import pytest

pytest.importorskip("hermes_yaml", reason="Hermes's own YAML reader is not importable here")

from openshell.launcher import config_keys as K  # noqa: E402

RANDOM = "q7Zr2mXv9Ld4Kp8Ws3Tn6Yb1Hc5Jf0GaUe2Ri7Oq4Mx9Zl3Vk"  # 48 letters and digits
HEX = "3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a"  # 40
UUID = "c69964a6-ab8b-4f8a-9465-ec0925096ec8"
PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"

# Settings of an ordinary profile. None of them holds a secret.
ORDINARY = {
    "model": {"default": "anthropic/claude-sonnet-4-20250514", "provider": "custom", "key_env": "OPENAI_API_KEY",
              "api_key_env": "MY_KEY", "base_url": "http://127.0.0.1:11434/v1", "api_key": "${OPENAI_API_KEY}"},
    "voice": {"record_key": "ctrl+b", "push_to_talk_key": "space", "stop_key": "escape"},
    "display": {"keybindings": [{"key": "ctrl+p", "action": "palette"}, {"key": "f5", "action": "reload"}],
                "submit_key": "enter", "newline_key": "shift+enter", "theme": "midnight"},
    "tui": {"keys": {"quit": "ctrl+q"}, "leader_key": "ctrl+x"},
    "memory": {"partition_key": "user_id", "sort_key": "created_at", "provider": "builtin"},
    "cache": {"key": "sessions", "namespace_key": "hermes:v2"},
    "plugins": {"notes": {"settings": {"dedupe_key": "title", "primary_key": "id",
                                       "index_key": "notes-by-day-2026"}}},
    "tts": {"provider": "elevenlabs",
            "elevenlabs": {"voice_id": "21m00Tcm4TlvDq8ikWAM", "model_id": "eleven_turbo_v2_5"}},
    "terminal": {"docker_shared_container_key": "hermes-shared", "env": {"EDITOR": "vim", "TOKEN_LIMIT": "8000"},
                 "docker_image": "nikolaik/python-nodejs:python3.11-nodejs20"},
    "mcp_servers": {"fs": {"command": "npx",
                           "args": ["-y", "@modelcontextprotocol/server-filesystem", "--root", "/home/u/p"]},
                    "sorter": {"command": "sort-server", "args": ["--key", "name", "--max-tokens", "4096"]},
                    "web": {"url": "https://mcp.example.com/sse?session=abcdef123456"}},
    "agent": {"token_budget": "auto", "max_tokens": "4096", "tokenizer": "cl100k_base"},
    "git": {"remote": "ssh://git@github.com:22/org/repo.git", "signing_key": "~/.ssh/id_ed25519.pub"},
    "database": {"url": "postgres://localhost:5432/notes"},
    "security": {"redact_secrets": "true", "secret_scanning": "on"},
    "auth": {"token_file": "~/.config/tool/token.json", "password_prompt": "ask"},
    "updates": {"public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"},
    "session": {"key": "default"},
}
# The same kinds of place with a secret in each.
SECRETS = {
    "tts": {"openai": {"api_key": "sk-" + RANDOM}},
    "stt": {"groq": {"api_key": "gsk_" + RANDOM}},
    "telegram": {"bot_token": "123456789:" + RANDOM[:35]},
    "dashboard": {"password": "hunter2"},
    "terminal": {"env": {"GITHUB_TOKEN": "ghp_" + RANDOM[:36]}},
    "browser": {"cdp_url": "wss://user:" + RANDOM[:12] + "@browser.example.com/devtools"},
    "notify": {"webhook": "https://hooks.slack.com/services/T000/B000/" + RANDOM[:24]},
    "mcp_servers": {"x": {"command": "srv", "args": ["--api-key", "abc12345def"]}},
    "custom": {"header": "Bearer abcdefghijklmnop1234567890"},
}
SECRET_PLACES = ["tts.openai.api_key", "stt.groq.api_key", "telegram.bot_token", "dashboard.password",
                 "terminal.env.GITHUB_TOKEN", "browser.cdp_url", "notify.webhook", "mcp_servers.x.args.1",
                 "custom.header"]


def _places(node, path=()) -> list:
    """The dotted place of every string in *node*."""
    if isinstance(node, str):
        return [".".join(str(part) for part in path)]
    below = node.items() if isinstance(node, dict) else enumerate(node)
    return [place for key, value in below for place in _places(value, (*path, key))]


def _found(config: dict) -> list:
    return [row["path"] for row in K.inline_keys(config)]


@pytest.mark.parametrize("place", _places(ORDINARY))
def test_an_ordinary_setting_is_no_key(place):
    assert place not in _found(ORDINARY)


def test_an_ordinary_profile_turns_on():
    assert len(_places(ORDINARY)) == 56 and K.inline_keys(ORDINARY) == []


@pytest.mark.parametrize("place", SECRET_PLACES)
def test_a_secret_is_found_in_each_kind_of_place(place):
    assert place in _found(SECRETS)


def test_every_secret_is_found_once_and_none_is_moved():
    rows = K.inline_keys(SECRETS)
    assert [row["path"] for row in rows] == SECRET_PLACES
    assert all(row["env"] == "" and row["by_hand"] is True for row in rows)
    assert RANDOM[:12] not in repr(rows)


@pytest.mark.parametrize("name", ["api_key", "apikey", "openai_api_key", "access_key", "aws_access_key", "secret_key",
                                  "aws_secret_key", "token", "bot_token", "secret", "client_secret", "webhook_secret",
                                  "password", "passwd", "smtp_password", "authorization", "bearer", "jwt", "API-KEY",
                                  "X-Api-Key", "GITHUB_TOKEN"])
@pytest.mark.parametrize("value", ["hunter2", "1234", RANDOM])
def test_a_name_that_can_only_be_a_credentials_counts_for_any_value(name, value):
    assert _found({"plugins": {"mine": {name: value}}}) == [f"plugins.mine.{name}"]
    assert _found({"plugins": {"mine": {name: "${MINE_SECRET}"}}}) == []
    assert _found({"plugins": {"mine": {name: ""}}}) == []


KEY_LIKE = ["key", "private_key", "signing_key", "record_key", "sort_key", "cache_key", "ssh_private_key",
            "API-SIGNING-KEY"]
CREDENTIALS = {"random": RANDOM, "hex": HEX, "an-id": UUID, "an-id-and-hex": UUID + ":" + HEX,
               "base64": RANDOM[:42] + "==", "sixteen": "9f86d081884c7d65", "pem": PEM,
               "prefixed": "rk_live_" + RANDOM[:30]}
NO_CREDENTIALS = {
    "keyboard": "ctrl+shift+p", "column": "created_at", "label": "hermes-shared",
    "words-and-a-year": "notes-by-day-2026", "words": "sessions-of-the-production-cluster",
    "versioned": "sessions-v2-production-eu1", "number": "12345678901234567890",
    "letters": "abcdefghijklmnopqrstuvwxyz", "date": "2026-11-25T10:15:00Z", "host": "cache01.internal.example.com",
    "model": "anthropic/claude-sonnet-4-20250514", "sentence": "the key q7Zr2mXv9Ld4Kp8Ws3Tn is in the vault",
    "home-path": "~/.ssh/" + HEX + ".pem", "path": "/var/lib/keys/" + HEX + ".pem", "here-path": "./keys/" + HEX,
    "up-path": "../keys/" + HEX, "drive-path": "C:\\Users\\u\\keys\\" + HEX + ".pem",
    "share-path": "\\\\files\\keys\\" + HEX,
    "public-pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n",
    "short": "9f86d081884c7d6", "reference": "${SIGNING_KEY}",
}


@pytest.mark.parametrize("name", KEY_LIKE)
@pytest.mark.parametrize("kind", sorted(CREDENTIALS))
def test_a_key_like_name_counts_when_its_value_looks_like_a_credential(name, kind):
    assert _found({"fal": {name: CREDENTIALS[kind]}}) == [f"fal.{name}"]


@pytest.mark.parametrize("name", KEY_LIKE)
@pytest.mark.parametrize("kind", sorted(NO_CREDENTIALS))
def test_a_key_like_name_does_not_count_for_any_other_value(name, kind):
    assert _found({"fal": {name: NO_CREDENTIALS[kind]}}) == []


@pytest.mark.parametrize("name", ["public_key", "pubkey", "signing_public_key", "ssh_pubkey", "PUBLIC-KEY"])
@pytest.mark.parametrize("kind", ["random", "hex", "an-id-and-hex"])
def test_a_name_that_says_public_never_counts(name, kind):
    assert _found({"updates": {name: CREDENTIALS[kind]}}) == []


@pytest.mark.parametrize("args, found", [
    (["--key", "name"], []), (["--sort-key", "created_at", "--max-tokens", "4096"], []),
    (["--key", RANDOM], ["tool.args.1"]), (["--signing-key", UUID + ":" + HEX], ["tool.args.1"]),
    (["--api-key", "abc12345def"], ["tool.args.1"]), (["--token", "4096"], ["tool.args.1"]),
    (["-p", "x", "--password", "hunter2"], ["tool.args.3"]), (["--api-key", "${TOOL_KEY}"], []),
    (["--public-key", RANDOM], []), (["--key"], []), ([RANDOM, "--key"], []),
])
def test_the_argument_after_a_flag_counts_as_a_setting_of_that_name_does(args, found):
    assert _found({"tool": {"args": args}}) == found
    inside = [place.replace("tool.", "mcp_servers.tool.") for place in found]
    assert _found({"mcp_servers": {"tool": {"command": "tool", "args": args}}}) == inside


def test_a_value_in_a_list_has_the_name_of_the_list():
    assert _found({"dashboard": {"password": ["hunter2", ""], "sort_key": ["name", RANDOM]}}) == [
        "dashboard.password.0", "dashboard.sort_key.1"]


def test_the_sections_whose_keys_are_moved_read_names_as_hermes_does():
    """A key of a model route or of an MCP server is found and moved by Hermes's own rule for the name."""
    rows = K.inline_keys({"model": {"provider": "custom", "base_url": "http://127.0.0.1:9/v1", "api_key": "hunter2"},
                          "mcp_servers": {"s": {"env": {"SERVICE_TOKEN": "hunter2", "LOG_LEVEL": "debug"},
                                                "headers": {"Authorization": "hunter2", "Accept": "text/plain"}}}})
    assert [(row["path"], bool(row["env"])) for row in rows] == [
        ("model.api_key", True), ("mcp_servers.s.env.SERVICE_TOKEN", True),
        ("mcp_servers.s.headers.Authorization", True)]
