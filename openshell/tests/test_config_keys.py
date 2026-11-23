"""Keys written in config.yaml (launcher/config_keys.py): which values count as a key, where each moves to,
and the move itself. Every key here is made up."""
import os

import pytest

pytest.importorskip("hermes_yaml", reason="Hermes's own YAML reader is not importable here")

import hermes_yaml  # noqa: E402

from openshell.launcher import config_keys as K  # noqa: E402

KEY = "sk-made-up-" + "k" * 32
CONFIG = {
    "model": {"provider": "openrouter", "default": "a-model", "api_key": KEY + "1"},
    "fallback_model": {"provider": "custom", "base_url": "https://llm.example.com/v1", "api_key": KEY + "2"},
    "fallback_providers": [{"provider": "anthropic", "model": "m", "api_key": "${ANTHROPIC_API_KEY}"},
                           {"provider": "custom", "base_url": "https://b.example.com/v1", "key_env": "B_KEY", "api_key": KEY + "3"}],
    "auxiliary": {"title_generation": {"provider": "gemini", "api_key": KEY + "4"}, "compression": {"provider": "auto"}},
    "providers": {"mine": {"name": "mine", "base_url": "https://m.example.com/v1", "api_key": KEY + "5",
                           "key_env": "", "api_key_env": "MINE_KEY"}},
    "custom_providers": [{"name": "Home Box", "base_url": "http://127.0.0.1:1/v1", "api_key": KEY + "6"},
                         {"name": "named", "base_url": "http://127.0.0.1:2/v1", "key_env": "NAMED_KEY"}],
    "mcp_servers": {"github": {"url": "https://mcp.example.com", "auth": "oauth",
                               "headers": {"Authorization": "Bearer " + KEY + "7", "X-Api-Key": "${GH_KEY}", "Accept": "text/plain"},
                               "env": {"GITHUB_TOKEN": KEY + "8", "GITHUB_HOST": "example.com", "LOG_LEVEL": "debug"}}},
    "terminal": {"backend": "local"}, "display": {"token_count": "on"},
}


def test_which_values_count_as_a_key_and_where_each_would_move():
    found = {item["path"]: item["env"] for item in K.inline_keys(CONFIG)}
    assert found == {
        "model.api_key": "OPENROUTER_API_KEY",                # the provider's own registered variable
        "fallback_model.api_key": "FALLBACK_MODEL_API_KEY",    # an address of its own: a name made from the place
        "fallback_providers.1.api_key": "B_KEY",               # the variable the route names
        "auxiliary.title_generation.api_key": found["auxiliary.title_generation.api_key"],
        "providers.mine.api_key": "MINE_KEY",
        "custom_providers.0.api_key": "CUSTOM_HOME_BOX_API_KEY",
        "mcp_servers.github.headers.Authorization": "MCP_GITHUB_AUTHORIZATION",
        "mcp_servers.github.env.GITHUB_TOKEN": "MCP_GITHUB_GITHUB_TOKEN",
    }
    assert found["auxiliary.title_generation.api_key"] in ("GOOGLE_API_KEY", "GEMINI_API_KEY")
    assert KEY not in repr(K.inline_keys(CONFIG)), "a row carries a key's value"


@pytest.mark.parametrize("value", ["${OPENROUTER_API_KEY}", "Bearer ${TOKEN}", "  ${A}  ", "bearer   ${A_B1}"])
def test_a_reference_to_a_variable_is_never_a_key(value):
    assert K.is_reference(value)
    assert K.inline_keys({"model": {"api_key": value}, "mcp_servers": {"s": {"headers": {"Authorization": value}}}}) == []


@pytest.mark.parametrize("value", [KEY, "Bearer " + KEY, "${A}" + KEY, "$NOT_BRACED", ""])
def test_anything_else_is_not_a_reference(value):
    assert not K.is_reference(value)


def test_names_of_variables_and_plain_settings_are_not_keys():
    quiet = {"model": {"provider": "custom", "key_env": "MY_KEY", "api_key_env": "OTHER", "base_url": "https://x.example.com",
                       "api_key": "", "default": "m"},
             "mcp_servers": {"s": {"auth": "oauth", "env": {"HOME_DIR": "/x"}, "headers": {"Accept": "a"}}},
             "secrets": {"bitwarden": {"enabled": True}}, "token": "not in a section that is read"}
    assert K.inline_keys(quiet) == [] and K.inline_keys(None) == [] and K.inline_keys([]) == []


def test_two_keys_never_share_a_variable():
    config = {"custom_providers": [{"name": "a b", "api_key": KEY}, {"name": "a-b", "api_key": KEY + "x"}]}
    assert [item["env"] for item in K.inline_keys(config)] == ["CUSTOM_A_B_API_KEY", "CUSTOM_A_B_API_KEY_2"]


def _home(tmp_path, config, env=None):
    home = tmp_path / "root" / "profiles" / "work"
    home.mkdir(parents=True)
    (home / "config.yaml").write_text("# my settings\n" + hermes_yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    if env is not None:
        (home / ".env").write_text(env, encoding="utf-8")
    return home


def _env(home):
    from agent.secret_scope import load_env_file

    return dict(load_env_file(home / ".env"))


def test_the_move_puts_each_key_in_env_and_a_reference_in_its_place(tmp_path):
    home = _home(tmp_path, CONFIG, "EXISTING=1\n")
    before = {name: (home / name).read_bytes() for name in ("config.yaml", ".env")}
    moved = K.move_to_env(home)
    assert moved == [item["path"] for item in K.inline_keys(CONFIG)]
    after = hermes_yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    assert K.inline_keys(after) == [], "a key is still written in the config"
    assert KEY not in (home / "config.yaml").read_text(encoding="utf-8")
    env = _env(home)
    assert env["EXISTING"] == "1" and env["OPENROUTER_API_KEY"] == KEY + "1" and env["B_KEY"] == KEY + "3"
    assert env["MCP_GITHUB_AUTHORIZATION"] == KEY + "7", "the scheme word went into the variable"
    assert after["model"]["api_key"] == "${OPENROUTER_API_KEY}" and "key_env" not in after["model"]
    assert after["mcp_servers"]["github"]["headers"]["Authorization"] == "Bearer ${MCP_GITHUB_AUTHORIZATION}"
    assert after["mcp_servers"]["github"]["headers"]["X-Api-Key"] == "${GH_KEY}"
    # a route whose variable Hermes would not find by itself names it
    assert after["fallback_model"]["api_key"] == "${FALLBACK_MODEL_API_KEY}" and after["fallback_model"]["key_env"] == "FALLBACK_MODEL_API_KEY"
    assert after["custom_providers"][0]["key_env"] == "CUSTOM_HOME_BOX_API_KEY" and after["providers"]["mine"]["api_key_env"] == "MINE_KEY"
    assert after["terminal"] == {"backend": "local"} and after["model"]["default"] == "a-model"
    # no copy of the files as they were is kept: the launcher's folder holds none, and .env only grew
    assert not (tmp_path / "root" / "openshell" / "work" / K.BACKUP_DIRNAME).exists()
    assert (home / ".env").read_bytes().startswith(before[".env"]) and (home / "config.yaml").read_bytes() != before["config.yaml"]
    assert not [p for p in home.rglob("*") if p.is_file() and p.name not in ("config.yaml", ".env")
                and KEY.encode() in p.read_bytes()], "a copy of a key was left in the profile"
    assert K.move_to_env(home) == []  # nothing left to move


def test_only_the_named_keys_are_moved_and_a_place_without_a_key_is_skipped(tmp_path):
    home = _home(tmp_path, CONFIG)
    assert K.move_to_env(home, [{"path": "model.api_key"}, {"path": "model.default"}, {"path": "nowhere"}]) == ["model.api_key"]
    left = [item["path"] for item in K.inline_keys(hermes_yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8")))]
    assert "model.api_key" not in left and "fallback_model.api_key" in left
    assert _env(home) == {"OPENROUTER_API_KEY": KEY + "1"}


def test_a_variable_that_holds_another_value_is_not_overwritten(tmp_path):
    home = _home(tmp_path, {"model": {"provider": "openrouter", "api_key": KEY}}, "OPENROUTER_API_KEY=another-value\n")
    assert K.move_to_env(home) == ["model.api_key"]
    env = _env(home)
    assert env["OPENROUTER_API_KEY"] == "another-value" and env["OPENROUTER_API_KEY_2"] == KEY
    after = hermes_yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    assert after["model"]["api_key"] == "${OPENROUTER_API_KEY_2}"


def test_a_variable_that_already_holds_the_key_is_used_as_it_is(tmp_path):
    home = _home(tmp_path, {"model": {"provider": "openrouter", "api_key": KEY}}, f"OPENROUTER_API_KEY={KEY}\n")
    assert K.move_to_env(home) == ["model.api_key"]
    assert (home / ".env").read_text(encoding="utf-8") == f"OPENROUTER_API_KEY={KEY}\n"


@pytest.mark.parametrize("secret", ["with space and #hash", "quote'inside", 'double"quote', "back\\slash", "dollar$sign"])
def test_a_key_with_awkward_characters_is_read_back_by_hermes_as_it_was(tmp_path, secret):
    home = _home(tmp_path, {"model": {"provider": "openrouter", "api_key": secret}})
    try:
        moved = K.move_to_env(home)
    except K.MoveError:
        # Hermes would not read it back as written: nothing was moved, and the key is where it was.
        assert not (home / ".env").exists()
        assert hermes_yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))["model"]["api_key"] == secret
        return
    assert moved == ["model.api_key"] and _env(home)["OPENROUTER_API_KEY"] == secret


def test_a_stop_between_the_two_files_leaves_the_key_in_both_and_a_second_run_finishes(tmp_path, monkeypatch):
    home = _home(tmp_path, {"model": {"provider": "openrouter", "api_key": KEY}})
    import hermes_cli.config_backend as backend

    class Stopped(BaseException):
        pass

    def stopped(*_args, **_kwargs):
        raise Stopped()

    monkeypatch.setattr(backend, "write_config_document", stopped)
    with pytest.raises(Stopped):
        K.move_to_env(home)
    monkeypatch.undo()
    assert _env(home)["OPENROUTER_API_KEY"] == KEY and KEY in (home / "config.yaml").read_text(encoding="utf-8")
    assert K.move_to_env(home) == ["model.api_key"]
    assert (home / ".env").read_text(encoding="utf-8").count("OPENROUTER_API_KEY=") == 1
    assert KEY not in (home / "config.yaml").read_text(encoding="utf-8")


def test_no_temp_file_is_left_and_the_env_file_is_owner_only(tmp_path):
    home = _home(tmp_path, {"model": {"provider": "openrouter", "api_key": KEY}})
    K.move_to_env(home)
    assert sorted(p.name for p in home.iterdir()) == [".env", "config.yaml"]
    assert [p.name for p in tmp_path.rglob("*") if p.is_file() and p.parent != home] == []
    if os.name != "nt":
        assert (home / ".env").stat().st_mode & 0o777 == 0o600
