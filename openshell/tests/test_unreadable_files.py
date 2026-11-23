"""A file that cannot be read is not an empty file (launcher/settings_view.py, provider_rows.py, switch.py,
config_keys.py).

The provider rows are built from the profile's ``config.yaml``, its ``.env`` and its sign-in files. While another
program holds one of them open, the page keeps the rows it last read and says which file it cannot read, the
switch stays held, a switch-on is refused with that sentence, and "Move to .env" says what happened and changes
nothing. Every key here is made up.
"""
import json

import pytest

pytest.importorskip("openshell.launcher.signins", reason="the sign-in report is not in this tree")

import page_provider_fixtures as fx  # noqa: E402
from held_open import held_open  # noqa: E402
from page_provider_fixtures import INLINE_KEY, write_env  # noqa: E402
from signin_home import world  # noqa: E402,F401
from test_provider_rows_one_source import api  # noqa: E402,F401

from openshell import launcher_cli as CLI  # noqa: E402
from openshell.launcher import config_keys as K  # noqa: E402
from openshell.launcher import pins as P  # noqa: E402
from openshell.launcher import provider_rows as R  # noqa: E402
from openshell.launcher import settings_view as SV  # noqa: E402
from openshell.launcher import switch as SW  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402

API = "/api/plugins/openshell"
ONE_KEY = "A key is written in config.yaml, where the sandbox could read it. Move it to .env first."
CANT_READ = "Can't read this profile's {}. Another program may have it open."
NOT_YAML = "Can't read this profile's config.yaml. It isn't valid YAML."
WITH_KEY = {"model": {"provider": "openrouter", "api_key": INLINE_KEY, "default": "m"}}
PLAIN = {"model": {"provider": "openrouter", "default": "m"}}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    fx.offline_catalog(monkeypatch)
    SV.forget_providers()
    yield
    SV.forget_providers()


def _layout(world):  # noqa: F811
    return ProfileLayout(name="work", home=world.home, root=world.root)


def _page(world):  # noqa: F811
    """What the page's poll gets: the kept answer is dropped first, as a changed file does."""
    SV.forget_providers(_layout(world))
    return SV.provider_view(_layout(world))


def _unread(name, reason=None):
    return {"code": "unreadable", "file": name, "reason": reason or CANT_READ.format(name), "rows": []}


def test_a_config_held_open_keeps_the_rows_and_the_held_switch(world):  # noqa: F811
    world.config(WITH_KEY)
    write_env(world.home, ["TAVILY_API_KEY"])
    before = _page(world)
    assert before["providers_block"]["code"] == "key_in_config"
    assert [row["id"] for row in before["providers"]] == ["config:model.api_key", "key:TAVILY_API_KEY"]
    with held_open(world.home / "config.yaml"):
        during = _page(world)
        assert during["providers"] == before["providers"], "the rows of the last read are gone"
        assert during["providers_block"] == _unread("config.yaml")
        assert SV.provider_view(_layout(world))["providers_block"] == _unread("config.yaml")  # and at the next poll
    assert _page(world) == before  # the file is free again: the next read is the file's


def test_a_switch_that_was_free_is_held_while_the_config_cannot_be_read(world):  # noqa: F811
    world.config(PLAIN)
    write_env(world.home, ["OPENROUTER_API_KEY"])
    before = _page(world)
    assert before["providers_block"] is None and [row["id"] for row in before["providers"]] == ["key:OPENROUTER_API_KEY"]
    with held_open(world.home / "config.yaml"):
        during = _page(world)
    # A key may have been written there since: that cannot be ruled out, so the switch is held.
    assert during == {"providers": before["providers"], "providers_block": _unread("config.yaml")}


def test_a_config_that_was_never_read_is_not_a_profile_without_providers(world, caplog):  # noqa: F811
    world.config(WITH_KEY)
    with held_open(world.home / "config.yaml"), caplog.at_level("WARNING", logger="openshell.settings_view"):
        view = _page(world)
        again = _page(world)
    assert view == again == {"providers": [], "providers_block": _unread("config.yaml")}
    # The page looks every few seconds: the log gets one line for the file, not one per look.
    assert [record.getMessage() for record in caplog.records] == [
        "the providers of profile work were not read: " + CANT_READ.format("config.yaml")]
    caplog.clear()
    with caplog.at_level("WARNING", logger="openshell.settings_view"):
        assert _page(world)["providers_block"]["code"] == "key_in_config"
        with held_open(world.home / "config.yaml"):
            _page(world)
    assert len(caplog.records) == 1  # read once in between: held again is said again


def test_a_config_that_is_not_yaml_holds_the_switch_with_its_own_sentence(world):  # noqa: F811
    (world.home / "config.yaml").write_text("model: [unclosed\n  api_key: x\n", encoding="utf-8")
    assert _page(world) == {"providers": [], "providers_block": _unread("config.yaml", NOT_YAML)}
    assert R.refusal(_layout(world)) == {"code": "unreadable", "keys": [], "detail": NOT_YAML}


@pytest.mark.parametrize("name", [".env", "auth.json"])
def test_an_env_file_or_a_sign_in_file_held_open_keeps_the_rows_and_holds_the_switch(world, name):  # noqa: F811
    world.config({"model": {"provider": "nous", "default": "m"}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    world.sign_in("nous")
    before = _page(world)
    assert before["providers_block"] is None
    assert {row["id"]: row["state"] for row in before["providers"]} == {"sign_in:nous": "ready", "key:OPENROUTER_API_KEY": "ready"}
    with held_open(world.home / name):
        during = _page(world)
        refusal = R.refusal(_layout(world))
    assert during == {"providers": before["providers"], "providers_block": _unread(name)}
    assert refusal == {"code": "unreadable", "keys": [], "detail": CANT_READ.format(name)}
    assert _page(world) == before


def test_the_switch_and_the_terminal_refuse_while_a_file_cannot_be_read(world):  # noqa: F811
    world.config(WITH_KEY)
    layout = _layout(world)
    with held_open(world.home / "config.yaml"):
        assert R.refusal(layout) == {"code": "unreadable", "keys": [], "detail": CANT_READ.format("config.yaml")}
        with pytest.raises(SW.SwitchError) as refused:
            SW.refuse_unready(layout)
    assert refused.value.status == 422 and refused.value.code == "unreadable" and refused.value.keys == []
    assert str(refused.value) == CANT_READ.format("config.yaml")
    # No flag moves a key out of a file that cannot be read: the terminal's hint is for keys it can name.
    assert CLI._with_move_hint(layout, str(refused.value), refused.value, "on") == str(refused.value)
    assert R.refusal(layout)["code"] == "key_in_config"


@pytest.mark.parametrize("name", ["config.yaml", ".env", "auth.json"])
def test_a_file_that_becomes_unreadable_after_the_check_is_not_pinned_as_an_empty_one(world, name):  # noqa: F811
    world.config(PLAIN)
    write_env(world.home, ["OPENROUTER_API_KEY"])
    world.sign_in("nous")
    layout = _layout(world)
    with held_open(world.home / name):
        with pytest.raises(P.PinError) as failed:
            P.take(layout)
    assert str(failed.value) == CANT_READ.format(name) and not P.present(layout)
    assert isinstance(failed.value, OSError)  # what a switch-on already reports as its own refusal
    assert P.take(layout)["files"][".env"]["sha256"] and P.present(layout)
    P.release(layout)


def test_the_switch_route_refuses_and_nothing_starts(api, world, monkeypatch):  # noqa: F811
    world.config(PLAIN)
    write_env(world.home, ["OPENROUTER_API_KEY"])
    started = []
    monkeypatch.setattr(api.module._switch, "drop_leftover", lambda *a, **k: started.append("drop"))
    with held_open(world.home / "config.yaml"):
        refused = api.post(f"{API}/switch/on", json={})
    assert refused.status_code == 422 and started == [] and not P.present(_layout(world))
    assert refused.json() == {"code": "unreadable", "detail": CANT_READ.format("config.yaml"), "keys": []}


def test_the_move_says_what_happened_and_changes_nothing(api, world):  # noqa: F811
    world.config(WITH_KEY)
    write_env(world.home, ["TAVILY_API_KEY"])
    before = _page(world)
    files = {name: (world.home / name).read_bytes() for name in ("config.yaml", ".env")}
    with held_open(world.home / "config.yaml"):
        code, answer = SV.move_keys(_layout(world), {"keys": ["model.api_key"]})
        route = api.post(f"{API}/providers/move", json={"keys": ["model.api_key"]})
    said = "Couldn't move model.api_key to .env: config.yaml can't be read. Another program may have it open."
    assert (code, answer["detail"]) == (409, said) and "no longer" not in answer["detail"]
    assert answer["providers"] == before["providers"] and answer["providers_block"] == _unread("config.yaml")
    assert route.status_code == 409 and route.json()["detail"] == said
    assert {name: (world.home / name).read_bytes() for name in files} == files
    assert INLINE_KEY not in json.dumps(answer) and INLINE_KEY not in route.text
    with held_open(world.home / ".env"):
        code, answer = SV.move_keys(_layout(world), {"keys": ["model.api_key"]})
    assert code == 409 and answer["detail"] == (
        "Couldn't move model.api_key to .env: .env can't be read. Another program may have it open.")
    assert {name: (world.home / name).read_bytes() for name in files} == files
    # A place that really holds no key is still said as that.
    code, answer = SV.move_keys(_layout(world), {"keys": ["providers.gone.api_key"]})
    assert code == 409 and answer["detail"] == "config.yaml no longer has a key at providers.gone.api_key."


def test_an_env_file_that_cannot_be_written_leaves_the_key_where_it_was(world, monkeypatch):  # noqa: F811
    world.config(WITH_KEY)
    files = {"config.yaml": (world.home / "config.yaml").read_bytes()}
    write_whole = K._write_whole

    def refused(path, data, mode=0o600):
        if path.name == ".env":
            raise PermissionError(13, "Permission denied", str(path))
        return write_whole(path, data, mode)

    monkeypatch.setattr(K, "_write_whole", refused)
    code, answer = SV.move_keys(_layout(world), {"keys": ["model.api_key"]})
    assert code == 500 and answer["detail"] == (
        "Couldn't move model.api_key to .env: .env can't be written. Another program may have it open.")
    assert str(world.home) not in answer["detail"] and "Errno" not in answer["detail"]
    assert (world.home / "config.yaml").read_bytes() == files["config.yaml"] and not (world.home / ".env").exists()


def test_the_terminals_move_flag_says_it_in_plain_words(world):  # noqa: F811
    world.config(WITH_KEY)
    write_env(world.home, ["TAVILY_API_KEY"])
    files = {name: (world.home / name).read_bytes() for name in ("config.yaml", ".env")}
    for name in files:
        with held_open(world.home / name):
            with pytest.raises(K.MoveError) as failed:
                CLI._move_keys(_layout(world))
        assert str(failed.value) == f"{name} can't be read. Another program may have it open."
    (world.home / "config.yaml").write_text("model: [unclosed\n", encoding="utf-8")
    with pytest.raises(K.MoveError) as failed:
        CLI._move_keys(_layout(world))
    assert str(failed.value) == "config.yaml isn't valid YAML."
    assert (world.home / ".env").read_bytes() == files[".env"]


def test_an_error_of_the_system_is_said_without_its_path_and_number(world, monkeypatch):  # noqa: F811
    world.config(WITH_KEY)

    def refused(home, items=None):
        raise PermissionError(13, "Permission denied", str(world.home / "config.yaml"))

    monkeypatch.setattr(K, "move_to_env", refused)
    code, answer = SV.move_keys(_layout(world), {"keys": ["model.api_key"]})
    assert code == 500 and answer["detail"] == "Couldn't move model.api_key to .env: Permission denied"


def test_a_failure_of_the_row_builder_keeps_what_was_last_known(world, monkeypatch):  # noqa: F811
    world.config(WITH_KEY)
    before = _page(world)
    assert before["providers_block"]["code"] == "key_in_config"

    def broken(_layout):
        raise RuntimeError("no answer")

    monkeypatch.setattr(SV, "_host_rows", broken)
    assert _page(world) == before, "a held switch came free because the rows could not be made"
    SV.forget_providers()
    assert _page(world) == {"providers": [], "providers_block": None}  # nothing was ever known: as before


def test_while_on_a_key_written_in_the_config_stays_listed_while_the_file_cannot_be_read(world):  # noqa: F811
    world.config(WITH_KEY)
    layout = _layout(world)
    rows = R.live_rows(layout, [], [], [], [])
    assert [(row["id"], row["state"]) for row in rows] == [("config:model.api_key", "key_in_config")]
    with held_open(world.home / "config.yaml"):
        assert R.live_rows(layout, [], [], [], []) == rows
    world.config(PLAIN)
    assert R.live_rows(layout, [], [], [], []) == []
