"""After a key moved from config.yaml to .env, no other file holds it (launcher/config_keys.py).

The move writes ``.env`` first and the config second, each whole and renamed into place, and checks both
afterwards. It keeps the two files as they were in memory until then, never in a file: a move that completed
leaves the key in ``.env`` only, and one that was stopped between the two writes leaves it in ``.env`` and in
``config.yaml``, where the next move finishes it. Copies an earlier version kept are removed. Every key here is
made up.
"""
import os
import time

import pytest

pytest.importorskip("hermes_yaml", reason="Hermes's own YAML reader is not importable here")

import hermes_yaml  # noqa: E402
import page_provider_fixtures as fx  # noqa: E402

from openshell.launcher import config_keys as K  # noqa: E402
from openshell.launcher import provider_rows as R  # noqa: E402
from openshell.launcher import settings_view as SV  # noqa: E402
from openshell.launcher import switch as SW  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402

KEY = "sk-made-up-" + "m" * 32
CONFIG = {"model": {"provider": "custom", "base_url": "http://127.0.0.1:18500/v1", "api_key": KEY, "default": "m"}}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    fx.offline_catalog(monkeypatch)
    SV.forget_providers()
    yield
    SV.forget_providers()


def _profile(tmp_path, config=None, env=None):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    (home / "config.yaml").write_text(hermes_yaml.safe_dump(config or CONFIG, sort_keys=False), encoding="utf-8")
    if env is not None:
        (home / ".env").write_text(env, encoding="utf-8")
    return ProfileLayout(name="work", home=home, root=root)


def _holding(root, value=KEY):
    """Every file below the Hermes root that holds *value*, by its path below the root."""
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*")
                  if path.is_file() and value.encode() in path.read_bytes())


def _left_over(layout, stamp="20200101-000000"):
    """What a move of an earlier version kept for good: the config as it was, key included."""
    folder = layout.state_dir / K.BACKUP_DIRNAME / stamp
    folder.mkdir(parents=True)
    (folder / "config.yaml").write_text(f"model:\n  api_key: {KEY}\n", encoding="utf-8")
    (folder / ".env").write_text("OTHER=1\n", encoding="utf-8")
    return folder.parent


def test_after_a_move_only_the_env_file_holds_the_key(tmp_path):
    layout = _profile(tmp_path, env="EXISTING=1\n")
    assert _holding(layout.root) == ["profiles/work/config.yaml"]
    assert K.move_to_env(layout.home) == ["model.api_key"]
    assert _holding(layout.root) == ["profiles/work/.env"]
    assert not (layout.state_dir / K.BACKUP_DIRNAME).exists()
    assert sorted(path.name for path in layout.home.iterdir()) == [".env", "config.yaml"]
    after = hermes_yaml.safe_load((layout.home / "config.yaml").read_text(encoding="utf-8"))
    assert after["model"]["api_key"] == "${MODEL_API_KEY}" and after["model"]["key_env"] == "MODEL_API_KEY"


def test_the_pages_move_leaves_no_copy_either(tmp_path):
    layout = _profile(tmp_path)
    code, answer = SV.move_keys(layout, {"keys": ["model.api_key"]})
    assert code == 200 and answer["moved"] == [{"path": "model.api_key", "env": "MODEL_API_KEY"}]
    assert _holding(layout.root) == ["profiles/work/.env"]


def test_copies_an_earlier_move_kept_are_removed_by_the_next_move(tmp_path):
    layout = _profile(tmp_path)
    kept = _left_over(layout)
    assert "openshell/work/config-key-backups/20200101-000000/config.yaml" in _holding(layout.root)
    assert K.move_to_env(layout.home) == ["model.api_key"]
    assert not kept.exists() and _holding(layout.root) == ["profiles/work/.env"]


def test_they_are_removed_by_the_next_switch_on_and_by_the_next_look_at_the_page(tmp_path):
    layout = _profile(tmp_path, {"model": {"provider": "custom", "base_url": "http://127.0.0.1:18500/v1",
                                           "key_env": "MODEL_API_KEY", "default": "m"}}, f"MODEL_API_KEY={KEY}\n")
    kept = _left_over(layout)
    SW.refuse_unready(layout)  # what every switch-on runs before it changes anything
    assert not kept.exists() and _holding(layout.root) == ["profiles/work/.env"]
    # Also a switch-on that is refused for a key in the config, before any row is read.
    (layout.home / "config.yaml").write_text(hermes_yaml.safe_dump(CONFIG, sort_keys=False), encoding="utf-8")
    kept = _left_over(layout)
    with pytest.raises(SW.SwitchError):
        SW.refuse_unready(layout)
    assert not kept.exists()
    (layout.home / "config.yaml").write_text(hermes_yaml.safe_dump(
        {"model": {**CONFIG["model"], "api_key": "${MODEL_API_KEY}", "key_env": "MODEL_API_KEY"}}, sort_keys=False), encoding="utf-8")
    kept = _left_over(layout)
    assert SV.provider_view(layout)["providers_block"] is None
    assert not kept.exists() and _holding(layout.root) == ["profiles/work/.env"]
    assert K.sweep(layout.home) == []  # nothing left: nothing to do, and no folder is made
    assert not (layout.state_dir / K.BACKUP_DIRNAME).exists()


def test_a_move_stopped_between_the_two_writes_leaves_two_files_and_the_next_move_finishes(tmp_path, monkeypatch):
    layout = _profile(tmp_path)
    import hermes_cli.config_backend as backend

    class Stopped(BaseException):
        pass

    def stopped(*_args, **_kwargs):
        raise Stopped()

    monkeypatch.setattr(backend, "write_config_document", stopped)
    with pytest.raises(Stopped):
        K.move_to_env(layout.home)
    monkeypatch.undo()
    # The key is in both files and nowhere else; the page still names it and holds the switch.
    assert _holding(layout.root) == ["profiles/work/.env", "profiles/work/config.yaml"]
    assert R.refusal(layout)["code"] == "key_in_config"
    assert K.move_to_env(layout.home) == ["model.api_key"]
    assert _holding(layout.root) == ["profiles/work/.env"]
    assert (layout.home / ".env").read_text(encoding="utf-8").count("MODEL_API_KEY=") == 1
    assert R.refusal(layout) is None


def test_a_config_that_still_holds_the_key_after_its_write_puts_both_files_back(tmp_path, monkeypatch):
    layout = _profile(tmp_path, env="EXISTING=1\n")
    before = {name: (layout.home / name).read_bytes() for name in ("config.yaml", ".env")}
    import hermes_cli.config_backend as backend

    def kept_the_key(path, document, **_kwargs):  # says done; what it wrote still holds the key
        with open(path, "ab") as fh:
            fh.write(b"# written\n")

    monkeypatch.setattr(backend, "write_config_document", kept_the_key)
    with pytest.raises(K.MoveError, match="config.yaml still holds the key after it was written; nothing was moved"):
        K.move_to_env(layout.home)
    assert {name: (layout.home / name).read_bytes() for name in before} == before
    assert _holding(layout.root) == ["profiles/work/config.yaml"]


def test_a_config_write_that_fails_says_so_and_the_env_file_keeps_the_key(tmp_path, monkeypatch):
    layout = _profile(tmp_path)
    import hermes_cli.config_backend as backend

    def refused(*_args, **_kwargs):
        raise PermissionError(13, "Permission denied", str(layout.home / "config.yaml"))

    monkeypatch.setattr(backend, "write_config_document", refused)
    with pytest.raises(K.MoveError) as failed:
        K.move_to_env(layout.home)
    assert str(failed.value) == ("config.yaml can't be written. Another program may have it open. The key is now in "
                                 ".env as well; move it again to finish.")
    assert _holding(layout.root) == ["profiles/work/.env", "profiles/work/config.yaml"]


def test_a_temp_file_a_killed_move_left_in_the_profile_is_removed_once_it_is_old(tmp_path):
    layout = _profile(tmp_path, {"model": {"provider": "openrouter", "default": "m"}})
    old, new = layout.home / ".keys-old1.tmp", layout.home / ".keys-new1.tmp"
    for path in (old, new):
        path.write_text(f"MODEL_API_KEY={KEY}\n", encoding="utf-8")
    long_ago = time.time() - 3600
    os.utime(old, (long_ago, long_ago))
    assert K.sweep(layout.home) == [".keys-old1.tmp"]
    assert not old.exists() and new.exists()  # one a move is writing right now is not touched
