"""Copies of the keys file and of the sign-in file are hidden from the sandbox, whoever made them
(launcher/layout.py, launcher/supervisor.py). Every key here is made up."""
import asyncio
import os
import time

import pytest
from test_private_entry_while_on import _home, _listed, _supervisor

from openshell.launcher import layout as L

COPIES = [".env.save", ".env.swp", "..env.swp", ".env~", ".env.orig", ".env.old", ".env.tmp", ".env.backup",
          ".env (copy)", ".env.local", ".env.1", "#.env#", ".#.env", "~.env", ".env_k3j2x1.tmp", ".keys-ab12.tmp",
          ".op.env.bak", ".op.env~", "auth.json~", ".auth.json.swp", "auth.json.bak", ".ENV.SAVE", "AUTH.JSON~",
          ".env.bak-20261125T101500Z"]
OTHER_FILES = [".envoy", ".environment", "env.txt", "env.bak", ".env.lock", "auth.lock", "auth.bak",
               "auth - Copy.json", "config.yaml.bak", "config.yaml~", "notes.txt", "SOUL.md"]


@pytest.mark.parametrize("name", COPIES)
def test_a_copy_of_a_key_file_is_hidden_by_the_start_that_finds_it(tmp_path, name):
    home = _home(tmp_path)
    (home / name).write_text("MADE_UP_KEY=made-up\n", encoding="utf-8")
    assert home / name in L.credential_paths(home)
    assert L.new_private_entries(home, _listed(home)) == []


@pytest.mark.parametrize("name", OTHER_FILES)
def test_a_file_that_only_looks_like_one_stays_visible(tmp_path, name):
    home = _home(tmp_path)
    listed = _listed(home)
    (home / name).write_text("x", encoding="utf-8")
    assert home / name not in L.credential_paths(home)
    assert L.new_private_entries(home, listed) == []


@pytest.mark.parametrize("name", [".env.save", ".env.swp", ".env~", ".op.env.bak", "auth.json~"])
def test_a_copy_made_while_the_sandbox_is_on_is_found(tmp_path, name):
    home = _home(tmp_path)
    listed = _listed(home)
    (home / name).write_text("MADE_UP_KEY=made-up\n", encoding="utf-8")
    assert L.new_private_entries(home, listed) == [name]


def test_a_temp_file_of_a_write_under_way_is_found_once_it_stays(tmp_path):
    home = _home(tmp_path)
    listed = _listed(home)
    for name in (".env_k3j2x1.tmp", ".keys-ab12.tmp"):
        (home / name).write_text("MADE_UP_KEY=made-up\n", encoding="utf-8")
    assert L.new_private_entries(home, listed) == []
    old = time.time() - 4 * L.TEMP_GRACE
    os.utime(home / ".env_k3j2x1.tmp", (old, old))
    assert L.new_private_entries(home, listed) == [".env_k3j2x1.tmp"]


@pytest.mark.skipif(os.name == "nt", reason="on Windows two names that differ only in case are one file")
def test_a_name_in_another_case_is_another_file(tmp_path):
    home = _home(tmp_path)
    listed = _listed(home)
    (home / ".ENV").write_text("MADE_UP_KEY=made-up\n", encoding="utf-8")
    if (home / ".env").samefile(home / ".ENV"):
        pytest.skip("this folder's file system folds case")
    (home / "Auth.JSON").write_text("{}", encoding="utf-8")
    assert L.new_private_entries(home, listed) == [".ENV", "Auth.JSON"]
    assert L.new_private_entries(home, listed | L.listed_names(home, [home / ".ENV", home / "Auth.JSON"])) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows compares file names without regard to case")
def test_on_windows_a_listed_name_in_another_case_is_the_same_file(tmp_path):
    home = _home(tmp_path)
    named = [home / ".ENV.Save", home / "cache" / "below.json", tmp_path / "elsewhere"]
    assert L.listed_names(home, named) == {".env.save"}
    listed = _listed(home)
    (home / "AUTH.JSON").write_text("{}", encoding="utf-8")  # auth.json is on every start's list
    assert L.new_private_entries(home, listed) == []


def test_an_editors_copy_restarts_the_sandbox_once_with_it_listed(tmp_path, monkeypatch):
    sup, home, starts = _supervisor(tmp_path, monkeypatch)

    async def main():
        await sup.start()
        (home / ".env.save").write_bytes((home / ".env").read_bytes())
        assert await sup.hide_new_private() == [".env.save"]
        assert await sup.hide_new_private() == []

    asyncio.run(main())
    assert starts == [[".env"], [".env", ".env.save"]] and sup.state == "running"
