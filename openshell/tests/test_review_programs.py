"""Programs the sandbox creates where this computer runs programs from (launcher/handback.py).

Hermes on this computer starts programs from a few folders of the profile by name or by a setting: ``bin``,
``lsp/bin``, ``node/bin`` and ``mcp-installs``. The sandbox writes those folders, so the switch-off review lists a
file that is new there and a revert moves it out. The same holds for a program a setting names that was not there
at switch-on. An MCP server install is one row, new or changed, and a revert moves it out whole. Everything runs
in temp folders; nothing starts a sandbox.
"""
import errno
import json
import os
import time
from pathlib import Path

import pytest

import test_handback as TH
from openshell.launcher import handback as H
from test_handback import box  # noqa: F401  (fixture: a profile home, the state folder, a folder outside)
from test_handback_wiring import _switched_on, cli  # noqa: F401  (fixture: `hermes -p work sandbox ...`)
from test_switch_flow import env  # noqa: F401  (the switch fixture)

PROGRAM = "#!/bin/sh\necho made in the sandbox\n"
NEW = ["bin/planted", "lsp/bin/pyright-langserver", "node/bin/node"]


@pytest.mark.parametrize("there", [False, True], ids=["the folder is new", "the folder had a program"])
def test_a_new_program_where_this_computer_runs_programs_from_is_a_row_and_a_revert_moves_it_out(box, there):  # noqa: F811
    home, state, _ = box
    own = [rel.rsplit("/", 1)[0] + "/the-users-own" for rel in NEW] if there else []
    for rel in own:
        TH.put(home / rel, "#!/bin/sh\necho mine\n")
    assert H.take_baseline(home, state)["taken"] is True
    before = TH.tree_bytes(home)
    for rel in NEW:
        TH.put(home / rel, PROGRAM)
    view = H.diff(home, state)
    rows = TH.by_id(view)
    assert sorted(rows) == [f"file:{rel}" for rel in NEW] and view["incomplete"] == []
    shown = {(row["kind"], row["label"], row["detail"]) for row in rows.values()}
    assert shown == {("file_new", "Program file", "new")}
    done = H.revert(home, state, "all")
    assert done["reverted"] == [f"file:{rel}" for rel in NEW] and done["left"] == []
    assert TH.tree_bytes(home) == before
    assert not there or all((home / rel).is_file() for rel in own)
    assert there or not any((home / rel.split("/")[0]).exists() for rel in NEW)  # the folders it came in are gone too
    held = TH.held_dirs(state)[0] / "files"
    assert all((held / rel).read_text() == PROGRAM for rel in NEW)  # the sandbox's programs are kept, host-only


def test_a_program_the_sandbox_changed_comes_back_from_its_copy(box):  # noqa: F811
    home, state, _ = box
    TH.put(home / "bin" / "tool", "#!/bin/sh\necho mine\n")
    TH.put(home / "lsp" / "bin" / "server", "#!/bin/sh\necho my server\n")
    assert H.take_baseline(home, state)["taken"] is True
    before = TH.tree_bytes(home)
    TH.put(home / "bin" / "tool", PROGRAM)
    (home / "lsp" / "bin" / "server").unlink()
    rows = TH.by_id(H.diff(home, state))
    assert {rel: (row["kind"], row["can_restore"]) for rel, row in rows.items()} == {
        "file:bin/tool": ("file_changed", True), "file:lsp/bin/server": ("file_removed", True)}
    assert H.revert(home, state, "all")["left"] == [] and TH.tree_bytes(home) == before


MINE = "mcp-installs/mine"


def _an_install(home, name: str = "mine") -> None:
    TH.put(home / "mcp-installs" / name / "index.js", "console.log('mine')\n")
    TH.put(home / "mcp-installs" / name / "lib" / "a.js", "module.exports = 1\n")


def _many_files(home, name: str, count: int) -> None:
    for n in range(count):
        folder = home / "mcp-installs" / name / "node_modules" / f"pkg{n // 100}"
        TH.put(folder / f"f{n % 100}.js", "module.exports = 1\n")


def _shown(view) -> list:
    return [(row["id"], row["kind"], row["label"], row["name"], row["detail"]) for row in view["rows"]]


def test_a_new_install_of_3000_files_is_one_row_and_a_revert_moves_the_folder_out_in_seconds(box):  # noqa: F811
    home, state, _ = box
    _an_install(home)
    assert H.take_baseline(home, state)["taken"] is True
    before = TH.tree_bytes(home)
    _many_files(home, "srv", 3000)
    started = time.monotonic()
    view = H.diff(home, state)
    done = H.revert(home, state, "all")
    assert time.monotonic() - started < 5
    assert _shown(view) == [("install:mcp-installs/srv", "install_new", "MCP install", "mcp-installs/srv",
                             "new, 3,000 files")]
    assert done["reverted"] == ["install:mcp-installs/srv"] and done["left"] == [] and "reinstall" not in done
    assert TH.tree_bytes(home) == before
    held = TH.held_dirs(state)[0] / "files" / "mcp-installs" / "srv"
    assert sum(1 for _ in held.rglob("*.js")) == 3000  # the sandbox's install is kept, host-only


def test_an_install_is_compared_by_name_size_and_time_and_its_files_are_not_read(box, monkeypatch):  # noqa: F811
    home, state, _ = box
    _an_install(home)
    read = H._read
    opened = []
    monkeypatch.setattr(H, "_read", lambda path, st, want: (opened.append(path), read(path, st, want))[1])
    assert H.take_baseline(home, state)["taken"] is True
    assert H.diff(home, state)["rows"] == []
    TH.put(home / "mcp-installs" / "mine" / "index.js", "console.log('changed in the sandbox')\n")
    assert _shown(H.diff(home, state)) == [(f"install:{MINE}", "install_changed", "MCP install", MINE,
                                            "changed: files differ in name, size or time")]
    TH.put(home / "mcp-installs" / "mine" / "lib" / "new.js", "module.exports = 2\n")
    view = H.diff(home, state)
    assert _shown(view) == [(f"install:{MINE}", "install_changed", "MCP install", MINE, "changed: 1 file more")]
    assert view["rows"][0]["can_restore"] is True and view["unanswered"] == 1
    assert not [path for path in opened if "mcp-installs" in path]
    recorded = json.loads((state / "handback" / "baseline.json").read_text(encoding="utf-8"))["manifest"]
    assert sorted(rel for rel in recorded if rel.startswith("mcp-installs")) == ["mcp-installs", MINE]


def test_a_changed_install_is_one_row_and_a_revert_takes_it_out_whole(box):  # noqa: F811
    home, state, _ = box
    _an_install(home)
    _an_install(home, "untouched")
    assert H.take_baseline(home, state)["taken"] is True
    TH.put(home / "mcp-installs" / "mine" / "index.js", "console.log('changed in the sandbox')\n")
    assert [row["id"] for row in H.diff(home, state)["rows"]] == [f"install:{MINE}"]
    done = H.revert(home, state, "all")
    assert done["reverted"] == [f"install:{MINE}"] and done["left"] == [] and "unreverted" not in done
    assert done["reinstall"] == [MINE]  # the profile had it: the server has to be installed again
    assert not (home / "mcp-installs" / "mine").exists()  # never left for this computer to run
    assert (home / "mcp-installs" / "untouched" / "index.js").is_file()
    held = TH.held_dirs(state)[0] / "files" / "mcp-installs" / "mine"
    assert (held / "index.js").read_text() == "console.log('changed in the sandbox')\n"
    assert (held / "lib" / "a.js").is_file()  # the whole install is kept, host-only


def test_keep_leaves_a_new_and_a_changed_install_where_they_are(box):  # noqa: F811
    home, state, _ = box
    _an_install(home)
    assert H.take_baseline(home, state)["taken"] is True
    TH.put(home / "mcp-installs" / "mine" / "index.js", "console.log('changed in the sandbox')\n")
    _many_files(home, "srv", 3)
    ids = [f"install:{MINE}", "install:mcp-installs/srv"]
    assert H.keep(home, state, "all")["kept"] == ids
    after = TH.tree_bytes(home)
    done = H.revert(home, state, "unanswered")
    assert done["reverted"] == [] and "reinstall" not in done and TH.tree_bytes(home) == after
    assert [row["answer"] for row in H.diff(home, state)["rows"]] == ["keep", "keep"]
    H.remember_kept(home, state, ids)
    assert [item["id"] for item in H.kept(home, state)] == ids
    TH.put(home / "mcp-installs" / "srv" / "later.js", "module.exports = 3\n")
    assert [item["id"] for item in H.kept(home, state)] == [ids[0]]  # what changed after the keep is not the kept one


def test_two_installs_are_two_rows_and_a_file_at_the_top_is_one(box):  # noqa: F811
    home, state = TH.taken(box)
    _many_files(home, "one", 2)
    _many_files(home, "two", 1)
    TH.put(home / "mcp-installs" / "registry.json", "{}\n")
    assert _shown(H.diff(home, state)) == [
        ("install:mcp-installs/one", "install_new", "MCP install", "mcp-installs/one", "new, 2 files"),
        ("install:mcp-installs/registry.json", "install_new", "MCP install", "mcp-installs/registry.json", "new"),
        ("install:mcp-installs/two", "install_new", "MCP install", "mcp-installs/two", "new, 1 file")]
    assert len(H.revert(home, state, "all")["reverted"]) == 3 and not (home / "mcp-installs").exists()


def test_an_install_that_is_gone_is_a_row_that_a_revert_cannot_bring_back(box):  # noqa: F811
    home, state, _ = box
    _an_install(home)
    assert H.take_baseline(home, state)["taken"] is True
    for path in sorted((home / "mcp-installs" / "mine").rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    (home / "mcp-installs" / "mine").rmdir()
    view = H.diff(home, state)
    assert _shown(view) == [(f"install:{MINE}", "install_removed", "MCP install", MINE, "removed")]
    assert view["rows"][0]["can_restore"] is False
    done = H.revert(home, state, "all")
    assert done["reverted"] == [] and done["left"] == []
    assert done["skipped"] == [{"id": f"install:{MINE}", "reason": "no copy to restore"}]


def test_a_program_a_setting_names_inside_a_changed_install_is_no_second_row(box):  # noqa: F811
    home, state, _ = box
    _an_install(home)
    TH.edit_config(home, lambda doc: doc["mcp_servers"].update(named={"command": "node", "args": [f"{MINE}/index.js"]}))
    assert H.take_baseline(home, state)["taken"] is True
    TH.put(home / "mcp-installs" / "mine" / "index.js", "console.log('changed in the sandbox')\n")
    assert [row["id"] for row in H.diff(home, state)["rows"]] == [f"install:{MINE}"]
    assert H.revert(home, state, "all")["reinstall"] == [MINE] and not (home / "mcp-installs" / "mine").exists()


def test_a_large_install_is_no_row_by_itself_and_a_new_one_beside_it_is_seen(box, monkeypatch):  # noqa: F811
    home, state, _ = box
    _many_files(home, "large", 60)
    monkeypatch.setattr(H, "MAX_ENTRIES", 40)
    assert H.take_baseline(home, state)["incomplete"] == ["mcp-installs/large"]
    view = H.diff(home, state)
    assert view["rows"] == [] and view["incomplete"] == ["mcp-installs/large"]
    _many_files(home, "zzz", 2)
    assert [row["id"] for row in H.diff(home, state)["rows"]] == ["install:mcp-installs/zzz"]


def test_an_install_is_moved_out_when_the_held_folder_is_on_another_volume(box, monkeypatch):  # noqa: F811
    home, state, _ = box
    _an_install(home)
    assert H.take_baseline(home, state)["taken"] is True
    TH.put(home / "mcp-installs" / "mine" / "index.js", "console.log('changed in the sandbox')\n")
    replace = H._replace

    def across_volumes(src, dst):
        if os.path.isdir(src):
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return replace(src, dst)

    monkeypatch.setattr(H, "_replace", across_volumes)
    monkeypatch.setattr(os, "rename", lambda *a, **kw: (_ for _ in ()).throw(OSError(errno.EXDEV, "cross-device")))
    done = H.revert(home, state, "all")
    assert done["reverted"] == [f"install:{MINE}"] and done["left"] == []
    assert not (home / "mcp-installs" / "mine").exists()
    assert (TH.held_dirs(state)[0] / "files" / "mcp-installs" / "mine" / "lib" / "a.js").is_file()


@pytest.mark.parametrize("named", ["{home}/mcp-bin/the-server", "$HERMES_HOME/mcp-bin/the-server", "mcp-bin/the-server"])
def test_a_program_a_setting_names_that_appears_during_the_session_is_a_row(box, named):  # noqa: F811
    home, state, _ = box
    command = named.format(home=Path(os.path.realpath(home)).as_posix())
    TH.edit_config(home, lambda doc: doc["mcp_servers"].update(named={"command": command, "args": []}))
    TH.edit_config(home, lambda doc: doc.update(browser={"executable_path": "tools/browser/chrome"}))
    assert H.take_baseline(home, state)["taken"] is True
    settings = (home / "config.yaml").read_bytes()
    assert H.diff(home, state)["rows"] == []
    TH.put(home / "mcp-bin" / "the-server", PROGRAM)
    TH.put(home / "tools" / "browser" / "chrome", PROGRAM)
    rows = TH.by_id(H.diff(home, state))
    assert sorted(rows) == ["file:mcp-bin/the-server", "file:tools/browser/chrome"]
    assert {(row["kind"], row["label"]) for row in rows.values()} == {("file_new", "Program file")}
    done = H.revert(home, state, "all")
    assert done["reverted"] == sorted(rows) and done["left"] == []
    assert not (home / "mcp-bin").exists() and not (home / "tools" / "browser").exists()
    assert (home / "config.yaml").read_bytes() == settings  # the entries that name them are as they were
    assert (home / "tools" / "server.js").is_file()


def test_a_record_that_does_not_cover_the_program_folders_lists_nothing_of_the_users_there(box):  # noqa: F811
    home, state, _ = box
    TH.put(home / "bin" / "the-users-own", "#!/bin/sh\necho mine\n")
    TH.put(home / "mcp-installs" / "mine" / "index.js", "console.log('mine')\n")
    assert H.take_baseline(home, state)["taken"] is True
    record = state / "handback" / "baseline.json"
    without = json.loads(record.read_text(encoding="utf-8"))
    del without["trees"]
    without["manifest"] = {rel: entry for rel, entry in without["manifest"].items()
                           if H._tree_of(rel) not in H.PROGRAM_TREES}
    record.write_text(json.dumps(without), encoding="utf-8")
    TH.put(home / "bin" / "planted", PROGRAM)
    TH.put(home / "scripts" / "planted.sh", PROGRAM)
    view = H.diff(home, state)
    assert [row["id"] for row in view["rows"]] == ["file:scripts/planted.sh"]
    assert view["incomplete"] == ["bin", "lsp/bin", "mcp-installs", "node/bin"]
    H.revert(home, state, "all")
    assert (home / "bin" / "the-users-own").is_file() and (home / "bin" / "planted").is_file()
    H.close(state)
    assert H.take_baseline(home, state)["taken"] is True  # the next switch-on covers the folders
    TH.put(home / "bin" / "second", PROGRAM)
    view = H.diff(home, state)
    assert [row["id"] for row in view["rows"]] == ["file:bin/second"] and view["incomplete"] == []


def test_a_revert_without_a_list_moves_new_programs_out_too(box):  # noqa: F811
    home, state, _ = box
    TH.edit_config(home, lambda doc: doc["mcp_servers"].update(named={"command": "mcp-bin/the-server"}))
    assert H.take_baseline(home, state)["taken"] is True
    before = TH.tree_bytes(home)
    for rel in (*NEW, "mcp-bin/the-server", "mcp-installs/planted/server.py"):
        TH.put(home / rel, PROGRAM)
    done = H.revert_from_copies(home, state)
    files = sorted(f"file:{rel}" for rel in (*NEW, "mcp-bin/the-server"))
    assert done["reverted"] == [*files, "install:mcp-installs/planted"] and done["left"] == []
    assert TH.tree_bytes(home) == before


def test_settings_with_very_many_names_cost_no_more_than_their_length(box):  # noqa: F811
    home, state, _ = box
    hostile = ("'\"\\[{(/ " * 30000)[:200_000]
    names = {f"n{n:05d}": {"command": f"made/up/{n}/program --flag '{n}"} for n in range(4000)}
    TH.edit_config(home, lambda doc: doc.update(mcp_servers={**doc["mcp_servers"], **names},
                                                browser={"executable_path": hostile}))
    started = time.monotonic()
    assert H.take_baseline(home, state)["taken"] is True
    TH.put(home / "made" / "up" / "7" / "program", PROGRAM)
    rows = [row["id"] for row in H.diff(home, state)["rows"]]
    assert time.monotonic() - started < 5
    assert rows == ["file:made/up/7/program"]


def test_sandbox_off_lists_a_new_program_and_revert_moves_it_out(env, cli, capsys):  # noqa: F811
    lay = _switched_on(env)
    env["markers"].marked.add("work")
    TH.put(lay.home / "bin" / "planted", PROGRAM)
    assert cli("off") == 3
    assert capsys.readouterr().out == ("Changed in the sandbox (profile work)\n"
                                       "  1  Program file  bin/planted  new\n")
    assert (lay.home / "bin" / "planted").is_file() and "work" in env["markers"].marked
    assert cli("off", "--revert") == 0
    assert not (lay.home / "bin").exists() and "work" not in env["markers"].marked


def test_sandbox_off_revert_moves_a_changed_install_out_and_says_to_install_the_server_again(env, cli, capsys):  # noqa: F811
    _an_install(env["layout"].home)
    lay = _switched_on(env)
    env["markers"].marked.add("work")
    TH.put(lay.home / "mcp-installs" / "mine" / "index.js", "console.log('changed in the sandbox')\n")
    assert cli("off") == 3
    assert capsys.readouterr().out == (
        "Changed in the sandbox (profile work)\n"
        "  1  MCP install  mcp-installs/mine  changed: files differ in name, size or time\n")
    assert cli("off", "--revert") == 0
    err = capsys.readouterr().err
    assert "Reverted 1 change." in err and err.endswith(
        "hermes sandbox: The sandbox changed the MCP server install mine, so it was moved out: install that server "
        "again.\n")
    assert not (lay.home / "mcp-installs" / "mine").exists() and "work" not in env["markers"].marked
