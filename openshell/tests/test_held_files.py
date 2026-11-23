"""The Linux driver keeps a profile's top-level credential files in one folder that is mounted over as a whole
(launcher/held.py), instead of hiding each behind a mount on its own name.

Why: a mount on a name is gone as soon as a process on this computer replaces the file by rename, and Hermes
writes ``.env`` and ``auth.json`` exactly that way (a temp file beside the target, then a rename). The file, and
the temp file before it, were then readable inside the running sandbox until its next restart. These tests drive
the real driver, pins and hand-back code over a real folder; the "host writers" are Hermes's own write helpers.

Most of them need to make a link, which needs a privilege on Windows; the driver that does this runs Linux
sandboxes only (Windows hides by path).
"""
import asyncio
import json
import os
import stat
from pathlib import Path

import pytest

import test_openshell_driver as LD
from openshell.launcher import handback as H
from openshell.launcher import held
from openshell.launcher import layout as L
from openshell.launcher import openshell_driver as OD
from openshell.launcher import pins as P
from openshell.launcher import supervisor as S
from openshell.launcher import switch as SW
from openshell.launcher.driver import DriverUnavailable, LaunchRequest

posix = pytest.mark.skipif(os.name == "nt", reason="making a link needs a privilege on Windows; the driver that "
                                                   "keeps files this way runs Linux sandboxes only")
NEW = "sk-new-" + "n" * 24


def _take_out(layout):
    return lambda path: held.quarantine(layout.state_dir, path)


def _top(home: Path) -> dict:
    """Every entry at the top of the home: name -> 'link' | 'dir' | 'file'."""
    return {p.name: "link" if p.is_symlink() else "dir" if p.is_dir() else "file" for p in home.iterdir()}


def _core_write_env(path: Path, text: str) -> None:
    """Hermes's own ``.env`` write (hermes_cli.config._write_env_lines): a temp file beside the file the name
    resolves to, then ``atomic_replace`` onto it."""
    from utils.files import atomic_replace, mkstemp_beside

    fd, tmp = mkstemp_beside(path, suffix=".tmp", prefix=".env_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    atomic_replace(tmp, path)


def _core_write_json(path: Path, doc: dict) -> None:
    """Hermes's own store write (auth.json, the secret caches): ``utils.atomic_json_write``."""
    from utils import atomic_json_write

    atomic_json_write(path, doc, mode=0o600)


def _request(layout, tmp_path, folders=()):
    grants = L.profile_grants(layout, LD._runtime(tmp_path), list(folders))
    return LaunchRequest(sandbox_id="x", argv=[], cwd=tmp_path, env={}, grants=grants, network={},
                         log_path=tmp_path / "l", config_dir=layout.state_dir, home=layout.home, folders=list(folders))


def _names(layout, tmp_path) -> list[str]:
    return [Path(p).name for p in _request(layout, tmp_path).grants.denied if Path(p).parent == layout.home]


# -- the layout itself -------------------------------------------------------------------------------

def test_a_plain_home_is_untouched_by_every_helper(tmp_path):
    """Windows, and Linux while no sandbox runs: nothing is held, and every helper answers for the plain file."""
    layout = LD._layout(tmp_path)
    env = layout.home / ".env"
    before = _top(layout.home)
    assert not held.active(layout.home) and not held.is_link(env)
    assert held.source(env) == env and held.destination(env) == env and held.displaced(env) == env
    assert held.displaced(layout.home / ".op.env") is None
    assert held.relink(env) is False and held.guard(layout.home, _take_out(layout)) == []
    assert held.release(layout.home, _take_out(layout)) == {"restored": [], "taken_out": []}
    assert _top(layout.home) == before and env.read_text().startswith("LLAMA_API_KEY=")
    assert not (layout.state_dir / "quarantine").exists()


@posix
def test_hold_moves_the_files_into_one_folder_and_leaves_links_that_read_the_same(tmp_path):
    layout = LD._layout(tmp_path)
    (layout.home / "honcho.json").write_text('{"apiKey": "h"}', encoding="utf-8")
    (layout.home / "mcp-tokens").mkdir()  # a credential folder: hidden by its own mount, never moved
    env_bytes, mode = (layout.home / ".env").read_bytes(), stat.S_IMODE((layout.home / ".env").stat().st_mode)
    linked = held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    assert set(linked) == {".env", "auth.json", ".op.env", "honcho.json"}
    folder = held.folder(layout.home)
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    # The files, and the launcher's own record of the names it linked (what the guard watches).
    assert sorted(p.name for p in folder.iterdir()) == [".env", ".linked.json", "auth.json", "honcho.json"]
    assert sorted(json.loads((folder / ".linked.json").read_text())) == sorted(linked)
    top = _top(layout.home)
    assert top[".env"] == top["auth.json"] == top["honcho.json"] == top[".op.env"] == "link"
    assert top["mcp-tokens"] == "dir"
    for name in linked:
        assert os.readlink(layout.home / name) == f"{held.DIRNAME}/{name}"  # relative: resolves wherever the home is
    # Readers on this computer follow the link; the file kept its bytes and its mode.
    assert (layout.home / ".env").read_bytes() == env_bytes
    assert stat.S_IMODE((folder / ".env").stat().st_mode) == mode
    # A held name with nothing behind it reads as absent, as before.
    assert not (layout.home / ".op.env").exists() and held.displaced(layout.home / ".op.env") is None
    assert held.source(layout.home / ".env") == folder / ".env"


@posix
def test_hermes_own_writers_never_put_a_readable_file_under_a_held_name(tmp_path):
    """The reported exposure. Before: the save renamed a new file over ``.env`` and staged its temp file beside
    it, both readable inside. Now both land in the held folder; the name stays the launcher's link."""
    layout = LD._layout(tmp_path)
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    folder, before = held.folder(layout.home), _top(layout.home)
    seen: list = []
    real_replace = os.replace

    def watching_replace(src, dst):  # what is at the top of the home at the moment of the rename
        seen.append(sorted(set(_top(layout.home)) - set(before)))
        return real_replace(src, dst)

    os.replace = watching_replace
    try:
        _core_write_env(layout.home / ".env", f"LLAMA_API_KEY={NEW}\n")
        _core_write_json(layout.home / "auth.json", {"providers": {"x": {"refresh": NEW}}})
    finally:
        os.replace = real_replace
    assert seen == [[], []], "a temp file was staged at the top of the home, where the sandbox reads"
    assert _top(layout.home) == before and held.is_link(layout.home / ".env") and held.is_link(layout.home / "auth.json")
    assert NEW in (folder / ".env").read_text() and NEW in (folder / "auth.json").read_text()
    assert (layout.home / ".env").read_text() == f"LLAMA_API_KEY={NEW}\n"  # a reader on this computer sees the save


@posix
def test_a_first_key_saved_while_the_sandbox_runs_is_created_inside_the_folder(tmp_path):
    layout = LD._layout(tmp_path)
    (layout.home / ".env").unlink()
    (layout.home / "auth.json").unlink()
    assert set(held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))) == set(held.ALWAYS)
    before = _top(layout.home)
    assert before[".env"] == "link" and not (layout.home / ".env").exists()
    _core_write_env(layout.home / ".env", f"FIRST_KEY={NEW}\n")
    _core_write_json(layout.home / "auth.json", {"first": NEW})
    assert _top(layout.home) == before and held.is_link(layout.home / ".env")
    assert (held.folder(layout.home) / ".env").read_text() == f"FIRST_KEY={NEW}\n"
    done = held.release(layout.home, _take_out(layout))
    assert sorted(done["restored"]) == [".env", "auth.json"] and done["taken_out"] == []
    top = _top(layout.home)
    assert top[".env"] == top["auth.json"] == "file" and ".op.env" not in top and held.DIRNAME not in top
    assert (layout.home / ".env").read_text() == f"FIRST_KEY={NEW}\n"


@posix
def test_release_puts_every_file_back_and_takes_out_what_replaced_a_link(tmp_path):
    layout = LD._layout(tmp_path)
    original = (layout.home / ".env").read_bytes()
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    os.unlink(layout.home / ".env")  # as the sandbox can: the link is an entry of a folder it writes
    (layout.home / ".env").write_text("PLANTED=1\n", encoding="utf-8")
    done = held.release(layout.home, _take_out(layout))
    assert done == {"restored": [".env", "auth.json"], "taken_out": [".env"]}
    top = _top(layout.home)
    assert top[".env"] == top["auth.json"] == "file" and held.DIRNAME not in top and ".op.env" not in top
    assert (layout.home / ".env").read_bytes() == original  # the file only this computer wrote
    (moved,) = (layout.state_dir / "quarantine").glob("*/.env")
    assert moved.read_text() == "PLANTED=1\n"
    assert held.release(layout.home, _take_out(layout)) == {"restored": [], "taken_out": []}  # nothing left to do


@posix
@pytest.mark.parametrize("plant", ["file", "link", "dir", "gone"])
def test_the_guard_takes_out_whatever_stands_under_a_held_name_and_puts_the_link_back(tmp_path, plant):
    layout = LD._layout(tmp_path)
    original = (layout.home / ".env").read_bytes()
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    assert held.guard(layout.home, _take_out(layout)) == []  # nothing replaced: nothing done
    name = layout.home / ".env"
    os.unlink(name)
    if plant == "file":
        name.write_text("PLANTED=1\n", encoding="utf-8")
    elif plant == "link":
        os.symlink("config.yaml", name)  # a link of the sandbox's own: a writer that followed it would write there
    elif plant == "dir":
        name.mkdir()
    assert held.guard(layout.home, _take_out(layout)) == [".env"]
    assert held.is_link(name) and name.read_bytes() == original
    assert len(list((layout.state_dir / "quarantine").glob("*/.env"))) == (0 if plant == "gone" else 1)
    assert (layout.home / "config.yaml").read_text().startswith("model:")  # the link's target was never written
    assert held.guard(layout.home, _take_out(layout)) == []


@posix
def test_a_name_with_nothing_behind_it_is_guarded_too_and_a_link_of_the_users_own_is_left_alone(tmp_path):
    layout = LD._layout(tmp_path)
    own = tmp_path / "dotfiles" / "auth.json"
    own.parent.mkdir()
    own.write_text('{"mine": true}', encoding="utf-8")
    (layout.home / "auth.json").unlink()
    os.symlink(own, layout.home / "auth.json")  # the user's own arrangement: not a file the launcher can hold
    linked = held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    assert "auth.json" not in linked and ".op.env" in linked
    (layout.home / ".op.env").unlink()  # the launcher's link for a file that does not exist yet
    (layout.home / ".op.env").write_text("PLANTED=1\n", encoding="utf-8")
    assert held.guard(layout.home, _take_out(layout)) == [".op.env"]
    assert held.is_link(layout.home / ".op.env") and not (layout.home / ".op.env").exists()
    assert os.readlink(layout.home / "auth.json") == str(own)  # never taken out, never replaced
    assert [p.name for p in (layout.state_dir / "quarantine").glob("*/*")] == [".op.env"]
    held.release(layout.home, _take_out(layout))
    assert os.readlink(layout.home / "auth.json") == str(own) and held.DIRNAME not in _top(layout.home)


def test_the_watch_looks_several_times_a_second():
    """What stands under a held name without being the link is readable inside until the next look."""
    assert S.WATCH_INTERVAL <= 0.25 and S.GUARD_LIMIT == 3 and S.GUARD_WINDOW >= 60


@posix
def test_hold_settles_what_a_killed_launcher_left_and_refuses_a_folder_that_is_not_its_own(tmp_path):
    layout = LD._layout(tmp_path)
    names = _names(layout, tmp_path)
    held.hold(layout.home, names, _take_out(layout))
    _core_write_env(layout.home / ".env", f"LLAMA_API_KEY={NEW}\n")  # written on this computer meanwhile
    held.hold(layout.home, names, _take_out(layout))  # the next start: no second folder, nothing lost
    assert (held.folder(layout.home) / ".env").read_text() == f"LLAMA_API_KEY={NEW}\n"
    assert not (layout.state_dir / "quarantine").exists()
    held.release(layout.home, _take_out(layout))
    held.folder(layout.home).write_text("not a folder", encoding="utf-8")
    with pytest.raises(held.HeldError):
        held.hold(layout.home, names, _take_out(layout))
    assert _top(layout.home)[".env"] == "file"  # refused before anything was moved


# -- the driver --------------------------------------------------------------------------------------

@posix
def test_the_mount_plan_covers_the_folder_and_puts_no_mount_on_a_held_name(tmp_path):
    layout, folders = LD._layout(tmp_path), LD._folders(tmp_path)
    (layout.home / "honcho.json").write_text('{"apiKey": "h"}', encoding="utf-8")
    (layout.home / "mcp-tokens").mkdir()
    req = _request(layout, tmp_path, folders)
    held.hold(layout.home, [Path(p).name for p in req.grants.denied if Path(p).parent == layout.home], _take_out(layout))
    plan = OD.plan_mounts(req, OD.ensure_masks(layout.state_dir))
    by_target = {m["target"]: m for m in plan.mounts}
    for name in (".env", "auth.json", ".op.env", "honcho.json"):
        assert str(layout.home / name) not in by_target, f"a mount on {name}: a rename on this computer removes it"
        assert str(layout.home / name) in plan.held
        assert str(layout.home / name) not in plan.unmasked_absent and str(layout.home / name) not in plan.masked
    over = by_target[str(held.folder(layout.home))]
    assert over["read_only"] is True and str(held.folder(layout.home)) in plan.masked
    stand = Path(over["source"])
    assert layout.state_dir in stand.parents and stand != held.folder(layout.home)
    # What the sandbox sees through each link: what the mask on the name showed before (empty, {} for a store).
    assert sorted(p.name for p in stand.iterdir()) == [".env", "auth.json", "honcho.json"]
    assert (stand / ".env").read_text() == "" and (stand / "auth.json").read_text().strip() == "{}"
    assert LD.SECRET not in "".join(p.read_text() for p in stand.iterdir())
    # Credential folders are hidden as before, by a mount on the folder itself.
    assert by_target[str(layout.home / "mcp-tokens")]["read_only"] is True


@posix
def test_the_driver_holds_at_start_and_puts_the_files_back_at_stop(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    env_before = (layout.home / ".env").read_bytes()

    async def scenario():
        await sup.start()
        try:
            (spec,) = [c[2] for c in api.calls if c[0] == "create"]
            targets = {m["target"] for m in spec["template"]["driver_config"]["docker"]["mounts"]}
            assert str(layout.home / ".env") not in targets and str(layout.home / "auth.json") not in targets
            assert str(held.folder(layout.home)) in targets
            assert held.is_link(layout.home / ".env") and held.is_link(layout.home / "auth.json")
            view = sup.policy()["enforced"]
            assert str(layout.home / ".env") in view["credential_held"]
            # A key saved on this computer while the sandbox runs: inside the folder, the name still the link.
            _core_write_env(layout.home / ".env", env_before.decode() + f"SAVED_WHILE_ON={NEW}\n")
            assert held.is_link(layout.home / ".env") and await sup.guard() == []
        finally:
            await sup.stop()

    asyncio.run(scenario())
    top = _top(layout.home)
    assert top[".env"] == top["auth.json"] == "file" and held.DIRNAME not in top and ".op.env" not in top
    assert (layout.home / ".env").read_text().endswith(f"SAVED_WHILE_ON={NEW}\n")


@posix
def test_a_sandbox_that_could_not_be_removed_keeps_the_files_out_of_its_reach(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()

        def refuse(name, timeout):
            raise RuntimeError("gateway unavailable")

        monkeypatch.setattr(api, "delete_sandbox", refuse)
        await sup.stop()

    asyncio.run(scenario())
    assert sup.driver.sandbox_gone() is False
    assert held.is_link(layout.home / ".env") and held.active(layout.home), "put back under a sandbox that may run"
    # The switch-off's own release is told the same and leaves them too; once it is gone they come back.
    P.release(layout, unhold=sup.driver.sandbox_gone())
    assert held.is_link(layout.home / ".env")
    P.take(layout)  # the next switch-on (it stops a leftover sandbox first)
    assert _top(layout.home)[".env"] == "file" and held.DIRNAME not in _top(layout.home)


@posix
def test_a_home_that_cannot_take_the_layout_refuses_the_start(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    held.folder(layout.home).write_text("in the way", encoding="utf-8")

    async def scenario():
        with pytest.raises(DriverUnavailable, match="out of the sandbox's reach"):
            await sup.start()

    asyncio.run(scenario())
    assert not any(c[0] == "create" for c in api.calls)  # no sandbox was created over readable key files


@posix
def test_the_supervisor_stops_a_sandbox_whose_credential_names_keep_being_replaced(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        for n in range(S.GUARD_LIMIT):
            os.unlink(layout.home / ".env")
            (layout.home / ".env").write_text(f"PLANTED={n}\n", encoding="utf-8")
            assert sup.state == "running"
            assert await sup.guard() == [".env"]
        return sup.status()

    status = asyncio.run(scenario())
    assert status["state"] == "failed" and ".env" in status["error"] and "kept being replaced" in status["error"]
    assert ("delete", "hermes-work") in api.calls
    assert _top(layout.home)[".env"] == "file" and "PLANTED" not in (layout.home / ".env").read_text()
    assert len(list((layout.state_dir / "quarantine").glob("*/.env*"))) == S.GUARD_LIMIT


@posix
def test_one_replaced_name_is_put_right_and_the_sandbox_keeps_running(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        try:
            os.unlink(layout.home / "auth.json")
            (layout.home / "auth.json").write_text('{"planted": true}', encoding="utf-8")
            assert await sup.guard() == ["auth.json"] and sup.state == "running"
            assert held.is_link(layout.home / "auth.json") and (layout.home / "auth.json").read_text() == "{}"
        finally:
            await sup.stop()

    asyncio.run(scenario())


# -- the pins and the hand-back see the file, not where it is ------------------------------------------

@posix
def test_the_pins_read_and_write_the_held_file_and_never_put_a_key_file_under_the_name(tmp_path):
    layout = LD._layout(tmp_path)
    P.take(layout)
    pinned = (layout.home / ".env").read_bytes()
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    assert P.restore_env(layout) == [] and P.restore_stores(layout) == []  # the link is the pinned file: no change
    assert not (layout.state_dir / "quarantine").exists()
    # A key written through the launcher's route (Hermes's writer), then the pin follows it.
    _core_write_env(layout.home / ".env", pinned.decode() + f"ROUTE_KEY={NEW}\n")
    assert P.update_env(layout) is True
    assert P.env_values(layout)["ROUTE_KEY"] == NEW and P.restore_env(layout) == []
    # A change that is not the pin's (an edit by hand, a `hermes config set` in a terminal) is put back as
    # before: its version goes to quarantine and the pinned file is written into the folder, not under the name.
    _core_write_env(layout.home / ".env", "EDITED=1\n")
    assert P.restore_env(layout) == [".env"]
    assert held.is_link(layout.home / ".env") and _top(layout.home)[".env"] == "link"
    assert (held.folder(layout.home) / ".env").read_bytes() == pinned + f"ROUTE_KEY={NEW}\n".encode()
    (moved,) = (layout.state_dir / "quarantine").glob("*/.env")
    assert moved.read_text() == "EDITED=1\n"


@posix
def test_what_the_sandbox_puts_under_a_held_name_is_never_pinned_followed_or_read(tmp_path):
    layout = LD._layout(tmp_path)
    P.take(layout)
    auth = (layout.home / "auth.json").read_bytes()
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    os.unlink(layout.home / "auth.json")
    (layout.home / "auth.json").write_text('{"planted": true}', encoding="utf-8")
    os.unlink(layout.home / ".env")
    (layout.home / ".env").write_text("PLANTED=1\n", encoding="utf-8")
    # The look before the list is made moves nothing and follows nothing that is not behind the link.
    assert P.restore_stores(layout, replaceable=False, follow_only=True) == []
    assert (P.pin_dir(layout) / "auth.json").read_bytes() == auth
    assert (layout.home / "auth.json").read_text() == '{"planted": true}'
    # Every other entry settles first: the planted files go to quarantine, the links come back.
    assert P.update_env(layout) is True and "PLANTED" not in json.dumps(P.env_values(layout))
    assert P.restore_stores(layout, replaceable=False) == []
    assert held.is_link(layout.home / "auth.json") and held.is_link(layout.home / ".env")
    assert (layout.home / "auth.json").read_bytes() == auth and (P.pin_dir(layout) / "auth.json").read_bytes() == auth
    assert sorted(p.name for p in (layout.state_dir / "quarantine").glob("*/*")) == [".env", "auth.json"]


@posix
def test_a_planted_name_never_costs_the_file_behind_the_link(tmp_path):
    """The pins settle the layout before they compare: what stands under the name goes to quarantine, and the
    file this computer wrote through the link is then judged on its own (here: not the pinned one, so it goes to
    quarantine too and the pinned copy is written into the folder). Neither version is lost."""
    layout = LD._layout(tmp_path)
    P.take(layout)
    pinned = (layout.home / ".env").read_bytes()
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    _core_write_env(layout.home / ".env", "HOST_EDIT=1\n")
    os.unlink(layout.home / ".env")
    (layout.home / ".env").write_text("PLANTED=1\n", encoding="utf-8")
    assert P.restore_env(layout) == [".env"]
    assert sorted(p.read_text() for p in (layout.state_dir / "quarantine").glob("*/.env*")) == ["HOST_EDIT=1\n", "PLANTED=1\n"]
    assert held.is_link(layout.home / ".env") and (held.folder(layout.home) / ".env").read_bytes() == pinned


@posix
def test_a_sign_in_written_on_this_computer_through_the_link_is_followed_by_the_pin(tmp_path):
    layout = LD._layout(tmp_path)
    P.take(layout)
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    _core_write_json(layout.home / "auth.json", {"providers": {"nous": {"refresh": NEW}}})
    assert P.restore_stores(layout, replaceable=False) == []  # followed, nothing put back or taken out
    assert NEW in (P.pin_dir(layout) / "auth.json").read_text() and held.is_link(layout.home / "auth.json")
    assert not (layout.state_dir / "quarantine").exists()


@posix
def test_the_switch_off_puts_the_files_back_before_the_pins_are_released(tmp_path):
    layout = LD._layout(tmp_path)
    P.take(layout)
    env = (layout.home / ".env").read_bytes()
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    assert P.release(layout) == []
    top = _top(layout.home)
    assert top[".env"] == top["auth.json"] == "file" and held.DIRNAME not in top
    assert (layout.home / ".env").read_bytes() == env and not P.present(layout)


@posix
def test_the_review_list_has_no_row_for_a_file_that_is_only_held(tmp_path):
    layout = LD._layout(tmp_path)
    H.take_baseline(layout.home, layout.state_dir)
    stamp = H.stamp(layout.home, layout.state_dir)
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    view = H.diff(layout.home, layout.state_dir)
    assert view["open"] and view["rows"] == [], [row["id"] for row in view["rows"]]
    assert H.stamp(layout.home, layout.state_dir) == stamp  # same files, same sizes and times
    # A change made on this computer through the link is seen as a change of that file.
    _core_write_json(layout.home / "auth.json", {"changed": NEW})
    assert [row["id"] for row in H.diff(layout.home, layout.state_dir)["rows"]] == ["env:auth.json"]
    assert H.stamp(layout.home, layout.state_dir) != stamp


@posix
def test_a_terminal_switch_off_without_its_launcher_leaves_the_files_where_a_running_sandbox_cannot_read(tmp_path, monkeypatch):
    layout = LD._layout(tmp_path)
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))

    def cannot(layout_, driver):
        raise SW.SwitchError("could not be stopped", 502)

    monkeypatch.setattr(SW, "drop_leftover", cannot)
    assert SW._leftover_gone(layout) is False
    monkeypatch.setattr(SW, "drop_leftover", lambda layout_, driver: True)
    monkeypatch.setattr("openshell.launcher_cli.make_driver", lambda spec: object())
    assert SW._leftover_gone(layout) is True
    held.release(layout.home, _take_out(layout))
    monkeypatch.setattr(SW, "drop_leftover", cannot)
    assert SW._leftover_gone(layout) is True  # nothing held: nothing to ask


@posix
def test_the_hand_back_leaves_the_files_held_when_told_the_sandbox_may_still_run(tmp_path):
    layout = LD._layout(tmp_path)
    P.take(layout)
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    nothing = {"open": False, "rows": [], "unanswered": 0}
    assert SW.hand_back(layout, nothing, None, sandbox_gone=False) == {"result": None, "blocked": None}
    assert held.is_link(layout.home / ".env") and held.active(layout.home) and not P.present(layout)
    assert SW.hand_back(layout, nothing, None) == {"result": None, "blocked": None}  # gone: back under their names
    assert _top(layout.home)[".env"] == "file" and held.DIRNAME not in _top(layout.home)


@posix
def test_the_switch_off_route_asks_the_driver_whether_its_sandbox_is_gone(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import test_pins as TP

    layout = LD._layout(tmp_path)
    P.take(layout)
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    routes = TP._off_route(layout, monkeypatch, [])
    routes._sup.driver = SimpleNamespace(sandbox_gone=lambda: False)  # its delete failed
    status, payload, _ = TP._send(routes, "POST", "/api/plugins/openshell/switch/off", {})
    assert status == 200 and payload["state"] == "off"
    assert held.is_link(layout.home / ".env"), "put back under a sandbox that may still run"
    held.release(layout.home, _take_out(layout))
    P.take(layout)
    held.hold(layout.home, _names(layout, tmp_path), _take_out(layout))
    routes = TP._off_route(layout, monkeypatch, [])
    routes._sup.driver = SimpleNamespace(sandbox_gone=lambda: True)
    assert TP._send(routes, "POST", "/api/plugins/openshell/switch/off", {})[0] == 200
    assert _top(layout.home)[".env"] == "file"


def test_the_windows_driver_hides_by_path_whatever_file_stands_there(tmp_path):
    """Windows needs none of this: its deny list names paths, not files, and is built from the same grants. A
    file replaced by rename is under the same path."""
    from openshell.launcher import openshell_windows as W

    layout = LD._layout(tmp_path)
    grants = L.profile_grants(layout, LD._runtime(tmp_path), [])
    denied = {os.path.normcase(str(p)) for p in grants.denied}
    for name in (".env", ".op.env", "auth.json"):
        assert os.path.normcase(str(layout.home / name)) in denied  # present or absent, by path
    text = Path(W.__file__).read_text(encoding="utf-8")
    assert "import held" not in text and "held.hold" not in text  # nothing is moved or linked on Windows
