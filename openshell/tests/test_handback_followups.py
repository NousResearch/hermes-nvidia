"""The hand-back's follow-ups (launcher/handback.py, pins.py, switch.py and the commands).

* Files that change under a reader: a settings file replaced by rename between the look and the read is read
  again; one caught empty or half-written is read again a moment later; nothing loops.
* Files the pins write: a file put back into the home, a pinned copy and ``pins.json`` are written whole to a temp
  file in the pin folder and renamed into place; a pinned copy that is not the recorded file is never put back.
* The list follows the status: ``handback.stamp`` changes when the watched files do, the launcher's status carries
  it, and ``GET handback`` answers the new list at once.
* What the user kept is remembered: ``handback.kept`` names it for as long as it is in the profile; the status
  counts it, ``sandbox status`` says so in one line, ``sandbox handback`` lists it.
* A revert that leaves no setting different writes the saved copy's bytes; a jobs file the sandbox made goes when
  its last job does; a refused switch-on says what to run next.

Everything runs in temp folders; nothing starts a sandbox.
"""
import hashlib
import json
import os
import threading
import time

import pytest

import test_handback as TH
import test_settings_routes as SR
from openshell import launcher_cli as CLI
from openshell.launcher import handback as H
from openshell.launcher import host_routes as HR
from openshell.launcher import pins as P
from openshell.launcher import switch as SW
from test_handback import box, by_id, put, taken  # noqa: F401  (fixtures and helpers)
from test_handback_wiring import _ids, _in_use, _send, _switched_on, cli  # noqa: F401
from test_pins import ENV, layout, writes  # noqa: F401
from test_switch_flow import _on, env  # noqa: F401

HOOKS_ON = b"hooks_auto_accept: true\n"


def _replace(path, data: bytes) -> None:
    """Write the way Hermes's own config writer does: a temp file, flushed, renamed over the target. (Windows
    refuses the rename while another handle has the target open: tried again, as that writer does.)"""
    tmp = path.with_name(path.name + ".writer.tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    for attempt in range(200):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 199:
                raise
            time.sleep(0.002)


def _on_open_of(monkeypatch, target, action, times=1):
    """Run *action* right before each of the next *times* opens of *target* (the moment between a look at a file
    and the read of it)."""
    real, left, wanted = os.open, [times], os.path.normcase(os.path.abspath(target))

    def opening(path, flags, *args, **kwargs):
        if left[0] and os.path.normcase(os.path.abspath(os.fspath(path))) == wanted and not flags & (os.O_WRONLY | os.O_RDWR):
            left[0] -= 1
            action()
        return real(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", opening)
    return left


# -- a file that changes under the reader ---------------------------------------------------------------------------

def test_a_settings_file_replaced_by_rename_between_the_look_and_the_read_is_read_again(box, monkeypatch):  # noqa: F811
    home, state = taken(box)
    config = home / "config.yaml"
    left = _on_open_of(monkeypatch, config, lambda: _replace(config, TH.CONFIG + HOOKS_ON))
    monkeypatch.setattr(H, "_pause", lambda seconds: pytest.fail("the new file is read at once, without a wait"))
    view = H.diff(home, state)
    assert left == [0]  # the writer came in between
    assert _ids(view) == ["cfg:hooks_auto_accept"]  # the new file's settings, not "Settings file ... not valid YAML"
    assert view["incomplete"] == []


@pytest.mark.skipif(os.name == "nt", reason="a folder listing carries no file id on Windows: nothing to compare")
def test_a_script_replaced_by_rename_with_the_same_bytes_while_it_is_read_is_no_row(box, monkeypatch):  # noqa: F811
    """Any writer that saves by rename (an editor, a sync tool) does this to a file that did not change. Left
    unread it would be listed as changed."""
    home, state = taken(box)
    script = home / "scripts" / "backup.sh"
    left = _on_open_of(monkeypatch, script, lambda: _replace(script, script.read_bytes()))
    view = H.diff(home, state)
    assert left == [0] and view["rows"] == []
    left = _on_open_of(monkeypatch, script, lambda: _replace(script, b"#!/bin/sh\necho changed\n"))
    assert _ids(H.diff(home, state)) == ["file:scripts/backup.sh"] and left == [0]  # and a real change is read


def test_a_file_that_is_replaced_at_every_read_is_given_up_on_not_read_forever(box, monkeypatch):  # noqa: F811
    home, state = taken(box)
    config, n = home / "config.yaml", [0]

    def again():
        n[0] += 1
        _replace(config, TH.CONFIG + b"# rewrite %d\n" % n[0])

    _on_open_of(monkeypatch, config, again, times=10_000)
    monkeypatch.setattr(H, "_pause", lambda seconds: None)
    view = H.diff(home, state)
    assert _ids(view) == ["cfgfile:config.yaml"]  # said as it is: it could not be read
    assert n[0] <= H._SWAP_RETRIES * (H._REREADS + 1) + 4


@pytest.mark.parametrize("caught", [b"", b"model:\n  default: [half"], ids=["empty", "half"])
def test_a_settings_file_caught_while_it_is_rewritten_in_place_is_read_again(box, monkeypatch, caught):  # noqa: F811
    """A writer that truncates and rewrites in place leaves the file empty or cut for an instant. Read at that
    instant an empty file is no settings at all (every entry "removed") and a cut one is not YAML. (A file cut
    where what is left still reads as YAML cannot be told from a real edit: it is listed as it reads, and the
    next list is right. The switch-off's own revert looks again after the sandbox has stopped.)"""
    home, state = taken(box)
    config, pauses = home / "config.yaml", []
    put(config, caught)

    def writer_finishes(seconds):
        pauses.append(seconds)
        put(config, TH.CONFIG + HOOKS_ON)

    monkeypatch.setattr(H, "_pause", writer_finishes)
    assert _ids(H.diff(home, state)) == ["cfg:hooks_auto_accept"]
    assert pauses == [H._REREAD_PAUSE]


def test_a_settings_file_that_stays_broken_is_a_row_after_two_more_looks(box, monkeypatch):  # noqa: F811
    home, state = taken(box)
    pauses = []
    monkeypatch.setattr(H, "_pause", pauses.append)
    put(home / "config.yaml", b"model: [broken\n")
    view = H.diff(home, state)
    assert [(r["id"], r["detail"]) for r in view["rows"]] == [("cfgfile:config.yaml", "not valid YAML")]
    assert pauses == [H._REREAD_PAUSE] * H._REREADS
    pauses.clear()
    put(home / "config.yaml", TH.CONFIG)
    put(home / "cron" / "jobs.json", b'{"jobs": [')  # the jobs file the same
    assert _ids(H.diff(home, state)) == ["cronfile:cron/jobs.json"] and len(pauses) == H._REREADS
    pauses.clear()
    put(home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB))
    assert H.diff(home, state)["rows"] == [] and pauses == []  # a file that reads is never waited for


def test_the_list_stays_right_while_a_writer_replaces_the_settings_file(box):  # noqa: F811
    """A stress loop: one thread keeps replacing config.yaml (by rename, as Hermes writes it) with one of two
    valid files while the list is made again and again. Every list is one of the two right answers.
    HANDBACK_STRESS_RUNS sets the number of lists (default 150; 2,000 for a longer run)."""
    home, state = taken(box)
    config, stop, runs = home / "config.yaml", threading.Event(), int(os.environ.get("HANDBACK_STRESS_RUNS", "150"))
    versions = [TH.CONFIG, TH.CONFIG + HOOKS_ON]
    writes_done = [0]

    def writer():
        while not stop.is_set():
            _replace(config, versions[writes_done[0] % 2])
            writes_done[0] += 1

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    seen, bad = set(), []
    try:
        for _ in range(runs):
            ids = tuple(_ids(H.diff(home, state)))
            seen.add(ids)
            if ids not in ((), ("cfg:hooks_auto_accept",)):
                bad.append(ids)
    finally:
        stop.set()
        thread.join(10)
    assert bad == [] and writes_done[0] > 0
    assert not [p.name for p in home.iterdir() if p.name.startswith(".handback-")]  # the reader leaves nothing


# -- files the pins write -------------------------------------------------------------------------------------------

def _spy_replace(monkeypatch):
    calls, real = [], os.replace

    def replace(src, dst, **kw):
        calls.append((os.fspath(src), os.fspath(dst)))
        return real(src, dst, **kw)

    monkeypatch.setattr(os, "replace", replace)
    return calls


def test_an_env_file_is_put_back_whole_through_a_temp_file_in_the_pin_folder(layout, monkeypatch):  # noqa: F811
    P.take(layout)
    put(layout.home / ".env", "MODEL_API_KEY=replaced-inside\n")
    calls = _spy_replace(monkeypatch)
    created = []
    real_open = os.open

    def opening(path, flags, *a, **kw):
        if flags & os.O_CREAT:
            created.append(os.fspath(path))
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", opening)
    assert P.restore_env(layout) == [".env"]
    assert (layout.home / ".env").read_bytes() == ENV.encode()
    pin, home_env = str(P.pin_dir(layout)), str(layout.home / ".env")
    # written in the pin folder (which no sandbox reads), then renamed over the home's file: never a key file in
    # the home under another name, never a half-written one
    assert [dst for _src, dst in calls] == [home_env] and os.path.dirname(calls[0][0]) == pin
    assert all(os.path.dirname(path) != str(layout.home) for path in created)
    assert sorted(p.name for p in P.pin_dir(layout).iterdir()) == [".env", "config.yaml", "pins.json"]  # no temp file left
    if os.name != "nt":
        assert (layout.home / ".env").stat().st_mode & 0o777 == 0o600


def test_a_put_back_that_fails_leaves_no_partial_file_anywhere(layout, monkeypatch):  # noqa: F811
    P.take(layout)
    put(layout.home / ".env", "MODEL_API_KEY=replaced-inside\n")
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    assert P.restore_env(layout) == []  # said in the log; the switch goes on
    assert not (layout.home / ".env").exists()  # not a cut key file: none (the other version is in quarantine)
    assert [p.read_bytes() for p in (layout.state_dir / "quarantine").rglob(".env")] == [b"MODEL_API_KEY=replaced-inside\n"]
    assert sorted(p.name for p in P.pin_dir(layout).iterdir()) == [".env", "config.yaml", "pins.json"]
    assert (P.pin_dir(layout) / ".env").read_bytes() == ENV.encode()  # the pinned copy is untouched


def test_a_pinned_copy_that_is_not_the_recorded_file_is_never_put_into_the_home(layout):  # noqa: F811
    P.take(layout)
    (P.pin_dir(layout) / ".env").write_bytes(ENV.encode()[:20])  # a launcher killed while it copied
    put(layout.home / ".env", "MODEL_API_KEY=replaced-inside\n")
    assert P.restore_env(layout) == []
    assert not (layout.home / ".env").exists()
    assert len(list((layout.state_dir / "quarantine").rglob(".env"))) == 1


def test_a_pinned_copy_is_replaced_whole_never_removed_first(layout, monkeypatch):  # noqa: F811
    P.take(layout)
    put(layout.home / ".env", ENV + "NEW_API_KEY=sk-new\n")  # the user's write through the launcher's route
    real = P._write_private
    seen = []

    def write(path, data, **kw):
        if os.path.basename(os.fspath(path)) == ".env":
            seen.append((P.pin_dir(layout) / ".env").read_bytes())  # what a reader finds at this moment
        return real(path, data, **kw)

    monkeypatch.setattr(P, "_write_private", write)
    assert P.update_env(layout) is True
    assert seen == [ENV.encode()]  # the old copy was still there, whole
    assert (P.pin_dir(layout) / ".env").read_bytes() == (ENV + "NEW_API_KEY=sk-new\n").encode()
    assert P.load(layout)["files"][".env"]["sha256"] == hashlib.sha256((ENV + "NEW_API_KEY=sk-new\n").encode()).hexdigest()
    assert not [p.name for p in P.pin_dir(layout).iterdir() if p.name.endswith(".tmp")]


def test_the_sign_in_store_and_the_pin_record_are_written_the_same_way(layout, monkeypatch):  # noqa: F811
    put(layout.home / "auth.json", '{"version": 1}\n')
    P.take(layout)
    put(layout.home / "auth.json", '{"planted": true}\n')
    calls = _spy_replace(monkeypatch)
    assert P.restore_stores(layout, replaceable=True) == ["auth.json"]
    assert (layout.home / "auth.json").read_bytes() == b'{"version": 1}\n'
    assert [os.path.basename(dst) for _src, dst in calls] == ["auth.json"]
    calls.clear()
    assert P.allow(layout, {"env": "OTHER_API_KEY", "host": "127.0.0.1", "port": 18923}) is True
    assert [(os.path.basename(src).startswith(".pin-"), os.path.basename(dst)) for src, dst in calls] == [(True, "pins.json")]


# -- the list follows the status --------------------------------------------------------------------------------------

def test_the_stamp_changes_when_the_list_may_have_and_only_then(box, monkeypatch):  # noqa: F811
    home, state = taken(box)
    monkeypatch.setattr(H, "_read", lambda *a, **kw: pytest.fail("the stamp reads no file"))
    first = H.stamp(home, state)
    assert first == H.stamp(home, state) and len(first) == 20
    put(home / "logs" / "agent.log", "more\n")       # not watched
    put(home / "sessions" / "s2.json", "{}\n")
    put(home / "plugins" / "p1" / "__pycache__" / "x.pyc", b"\x00")  # the host's own
    assert H.stamp(home, state) == first
    seen = {first}
    for change in (lambda: put(home / "config.yaml", TH.CONFIG + HOOKS_ON),
                   lambda: put(home / "scripts" / "planted.sh", "id\n"),
                   lambda: put(home / "hooks" / "notify" / "handler.py", "def handle(event, ctx):\n    return 1\n"),
                   lambda: put(home / "hooks" / "deep" / "er" / "x.py", "x = 1\n"),
                   lambda: put(home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB, {**TH.JOB, "id": "bbbbbbbbbbbb"})),
                   lambda: put(home / "shell-hooks-allowlist.json", '{"approvals": [1]}\n'),
                   lambda: put(home / ".op.env", "PLANTED=1\n"),
                   lambda: (home / "scripts" / "backup.sh").unlink(),
                   lambda: put(home / "SOUL.md", "You are something else, entirely.\n")):
        change()
        now = H.stamp(home, state)
        assert now not in seen
        seen.add(now)
    monkeypatch.undo()
    H.keep(home, state, "all")  # an answer changes what the list says
    assert H.stamp(home, state) not in seen
    assert H.stamp(home / "none-such", state / "none-such")  # never raises


def test_the_launchers_status_carries_the_stamp_and_the_kept_count(layout, tmp_path):  # noqa: F811
    P.take(layout)
    H.take_baseline(layout.home, layout.state_dir)
    sup = SR._supervisor(tmp_path, layout)
    first = sup.status()["handback"]
    assert first == {"open": True, "stamp": H.stamp(layout.home, layout.state_dir), "kept": 0}
    put(layout.home / "scripts" / "planted.sh", "id\n")
    assert sup.status()["handback"]["stamp"] != first["stamp"]


def test_the_host_status_carries_them_too_for_a_profile_that_is_off(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    api = SR._plugin_api()
    state = api._handback_state(lay)
    assert state["open"] is True and state["kept"] == 0 and state["held"] == 0 and len(state["stamp"]) == 20
    TH.plant_the_four(lay.home)
    assert api._handback_state(lay)["stamp"] != state["stamp"]


def test_the_list_route_answers_the_new_list_at_once_when_the_files_changed(layout, writes, monkeypatch):  # noqa: F811
    routes, _ = writes
    H.take_baseline(layout.home, layout.state_dir)
    made, real = [], HR.review
    monkeypatch.setattr(HR, "review", lambda lay, **kw: (made.append(1), real(lay, **kw))[1])
    assert _ids(_send(routes, "GET", "handback")[1]) == []
    assert _ids(_send(routes, "GET", "handback")[1]) == [] and len(made) == 1  # a moment later: the same answer
    put(layout.home / "scripts" / "planted.sh", "id\n")
    assert _ids(_send(routes, "GET", "handback")[1]) == ["file:scripts/planted.sh"]  # not the list of a moment ago
    assert len(made) == 2
    assert _ids(_send(routes, "GET", "handback")[1]) == ["file:scripts/planted.sh"] and len(made) == 2


# -- what the user kept -----------------------------------------------------------------------------------------------

def _kept_at_a_switch_off(lay):
    """The four proven changes planted, answered Keep at a switch-off (the terminal's path: no launcher)."""
    TH.plant_the_four(lay.home)
    view = SW.review(lay)
    done = SW.hand_back(lay, view, "keep", record_keep=True)
    assert done["blocked"] is None and done["result"]["kept"] == TH.FOUR
    return done


def test_what_was_kept_is_remembered_after_the_switch_off(env):  # noqa: F811
    lay = _switched_on(env)
    assert H.kept(lay.home, lay.state_dir) == []
    _kept_at_a_switch_off(lay)
    assert not H.is_open(lay.state_dir)  # the record of the home is closed; what was kept is its own record
    kept = H.kept(lay.home, lay.state_dir)
    assert [item["id"] for item in kept] == TH.FOUR
    shown = {item["id"]: (item["label"], item["name"], item["detail"]) for item in kept}
    assert shown["cfg:secrets.command"] == ("Secret source", "command", "new, runs sh -c 'id >> /tmp/markers/w.log'")
    assert shown["cron:bbbbbbbbbbbb"] == ("Cron job", "injected-job", "new, runs scripts/cron-injected.sh")
    assert shown["file:scripts/hook-injected.sh"] == ("Script", "scripts/hook-injected.sh", "new")
    assert all(set(item) == {"id", "kind", "label", "name", "detail", "kept_at"} for item in kept)
    record = lay.state_dir / "handback" / "kept.json"
    assert record.is_file()  # host only: the launcher's state folder
    if os.name != "nt":
        assert record.stat().st_mode & 0o777 == 0o600
    assert H.status_view(lay.home, lay.state_dir)["kept"] == 7


def test_a_kept_change_the_user_later_removes_or_changes_is_no_longer_named(env):  # noqa: F811
    lay = _switched_on(env)
    _kept_at_a_switch_off(lay)
    TH.edit_config(lay.home, lambda doc: doc.pop("secrets"))            # removed by hand
    assert "cfg:secrets.command" not in [i["id"] for i in H.kept(lay.home, lay.state_dir)]
    TH.put(lay.home / "scripts" / "hook-injected.sh", "#!/bin/sh\n# rewritten by the user\n")
    TH.edit_config(lay.home, lambda doc: doc["mcp_servers"]["injected"].update(command="/usr/bin/true"))
    ids = [i["id"] for i in H.kept(lay.home, lay.state_dir)]
    assert ids == ["cfg:hooks.on_session_start", "cfg:hooks_auto_accept", "cron:bbbbbbbbbbbb", "file:scripts/cron-injected.sh"]
    assert H.status_view(lay.home, lay.state_dir)["kept"] == 4
    put(lay.home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB))        # the kept job deleted
    assert "cron:bbbbbbbbbbbb" not in [i["id"] for i in H.kept(lay.home, lay.state_dir)]
    put(lay.home / "config.yaml", b"model: [unreadable just now\n")     # cannot be told: no setting is dropped
    assert [i["id"] for i in H.kept(lay.home, lay.state_dir)] == [
        "cfg:hooks.on_session_start", "cfg:hooks_auto_accept", "cfg:mcp_servers.injected", "cfg:secrets.command",
        "file:scripts/cron-injected.sh"]
    (lay.state_dir / "handback" / "kept.json").unlink()                 # deleting the record forgets it
    assert H.kept(lay.home, lay.state_dir) == [] and H.status_view(lay.home, lay.state_dir)["kept"] == 0


def test_what_was_kept_stays_named_through_the_next_session_and_a_revert_there(env):  # noqa: F811
    lay = _switched_on(env)
    _kept_at_a_switch_off(lay)
    H.take_baseline(lay.home, lay.state_dir)  # the next switch-on: the kept changes are part of that record
    assert H.diff(lay.home, lay.state_dir)["rows"] == []
    assert len(H.kept(lay.home, lay.state_dir)) == 7  # still named while that sandbox is on
    put(lay.home / "scripts" / "second.sh", "id\n")
    done = SW.hand_back(lay, SW.review(lay), "revert")
    assert done["result"]["reverted"] == ["file:scripts/second.sh"] and done["result"]["kept"] == []
    assert [i["id"] for i in H.kept(lay.home, lay.state_dir)] == TH.FOUR  # a revert of that session touches none


def test_only_what_was_kept_is_remembered(env):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    assert SW.hand_back(lay, SW.review(lay), "revert")["result"]["kept"] == []
    assert H.kept(lay.home, lay.state_dir) == [] and not (lay.state_dir / "handback" / "kept.json").exists()
    # a keep through the page: one row changed after it was shown, so it is put back, and not remembered
    TH.put(lay.home / "config.yaml", TH.CONFIG)
    H.take_baseline(lay.home, lay.state_dir)
    TH.plant_the_four(lay.home)
    seen = {row["id"]: row["state"] for row in H.diff(lay.home, lay.state_dir)["rows"]}
    H.keep(lay.home, lay.state_dir, "all", seen=seen)
    TH.put(lay.home / "scripts" / "cron-injected.sh", "#!/bin/sh\n# changed after the list was shown\n")
    done = SW.hand_back(lay, SW.review(lay), "keep")
    assert done["result"]["reverted"] == ["file:scripts/cron-injected.sh"]
    assert [i["id"] for i in H.kept(lay.home, lay.state_dir)] == [i for i in TH.FOUR if i != "file:scripts/cron-injected.sh"]


def test_a_change_that_could_not_be_put_back_is_not_recorded_as_kept(env, monkeypatch):  # noqa: F811
    """With Keep, a row the user was not shown is put back. When that fails (the file is held open) the row stays
    in the profile and the answer names it; it is not something the user kept."""
    lay = _switched_on(env)
    TH.put(lay.home / "scripts" / "kept.sh", "id\n")
    seen = {row["id"]: row["state"] for row in H.diff(lay.home, lay.state_dir)["rows"]}
    H.keep(lay.home, lay.state_dir, "all", seen=seen)
    TH.put(lay.home / "scripts" / "late.sh", "id\n")  # made after the list was shown
    _in_use(monkeypatch, "late.sh")
    done = SW.hand_back(lay, SW.review(lay), "keep")
    assert done["blocked"] is None and done["result"]["left"] == ["file:scripts/late.sh"]
    assert done["result"]["kept"] == ["file:scripts/kept.sh"]
    assert [i["id"] for i in H.kept(lay.home, lay.state_dir)] == ["file:scripts/kept.sh"]


def test_a_keep_that_cannot_be_recorded_never_holds_the_switch(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    monkeypatch.setattr(H, "remember_kept", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full")))
    done = SW.hand_back(lay, SW.review(lay), "keep", record_keep=True)
    assert done["blocked"] is None and done["result"]["kept"] == TH.FOUR and not H.is_open(lay.state_dir)


def test_sandbox_status_says_in_one_line_what_was_kept(env, cli, capsys, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    assert cli("status") == 1
    assert capsys.readouterr().err == "hermes sandbox: no sandbox running for profile 'work'\n"  # nothing kept: as before
    _kept_at_a_switch_off(lay)
    assert cli("status") == 1  # the sandbox is off; the kept changes run on this computer all the same
    assert capsys.readouterr().err == ("Kept from the sandbox: 7 items. Run `hermes -p work sandbox handback` to list them.\n"
                                       "hermes sandbox: no sandbox running for profile 'work'\n")
    # with a launcher running, its status carries the count
    status = {"profile": "work", "sandboxed": True, "state": "running", "handback": {"open": True, "stamp": "s", "kept": 1}}
    monkeypatch.setattr(CLI, "_call_running", lambda method, route, body=None: (status, None))
    assert cli("status") == 0
    out = capsys.readouterr()
    assert json.loads(out.out) == status
    assert out.err == "Kept from the sandbox: 1 item. Run `hermes -p work sandbox handback` to list them.\n"
    monkeypatch.setattr(CLI, "_call_running", lambda method, route, body=None: ({**status, "handback": {"open": True}}, None))
    assert cli("status") == 0 and capsys.readouterr().err == ""  # an older launcher, or nothing kept: no line


def test_sandbox_handback_lists_what_was_kept(env, cli, capsys):  # noqa: F811
    lay = _switched_on(env)
    _kept_at_a_switch_off(lay)
    assert cli("handback") == 0
    assert capsys.readouterr().out == """\
No sandbox changes to review for profile 'work'.
Kept from the sandbox: 7 items
  Shell hook     on_session_start          new, runs hook-injected.sh
  Shell hooks    hooks_auto_accept         turned on
  MCP server     injected                  new, runs /bin/sh -c id >> /tmp/markers/w.log
  Secret source  command                   new, runs sh -c 'id >> /tmp/markers/w.log'
  Cron job       injected-job              new, runs scripts/cron-injected.sh
  Script         scripts/cron-injected.sh  new
  Script         scripts/hook-injected.sh  new
"""
    assert cli("handback", "--json") == 0
    assert [item["id"] for item in json.loads(capsys.readouterr().out)["kept"]] == TH.FOUR


def test_the_list_route_names_what_was_kept(layout, writes):  # noqa: F811
    routes, sup = writes
    H.take_baseline(layout.home, layout.state_dir)
    put(layout.home / "scripts" / "kept.sh", "id\n")
    assert SW.hand_back(layout, SW.review(layout), "keep", record_keep=True)["result"]["kept"] == ["file:scripts/kept.sh"]
    P.take(layout)
    H.take_baseline(layout.home, layout.state_dir)  # the next session
    status, view, _ = _send(routes, "GET", "handback")
    assert status == 200 and view["rows"] == []
    assert [(i["id"], i["label"], i["detail"]) for i in view["kept"]] == [("file:scripts/kept.sh", "Script", "new")]
    assert sup.status()["handback"]["kept"] == 1
    api = SR._plugin_api()  # and the host route, for the profile when it is off
    assert api._handback_state(layout)["kept"] == 1


# -- small ones -------------------------------------------------------------------------------------------------------

BLOCKS = [b"\nsecrets:\n  command:\n    enabled: true\n    command: print-keys\n",
          b"\n\n# added by the agent\nhooks_auto_accept: true\nquick_commands:\n  q:\n    type: exec\n    command: id\n",
          b"secrets:\n  command:\n    enabled: true\n    command: print-keys\n"]


@pytest.mark.parametrize("block", BLOCKS, ids=["empty-line-first", "empty-lines-and-a-comment", "no-empty-line"])
def test_a_revert_that_leaves_no_setting_different_gives_the_saved_file_back_byte_for_byte(box, block):  # noqa: F811
    home, state = taken(box)
    put(home / "config.yaml", TH.CONFIG + block)  # appended the way a sandboxed agent does it
    assert H.diff(home, state)["unanswered"] >= 1
    done = H.revert(home, state, "all")
    assert done["left"] == [] and done["skipped"] == []
    assert (home / "config.yaml").read_bytes() == TH.CONFIG  # not one empty line more
    held = TH.held_dirs(state)[0] / "files" / "config.yaml"
    assert held.read_bytes() == TH.CONFIG + block  # the sandbox's whole file is kept


def test_a_revert_beside_another_changed_setting_changes_only_its_keys(box):  # noqa: F811
    home, state = taken(box)
    put(home / "config.yaml", TH.CONFIG + b"\ntimezone: UTC\nhooks_auto_accept: true\n")
    H.revert(home, state, "all")
    after = (home / "config.yaml").read_bytes()
    assert after != TH.CONFIG and b"timezone: UTC" in after and b"hooks_auto_accept" not in after  # the setting stays
    assert H.diff(home, state)["rows"] == [] and H.diff(home, state)["other_settings"]["paths"] == ["timezone"]


def test_a_saved_copy_that_is_not_the_recorded_file_is_never_written_back_whole(box):  # noqa: F811
    home, state = taken(box)
    copy = state / "handback" / "base" / "config.yaml"
    copy.write_bytes(copy.read_bytes() + b"# not what was recorded\n")  # same settings, other bytes
    put(home / "config.yaml", TH.CONFIG + b"\nhooks_auto_accept: true\n")
    H.revert(home, state, "all")
    after = (home / "config.yaml").read_bytes()
    assert b"not what was recorded" not in after and b"hooks_auto_accept" not in after
    assert TH.load(home / "config.yaml") == TH.load(put(home.parent / "users.yaml", TH.CONFIG))


def test_a_revert_keeps_a_users_write_that_joined_the_record(box):  # noqa: F811
    """The saved copy follows what the user wrote through the launcher: the bytes that come back hold it."""
    home, state = taken(box)
    put(home / "config.yaml", TH.CONFIG + b"custom_providers:\n  - name: mine\n    base_url: http://127.0.0.1:18700/v1\n")
    H.update_baseline_for_host_write(home, state, config_keys=["custom_providers"])
    with open(home / "config.yaml", "rb") as fh:
        users = fh.read()
    put(home / "config.yaml", users + b"\nhooks_auto_accept: true\n")
    H.revert(home, state, "all")
    after = TH.load(home / "config.yaml")
    assert "hooks_auto_accept" not in after and after["custom_providers"][0]["name"] == "mine"
    assert H.diff(home, state)["rows"] == []


def test_a_jobs_file_the_sandbox_made_goes_with_its_last_job(box):  # noqa: F811
    home, state, _ = box
    (home / "cron" / "jobs.json").unlink()
    H.take_baseline(home, state)
    put(home / "cron" / "jobs.json", TH.jobs_bytes({**TH.JOB, "id": "bbbbbbbbbbbb", "name": "planted"}))
    put(home / "cron" / "output" / "run.md", "x\n")  # the backend's own files beside it stay
    assert H.revert(home, state, "all")["reverted"] == ["cron:bbbbbbbbbbbb"]
    assert not (home / "cron" / "jobs.json").exists() and (home / "cron" / "output" / "run.md").is_file()
    assert H.diff(home, state)["rows"] == []


def test_a_jobs_file_of_the_users_own_stays_with_the_users_jobs(box):  # noqa: F811
    home, state = taken(box)
    put(home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB, {**TH.JOB, "id": "bbbbbbbbbbbb", "name": "planted"}))
    H.revert(home, state, "all")
    assert [job["id"] for job in json.loads((home / "cron" / "jobs.json").read_bytes())["jobs"]] == ["aaaaaaaaaaaa"]
    home2 = home.parent / "home2"  # and one whose only job is removed: an empty list, the file was the user's
    put(home2 / "cron" / "jobs.json", TH.jobs_bytes())
    H.take_baseline(home2, state, replace=True)
    put(home2 / "cron" / "jobs.json", TH.jobs_bytes({**TH.JOB, "id": "bbbbbbbbbbbb"}))
    H.revert(home2, state, "all")
    assert json.loads((home2 / "cron" / "jobs.json").read_bytes())["jobs"] == []


def test_a_switch_on_refused_after_an_unclean_end_says_what_to_run(env, cli, capsys, monkeypatch):  # noqa: F811
    lay = env["layout"]
    _on(env)  # marked, service definition in place; then the launcher dies (no state file: none answers)
    assert "work" in env["markers"].marked and SW.running_launcher(lay) is None
    with pytest.raises(SW.SwitchError) as refused:
        _on(env)
    assert str(refused.value) == ("The sandbox is still switched on for this profile, but it isn't running. "
                                  "Run `hermes -p work sandbox off`, then turn it on again.")
    assert cli("on") == 1
    assert capsys.readouterr().err == ("hermes sandbox: The sandbox is still switched on for this profile, but it isn't "
                                       "running. Run `hermes -p work sandbox off`, then turn it on again.\n")
    assert cli("on", "--revert") == 1 and "sandbox off" in capsys.readouterr().err  # the flag changes nothing here
    monkeypatch.setattr(SW, "running_launcher", lambda layout_: {"port": 47999})
    assert SW.already_marked(lay) == "The sandbox is already on for this profile."


def test_the_refusal_names_the_default_profiles_command_and_another_plugins_marker(env, monkeypatch):  # noqa: F811
    from openshell.launcher.layout import ProfileLayout
    from types import SimpleNamespace

    lay = env["layout"]
    root = ProfileLayout(name="default", home=lay.root, root=lay.root)
    assert "Run `hermes sandbox off`, then" in SW.already_marked(root)
    monkeypatch.setattr(env["markers"], "run_elsewhere", lambda profile, root=None: SimpleNamespace(plugin="remote-box"))
    assert SW.already_marked(lay) == "This profile already runs elsewhere (the remote-box plugin). Turn that off first."
    monkeypatch.setattr(env["markers"], "run_elsewhere", lambda profile, root=None: SimpleNamespace(plugin="openshell"))
    assert "Run `hermes -p work sandbox off`" in SW.already_marked(lay)


@pytest.mark.parametrize("flags,second,first", [(("--revert", "--keep"), "--keep", "--revert"),
                                                (("--keep", "--revert"), "--revert", "--keep")])
@pytest.mark.parametrize("verb", ["off", "on"])
def test_both_answers_at_once_is_a_usage_error_that_names_the_two_flags_and_changes_nothing(env, cli, capsys, verb, flags, second, first):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    before = TH.tree_bytes(lay.home)
    with pytest.raises(SystemExit) as err:
        cli(verb, *flags)
    out = capsys.readouterr()
    assert err.value.code == 2 and out.out == ""
    more = " [--move-keys]" if verb == "on" else ""  # the switch-on's own flag (keys written in config.yaml)
    assert out.err == (f"usage: hermes sandbox {verb} [-h] [--revert | --keep]{more}\n"
                       f"hermes sandbox {verb}: error: argument {second}: not allowed with argument {first}\n")
    assert TH.tree_bytes(lay.home) == before and H.is_open(lay.state_dir) and env["log"] == []  # nothing ran
