"""The hand-back step wired into the switch (launcher/handback.py is the module; its own tests are test_handback.py).

At switch-on, on the host, ``turn_on`` records the profile home (the baseline). At switch-off, while the profile
is still marked, the home is compared with it: with no change among the files that run on this computer the
switch turns off as before; with such changes the launcher's ``switch/off`` and ``hermes sandbox off`` need an
answer (``revert`` or ``keep``) and change nothing without one. ``revert`` puts every such change back and keeps
the sandbox's versions in a host-only folder. A hand-back step that cannot run never holds the switch.
Everything here runs in temp folders with stand-ins for the service and the launcher; nothing starts a sandbox.
"""
import argparse
import asyncio
import json
import os
import time
from types import SimpleNamespace

import pytest

import test_handback as TH
import test_settings_routes as SR
from openshell import launcher_cli as CLI
from openshell.launcher import handback as H
from openshell.launcher import host_routes as HR
from openshell.launcher import layout as L
from openshell.launcher import login_service as LS
from openshell.launcher import openshell_windows as W
from openshell.launcher import pins as P
from openshell.launcher import switch as SW
from openshell.launcher.proxy import parse_head
from test_pins import _serve_args, layout, serve, writes  # noqa: F401  (fixtures: a pinned layout, its key routes)
from test_switch_flow import OUTER, FakeService, _on, _request, _routes, _serve, env  # noqa: F401

P_ = "/api/plugins/openshell/"
LIST = """\
Changed in the sandbox (profile work)
  1  Shell hook     on_session_start          new, runs hook-injected.sh
  2  Shell hooks    hooks_auto_accept         turned on
  3  MCP server     injected                  new, runs /bin/sh -c id >> /tmp/markers/w.log
  4  Secret source  command                   new, runs sh -c 'id >> /tmp/markers/w.log'
  5  Cron job       injected-job              new, runs scripts/cron-injected.sh
  6  Script         scripts/cron-injected.sh  new
  7  Script         scripts/hook-injected.sh  new
Always reverted
  8  Env file       .op.env                   created
Also changed: 2 skills, 1 memory, SOUL.md, 2 other settings.
"""


def _user_home(lay):
    """A profile home as the user left it."""
    home = lay.home
    TH.put(home / "config.yaml", TH.CONFIG)
    TH.put(home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB))
    TH.put(home / "scripts" / "backup.sh", "#!/bin/sh\necho backup\n")
    TH.put(home / "tools" / "server.js", "console.log('mine')\n")
    TH.put(home / "skills" / "writing" / "SKILL.md", "---\nname: writing\n---\nWrite well.\n")
    TH.put(home / "memories" / "MEMORY.md", "likes tea\n")
    TH.put(home / "SOUL.md", "You are helpful.\n")
    TH.put(home / ".env", "A_KEY=one\n")
    return home


def _switched_on(env_):
    """The profile as ``turn_on`` leaves it: the user's home, recorded."""
    lay = env_["layout"]
    _user_home(lay)
    assert H.take_baseline(lay.home, lay.state_dir)["taken"] is True
    return lay


def _text_and_settings(home):
    """What the sandbox may change without it running here: text the agent reads, and ordinary settings."""
    TH.put(home / "skills" / "writing" / "SKILL.md", "changed\n")
    TH.put(home / "skills" / "new-one" / "SKILL.md", "new\n")
    TH.put(home / "memories" / "MEMORY.md", "likes coffee\n")
    TH.put(home / "SOUL.md", "You are something else.\n")


def _req(path):
    req = parse_head(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
    req.authenticated = True
    return req


def _send(routes, method, path, body=None, query=""):
    handler = routes.match(method, P_ + path)
    raw = b"" if body is None else json.dumps(body).encode()
    return asyncio.run(handler(_req(P_ + path + query), raw))


def _off(routes, answer=None):
    return _send(routes, "POST", "switch/off", {} if answer is None else {"handback": answer})


def _ids(view):
    return [row["id"] for row in view["rows"]]


def _append(path, data: bytes) -> None:
    """Add *data* at the end of a file, written whole. Not opened for append: on one Linux kernel these tests
    run on (WSL2, 6.6) an append to a small file that was written a moment earlier can lose its bytes (the file
    gets its new size and the new bytes read back as NUL; a program without any Hermes code shows it too), and a
    test that appended right after a rewrite then failed now and then over a file the plugin had only read."""
    path.write_bytes(path.read_bytes() + data)


def _in_use(monkeypatch, name=""):
    """Files whose path ends with *name* cannot be moved out of the home (another program holds them open)."""
    hold = H._Revert._hold

    def held_open(self, rel):
        if rel.endswith(name):
            raise PermissionError(13, "The process cannot access the file because it is being used by another process")
        return hold(self, rel)

    monkeypatch.setattr(H._Revert, "_hold", held_open)
    return lambda: monkeypatch.setattr(H._Revert, "_hold", hold)


def _held_files(lay):
    return {rel: data for folder in TH.held_dirs(lay.state_dir) for rel, data in TH.tree_bytes(folder / "files").items()}


# -- switch-on: the baseline --------------------------------------------------------------------------------

def test_turn_on_takes_the_baseline_on_the_host_before_the_service_is_installed(env, monkeypatch):  # noqa: F811
    lay = env["layout"]
    _user_home(lay)
    seen = []
    install = FakeService.install
    monkeypatch.setattr(FakeService, "install", lambda self: (seen.append(H.is_open(lay.state_dir)), install(self))[1])
    _on(env)
    assert seen == [True] and H.is_open(lay.state_dir)
    view = H.diff(lay.home, lay.state_dir)
    assert view["rows"] == [] and view["unanswered"] == 0  # the home as it was then is the user's
    TH.plant_the_four(lay.home)
    assert _ids(H.diff(lay.home, lay.state_dir)) == TH.FOUR


def test_the_launchers_own_cleanup_of_the_home_is_not_listed_as_the_sandboxs(env, monkeypatch):  # noqa: F811
    """Before every launch the launcher deletes the old copies of the secret stores (layout.profile_grants). The
    switch-on does the same before it records the home, so those files never show as removed in the sandbox."""
    from hermes_cli import profiles

    lay = env["layout"]
    _user_home(lay)
    old_copy = "cache/bws_cache.json"
    monkeypatch.setattr(L, "legacy_secret_cache_paths", lambda: (old_copy,))
    monkeypatch.setattr(profiles, "PROFILE_CREDENTIAL_PATHS", (*profiles.PROFILE_CREDENTIAL_PATHS, old_copy))
    TH.put(lay.home / old_copy, '{"token": "old"}\n')
    seen = []
    install = FakeService.install
    monkeypatch.setattr(FakeService, "install", lambda self: (
        seen.append(((lay.home / old_copy).exists(), H.is_open(lay.state_dir))), install(self))[1])
    _on(env)
    assert seen == [(False, True)]  # removed, then recorded, then the service
    assert L.remove_legacy_secret_copies(lay.home) == []  # what the launcher's own start then finds
    view = H.diff(lay.home, lay.state_dir)
    assert view["rows"] == [] and view["unanswered"] == 0
    # the control: such a file removed after the home was recorded is a row
    TH.put(lay.home / "auth.json", "{}\n")
    H.close(lay.state_dir)
    H.take_baseline(lay.home, lay.state_dir)
    (lay.home / "auth.json").unlink()
    assert _ids(H.diff(lay.home, lay.state_dir)) == ["env:auth.json"]


def test_a_refused_driver_takes_no_baseline(env):  # noqa: F811
    from test_switch_flow import FakeDriver

    with pytest.raises(SW.SwitchError):
        _on(env, driver=FakeDriver(refuse="no"))
    assert not H.is_open(env["layout"].state_dir)


def test_a_switch_on_that_fails_is_undone_with_its_baseline(env):  # noqa: F811
    lay = env["layout"]
    _user_home(lay)
    env["launcher"].update(state="failed", error="sandbox exited with 1")
    with pytest.raises(SW.SwitchError, match="sandbox exited with 1"):
        _on(env)
    assert not H.is_open(lay.state_dir) and "mark" not in env["log"]


def test_what_a_failed_switch_ons_sandbox_wrote_is_put_back(env, monkeypatch):  # noqa: F811
    lay = env["layout"]
    _user_home(lay)
    start = FakeService.start

    def start_and_write(self):  # the sandbox ran for a moment before the switch-on failed
        start(self)
        TH.put(lay.home / "scripts" / "planted.sh", "#!/bin/sh\nid\n")

    monkeypatch.setattr(FakeService, "start", start_and_write)
    env["launcher"].update(state="failed", error="sandbox exited with 1")
    with pytest.raises(SW.SwitchError):
        _on(env)
    assert not (lay.home / "scripts" / "planted.sh").exists()
    assert _held_files(lay) == {"scripts/planted.sh": b"#!/bin/sh\nid\n"}
    assert not H.is_open(lay.state_dir)


def test_a_failed_switch_on_keeps_its_baseline_while_a_row_could_not_be_put_back(env, monkeypatch):  # noqa: F811
    lay = env["layout"]
    _user_home(lay)
    start = FakeService.start
    monkeypatch.setattr(FakeService, "start",
                        lambda self: (start(self), TH.put(lay.home / "scripts" / "planted.sh", "#!/bin/sh\nid\n"))[0])
    _in_use(monkeypatch, "planted.sh")
    env["launcher"].update(state="failed", error="sandbox exited with 1")
    with pytest.raises(SW.SwitchError):
        _on(env)
    assert H.is_open(lay.state_dir)  # not ended: the next switch-off lists what is still in the home
    assert _ids(H.diff(lay.home, lay.state_dir)) == ["file:scripts/planted.sh"]


def test_an_open_baseline_is_kept_by_the_next_switch_on_and_survives_its_undo(env):  # noqa: F811
    lay = _switched_on(env)  # the last session ended without a switch-off
    TH.put(lay.home / "scripts" / "planted.sh", "#!/bin/sh\nid\n")
    env["launcher"].update(state="failed", error="sandbox exited with 1")
    with pytest.raises(SW.SwitchError):
        _on(env)
    assert H.is_open(lay.state_dir)  # not closed by the undo: it is not this switch-on's
    assert _ids(H.diff(lay.home, lay.state_dir)) == ["file:scripts/planted.sh"]  # still listed, nothing reverted
    assert (lay.home / "scripts" / "planted.sh").exists() and TH.held_dirs(lay.state_dir) == []


def test_a_baseline_that_cannot_be_written_refuses_the_switch_on_and_releases_the_pin(env, monkeypatch):  # noqa: F811
    lay = env["layout"]
    _user_home(lay)

    def full(home, state_dir, **kw):
        raise OSError("No space left on device")

    monkeypatch.setattr(H, "take_baseline", full)
    with pytest.raises(SW.SwitchError) as err:
        _on(env)
    assert err.value.status == 500
    assert str(err.value) == "Couldn't save a copy of this profile's settings: No space left on device"
    assert "install" not in env["log"] and "start" not in env["log"] and "mark" not in env["log"]
    assert not P.present(lay) and not LS.switched_on(lay)


def test_a_restart_takes_no_baseline(layout, serve, tmp_path, monkeypatch):  # noqa: F811
    _user_home(layout)
    H.take_baseline(layout.home, layout.state_dir)
    P.take(layout)
    TH.put(layout.home / "scripts" / "planted.sh", "#!/bin/sh\nid\n")
    monkeypatch.setattr(H, "take_baseline", lambda *a, **kw: pytest.fail("a restart must not take a baseline"))
    sup = SR._supervisor(tmp_path, layout)

    async def restart():
        await sup.start()
        await sup.restart()
        await sup.stop()

    asyncio.run(restart())
    monkeypatch.setattr(LS, "switched_on", lambda lay: True)  # the login service's start: the switch is on
    SW.mark(layout)  # and its profile is marked: a login service runs a sandbox for no other
    assert CLI._cmd_serve(_serve_args(service=True)) == 0
    assert _ids(H.diff(layout.home, layout.state_dir)) == ["file:scripts/planted.sh"]


def test_a_foreground_serve_that_changed_nothing_leaves_no_baseline_open(layout, serve):  # noqa: F811
    # A foreground `hermes sandbox serve` pins the keys, records the home while it runs and compares when it stops
    # (tests/test_review_before_on.py); with nothing to answer the record ends there. (Before: it took none.)
    assert CLI._cmd_serve(_serve_args()) == 0
    assert serve[-1]["own_pin"] is True and not H.is_open(layout.state_dir)


# -- the launcher's switch/off --------------------------------------------------------------------------------

def test_switch_off_with_nothing_changed_is_todays_sequence(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    stopped = []
    status, payload, _ = _off(_routes(env, monkeypatch, stopped))
    assert status == 200 and payload["marker_cleared"] is True
    assert payload["handback"] == {"reverted": [], "kept": [], "held": None}
    assert env["log"] == ["sandbox stopped", "unregistered", "clear"]
    assert not H.is_open(lay.state_dir)


def test_switch_off_without_a_baseline_answers_no_hand_back(env, monkeypatch):  # noqa: F811
    _user_home(env["layout"])
    status, payload, _ = _off(_routes(env, monkeypatch, []))
    assert status == 200 and payload["handback"] is None
    assert env["log"] == ["sandbox stopped", "unregistered", "clear"]


def test_nothing_is_asked_when_only_text_and_ordinary_settings_changed(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    _text_and_settings(lay.home)
    TH.edit_config(lay.home, lambda doc: doc["display"].update(skin="dark"))
    routes = _routes(env, monkeypatch, [])
    view = _send(routes, "GET", "handback")[1]
    assert view["rows"] == [] and view["unanswered"] == 0
    assert view["other_settings"]["paths"] == ["display.skin"] and view["tier2"]["files"] == 4
    status, payload, _ = _off(routes)  # no answer, and none is needed
    assert status == 200 and payload["handback"] == {"reverted": [], "kept": [], "held": None}
    assert env["log"] == ["sandbox stopped", "unregistered", "clear"]
    assert (lay.home / "SOUL.md").read_bytes() == b"You are something else.\n"  # kept, as text always is
    assert TH.load(lay.home / "config.yaml")["display"]["skin"] == "dark" and TH.held_dirs(lay.state_dir) == []


def test_rows_and_no_answer_stop_nothing(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    before = TH.tree_bytes(lay.home)
    routes = _routes(env, monkeypatch, [])
    status, payload, _ = _off(routes)
    assert status == 409 and payload["code"] == "handback_needs_answer" and payload["unanswered"] == 7
    assert payload["detail"] == "7 changes need an answer."
    assert "rows" not in payload  # this route answers cross-origin: the list comes from GET handback
    assert env["log"] == [] and H.is_open(lay.state_dir) and TH.tree_bytes(lay.home) == before
    assert not getattr(routes._sup, "switching_off", False)


def test_revert_puts_everything_back_after_the_stop_and_before_the_marker_is_cleared(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    user = TH.tier1_state(lay.home)
    TH.plant_the_four(lay.home)
    routes = _routes(env, monkeypatch, [])
    log = env["log"]
    monkeypatch.setattr(HR, "unregister", lambda layout, runtime: log.append(
        ("unregistered", TH.tier1_state(lay.home) == user, H.is_open(lay.state_dir))))
    status, payload, _ = _off(routes, "revert")
    assert status == 200 and payload["handback"]["reverted"] == TH.FOUR and payload["handback"]["kept"] == []
    # stopped, then reverted and closed, then the service and the marker
    assert log == ["sandbox stopped", ("unregistered", True, False), "clear"]
    assert TH.tier1_state(lay.home) == user
    [held] = TH.held_dirs(lay.state_dir)
    assert payload["handback"]["held"] == held.name  # a name, not a path
    assert (held / "files" / "scripts" / "cron-injected.sh").read_bytes() == b"#!/bin/sh\nid >> /tmp/markers/w.log\n"
    assert b"hooks_auto_accept: true" in (held / "files" / "config.yaml").read_bytes()  # the sandbox's version, kept
    assert TH.load(lay.home / "config.yaml")["display"]["skin"] == "dark"  # not a row: left as the sandbox set it


def test_revert_means_every_row_whatever_was_kept_before(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    routes = _routes(env, monkeypatch, [])
    assert _send(routes, "POST", "handback/answer", {"answer": "keep", "rows": "all"})[0] == 200
    status, payload, _ = _off(routes, "revert")
    assert status == 200 and payload["handback"]["reverted"] == TH.FOUR and payload["handback"]["kept"] == []


def test_keep_keeps_the_rows_shown_and_reverts_one_that_was_not(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    routes = _routes(env, monkeypatch, [])
    view = _send(routes, "GET", "handback")[1]
    shown = {row["id"]: row["state"] for row in view["rows"]}
    status, kept, _ = _send(routes, "POST", "handback/answer", {"answer": "keep", "rows": list(shown), "seen": shown})
    assert status == 200 and kept["kept"] == TH.FOUR and kept["unanswered"] == 0
    TH.put(lay.home / "scripts" / "later.sh", "#!/bin/sh\nid\n")  # after the list was shown
    status, payload, _ = _off(routes, "keep")
    assert status == 200
    assert payload["handback"]["kept"] == TH.FOUR and payload["handback"]["reverted"] == ["file:scripts/later.sh"]
    assert (lay.home / "scripts" / "cron-injected.sh").exists()
    assert TH.load(lay.home / "config.yaml")["hooks_auto_accept"] is True
    assert _held_files(lay) == {"scripts/later.sh": b"#!/bin/sh\nid\n"}
    assert not H.is_open(lay.state_dir) and env["log"] == ["sandbox stopped", "unregistered", "clear"]


def test_no_answer_is_enough_once_every_row_is_kept_and_a_late_row_is_reverted(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.put(lay.home / "scripts" / "one.sh", "one\n")
    routes = _routes(env, monkeypatch, [])
    assert _send(routes, "POST", "handback/answer", {"answer": "keep", "rows": "all"})[1]["kept"] == ["file:scripts/one.sh"]
    status, payload, _ = _off(routes)
    assert status == 200 and payload["handback"] == {"reverted": [], "kept": ["file:scripts/one.sh"], "held": None}


def test_a_row_that_cannot_be_put_back_keeps_the_marker_until_it_can(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.edit_config(lay.home, lambda doc: doc.update(hooks_auto_accept=True))
    TH.put(lay.home / "scripts" / "planted.sh", "x\n")
    routes = _routes(env, monkeypatch, [])
    write, config = H._write, lay.home / "config.yaml"

    def held_open(path, data, *a, **kw):
        if os.path.basename(str(path)) == "config.yaml" and "handback" not in str(path):  # the home's own
            raise PermissionError(13, "The process cannot access the file because it is being used by another process")
        return write(path, data, *a, **kw)

    monkeypatch.setattr(H, "_write", held_open)
    status, payload, _ = _off(routes, "revert")
    assert status == 409 and payload["code"] == "handback_incomplete" and payload["left"] == ["cfg:hooks_auto_accept"]
    assert payload["detail"] == ("Couldn't revert 1 change: hooks_auto_accept. The sandbox is stopped. Close any app "
                                 "using this profile's files, then turn off again.")
    assert "clear" not in env["log"] and "unregistered" not in env["log"] and env["log"] == ["sandbox stopped"]
    assert routes._sup.switching_off is False and H.is_open(lay.state_dir)
    assert not (lay.home / "scripts" / "planted.sh").exists()  # the rows that could be reverted were
    monkeypatch.setattr(H, "_write", write)  # the app that held the file is closed
    status, payload, _ = _off(routes, "revert")
    assert status == 200 and payload["handback"]["reverted"] == ["cfg:hooks_auto_accept"]
    assert env["log"][-2:] == ["unregistered", "clear"] and not H.is_open(lay.state_dir)
    assert "hooks_auto_accept" not in TH.load(config)


def test_keep_and_turn_off_is_never_refused_for_a_row_that_cannot_be_put_back(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.put(lay.home / "scripts" / "one.sh", "one\n")
    routes = _routes(env, monkeypatch, [])
    shown = {row["id"]: row["state"] for row in _send(routes, "GET", "handback")[1]["rows"]}
    assert _send(routes, "POST", "handback/answer", {"answer": "keep", "rows": list(shown), "seen": shown})[0] == 200
    TH.put(lay.home / "scripts" / "late.sh", "late\n")  # not shown, so it is reverted, and that fails
    _in_use(monkeypatch, "late.sh")
    status, payload, _ = _off(routes, "keep")
    assert status == 200 and payload["marker_cleared"] is True  # the way out always works
    assert payload["handback"]["left"] == ["file:scripts/late.sh"] and payload["handback"]["reverted"] == []
    assert payload["handback"]["problem"] == "Couldn't revert 1 change: scripts/late.sh."
    assert payload["handback"]["kept"] == ["file:scripts/one.sh"] and (lay.home / "scripts" / "late.sh").exists()
    assert env["log"] == ["sandbox stopped", "unregistered", "clear"] and not H.is_open(lay.state_dir)


def test_a_bad_answer_is_refused_and_changes_nothing(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    status, payload, _ = _off(_routes(env, monkeypatch, []), "maybe")
    assert status == 422 and payload["detail"] == 'handback is "revert" or "keep".'
    assert env["log"] == [] and H.is_open(lay.state_dir)


def test_a_credential_file_the_sandbox_removed_does_not_block(env, monkeypatch):  # noqa: F811
    lay = env["layout"]
    _user_home(lay)
    TH.put(lay.home / "auth.json", '{"providers": {}}\n')
    H.take_baseline(lay.home, lay.state_dir)
    (lay.home / "auth.json").unlink()
    routes = _routes(env, monkeypatch, [])
    view = _send(routes, "GET", "handback")[1]
    assert _ids(view) == ["env:auth.json"] and view["rows"][0]["fixed"] and view["unanswered"] == 0
    status, payload, _ = _off(routes)
    assert status == 200 and payload["handback"]["reverted"] == [] and "left" not in payload["handback"]
    assert env["log"] == ["sandbox stopped", "unregistered", "clear"]


def test_the_pin_puts_the_env_file_back_before_the_hand_back_looks(env, monkeypatch):  # noqa: F811
    lay = env["layout"]
    _user_home(lay)
    P.take(lay)
    H.take_baseline(lay.home, lay.state_dir)
    TH.put(lay.home / ".env", "A_KEY=replaced-inside\n")
    TH.put(lay.home / ".op.env", "PLANTED=1\n")
    routes = _routes(env, monkeypatch, [])
    assert _ids(_send(routes, "GET", "handback")[1]) == ["env:.env", "env:.op.env"]  # listed while the sandbox is on
    status, payload, _ = _off(routes)  # always reverted: no answer is needed for them
    assert status == 200 and payload["handback"] == {"reverted": [], "kept": [], "held": None}
    assert (lay.home / ".env").read_bytes() == b"A_KEY=one\n" and not (lay.home / ".op.env").exists()
    kept = {p.name: p.read_bytes() for p in (lay.state_dir / "quarantine").glob("*/*")}
    assert kept == {".env": b"A_KEY=replaced-inside\n", ".op.env": b"PLANTED=1\n"}  # the pin's folder, one owner
    assert TH.held_dirs(lay.state_dir) == [] and not P.present(lay)


# -- a hand-back step that cannot run never holds the switch ---------------------------------------------------

def test_a_review_that_cannot_run_turns_off_and_says_so(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    before = TH.tree_bytes(lay.home)
    monkeypatch.setattr(H, "diff", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("unexpected shape")))
    routes = _routes(env, monkeypatch, [])
    view = _send(routes, "GET", "handback")[1]
    assert view["rows"] == [] and view["unanswered"] == 0 and view["error"] == "RuntimeError: unexpected shape"
    status, payload, _ = _off(routes)
    assert status == 200 and payload["marker_cleared"] is True
    assert payload["handback"] == {"reverted": [], "kept": [], "held": None, "error": "RuntimeError: unexpected shape"}
    assert env["log"] == ["sandbox stopped", "unregistered", "clear"]
    assert TH.tree_bytes(lay.home) == before  # nothing was reverted without a list
    assert H.is_open(lay.state_dir)  # kept: the next switch-off, or `hermes sandbox handback`, can still list it


def test_a_revert_that_breaks_is_answered_from_the_saved_copies_and_turns_off(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    before = TH.tree_bytes(lay.home)
    TH.plant_the_four(lay.home)
    monkeypatch.setattr(H, "revert", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    status, payload, _ = _off(_routes(env, monkeypatch, []), "revert")
    done = payload["handback"]
    assert status == 200 and "error" not in done
    assert done["reverted"] == ["cfgfile:config.yaml", "cronfile:cron/jobs.json", "file:scripts/cron-injected.sh",
                                "file:scripts/hook-injected.sh"]
    assert done["problem"] == ("Couldn't review the sandbox's changes (RuntimeError: boom). Reverted from the copies "
                               "saved at switch-on: config.yaml, cron/jobs.json, scripts/cron-injected.sh and 1 more.")
    assert TH.tree_bytes(lay.home) == before
    assert env["log"] == ["sandbox stopped", "unregistered", "clear"] and H.is_open(lay.state_dir)


def test_a_review_that_does_not_come_back_does_not_hang_the_switch(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    gate = []
    monkeypatch.setattr(SW, "HANDBACK_TIMEOUT", 0.2)
    monkeypatch.setattr(H, "diff", lambda *a, **kw: (gate.append(1), time.sleep(30))[1])
    started = time.monotonic()
    status, payload, _ = _off(_routes(env, monkeypatch, []))
    assert status == 200 and time.monotonic() - started < 10 and gate
    assert payload["handback"]["error"] == "TimeoutError: took longer than 0.2 seconds"
    assert env["log"] == ["sandbox stopped", "unregistered", "clear"] and H.is_open(lay.state_dir)


def test_a_baseline_that_cannot_be_read_is_said_and_dropped(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    (lay.state_dir / "handback" / "baseline.json").write_bytes(b"{not json")
    status, payload, _ = _off(_routes(env, monkeypatch, []))
    assert status == 200 and "cannot be read" in payload["handback"]["error"]
    assert not H.is_open(lay.state_dir)  # nothing a later review could use: the next switch-on takes a new one


def test_the_revert_never_follows_a_link_out_of_the_home(env, monkeypatch, tmp_path):  # noqa: F811
    lay = _switched_on(env)
    outside = tmp_path / "outside"
    TH.put(outside / "backup.sh", "outside: not the profile's\n")
    TH.put(outside / "config.yaml", "outside: true\n")
    # the sandbox swaps the scripts folder for a link to a folder outside the home, and plants a link beside it
    scripts = lay.home / "scripts"
    (scripts / "backup.sh").unlink()
    scripts.rmdir()
    TH.symlink(outside, scripts, is_dir=True)
    TH.symlink(outside / "config.yaml", lay.home / "hooks" / "linked.yaml")
    routes = _routes(env, monkeypatch, [])
    assert "link:scripts" in _ids(_send(routes, "GET", "handback")[1])
    status, payload, _ = _off(routes, "revert")
    assert status == 200 and "link:scripts" in payload["handback"]["reverted"]
    # outside: byte for byte what it was, nothing added, nothing written through the link
    assert TH.tree_bytes(outside) == {"backup.sh": b"outside: not the profile's\n", "config.yaml": b"outside: true\n"}
    assert scripts.is_dir() and not scripts.is_symlink()
    assert (scripts / "backup.sh").read_bytes() == b"#!/bin/sh\necho backup\n"  # the user's own file, back in the home
    assert not os.path.lexists(lay.home / "hooks" / "linked.yaml")
    assert _held_files(lay) == {}  # a link is removed, never moved or read


# -- the launcher's routes -------------------------------------------------------------------------------------

def test_the_list_needs_the_outer_token(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    routes = _routes(env, monkeypatch, [])

    async def scenario(port):
        token = [f"X-Hermes-Session-Token: {OUTER}"]
        assert (await _request(port, "GET", P_ + "handback")).startswith(b"HTTP/1.1 401")
        answer = b'{"answer": "keep", "rows": "all"}'
        assert (await _request(port, "POST", P_ + "handback/answer", answer)).startswith(b"HTTP/1.1 401")
        assert H.diff(lay.home, lay.state_dir)["unanswered"] == 7  # the sandbox (no token) cannot answer for the user
        out = await _request(port, "GET", P_ + "handback?full=1", headers=token)
        assert out.startswith(b"HTTP/1.1 200")
        return json.loads(out.split(b"\r\n\r\n", 1)[1])

    view = _serve(routes, scenario)
    assert _ids(view) == TH.FOUR and view["unanswered"] == 7 and view["open"] is True
    assert view["tier2"]["counts"] == {"skills": 0, "memories": 0, "context": 0}
    assert view["other_settings"]["paths"] == ["display.skin", "max_live_sessions"]


def test_the_list_is_kept_for_a_few_seconds_and_dropped_by_an_answer(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.put(lay.home / "scripts" / "one.sh", "one\n")
    routes = _routes(env, monkeypatch, [])
    calls = []
    diff = H.diff
    monkeypatch.setattr(H, "diff", lambda *a, **kw: (calls.append(kw.get("quick")), diff(*a, **kw))[1])
    first = _send(routes, "GET", "handback")[1]
    assert _send(routes, "GET", "handback")[1] == first and calls == [True]  # the page's preview: the quick diff
    TH.put(lay.home / "scripts" / "two.sh", "two\n")
    # the files changed: the list of a moment ago is not served again (the page asks because the status said so)
    assert _ids(_send(routes, "GET", "handback")[1]) == ["file:scripts/one.sh", "file:scripts/two.sh"]
    assert calls == [True, True]
    assert _ids(_send(routes, "GET", "handback", query="?full=1")[1]) == ["file:scripts/one.sh", "file:scripts/two.sh"]
    assert calls == [True, True, False]  # a full read is not answered from a quick one
    assert _send(routes, "POST", "handback/answer", {"answer": "keep", "rows": ["file:scripts/one.sh"]})[0] == 200
    after = _send(routes, "GET", "handback", query="?full=1")[1]  # not the full list made before the answer
    assert [(row["id"], row["answer"]) for row in after["rows"]] == [("file:scripts/one.sh", "keep"),
                                                                    ("file:scripts/two.sh", None)]
    # older than the few seconds, the files as they are: read again
    routes._handback_view = (time.monotonic() - 6, False, first, H.stamp(lay.home, lay.state_dir))
    assert _ids(_send(routes, "GET", "handback")[1]) == ["file:scripts/one.sh", "file:scripts/two.sh"]


def test_keep_with_what_was_shown_skips_a_row_that_changed_since(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.put(lay.home / "scripts" / "one.sh", "one\n")
    TH.put(lay.home / "scripts" / "two.sh", "two\n")
    routes = _routes(env, monkeypatch, [])
    shown = {row["id"]: row["state"] for row in _send(routes, "GET", "handback")[1]["rows"]}
    TH.put(lay.home / "scripts" / "two.sh", "two, changed after the list was shown\n")
    status, payload, _ = _send(routes, "POST", "handback/answer", {"answer": "keep", "rows": list(shown), "seen": shown})
    assert status == 200 and payload["kept"] == ["file:scripts/one.sh"] and payload["unanswered"] == 1
    assert payload["skipped"] == [{"id": "file:scripts/two.sh", "reason": "changed since it was shown"}]


def test_the_answer_route_takes_keep_only(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.put(lay.home / "scripts" / "one.sh", "one\n")
    routes = _routes(env, monkeypatch, [])
    status, payload, _ = _send(routes, "POST", "handback/answer", {"answer": "revert", "rows": "all"})
    assert status == 409 and payload["detail"] == "Changes are reverted when the sandbox turns off."
    for bad in ({"answer": "delete"}, {"rows": "all"}, {"answer": "keep", "rows": 3}, {"answer": "keep", "seen": []}):
        assert _send(routes, "POST", "handback/answer", bad)[0] == 422, bad
    assert H.diff(lay.home, lay.state_dir)["unanswered"] == 1 and (lay.home / "scripts" / "one.sh").exists()


def test_the_text_list_is_cut_at_200_with_the_rest_counted(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    for n in range(250):
        TH.put(lay.home / "skills" / "bulk" / f"note-{n:03}.md", f"{n}\n")
    view = _send(_routes(env, monkeypatch, []), "GET", "handback")[1]
    assert view["tier2"]["files"] == 250 and len(view["tier2"]["items"]) == 200 and view["tier2"]["more"] == 50
    assert view["rows"] == []


# -- the user's own writes through the launcher's routes are not the sandbox's ---------------------------------

def test_a_key_saved_through_the_launcher_is_not_listed_and_a_later_replacement_is(layout, writes):  # noqa: F811
    routes, _ = writes
    H.take_baseline(layout.home, layout.state_dir)
    status, _, _ = asyncio.run(routes.match("PUT", "/api/env")(
        SimpleNamespace(authenticated=True), json.dumps({"key": "NEW_API_KEY", "value": "sk-new"}).encode()))
    assert status == 200 and b"NEW_API_KEY=sk-new" in (layout.home / ".env").read_bytes()
    assert H.diff(layout.home, layout.state_dir)["rows"] == []  # the user's own write
    TH.put(layout.home / ".env", "MODEL_API_KEY=replaced-inside\n")
    assert _ids(H.diff(layout.home, layout.state_dir)) == ["env:.env"]


def test_an_endpoint_saved_through_the_launcher_is_not_listed_and_the_sandboxs_changes_beside_it_are(layout, writes, monkeypatch):  # noqa: F811
    from hermes_cli.web_routers import config_env

    routes, _ = writes
    H.take_baseline(layout.home, layout.state_dir)
    upsert = config_env.upsert_custom_endpoint

    def racing(model, profile):  # the sandbox edits config.yaml while the user's endpoint is being saved
        done = upsert(model, profile)
        _append(layout.home / "config.yaml", b"hooks_auto_accept: true\n")
        return done

    monkeypatch.setattr(config_env, "upsert_custom_endpoint", racing)
    # the sandbox's, before the user saves an endpoint
    _append(layout.home / "config.yaml", b"fallback_model:\n  provider: custom\n  base_url: http://127.0.0.1:18923/v1\n"
                                         b"  key_env: MODEL_API_KEY\n")
    assert asyncio.run(routes.match("GET", P_ + "handback")(_req(P_ + "handback"), b""))[0] == 200
    assert routes._handback_view is not None  # the page has read the list
    body = {"name": "Mine", "base_url": "http://127.0.0.1:18700/v1", "model": "m", "make_default": True}
    status, _, _ = asyncio.run(routes.match("POST", "/api/providers/custom-endpoints")(
        SimpleNamespace(authenticated=True), json.dumps(body).encode()))
    assert status == 200 and b"18700" in (layout.home / "config.yaml").read_bytes()
    # the model entry is the user's; what the sandbox wrote beside it is still listed
    assert _ids(H.diff(layout.home, layout.state_dir)) == ["cfg:fallback_model", "cfg:hooks_auto_accept"]
    assert routes._handback_view is None  # a list shown before the write is not served again


def test_a_key_write_takes_no_setting_into_the_baseline(layout, writes, monkeypatch):  # noqa: F811
    from hermes_cli.web_routers import config_env

    routes, _ = writes
    H.take_baseline(layout.home, layout.state_dir)
    set_env_var = config_env.set_env_var

    async def racing(model, profile):  # the sandbox edits config.yaml while the user's key is being saved
        _append(layout.home / "config.yaml", b"hooks_auto_accept: true\nmodel_note: x\n")
        (layout.home / "config.yaml").write_bytes((layout.home / "config.yaml").read_bytes().replace(b"18500", b"18923"))
        return await set_env_var(model, profile)

    monkeypatch.setattr(config_env, "set_env_var", racing)
    status, _, _ = asyncio.run(routes.match("PUT", "/api/env")(
        SimpleNamespace(authenticated=True), json.dumps({"key": "NEW_API_KEY", "value": "sk-new"}).encode()))
    assert status == 200
    assert _ids(H.diff(layout.home, layout.state_dir)) == ["cfg:hooks_auto_accept", "cfg:model", "cfg:model_note"]


def test_a_hand_back_failure_never_fails_the_users_key_write(layout, writes, monkeypatch):  # noqa: F811
    routes, _ = writes
    H.take_baseline(layout.home, layout.state_dir)
    monkeypatch.setattr(H, "update_baseline_for_host_write", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk")))
    status, _, _ = asyncio.run(routes.match("PUT", "/api/env")(
        SimpleNamespace(authenticated=True), json.dumps({"key": "NEW_API_KEY", "value": "sk-new"}).encode()))
    assert status == 200 and b"NEW_API_KEY=sk-new" in (layout.home / ".env").read_bytes()


# -- `hermes sandbox off` from a terminal ----------------------------------------------------------------------

def _launcher(monkeypatch, answers):
    """A running launcher that answers each route from *answers*; returns the calls made."""
    calls = []

    def call(port, token, method, route, body=None, timeout=5.0):
        calls.append((method, route, body))
        return answers.get((method, route), (404, None))

    monkeypatch.setattr(SW, "running_launcher", lambda lay: {"port": 47999})
    monkeypatch.setattr(SW, "launcher_call", call)
    return calls


# Before anything else the terminal asks the launcher for its status: one that does not answer is not handed the
# switch-off (tests/test_gateway_gone.py).
ASKED_FIRST = ("GET", "status", None)


def _off_here(env_, answer=None):
    return SW.turn_off_here(env_["layout"], handback_answer=answer, runtime=env_["runtime"], manager=env_["manager"])


def test_off_through_a_launcher_that_needs_an_answer_fetches_the_list(env, monkeypatch):  # noqa: F811
    view = {"open": True, "rows": [{"id": "file:scripts/x.sh"}], "unanswered": 1}
    calls = _launcher(monkeypatch, {
        ("POST", "switch/off"): (409, {"detail": "1 change needs an answer.", "code": "handback_needs_answer", "unanswered": 1}),
        ("GET", "handback?full=1"): (200, view)})
    with pytest.raises(SW.HandbackNeeded) as err:
        _off_here(env)
    assert err.value.view == view and str(err.value) == "1 change needs an answer." and err.value.status == 409
    assert calls == [ASKED_FIRST, ("POST", "switch/off", {}), ("GET", "handback?full=1", None)]
    assert env["services"] == [] and "clear" not in env["log"]  # nothing was done here either


def test_off_through_a_launcher_records_keep_before_it_turns_off(env, monkeypatch):  # noqa: F811
    done = {"ok": True, "state": "off", "marker_cleared": True, "handback": {"reverted": [], "kept": ["a"], "held": None}}
    calls = _launcher(monkeypatch, {("POST", "handback/answer"): (200, {"kept": ["a"], "skipped": [], "unanswered": 0}),
                                    ("POST", "switch/off"): (200, done)})
    assert _off_here(env, "keep") == {"stopped": "launcher", **done}
    assert calls == [ASKED_FIRST, ("POST", "handback/answer", {"answer": "keep", "rows": "all"}),
                     ("POST", "switch/off", {"handback": "keep"})]
    calls.clear()
    assert _off_here(env, "revert")["stopped"] == "launcher"
    assert calls == [ASKED_FIRST, ("POST", "switch/off", {"handback": "revert"})]  # nothing to record for a revert


def test_a_keep_the_launcher_did_not_record_never_turns_off_as_a_revert(env, monkeypatch):  # noqa: F811
    calls = _launcher(monkeypatch, {("POST", "handback/answer"): (500, {"detail": "boom"}),
                                    ("POST", "switch/off"): (200, {"ok": True})})
    with pytest.raises(SW.SwitchError, match="The launcher refused: 500"):
        _off_here(env, "keep")
    assert calls == [ASKED_FIRST, ("POST", "handback/answer", {"answer": "keep", "rows": "all"})]


def test_a_launcher_that_could_not_revert_is_reported_in_its_own_words(env, monkeypatch):  # noqa: F811
    text = "Couldn't revert 1 change: x. The sandbox is stopped. Close any app using this profile's files, then turn off again."
    _launcher(monkeypatch, {("POST", "switch/off"): (409, {"detail": text, "code": "handback_incomplete", "left": ["x"]})})
    with pytest.raises(SW.SwitchError) as err:
        _off_here(env, "revert")
    assert str(err.value) == text and not isinstance(err.value, SW.HandbackNeeded)
    _launcher(monkeypatch, {("POST", "switch/off"): (500, {"detail": "The sandbox didn't turn off: x"})})
    with pytest.raises(SW.SwitchError, match="The launcher refused: 500"):  # any other refusal reads as before
        _off_here(env)


def test_off_without_a_launcher_changes_nothing_until_it_has_an_answer(env):  # noqa: F811
    lay = _switched_on(env)
    _on_disk = _on(env)  # the service definition and the marker, as a switched-on profile has them
    assert _on_disk and LS.switched_on(lay) and "work" in env["markers"].marked
    TH.plant_the_four(lay.home)
    before, log = TH.tree_bytes(lay.home), list(env["log"])
    with pytest.raises(SW.HandbackNeeded) as err:
        _off_here(env)
    assert _ids(err.value.view) == TH.FOUR and str(err.value) == "7 changes need an answer."
    assert LS.switched_on(lay) and "work" in env["markers"].marked and env["log"] == log
    assert TH.tree_bytes(lay.home) == before and H.is_open(lay.state_dir) and P.present(lay)


def test_off_without_a_launcher_reverts_before_it_clears_the_marker(env):  # noqa: F811
    lay = _switched_on(env)
    user = TH.tier1_state(lay.home)
    TH.plant_the_four(lay.home)
    env["markers"].marked.add("work")
    state = []
    clear = env["markers"].clear_profile_run_elsewhere
    env["markers"].clear_profile_run_elsewhere = lambda *a, **kw: (
        state.append((TH.tier1_state(lay.home) == user, H.is_open(lay.state_dir))), clear(*a, **kw))[1]
    result = _off_here(env, "revert")
    assert state == [(True, False)]  # reverted and closed while the profile was still marked
    assert result["stopped"] == "service" and result["marker_cleared"] is True
    assert result["handback"]["reverted"] == TH.FOUR and result["handback"]["kept"] == []
    assert result["handback"]["held"] == TH.held_dirs(lay.state_dir)[0].name
    assert env["log"].index("uninstall") < env["log"].index("clear")


def test_off_without_a_launcher_keeps_what_was_listed(env):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    TH.put(lay.home / ".op.env", "PLANTED=1\n")
    result = _off_here(env, "keep")
    assert result["handback"]["kept"] == TH.FOUR and result["handback"]["reverted"] == ["env:.op.env"]
    assert (lay.home / "scripts" / "cron-injected.sh").exists() and not (lay.home / ".op.env").exists()
    assert TH.load(lay.home / "config.yaml")["hooks_auto_accept"] is True and not H.is_open(lay.state_dir)


def test_off_without_a_launcher_keeps_only_the_rows_as_they_were_listed(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.put(lay.home / "scripts" / "one.sh", "one\n")
    TH.put(lay.home / "scripts" / "two.sh", "two\n")
    stop = FakeService.stop

    def stop_late(self):  # the sandbox writes once more between the list and its stop
        TH.put(lay.home / "scripts" / "one.sh", "one, changed after the list\n")
        TH.put(lay.home / "scripts" / "late.sh", "late\n")
        stop(self)

    monkeypatch.setattr(FakeService, "stop", stop_late)
    result = _off_here(env, "keep")
    assert result["handback"]["kept"] == ["file:scripts/two.sh"]
    assert result["handback"]["reverted"] == ["file:scripts/late.sh", "file:scripts/one.sh"]
    assert (lay.home / "scripts" / "two.sh").exists() and not (lay.home / "scripts" / "one.sh").exists()


def test_off_without_a_launcher_keeps_the_marker_when_a_row_cannot_be_put_back(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.put(lay.home / "scripts" / "planted.sh", "x\n")
    env["markers"].marked.add("work")
    _in_use(monkeypatch)
    with pytest.raises(SW.SwitchError) as err:
        _off_here(env, "revert")
    assert err.value.status == 409 and str(err.value).startswith("Couldn't revert 1 change: scripts/planted.sh. ")
    assert "clear" not in env["log"] and "work" in env["markers"].marked and H.is_open(lay.state_dir)


def test_off_without_a_launcher_turns_off_when_the_review_cannot_run(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.plant_the_four(lay.home)
    env["markers"].marked.add("work")
    monkeypatch.setattr(H, "diff", lambda *a, **kw: (_ for _ in ()).throw(OSError("unreadable")))
    result = _off_here(env)
    assert result["marker_cleared"] is True and result["handback"]["error"] == "OSError: unreadable"
    assert (lay.home / "scripts" / "cron-injected.sh").exists() and H.is_open(lay.state_dir)


# -- the commands ----------------------------------------------------------------------------------------------

@pytest.fixture
def cli(env, monkeypatch):  # noqa: F811
    """``hermes -p work sandbox ...`` for the fixture's profile, with no launcher running."""
    lay = env["layout"]
    monkeypatch.setattr(L, "current_profile", lambda: lay)
    real = SW.turn_off_here
    monkeypatch.setattr(SW, "turn_off_here",
                        lambda layout_, **kw: real(layout_, runtime=env["runtime"], manager=env["manager"], **kw))
    parser = argparse.ArgumentParser(prog="hermes sandbox")
    CLI._setup(parser)
    return lambda *argv: CLI._dispatch(parser.parse_args(list(argv)))


def _the_report(lay):
    """The four changes of the report, a created env file, and text and settings that are not rows."""
    TH.plant_the_four(lay.home)
    TH.put(lay.home / ".op.env", "PLANTED=1\n")
    _text_and_settings(lay.home)


def test_sandbox_off_lists_and_exits_3_until_it_has_an_answer(env, cli, capsys):  # noqa: F811
    lay = _switched_on(env)
    env["markers"].marked.add("work")
    _the_report(lay)
    before = TH.tree_bytes(lay.home)
    assert cli("off") == 3
    out = capsys.readouterr()
    assert out.out == LIST
    assert out.err == "hermes sandbox: 7 changes need an answer. Run again with --revert or --keep.\n"
    assert TH.tree_bytes(lay.home) == before and "work" in env["markers"].marked and "clear" not in env["log"]


def test_sandbox_off_revert_and_keep(env, cli, capsys):  # noqa: F811
    lay = _switched_on(env)
    user = TH.tier1_state(lay.home)
    _the_report(lay)
    assert cli("off", "--revert") == 0
    out = capsys.readouterr()
    result = json.loads(out.out)
    assert result["state"] == "off" and len(result["handback"]["reverted"]) == 8
    held = lay.state_dir / "handback" / "held" / result["handback"]["held"]
    assert out.err == f"Reverted 8 changes. The sandbox's versions are in {held}.\n" and held.is_dir()
    assert TH.tier1_state(lay.home) == user and "clear" in env["log"]
    # the same, kept
    TH.put(lay.home / "config.yaml", TH.CONFIG)
    H.take_baseline(lay.home, lay.state_dir)
    TH.plant_the_four(lay.home)
    TH.put(lay.home / ".op.env", "PLANTED=1\n")
    assert cli("off", "--keep") == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["handback"]["kept"] == TH.FOUR
    held = TH.held_dirs(lay.state_dir)[-1]
    assert out.err == f"Kept 7 changes.\nReverted 1 change. The sandbox's version is in {held}.\n"
    assert TH.load(lay.home / "config.yaml")["hooks_auto_accept"] is True


def test_sandbox_off_with_nothing_to_answer_is_as_before(env, cli, capsys):  # noqa: F811
    lay = _switched_on(env)
    _text_and_settings(lay.home)
    assert cli("off") == 0
    out = capsys.readouterr()
    assert json.loads(out.out) == {"stopped": "service", "marker_cleared": False, "state": "off",
                                   "handback": {"reverted": [], "kept": [], "held": None}}
    assert out.err == ""


def test_sandbox_off_says_when_a_row_could_not_be_put_back_or_the_review_could_not_run(env, cli, capsys, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    TH.put(lay.home / "scripts" / "planted.sh", "x\n")
    closed = _in_use(monkeypatch)
    assert cli("off", "--revert") == 1
    out = capsys.readouterr()
    assert out.out == "" and out.err == (
        "hermes sandbox: Couldn't revert 1 change: scripts/planted.sh. The sandbox is stopped. Close any app using "
        "this profile's files, then turn off again.\n")
    closed()
    monkeypatch.setattr(H, "diff", lambda *a, **kw: (_ for _ in ()).throw(OSError("unreadable")))
    assert cli("off") == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["handback"]["error"] == "OSError: unreadable"
    assert out.err == "hermes sandbox: Couldn't review the sandbox's changes (OSError: unreadable). The sandbox is off.\n"


def test_revert_and_keep_together_is_a_usage_error(cli, capsys):
    with pytest.raises(SystemExit) as err:
        cli("off", "--revert", "--keep")
    assert err.value.code == 2 and "argument --keep: not allowed with argument --revert" in capsys.readouterr().err


def test_sandbox_handback_lists(env, cli, capsys):  # noqa: F811
    lay = env["layout"]
    _user_home(lay)
    assert cli("handback") == 0
    assert capsys.readouterr().out == "No sandbox changes to review for profile 'work'.\n"  # no baseline open
    H.take_baseline(lay.home, lay.state_dir)
    assert cli("handback") == 0
    assert capsys.readouterr().out == "No sandbox changes to review for profile 'work'.\n"  # open, nothing changed
    _the_report(lay)
    before = TH.tree_bytes(lay.home)
    assert cli("handback") == 0
    out = capsys.readouterr()
    assert out.out == LIST and out.err == ""
    assert cli("handback", "--json") == 0
    view = json.loads(capsys.readouterr().out)
    assert _ids(view) == [*TH.FOUR[:5], "env:.op.env", *TH.FOUR[5:]] and view["unanswered"] == 7
    assert TH.tree_bytes(lay.home) == before and H.is_open(lay.state_dir)  # listing changes nothing


def test_sandbox_handback_asks_a_running_launcher(env, cli, capsys, monkeypatch):  # noqa: F811
    lay = env["layout"]
    monkeypatch.setattr(SW, "running_launcher", lambda layout_: {"port": 47999})
    asked = []
    row = {"id": "file:scripts/x.sh", "label": "Script", "name": "scripts/x.sh", "detail": "new", "fixed": False}
    view = {"open": True, "rows": [row], "unanswered": 1, "incomplete": ["skills"],
            "tier2": {"counts": {"skills": 1, "memories": 0, "context": 0}}, "other_settings": {"count": 1}}
    monkeypatch.setattr(CLI, "_call_running", lambda method, route, body=None: (asked.append((method, route)), (view, None))[1])
    assert cli("handback") == 0 and asked == [("GET", "handback?full=1")]
    assert capsys.readouterr().out == ("Changed in the sandbox (profile work)\n  1  Script  scripts/x.sh  new\n"
                                       "Also changed: 1 skill, 1 other setting.\nNot fully checked: skills.\n")
    assert lay.name == "work"


# -- status ----------------------------------------------------------------------------------------------------

def test_the_launcher_status_says_whether_a_baseline_is_open(layout, tmp_path):  # noqa: F811
    sup = SR._supervisor(tmp_path, layout)
    assert sup.status()["handback"] == {"open": False, "stamp": H.stamp(layout.home, layout.state_dir), "kept": 0}
    H.take_baseline(layout.home, layout.state_dir)
    assert sup.status()["handback"] == {"open": True, "stamp": H.stamp(layout.home, layout.state_dir), "kept": 0}


def test_the_unsandboxed_status_counts_what_is_held(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    api = SR._plugin_api()
    monkeypatch.setattr(api._layout, "current_profile", lambda: lay)
    monkeypatch.setattr(api, "_capabilities", lambda spec=None: {"driver": "fake"})
    monkeypatch.setattr(api._switch, "switch_view", lambda layout_, **kw: {"available": True})
    assert api.status()["handback"] == {"open": True, "held": 0, "stamp": H.stamp(lay.home, lay.state_dir), "kept": 0}
    TH.put(lay.home / "scripts" / "planted.sh", "x\n")
    H.revert(lay.home, lay.state_dir, "all")
    H.close(lay.state_dir)
    assert api.status()["handback"] == {"open": False, "held": 1, "stamp": H.stamp(lay.home, lay.state_dir), "kept": 0}


def test_the_hand_back_folder_is_host_only(tmp_path):
    root = tmp_path / "root"
    named = L.ProfileLayout(name="work", home=root / "profiles" / "work", root=root)
    assert not str(named.state_dir / "handback").startswith(str(named.home))  # outside the home the sandbox is granted
    assert "handback" in W._HOST_ONLY_FILES  # and denied by name where the root itself is granted (Windows)
