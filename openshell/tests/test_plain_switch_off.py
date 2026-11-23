"""A switch-off with nothing planted is plain: no row, no question.

The hand-back (launcher/handback.py) compares the profile home with the record taken at switch-on. Only what the
sandbox can write is compared. The folders every launch grants it read-only (``layout.sandbox_readonly_dirs``: the
plugin folders) are left out, so the bytecode Python writes beside a plugin's sources when the launcher and
``hermes`` commands import it, and a plugin update made while the sandbox is on, are never rows. Bytecode in a
folder the sandbox can write is a file that runs here like any other, and stays a row.

The last tests replay one whole session of ordinary use (the launcher starting and restarting, host commands, a
key saved and folders and websites written through the launcher, a plugin update, the sandboxed backend's own
writes) and end with an empty list and a switch-off that asks nothing, on the code paths of both operating
systems. Everything runs in temp folders; nothing starts a sandbox.
"""
import asyncio
import json
import os
import py_compile
import sys

import pytest

import test_handback as TH
import test_openshell_driver as LD
import test_openshell_windows as WD
import test_settings_routes as SR
from openshell.launcher import handback as H
from openshell.launcher import host_routes as HR
from openshell.launcher import layout as L
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_windows as W
from openshell.launcher import pins as P
from openshell.launcher import switch as SW
from openshell.launcher.driver import LaunchRequest
from test_handback import box, by_id, put, taken  # noqa: F401  (fixtures and helpers)
from test_handback_wiring import _ids, _off, _send, cli  # noqa: F401
from test_pins import layout, writes  # noqa: F401
from test_switch_flow import env  # noqa: F401

PLUGIN = "plugins/openshell"
SOURCES = {f"{PLUGIN}/__init__.py": "X = 1\n", f"{PLUGIN}/launcher/__init__.py": "", f"{PLUGIN}/launcher/switch.py": "Y = 2\n",
           f"{PLUGIN}/dashboard/plugin_api.py": "Z = 3\n", "desktop-plugins/notes/hook.py": "W = 4\n"}


def _install_plugin(home):
    for rel, text in SOURCES.items():
        put(home / rel, text)
    put(home / "plugins" / ".install-metadata.json", '{"openshell": {"commit": "1111111"}}\n')


def _host_imports(home) -> list:
    """What a host Python leaves beside a plugin's sources when it imports them: ``__pycache__/<name>.<tag>.pyc``,
    written by the interpreter itself."""
    made = []
    for rel in SOURCES:
        source = home / rel
        # where the interpreter puts it without a bytecode prefix of its own (the test run may have one)
        target = source.parent / "__pycache__" / f"{source.stem}.{sys.implementation.cache_tag}.pyc"
        py_compile.compile(str(source), cfile=str(target), doraise=True)
        made.append(target.relative_to(home).as_posix())
    return made


# -- the rule, both ways ------------------------------------------------------------------------------------------

def test_bytecode_the_host_writes_beside_a_plugin_is_not_listed(box):  # noqa: F811
    home, state, _ = box
    _install_plugin(home)
    H.take_baseline(home, state)
    made = _host_imports(home)
    assert len(made) == 5 and all("/__pycache__/" in rel and (home / rel).is_file() for rel in made)
    view = H.diff(home, state)
    assert view["rows"] == [] and view["unanswered"] == 0 and view["incomplete"] == []
    assert H.revert(home, state, "all")["reverted"] == [] and all((home / rel).is_file() for rel in made)  # left alone


PLANTED = [("scripts/__pycache__/helper.cpython-314.pyc", "Script"),
           ("hooks/notify/__pycache__/handler.cpython-314.pyc", "Hook file"),
           ("scripts/lib/__pycache__/deep.cpython-311.pyc", "Script")]


@pytest.mark.parametrize("rel,label", PLANTED, ids=[c[0] for c in PLANTED])
def test_bytecode_in_a_folder_the_sandbox_can_write_is_a_row(box, rel, label):  # noqa: F811
    """A cron job's script or a hook handler imports its neighbours through these files: what the sandbox puts
    there runs on this computer once the sandbox is off."""
    home, state = taken(box)
    before = TH.tree_bytes(home)
    put(home / rel, b"\x00planted bytecode")
    view = H.diff(home, state)
    assert [(r["id"], r["kind"], r["tier"], r["label"], r["detail"]) for r in view["rows"]] == [
        (f"file:{rel}", "file_new", 1, label, "new")]
    assert view["unanswered"] == 1  # it needs an answer
    assert H.revert(home, state, "all")["reverted"] == [f"file:{rel}"]
    assert TH.tree_bytes(home) == before and not (home / rel).parent.exists()  # the folder it came in goes with it


def test_bytecode_for_a_script_of_the_users_own_is_compared_too(box):  # noqa: F811
    home, state, _ = box
    cached = put(home / "scripts" / "__pycache__" / "backup.cpython-314.pyc", b"\x00the user's own")
    H.take_baseline(home, state)
    assert H.diff(home, state)["rows"] == []
    cached.write_bytes(b"\x00swapped by the sandbox")
    row = by_id(H.diff(home, state))["file:scripts/__pycache__/backup.cpython-314.pyc"]
    assert (row["kind"], row["label"], row["can_restore"]) == ("file_changed", "Script", True)
    H.revert(home, state, "all")
    assert cached.read_bytes() == b"\x00the user's own"


def test_a_plugin_updated_on_this_computer_while_the_sandbox_is_on_is_not_listed(box):  # noqa: F811
    home, state, _ = box
    _install_plugin(home)
    H.take_baseline(home, state)
    put(home / PLUGIN / "__init__.py", "X = 2  # updated\n")                       # changed
    put(home / PLUGIN / "launcher" / "handback.py", "NEW = True\n")                # new
    (home / PLUGIN / "dashboard" / "plugin_api.py").unlink()                       # removed
    put(home / "plugins" / ".install-metadata.json", '{"openshell": {"commit": "2222222"}}\n')
    put(home / "plugins" / "another" / "plugin.yaml", "name: another\n")           # a plugin installed meanwhile
    put(home / "desktop-plugins" / "notes" / "plugin.js", "export default {}\n")
    (home / "plugins" / "p1" / "__init__.py").unlink()                             # one uninstalled
    view = H.diff(home, state)
    assert view["rows"] == [] and view["unanswered"] == 0


def test_a_link_a_plugin_install_makes_on_this_computer_is_not_listed(box):  # noqa: F811
    home, state, outside = box
    _install_plugin(home)
    H.take_baseline(home, state)
    TH.symlink(outside / "dir", home / "plugins" / "dev-linked", is_dir=True)  # a development install
    assert H.diff(home, state)["rows"] == []
    TH.symlink(outside / "dir", home / "scripts" / "linked", is_dir=True)  # the same in a folder the sandbox writes
    assert _ids(H.diff(home, state)) == ["link:scripts/linked"]


def test_a_record_taken_by_an_older_version_does_not_turn_the_plugin_folders_into_rows(box, monkeypatch):  # noqa: F811
    """A sandbox switched on before this rule recorded the plugin folders. Updated while it is on, the launcher
    compares that record: nothing there is listed, removed files included."""
    home, state, _ = box
    _install_plugin(home)
    with monkeypatch.context() as older:
        older.setattr(H, "host_written_trees", lambda: ())
        H.take_baseline(home, state)
    base = json.loads((state / "handback" / "baseline.json").read_text(encoding="utf-8"))
    assert f"{PLUGIN}/__init__.py" in base["manifest"]  # the older record names them
    _host_imports(home)
    put(home / PLUGIN / "__init__.py", "X = 2\n")
    (home / PLUGIN / "launcher" / "switch.py").unlink()
    view = H.diff(home, state)
    assert view["rows"] == [] and view["unanswered"] == 0
    put(home / "scripts" / "planted.sh", "#!/bin/sh\nid\n")
    assert _ids(H.diff(home, state)) == ["file:scripts/planted.sh"]  # the rest of that record still compares


def test_a_setting_that_names_a_file_in_a_plugin_folder_does_not_make_that_file_a_row(box):  # noqa: F811
    home, state, _ = box
    _install_plugin(home)
    put(home / PLUGIN / "bin" / "server.py", "print('server')\n")
    TH.edit_config(home, lambda doc: doc["mcp_servers"].update(
        plugin={"command": "python", "args": [f"{PLUGIN}/bin/server.py"]}))
    H.take_baseline(home, state)
    base = json.loads((state / "handback" / "baseline.json").read_text(encoding="utf-8"))
    assert f"{PLUGIN}/bin/server.py" not in base["manifest"] and "tools/server.js" in base["manifest"]
    assert not (state / "handback" / "base" / "plugins").exists()  # nor is a copy of it kept
    put(home / PLUGIN / "bin" / "server.py", "print('server 2')\n")  # the plugin's update, on this computer
    assert H.diff(home, state)["rows"] == []
    put(home / "tools" / "server.js", "console.log('changed inside')\n")  # a named file the sandbox can write
    assert _ids(H.diff(home, state)) == ["file:tools/server.js"]


def test_with_the_decision_turned_the_plugin_folders_are_compared_again(box, monkeypatch):  # noqa: F811
    home, state, _ = box
    _install_plugin(home)
    TH.compare_plugin_folders(monkeypatch)
    H.take_baseline(home, state)
    made = _host_imports(home)
    assert _ids(H.diff(home, state)) == sorted(f"file:{rel}" for rel in made)


# -- the rule is the grant: what is not compared is what both drivers keep the sandbox from writing ------------------

def test_what_is_not_compared_is_exactly_what_every_launch_grants_read_only_in_the_home(tmp_path):
    lay, runtime = LD._layout(tmp_path), LD._runtime(tmp_path)
    grants = L.profile_grants(lay, runtime, [])
    skipped = set(H.host_written_trees())
    assert skipped == set(L.sandbox_readonly_dirs()) == {"plugins", "desktop-plugins"}
    in_home_read_only = {p.name for p in grants.readonly if p.parent == lay.home}
    assert in_home_read_only == skipped and lay.home in grants.readwrite
    assert not skipped & {p.name for p in grants.readwrite}
    # everything else the hand-back watches is in the folder the sandbox writes
    assert set(H.TIER1_TREES) - skipped == set(H.COPIED_TREES) == {"scripts", "hooks"}


def test_the_linux_driver_mounts_those_folders_read_only(tmp_path):
    lay, runtime = LD._layout(tmp_path), LD._runtime(tmp_path)
    grants = L.profile_grants(lay, runtime, [])
    req = LaunchRequest(sandbox_id="x", argv=[], cwd=tmp_path, env={}, grants=grants, network={}, log_path=tmp_path / "l",
                        config_dir=lay.state_dir, home=lay.home, folders=[])
    plan = OD.plan_mounts(req, OD.ensure_masks(lay.state_dir))
    by_target = {m["target"]: m for m in plan.mounts}
    assert by_target[str(lay.home)]["read_only"] is False
    for name in H.host_written_trees():
        assert by_target[str(lay.home / name)]["read_only"] is True, name
        assert str(lay.home / name) not in plan.read_write


def test_the_windows_driver_lists_those_folders_read_only_and_rename_safe(tmp_path):
    lay, runtime, _cfg, _bb = WD._tree(tmp_path)
    grants = L.profile_grants(lay, runtime, [])
    policy, _denied, _notes = W.build_windows_policy(grants, {"egress": "deny", "allow": []}, [])
    fs = policy["filesystem_policy"]
    for name in H.host_written_trees():
        folder = lay.home / name
        assert W.native(folder) in fs["read_only"] and W.native(folder) not in fs["read_write"], name
        assert W._access(folder / "openshell" / "x.py", grants.readonly, grants.readwrite, []) == "ro"
        # no folder above it that the sandbox could rename to carry it away from its read-only grant
        assert W.rename_exposure(folder, grants.readonly, grants.readwrite, []) is None
    assert W._access(lay.home / "scripts" / "x.sh", grants.readonly, grants.readwrite, []) == "rw"


# -- one whole session of ordinary use ----------------------------------------------------------------------------

def _users_home(lay):
    """The profile before the first switch-on: the user's own settings, job, script, text and plugin."""
    home = lay.home
    put(home / "config.yaml", (home / "config.yaml").read_bytes() + b"plugins:\n  enabled:\n    - openshell\n  disabled: []\n")
    put(home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB))
    put(home / "scripts" / "backup.sh", "#!/bin/sh\necho backup\n")
    put(home / "skills" / "writing" / "SKILL.md", "---\nname: writing\n---\nWrite well.\n")
    put(home / "memories" / "MEMORY.md", "likes tea\n")
    put(home / "SOUL.md", "You are helpful.\n")
    put(home / "auth.json", '{"version": 1}\n')
    _install_plugin(home)


def _the_backends_own_writes(home):
    """What the sandboxed backend writes in an ordinary session: its sessions and state, memories and skills
    (text the agent reads), the run state of the user's cron job and its output, caches, logs, lock files, and an
    ordinary setting in config.yaml through Hermes's own writer."""
    put(home / "sessions" / "20300101-000000.json", '{"messages": []}\n')
    put(home / "state.db", b"SQLite format 3\x00" + b"\x01" * 64)
    put(home / "state.db-wal", b"\x02" * 32)
    put(home / "projects.db", b"SQLite format 3\x00")
    put(home / ".skills_prompt_snapshot.json", "{}\n")
    put(home / ".env.lock", "")
    put(home / "auth.lock", "")
    put(home / "memories" / "MEMORY.md", "likes tea\nasked for a hello today\n")
    put(home / "skills" / "notes" / "SKILL.md", "---\nname: notes\n---\nKeep notes.\n")
    job = {**TH.JOB, "last_run_at": "2030-01-01T01:00:00+00:00", "next_run_at": "2030-01-01T02:00:00+00:00",
           "repeat": {"times": None, "completed": 4}, "last_status": "ok"}
    put(home / "cron" / "jobs.json", TH.jobs_bytes(job))
    put(home / "cron" / "output" / "aaaaaaaaaaaa" / "2030-01-01.md", "backup\n")
    put(home / "cron" / ".tick.lock", "")
    put(home / "cache" / "web" / "page.html", "<html></html>\n")
    put(home / "runtime" / "active.json", "{}\n")
    put(home / "workspace" / "notes.txt", "scratch\n")
    put(home / "logs" / "agent.log", "turn done\n")
    put(home / "logs" / "errors.log", "")
    TH.edit_config(home, lambda doc: doc.update(onboarding={"seen": {"profile_build_offered": True}}))


def _ordinary_session(lay, routes, sup, tmp_path):
    """The session, in order. Returns nothing: every step is one a user or the product makes without the sandbox
    having planted anything."""
    home = lay.home
    # the launcher starting, restarting the sandbox, and starting again (a login): its own writes to the home
    async def starts():
        await sup.start()
        await sup.restart()
        await sup.stop()
        await sup.start()
        await sup.stop()

    asyncio.run(starts())
    # host commands under the marked profile (`hermes -p work sandbox status`, `status`, `config show`): what they
    # leave in the home is their log lines and the bytecode of the plugin they import
    put(home / "logs" / "agent.log", "host command\n")
    _host_imports(home)
    # the list itself, read by the page and by `sandbox handback`
    assert _send(routes, "GET", "handback")[0] == 200
    # a key saved through the launcher's host route (the Keys page)
    status, payload, _ = asyncio.run(routes.match("PUT", "/api/plugins/openshell/keys")(
        SR.REQ, json.dumps({"key": "NEW_API_KEY", "value": "sk-new"}).encode()))
    assert status == 200 and payload["ok"] is True
    # a website rule and a folder grant written through the launcher (what an Allow on a card saves)
    shared = tmp_path / "shared"
    shared.mkdir()
    assert SR._call(routes, "PUT", "network", {"egress": "deny", "allow": [{"cidr": "203.0.113.7", "port": 443}]})[0] == 200
    assert SR._call(routes, "PUT", "folders", {"folders": [{"path": str(shared), "access": "ro"}]})[0] == 200
    # a plugin update on this computer while the sandbox is on
    put(home / PLUGIN / "__init__.py", "X = 2  # updated\n")
    put(home / PLUGIN / "README.md", "updated\n")
    put(home / "plugins" / ".install-metadata.json", '{"openshell": {"commit": "2222222"}}\n')
    for cached in list((home / PLUGIN).rglob("*.pyc")):  # an update replaces the folder; the next import compiles again
        cached.unlink()
    _host_imports(home)
    _the_backends_own_writes(home)


@pytest.fixture(params=["windows", "linux"])
def either_os(request, monkeypatch):
    """The two places where the hand-back's and the pins' code differs by operating system."""
    windows = request.param == "windows"
    monkeypatch.setattr(P, "stores_replaceable_inside", lambda windows_=None: windows)
    monkeypatch.setattr(H, "_READERS", 8 if windows else 1)
    return request.param


def test_a_session_of_ordinary_use_ends_with_an_empty_list_and_a_plain_switch_off(layout, tmp_path, monkeypatch, either_os):  # noqa: F811
    from hermes_cli.web_routers import config_env

    async def set_env_var(model, profile):
        path = layout.home / ".env"
        put(path, path.read_text(encoding="utf-8") + f"{model.key}={model.value}\n")
        return {"ok": True, "key": model.key}

    monkeypatch.setattr(config_env, "set_env_var", set_env_var)
    _users_home(layout)
    # the switch-on: pin, then the record of the home (switch.turn_on's order)
    P.take(layout)
    assert H.take_baseline(layout.home, layout.state_dir)["taken"] is True
    sup = SR._supervisor(tmp_path, layout)
    log = []
    monkeypatch.setattr(HR, "unregister", lambda lay, runtime: log.append("unregistered"))
    monkeypatch.setattr(HR, "clear_marker", lambda lay: (log.append("clear"), True)[1])
    routes = HR.HostRoutes(sup, lambda: None)
    _ordinary_session(layout, routes, sup, tmp_path)

    view = H.diff(layout.home, layout.state_dir)
    assert view["rows"] == [] and view["unanswered"] == 0 and view["incomplete"] == []
    assert view["tier2"]["counts"] == {"skills": 1, "memories": 1, "context": 0}  # counted, never asked about
    assert view["other_settings"]["paths"] == ["onboarding.seen"]
    status, shown, _ = _send(routes, "GET", "handback")
    assert status == 200 and shown["rows"] == [] and shown["kept"] == []
    assert sup.status()["handback"]["open"] is True and sup.status()["handback"]["kept"] == 0

    status, payload, _ = _off(routes)  # no answer given: none is needed
    assert status == 200 and payload["state"] == "off" and payload["marker_cleared"] is True
    assert payload["handback"] == {"reverted": [], "kept": [], "held": None}
    assert log == ["unregistered", "clear"] and not H.is_open(layout.state_dir) and not P.present(layout)
    # the key the user saved is in the home's own file, the plugin as updated, nothing moved out of the home
    assert "NEW_API_KEY=sk-new" in (layout.home / ".env").read_text(encoding="utf-8")
    assert (layout.home / PLUGIN / "__init__.py").read_text(encoding="utf-8") == "X = 2  # updated\n"
    assert TH.held_dirs(layout.state_dir) == [] and not (layout.state_dir / "quarantine").exists()


def test_from_a_terminal_the_same_session_turns_off_without_a_question(env, cli, capsys, tmp_path, either_os):  # noqa: F811
    lay = env["layout"]
    put(lay.home / "config.yaml", "model:\n  provider: custom\n  base_url: http://127.0.0.1:18500/v1\n  key_env: MODEL_API_KEY\n")
    put(lay.home / ".env", "MODEL_API_KEY=sk-model\n")
    _users_home(lay)
    P.take(lay)
    H.take_baseline(lay.home, lay.state_dir)
    env["markers"].marked.add("work")
    _host_imports(lay.home)
    put(lay.home / "plugins" / ".install-metadata.json", '{"openshell": {"commit": "2222222"}}\n')
    put(lay.home / PLUGIN / "README.md", "updated\n")
    _the_backends_own_writes(lay.home)
    assert cli("handback") == 0
    assert capsys.readouterr().out == ("No sandbox changes to review for profile 'work'.\n"
                                       "Also changed: 1 skill, 1 memory, 1 other setting.\n")
    assert cli("off") == 0  # not 3: nothing to answer
    out = capsys.readouterr()
    assert json.loads(out.out) == {"stopped": "service", "marker_cleared": True, "state": "off",
                                   "handback": {"reverted": [], "kept": [], "held": None}}
    assert out.err == "" and "work" not in env["markers"].marked and not H.is_open(lay.state_dir)


def test_the_same_session_with_one_thing_planted_still_asks(env, cli, capsys, either_os):  # noqa: F811
    """The control for the two tests above: the list is empty because nothing was planted, not because it is blind."""
    lay = env["layout"]
    put(lay.home / "config.yaml", "model:\n  provider: custom\n  base_url: http://127.0.0.1:18500/v1\n  key_env: MODEL_API_KEY\n")
    _users_home(lay)
    P.take(lay)
    H.take_baseline(lay.home, lay.state_dir)
    env["markers"].marked.add("work")
    _host_imports(lay.home)
    _the_backends_own_writes(lay.home)
    put(lay.home / "scripts" / "__pycache__" / "backup.cpython-314.pyc", b"\x00planted")
    assert cli("off") == 3
    out = capsys.readouterr()
    assert out.out == ("Changed in the sandbox (profile work)\n"
                       "  1  Script  scripts/__pycache__/backup.cpython-314.pyc  new\n"
                       "Also changed: 1 skill, 1 memory, 1 other setting.\n")
    assert out.err == "hermes sandbox: 1 change needs an answer. Run again with --revert or --keep.\n"
    assert "work" in env["markers"].marked and H.is_open(lay.state_dir)
