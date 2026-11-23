"""A credential-named file that appears in the profile folder while the sandbox is on.

What a sandbox may not read at the top of the profile folder is listed when the sandbox starts: the stores Hermes
knows by name, present or not, and every entry there that Hermes calls a copy of one at that moment
(``layout.credential_paths``: ``.env.bak-<stamp>``, ``auth.json.<anything>``, ...). A copy made later is on no
list: Hermes's config migration leaves ``.env.bak-<stamp>`` beside ``.env``, a person copies ``.env`` to
``.env.bak``, a tool on this computer saves ``auth.json.old``. The launcher therefore looks at the top of the
folder about once a second while the sandbox runs and, for a name the start did not list, restarts the sandbox
through the restart a folder grant uses: the new start lists the entry, replies in flight are paused and continue.

No sandbox here: the supervisor's driver and start are stand-ins, the cards run against ``test_cards``'s fakes.
The names are judged by the Hermes on the path (``hermes_cli.profiles.profile_path_is_private``).
"""
import asyncio
import logging
import os
from pathlib import Path

import pytest
from test_cards import (FakeConn, _continuations, _interrupted_turn_ends, _interrupts, _settle,  # noqa: F401
                        _setup, _turn_start, harness)

from openshell.launcher import cards as C  # noqa: F401
from openshell.launcher import layout as L
from openshell.launcher import supervisor as S
from openshell.launcher.driver import SandboxDriver
from openshell.launcher.spec import load_spec
from openshell.launcher.supervisor import Supervisor

STAMPED = ".env.bak-20261120T224522Z"  # what Hermes's config migration leaves beside .env


# -- which names --------------------------------------------------------------------------------------

def _home(tmp_path) -> Path:
    home = tmp_path / "root" / "profiles" / "work"
    home.mkdir(parents=True)
    (home / ".env").write_text("MADE_UP_KEY=sk-made-up\n", encoding="utf-8")
    (home / "config.yaml").write_text("{}\n", encoding="utf-8")
    return home


def _listed(home: Path) -> frozenset:
    return L.listed_names(home, L.credential_paths(home))


def test_a_copy_of_the_keys_file_made_after_the_start_is_found(tmp_path):
    home = _home(tmp_path)
    listed = _listed(home)
    assert L.new_private_entries(home, listed) == []
    (home / STAMPED).write_bytes((home / ".env").read_bytes())
    assert L.new_private_entries(home, listed) == [STAMPED]


@pytest.mark.parametrize("name", [".env.bak", ".env.bak2", STAMPED, STAMPED + ".1", "auth.json.old",
                                  "auth.json.bak-1", "config.yaml.bak-20261120T224522Z"])
def test_every_name_hermes_calls_a_copy_of_a_store_is_found(tmp_path, name):
    home = _home(tmp_path)
    listed = _listed(home)
    (home / name).write_text("x", encoding="utf-8")
    assert L.new_private_entries(home, listed) == [name]


@pytest.mark.parametrize("name", [".env.lock", "notes.txt", "SOUL.md", "config.yaml.bak-my-note", "env.bak",
                                  "state.db"])
def test_an_ordinary_new_file_is_not(tmp_path, name):
    home = _home(tmp_path)
    listed = _listed(home)
    (home / name).write_text("x", encoding="utf-8")
    assert L.new_private_entries(home, listed) == []


def test_what_the_start_listed_is_not_found_again_present_or_absent(tmp_path):
    """A copy that was there at the start is hidden by that start. A store Hermes knows by name is listed by
    every start even when absent, so creating it later is no news either."""
    home = _home(tmp_path)
    (home / STAMPED).write_text("old copy", encoding="utf-8")
    listed = _listed(home)
    (home / "auth.json").write_text("{}", encoding="utf-8")
    (home / "mcp-tokens").mkdir()
    (home / STAMPED).write_text("rewritten", encoding="utf-8")
    assert L.new_private_entries(home, listed) == []


def test_names_are_compared_without_letter_case(tmp_path):
    """Hermes judges these names case-folded, and so does a volume that ignores case."""
    home = _home(tmp_path)
    assert L.listed_names(home, [home / ".ENV.Bak-X", home / "cache" / "below.json", tmp_path / "elsewhere"]) == {
        ".env.bak-x"}
    listed = _listed(home)
    (home / ".ENV.BAK9").write_text("x", encoding="utf-8")
    assert L.new_private_entries(home, listed) == [".ENV.BAK9"]
    assert L.new_private_entries(home, listed | {".env.bak9"}) == []


def test_a_home_that_cannot_be_listed_gives_nothing(tmp_path):
    assert L.new_private_entries(tmp_path / "gone", frozenset()) == []


def test_the_windows_deny_list_holds_a_copy_only_from_the_start_that_saw_it(tmp_path):
    """The deny list of a Windows sandbox is made at its start and fixed for its life: a copy that was there is
    on it, one made afterwards is on the next start's."""
    from openshell.launcher import openshell_windows as W

    home = _home(tmp_path)
    layout = L.ProfileLayout(name="work", home=home, root=tmp_path / "root")
    runtime = L.Runtime(python=tmp_path / "python.exe", code_dir=tmp_path / "code", env_dir=tmp_path / "env",
                        base_python=tmp_path / "base", store=None)

    def denied() -> set:
        grants = L.profile_grants(layout, runtime, [])
        return {os.path.normcase(path) for path in W.build_windows_policy(grants, {"egress": "deny", "allow": []}, [])[1]}

    copy = os.path.normcase(str(home / STAMPED))
    first = denied()
    assert os.path.normcase(str(home / ".env")) in first and copy not in first
    (home / STAMPED).write_bytes((home / ".env").read_bytes())
    assert copy in denied()


# -- the supervisor's look ---------------------------------------------------------------------------

class QuietDriver(SandboxDriver):
    name = "fake"
    uses_host_shell = False
    capabilities_info = {"label": "Fake"}

    def __init__(self):
        self.stops = 0

    def preflight(self):
        return {}

    def start(self, request):
        pass

    def exit_code(self):
        return None

    def stop(self, timeout=20.0):
        self.stops += 1

    def policy(self):
        return {}


def _supervisor(tmp_path, monkeypatch):
    """A running supervisor whose start is a stand-in that lists the home as a real start does."""
    home = _home(tmp_path)
    layout = L.ProfileLayout(name="work", home=home, root=tmp_path / "root")
    runtime = L.Runtime(python=tmp_path / "python.exe", code_dir=tmp_path, env_dir=tmp_path, base_python=tmp_path,
                        store=None)
    sup = Supervisor(layout, runtime, load_spec(layout), QuietDriver(), outer_port=1)
    starts = []

    async def start_locked():
        sup.state = "starting"
        sup._grants = L.profile_grants(layout, runtime, [])
        sup._listed_private = L.listed_names(home, sup._grants.denied)
        starts.append(sorted(p.name for p in sup._grants.denied if p.parent == home and p.exists()))
        sup.state = "running"

    sup._start_locked = start_locked
    monkeypatch.setattr(S, "PRIVATE_LOOK", 0.0)
    return sup, home, starts


def test_the_real_launch_request_records_what_it_listed(tmp_path):
    home = _home(tmp_path)
    (home / STAMPED).write_text("x", encoding="utf-8")
    layout = L.ProfileLayout(name="work", home=home, root=tmp_path / "root")
    runtime = L.Runtime(python=tmp_path / "python.exe", code_dir=tmp_path, env_dir=tmp_path, base_python=tmp_path,
                        store=None)
    sup = Supervisor(layout, runtime, load_spec(layout), QuietDriver(), outer_port=1)
    assert sup._listed_private is None  # nothing is looked for before a start listed the home
    sup._inner_port, sup._inner_token = 1, "inner"
    sup._launch_request({})
    assert {".env", "auth.json", STAMPED.casefold()} <= sup._listed_private
    assert os.path.normcase(str(home / STAMPED)) in {os.path.normcase(str(p)) for p in sup._grants.denied}


def test_a_new_copy_restarts_the_sandbox_with_it_listed(tmp_path, monkeypatch, caplog):
    sup, home, starts = _supervisor(tmp_path, monkeypatch)
    seen = []
    sup.on_down.append(lambda why: seen.append((why, sup.status()["restarting"])))

    async def main():
        await sup.start()
        assert await sup.hide_new_private() == []
        (home / STAMPED).write_bytes((home / ".env").read_bytes())
        with caplog.at_level(logging.WARNING, logger="openshell.supervisor"):
            assert await sup.hide_new_private() == [STAMPED]
        assert await sup.hide_new_private() == []  # listed by the new start: one restart, not one a second

    asyncio.run(main())
    assert starts == [[".env"], [".env", STAMPED]]
    assert sup.driver.stops == 1 and sup.state == "running"
    [(why, note)] = seen
    assert why == "restarting" and note["label"] == f"Restarting the sandbox to hide {STAMPED}"
    assert note["why"] == "hide" and note["hide"] == [STAMPED]
    assert [r.getMessage() for r in caplog.records if r.name == "openshell.supervisor"] == [
        f"profile work: {STAMPED} appeared in the profile folder while the sandbox was on; the sandbox restarts "
        "so that it cannot read it"]


def test_nothing_is_looked_for_while_no_sandbox_runs_or_a_restart_is_under_way(tmp_path, monkeypatch):
    sup, home, starts = _supervisor(tmp_path, monkeypatch)

    async def main():
        (home / STAMPED).write_text("x", encoding="utf-8")
        sup.state = "stopped"
        assert await sup.hide_new_private() == []  # never started: no list to compare with
        await sup.start()                          # the start lists it
        (home / ".env.bak").write_text("x", encoding="utf-8")
        sup.state = "restarting"
        assert await sup.hide_new_private() == []
        sup.state = "running"
        assert await sup.hide_new_private() == [".env.bak"]

    asyncio.run(main())
    assert len(starts) == 2


def test_the_look_is_taken_at_most_once_per_interval(tmp_path, monkeypatch):
    sup, home, starts = _supervisor(tmp_path, monkeypatch)
    monkeypatch.setattr(S, "PRIVATE_LOOK", 3600.0)
    looks = []
    real = L.new_private_entries
    monkeypatch.setattr(S, "new_private_entries", lambda *a: looks.append(1) or real(*a))

    async def main():
        await sup.start()
        for _ in range(5):
            await sup.hide_new_private()

    asyncio.run(main())
    assert len(looks) == 1


def test_the_first_look_is_due_at_once_on_a_computer_that_has_just_started(tmp_path, monkeypatch):
    """The monotonic clock counts from the start of the computer on some systems: a first look must not wait
    until that clock has passed the interval (here an interval no clock has reached)."""
    sup, home, starts = _supervisor(tmp_path, monkeypatch)
    monkeypatch.setattr(S, "PRIVATE_LOOK", 1e12)

    async def main():
        await sup.start()
        (home / STAMPED).write_text("x", encoding="utf-8")
        assert await sup.hide_new_private() == [STAMPED]

    asyncio.run(main())


def test_the_watch_loop_takes_the_look(tmp_path, monkeypatch):
    sup, home, starts = _supervisor(tmp_path, monkeypatch)
    monkeypatch.setattr(S, "WATCH_INTERVAL", 0.01)

    async def main():
        await sup.start()
        watcher = asyncio.create_task(sup.watch())
        await asyncio.sleep(0.05)
        (home / STAMPED).write_text("x", encoding="utf-8")
        for _ in range(200):
            if len(starts) == 2:
                break
            await asyncio.sleep(0.01)
        watcher.cancel()

    asyncio.run(main())
    assert starts == [[".env"], [".env", STAMPED]]


def test_copies_that_keep_appearing_stop_the_sandbox(tmp_path, monkeypatch):
    """The sandbox can write the profile folder, so it can make such names itself; each costs a restart. More
    than ``PRIVATE_LIMIT`` of them within ``GUARD_WINDOW`` seconds stop the sandbox with the reason."""
    sup, home, starts = _supervisor(tmp_path, monkeypatch)

    async def main():
        await sup.start()
        for n in range(S.PRIVATE_LIMIT + 1):
            (home / f".env.bak{n}").write_text("x", encoding="utf-8")
            await sup.hide_new_private()

    asyncio.run(main())
    assert len(starts) == 1 + S.PRIVATE_LIMIT  # the last one stops instead of restarting
    assert sup.state == "failed" and "kept appearing" in sup._last_error and "Turn the sandbox off" in sup._last_error


def test_a_restart_that_fails_is_reported_and_does_not_end_the_watch(tmp_path, monkeypatch):
    sup, home, starts = _supervisor(tmp_path, monkeypatch)

    async def main():
        await sup.start()

        async def broken():
            raise RuntimeError("no gateway")

        sup._start_locked = broken
        (home / STAMPED).write_text("x", encoding="utf-8")
        assert await sup.hide_new_private() == [STAMPED]  # the old sandbox is stopped either way

    asyncio.run(main())
    assert sup.driver.stops >= 1


# -- through the cards: replies in flight continue ---------------------------------------------------

def test_a_reply_in_flight_is_paused_and_continues_after_the_restart(harness):
    sup = harness["sup"]

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn, tool=False)
        await cards.hide_new([STAMPED])
        [interrupt] = _interrupts(conn)
        assert interrupt["params"] == {"session_id": "live1", "resume": True}  # a pause, not a stop
        assert sup.restarts == [] and cards.restart_queued()
        await _interrupted_turn_ends(cards, conn)
        for _ in range(200):
            if sup.restarts:
                break
            await asyncio.sleep(0.02)
        assert len(sup.restarts) == 1
        await _settle(80)
        [note] = sup.notes_seen
        assert note["label"] == f"Restarting the sandbox to hide {STAMPED}" and note["why"] == "hide"
        assert note["hide"] == [STAMPED] and note["reason"] is None
        [again] = _continuations(conn)
        assert again["params"]["session_id"] == "live1"
        assert "The sandbox restarted, which stopped your reply. Continue where you left off." in again["params"]["text"]
        assert STAMPED not in again["params"]["text"]  # the agent is not pointed at the file
        [said] = [e for e in cards._records if e.get("event") == "hiding"]  # the card log's line
        assert said["names"] == [STAMPED] and said["paused"] == ["chatA"]
        await cards.stop()

    asyncio.run(main())


def test_with_no_reply_in_flight_the_restart_does_not_wait_for_late_proposals(harness):
    """A folder answer waits ``SOON_QUIET`` after the last tool call so that late proposals become cards first.
    A copy of the keys file is readable meanwhile: this restart does not wait for them."""
    sup = harness["sup"]

    async def main():
        cards, conn = await _setup(harness, restart_quiet=C.RESTART_QUIET)
        cards._tool_seen = cards._clock()  # a tool call ended this instant
        started = cards._clock()
        await cards.hide_new([STAMPED])
        for _ in range(300):
            if sup.restarts:
                break
            await asyncio.sleep(0.01)
        assert len(sup.restarts) == 1
        assert cards._clock() - started < min(C.SOON_QUIET, C.RESTART_QUIET) - 0.5
        assert _interrupts(conn) == [] and _continuations(conn) == []
        await cards.stop()

    asyncio.run(main())


def test_two_copies_seen_together_cost_one_restart(harness):
    sup = harness["sup"]

    async def main():
        cards, conn = await _setup(harness)
        await cards.hide_new([STAMPED, "config.yaml.bak-20261120T224522Z"])
        for _ in range(200):
            if sup.restarts:
                break
            await asyncio.sleep(0.01)
        await _settle(30)
        assert len(sup.restarts) == 1
        assert sup.notes_seen[0]["label"] == (
            f"Restarting the sandbox to hide {STAMPED}, config.yaml.bak-20261120T224522Z")
        await cards.stop()

    asyncio.run(main())


def test_the_supervisor_hands_the_restart_to_the_cards_when_they_are_wired(tmp_path, monkeypatch):
    sup, home, starts = _supervisor(tmp_path, monkeypatch)
    asked = []

    async def hide_new(names):
        asked.append(list(names))

    sup.on_private = hide_new

    async def main():
        await sup.start()
        (home / STAMPED).write_text("x", encoding="utf-8")
        assert await sup.hide_new_private() == [STAMPED]
        assert await sup.hide_new_private() == []  # asked once; the cards' restart lists it

    asyncio.run(main())
    assert asked == [[STAMPED]] and len(starts) == 1 and sup.driver.stops == 0


def test_the_launcher_wires_the_cards_to_the_supervisor():
    source = (Path(L.__file__).resolve().parent.parent / "launcher_cli.py").read_text(encoding="utf-8")
    assert "sup.on_private = cards.hide_new" in source
