"""The switch-off review when something the sandbox wrote cannot be compared (launcher/handback.py, and the
hand-back steps of launcher/switch.py).

A value the sandbox wrote into a file the review parses (a cron record with a field of the wrong type, a settings
file that refers to itself, a file nested too deep) takes away that file's own rows at most: the file is one row,
"could not be compared", that a revert restores whole from the copy taken at switch-on, and every other change
keeps its row. A folder with more files than one listing takes is a row too. When no list can be made at all, a
revert puts the saved copies back without one and says what it reverted; one that reverted nothing says so, and
the command fails. A revert that runs out of time changes nothing after its answer.
Everything runs in temp folders with stand-ins for the service and the launcher; nothing starts a sandbox.
"""
import json
import time

import pytest

import test_handback as TH
from openshell.launcher import handback as H
from openshell.launcher import switch as SW
from test_handback import box  # noqa: F401  (fixture: a profile home, the state folder, a folder outside)
from test_handback_wiring import _in_use, _off, _switched_on, cli  # noqa: F401  (fixture: `hermes -p work sandbox ...`)
from test_review_before_on import _unanswered
from test_switch_flow import _on, _routes, env  # noqa: F401  (the switch fixture)

SCRIPT = "file:scripts/backup.sh"
PLANTED = {**TH.JOB, "id": "bbbbbbbbbbbb", "name": "planted"}
NO_LIST = "RuntimeError: the folder cannot be listed"


def _change_the_script(home) -> None:
    TH.put(home / "scripts" / "backup.sh", "#!/bin/sh\necho changed in the sandbox\n")


def _script_is_back(home) -> bool:
    return (home / "scripts" / "backup.sh").read_bytes() == b"#!/bin/sh\necho backup\n"


def _job_ids(home) -> list:
    return [job["id"] for job in json.loads((home / "cron" / "jobs.json").read_bytes())["jobs"]]


def _fails(*args, **kwargs):
    raise RuntimeError("a value it cannot walk")


def _no_list(monkeypatch, wait: float = 0.0) -> None:
    """The look at the whole home cannot be made: it fails, or (with *wait*) comes back too late."""
    def scan(*args, **kwargs):
        time.sleep(wait)
        raise RuntimeError("the folder cannot be listed")

    monkeypatch.setattr(H, "_Scan", scan)


# -- a value the sandbox wrote that cannot be compared ---------------------------------------------------------

@pytest.mark.parametrize("skills", [True, 7, {"a": 1}, [1, None, {"x": 1}]])
def test_one_unreadable_cron_record_keeps_the_other_rows(box, skills):  # noqa: F811
    home, state = TH.taken(box)
    _change_the_script(home)
    TH.put(home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB, {**PLANTED, "skills": skills}))
    rows = TH.by_id(H.diff(home, state))
    assert sorted(rows) == ["cron:bbbbbbbbbbbb", SCRIPT] and rows["cron:bbbbbbbbbbbb"]["kind"] == "cron_new"
    done = H.revert(home, state, "all")
    assert done["reverted"] == ["cron:bbbbbbbbbbbb", SCRIPT] and done["left"] == []
    assert _script_is_back(home) and _job_ids(home) == ["aaaaaaaaaaaa"]
    assert H.diff(home, state)["rows"] == []


@pytest.mark.parametrize("added", [b"zz: &a [*a]\n", b"zz: &a {k: *a}\n", b"zz: " + b"[" * 3000 + b"]" * 3000 + b"\n"],
                         ids=["a list that holds itself", "a map that holds itself", "nested 3000 deep"])
def test_a_settings_file_that_cannot_be_walked_is_one_row_and_the_others_stay(box, added):  # noqa: F811
    home, state = TH.taken(box)
    _change_the_script(home)
    TH.put(home / "config.yaml", TH.CONFIG + added)
    rows = TH.by_id(H.diff(home, state))
    assert sorted(rows) == ["cfgfile:config.yaml", SCRIPT]
    assert rows["cfgfile:config.yaml"]["kind"] == "config_file" and rows["cfgfile:config.yaml"]["can_restore"] is True
    done = H.revert(home, state, "all")
    assert done["reverted"] == ["cfgfile:config.yaml", SCRIPT] and done["left"] == []
    assert (home / "config.yaml").read_bytes() == TH.CONFIG and _script_is_back(home)


def test_a_jobs_file_nested_too_deep_is_one_row_and_the_others_stay(box):  # noqa: F811
    home, state = TH.taken(box)
    _change_the_script(home)
    deep = "[" * 100000 + "]" * 100000
    TH.put(home / "cron" / "jobs.json", '{"jobs": [{"id": "deep", "prompt": "p", "schedule": %s}]}' % deep)
    rows = TH.by_id(H.diff(home, state))
    assert sorted(rows) == ["cronfile:cron/jobs.json", SCRIPT]
    done = H.revert(home, state, "all")
    assert done["reverted"] == ["cronfile:cron/jobs.json", SCRIPT] and done["left"] == []
    assert (home / "cron" / "jobs.json").read_bytes() == TH.jobs_bytes(TH.JOB) and _script_is_back(home)


@pytest.mark.parametrize("step, row", [("_tier1", "cfgfile:config.yaml"), ("_job_runs", "cron:bbbbbbbbbbbb")])
def test_a_comparison_that_fails_is_one_row_and_the_other_comparisons_keep_theirs(box, monkeypatch, step, row):  # noqa: F811
    home, state = TH.taken(box)
    _change_the_script(home)
    TH.edit_config(home, lambda doc: doc["mcp_servers"].update(planted={"command": "/bin/sh"}))
    TH.put(home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB, PLANTED))
    assert sorted(TH.by_id(H.diff(home, state))) == ["cfg:mcp_servers.planted", "cron:bbbbbbbbbbbb", SCRIPT]
    real = getattr(H, step)
    monkeypatch.setattr(H, step, _fails)
    rows = TH.by_id(H.diff(home, state))
    config_row = "cfgfile:config.yaml" if step == "_tier1" else "cfg:mcp_servers.planted"
    assert sorted(rows) == sorted([config_row, "cron:bbbbbbbbbbbb", SCRIPT])
    assert rows[row]["detail"] == "could not be compared" and rows[row]["can_restore"] is True
    done = H.revert(home, state, "all")
    assert sorted(done["reverted"]) == sorted(rows) and done["left"] == []
    monkeypatch.setattr(H, step, real)
    assert H.diff(home, state)["rows"] == [] and _script_is_back(home) and _job_ids(home) == ["aaaaaaaaaaaa"]


def test_a_file_that_cannot_be_compared_and_did_not_change_is_no_row(box, monkeypatch):  # noqa: F811
    home, state = TH.taken(box)
    _change_the_script(home)
    monkeypatch.setattr(H, "_tier1", _fails)
    assert sorted(TH.by_id(H.diff(home, state))) == [SCRIPT]


def test_a_job_value_that_is_no_text_does_not_stop_the_revert(box):  # noqa: F811
    home, state = TH.taken(box)
    _change_the_script(home)
    TH.put(home / "cron" / "jobs.json", json.dumps({"jobs": [{**TH.JOB, "last_error": "x \ud800 y"}, PLANTED]}))
    done = H.revert(home, state, "all")
    assert done["reverted"] == ["cron:bbbbbbbbbbbb", SCRIPT] and done["left"] == []
    jobs = json.loads((home / "cron" / "jobs.json").read_bytes())["jobs"]
    assert [job["id"] for job in jobs] == ["aaaaaaaaaaaa"] and jobs[0]["last_error"] == "x \ud800 y"
    assert _script_is_back(home)


def test_a_revert_step_that_breaks_is_named_and_the_other_steps_are_reported(box, monkeypatch):  # noqa: F811
    home, state = TH.taken(box)
    _change_the_script(home)
    TH.put(home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB, PLANTED))
    monkeypatch.setattr(H._Revert, "cron_jobs", _fails)
    done = H.revert(home, state, "all")
    assert done["reverted"] == [SCRIPT] and done["left"] == ["cron:bbbbbbbbbbbb"]
    assert done["skipped"] == [{"id": "cron:bbbbbbbbbbbb", "reason": "could not be changed (RuntimeError)"}]
    assert _script_is_back(home) and [row["id"] for row in H.held(state)[0]["rows"]] == [SCRIPT]


# -- a folder with more files than one listing takes -------------------------------------------------------------

def test_a_folder_with_more_files_than_one_listing_takes_is_a_row_and_a_revert_empties_it_of_new_files(box, monkeypatch):  # noqa: F811
    home, state = TH.taken(box)
    before = TH.tree_bytes(home)
    _change_the_script(home)
    for n in range(60):
        TH.put(home / "scripts" / f"aaa_{n:03d}.txt", "x\n")
    TH.put(home / "scripts" / "sub" / "deeper.sh", "#!/bin/sh\n")
    TH.put(home / "hooks" / "planted" / "handler.py", "def handle(event, ctx):\n    return None\n")
    monkeypatch.setattr(H, "MAX_ENTRIES", 40)
    view = H.diff(home, state)
    rows = TH.by_id(view)
    assert view["incomplete"] == ["scripts"] and view["unanswered"] == len(rows)
    assert rows["folder:scripts"]["detail"] == "too many files to compare"
    assert rows["folder:scripts"]["can_restore"] is True
    assert "file:hooks/planted/handler.py" in rows  # every watched folder has a limit of its own
    done = H.revert(home, state, "all")
    assert "folder:scripts" in done["reverted"] and done["left"] == []
    assert TH.tree_bytes(home) == before
    monkeypatch.setattr(H, "MAX_ENTRIES", 50_000)
    assert H.diff(home, state)["rows"] == []


# -- no list at all: what a revert does ---------------------------------------------------------------------------

@pytest.mark.parametrize("wait", [0.0, 1.5], ids=["the list fails", "the list comes back too late"])
def test_revert_puts_the_saved_copies_back_when_the_list_cannot_be_made(env, monkeypatch, wait):  # noqa: F811
    lay = _switched_on(env)
    before = TH.tree_bytes(lay.home)
    TH.plant_the_four(lay.home)
    _change_the_script(lay.home)
    if wait:
        monkeypatch.setattr(SW, "HANDBACK_TIMEOUT", 0.3)
    _no_list(monkeypatch, wait)
    status, payload, _ = _off(_routes(env, monkeypatch, []), "revert")
    done = payload["handback"]
    assert status == 200 and payload["marker_cleared"] is True
    assert env["log"] == ["sandbox stopped", "unregistered", "clear"]  # the switch turned off all the same
    assert done["reverted"] == ["cfgfile:config.yaml", "cronfile:cron/jobs.json", SCRIPT,
                                "file:scripts/cron-injected.sh", "file:scripts/hook-injected.sh"]
    why = "TimeoutError: took longer than 0.3 seconds" if wait else NO_LIST
    assert "error" not in done and done["problem"] == (
        f"Couldn't review the sandbox's changes ({why}). Reverted from the copies saved at switch-on: "
        "config.yaml, cron/jobs.json, scripts/backup.sh and 2 more.")
    assert TH.tree_bytes(lay.home) == before
    assert H.is_open(lay.state_dir)  # nobody listed that session: the next switch-on reviews it


def test_a_revert_that_reverted_nothing_says_so_and_the_command_fails(env, cli, capsys, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    env["markers"].marked.add("work")
    TH.put(lay.home / "skills" / "planted" / "SKILL.md", "new\n")  # nothing a copy was kept of
    _no_list(monkeypatch)
    assert cli("off", "--revert") == 1
    out = capsys.readouterr()
    answer = json.loads(out.out)
    assert answer["state"] == "off" and answer["marker_cleared"] is True and "work" not in env["markers"].marked
    assert answer["handback"] == {"reverted": [], "kept": [], "held": None, "error": NO_LIST}
    assert out.err == (f"hermes sandbox: Couldn't review the sandbox's changes ({NO_LIST}). Nothing was reverted. "
                       "The sandbox is off.\n")


def test_keep_and_no_answer_still_turn_off_without_a_list_and_the_command_succeeds(env, cli, capsys, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    _change_the_script(lay.home)
    _no_list(monkeypatch)
    for answer in ((), ("--keep",)):
        env["markers"].marked.add("work")
        assert cli("off", *answer) == 0
        out = capsys.readouterr()
        assert json.loads(out.out)["handback"]["reverted"] == [] and "work" not in env["markers"].marked
        assert out.err == f"hermes sandbox: Couldn't review the sandbox's changes ({NO_LIST}). The sandbox is off.\n"
    assert not _script_is_back(lay.home)


def test_revert_at_the_next_switch_on_puts_the_copies_back_when_the_list_cannot_be_made(env, monkeypatch):  # noqa: F811
    lay = _unanswered(env)
    _no_list(monkeypatch)
    with pytest.raises(SW.SwitchError) as err:
        _on(env)
    assert str(err.value) == f"Couldn't review the last sandbox session's changes ({NO_LIST})."
    done = SW.previous_session(lay, "revert")
    assert done["reverted"] == ["cfgfile:config.yaml", "cronfile:cron/jobs.json", "file:scripts/cron-injected.sh",
                                "file:scripts/hook-injected.sh"]
    assert TH.tier1_state(lay.home) == env["user"] and not (lay.home / "scripts" / "hook-injected.sh").exists()


# -- a revert that runs out of time -------------------------------------------------------------------------------

def _did_not_finish(left: list) -> str:
    """The sentence for the planted scripts a revert did not reach, as the route and the command give it."""
    shown = [f"scripts/{name}" for name in left]
    listed = ", ".join(shown[:3]) + (f" and {len(shown) - 3} more" if len(shown) > 3 else "")
    count = "1 change is" if len(shown) == 1 else f"{len(shown)} changes are"
    return (f"The revert did not finish in time: {count} still to revert ({listed}). The sandbox is stopped. "
            "Turn off again with the same answer to go on with it, or keep the changes (--keep) to turn off "
            "without it.")


def test_a_revert_that_ran_out_of_time_says_so_and_a_keep_turns_off_without_it(env, cli, capsys, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    env["markers"].marked.add("work")
    for n in range(6):
        TH.put(lay.home / "scripts" / f"planted-{n}.sh", "#!/bin/sh\n")
    hold = H._Revert._hold

    def slow(self, rel):
        time.sleep(0.8)
        return hold(self, rel)

    def planted() -> list:
        return sorted(path.name for path in (lay.home / "scripts").glob("planted-*.sh"))

    monkeypatch.setattr(H._Revert, "_hold", slow)
    monkeypatch.setattr(SW, "HANDBACK_TIMEOUT", 2.0)
    assert cli("off", "--revert") == 1
    left = planted()
    assert 0 < len(left) < 6 and "work" in env["markers"].marked  # stopped part way, and the profile stays marked
    assert capsys.readouterr().err == f"hermes sandbox: {_did_not_finish(left)}\n"
    monkeypatch.setattr(H._Revert, "_hold", hold)
    assert cli("off", "--keep") == 0
    assert planted() == left and "work" not in env["markers"].marked  # off, and what was left is still there
    assert "Close any app" not in capsys.readouterr().err


def test_a_file_in_use_keeps_the_sentence_that_names_that_cause(env, cli, capsys, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    env["markers"].marked.add("work")
    TH.put(lay.home / "scripts" / "planted-0.sh", "#!/bin/sh\n")
    _in_use(monkeypatch, "planted-0.sh")
    assert cli("off", "--revert") == 1
    assert capsys.readouterr().err == ("hermes sandbox: Couldn't revert 1 change: scripts/planted-0.sh. The sandbox is "
                                       "stopped. Close any app using this profile's files, then turn off again.\n")

def test_a_revert_that_runs_out_of_time_changes_nothing_after_its_answer(env, monkeypatch):  # noqa: F811
    lay = _switched_on(env)
    for n in range(6):
        TH.put(lay.home / "scripts" / f"planted-{n}.sh", "#!/bin/sh\n")
    hold = H._Revert._hold

    def slow(self, rel):
        time.sleep(0.8)
        return hold(self, rel)

    def planted() -> list:
        return sorted(path.name for path in (lay.home / "scripts").glob("planted-*.sh"))

    monkeypatch.setattr(H._Revert, "_hold", slow)
    monkeypatch.setattr(SW, "HANDBACK_TIMEOUT", 2.0)
    status, payload, _ = _off(_routes(env, monkeypatch, []), "revert")
    left = planted()
    assert status == 409 and payload["code"] == "handback_incomplete" and "clear" not in env["log"]
    assert 0 < len(left) < 6 and sorted(payload["left"]) == [f"file:scripts/{name}" for name in left]
    assert payload["detail"] == _did_not_finish(left)
    time.sleep(2.0)
    assert planted() == left  # the step that was told to stop moved nothing after the answer
    monkeypatch.setattr(H._Revert, "_hold", hold)
    status, payload, _ = _off(_routes(env, monkeypatch, []), "revert")
    assert status == 200 and planted() == [] and "clear" in env["log"]


# -- what the sandbox wrote costs no more than its length ---------------------------------------------------------

HOSTILE = ("'\"\\[{(" * 40000)[:200_000]  # 200,000 characters of open quotes, brackets and backslashes


def test_a_cron_record_with_a_very_long_hostile_value_is_listed_and_reverted_in_seconds(box):  # noqa: F811
    home, state = TH.taken(box)
    _change_the_script(home)
    TH.put(home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB, {**PLANTED, "skills": HOSTILE, "name": HOSTILE,
                                                               "script": HOSTILE, "prompt": HOSTILE}))
    started = time.monotonic()
    rows = TH.by_id(H.diff(home, state))
    done = H.revert(home, state, "all")
    assert time.monotonic() - started < 5
    assert sorted(rows) == ["cron:bbbbbbbbbbbb", SCRIPT] and len(rows["cron:bbbbbbbbbbbb"]["name"]) <= 60
    assert done["reverted"] == ["cron:bbbbbbbbbbbb", SCRIPT] and _job_ids(home) == ["aaaaaaaaaaaa"]


def test_a_revert_without_a_list_has_one_row_for_a_folder_over_the_limit(box, monkeypatch):  # noqa: F811
    home, state = TH.taken(box)
    before = TH.tree_bytes(home)
    _change_the_script(home)
    for n in range(60):
        TH.put(home / "scripts" / f"aaa_{n:03d}.txt", "x\n")
    monkeypatch.setattr(H, "MAX_ENTRIES", 40)
    done = H.revert_from_copies(home, state)
    assert done["reverted"] == [SCRIPT, "folder:scripts"] and done["left"] == []
    assert TH.tree_bytes(home) == before
