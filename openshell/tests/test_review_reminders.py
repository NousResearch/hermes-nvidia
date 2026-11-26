"""Reminders in the switch-off review (launcher/handback.py): what of a cron job is compared and put back.

A job is compared by what it runs and when: its schedule, the next run, the run limit, where its output goes.
A revert puts those back, a job that was removed comes back, and so does a jobs file that was removed. What the
scheduler wrote while it worked is no change and stays: the runs that happened, their count, a next run it moved
along the schedule. Everything runs in temp folders; nothing starts a sandbox.
"""
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

import test_handback as TH
from openshell.launcher import handback as H
from test_handback import box  # noqa: F401  (fixture: a profile home, the state folder, a folder outside)


def _at(**delta) -> str:
    return (datetime.now(timezone.utc) + timedelta(**delta)).isoformat()


def job(name: str, **over) -> dict:
    """A reminder as Hermes writes it: every 180 minutes, five runs at most, the next one in an hour."""
    record = {"id": name, "name": name, "prompt": "Stretch your legs", "skills": [], "skill": None, "model": None,
              "provider": None, "base_url": None, "script": None, "no_agent": False,
              "schedule": {"kind": "interval", "minutes": 180, "display": "every 180m"},
              "schedule_display": "every 180m", "repeat": {"times": 5, "completed": 0}, "enabled": True,
              "state": "scheduled", "paused_at": None, "paused_reason": None, "created_at": _at(hours=-2),
              "next_run_at": NEXT, "last_run_at": None, "last_status": None, "last_error": None, "deliver": "local",
              "origin": None, "enabled_toolsets": None, "workdir": None}
    record.update(over)
    return record


NEXT = _at(hours=1)
NAMES = ["edited", "twin"]


def _recorded(box, names=NAMES):  # noqa: F811
    home, state, _ = box
    TH.put(home / "cron" / "jobs.json", TH.jobs_bytes(*[job(name) for name in names]))
    assert H.take_baseline(home, state)["taken"] is True
    return home, state


def _jobs(home) -> dict:
    return {record["id"]: record for record in json.loads((home / "cron" / "jobs.json").read_bytes())["jobs"]}


def _write(home, jobs: dict) -> None:
    TH.put(home / "cron" / "jobs.json", TH.jobs_bytes(*jobs.values()))


def test_revert_puts_back_the_next_run_and_the_run_limit(box):  # noqa: F811
    home, state = _recorded(box)
    saved = _jobs(home)
    jobs = _jobs(home)
    jobs["edited"].update(schedule={"kind": "interval", "minutes": 43200, "display": "every 43200m"},
                          schedule_display="every 43200m", next_run_at=_at(days=30),
                          repeat={"times": 1, "completed": 0})
    _write(home, jobs)
    rows = TH.by_id(H.diff(home, state))
    assert sorted(rows) == ["cron:edited"]
    assert rows["cron:edited"]["detail"] == ("changed (schedule, schedule_display, repeat, next_run_at), "
                                             "runs a prompt")
    assert H.revert(home, state, "all")["reverted"] == ["cron:edited"]
    after = _jobs(home)
    for field in ("schedule", "schedule_display", "next_run_at", "repeat"):
        assert after["edited"][field] == after["twin"][field], field
    assert after == saved and H.diff(home, state)["rows"] == []


@pytest.mark.parametrize("field, value", [
    ("repeat", {"times": 1, "completed": 0}), ("schedule_display", "every 43200m"),
    ("next_run_at", "2099-01-01T00:00:00+00:00"), ("next_run_at", None),
    ("next_run_at", "not a time"), ("next_run_at", "2020-01-01T00:00:00+00:00"), ("timezone", "Pacific/Kiritimati"),
    ("origin", {"platform": "telegram", "chat_id": "another-chat"}), ("grace_minutes", 0), ("catch_up", False),
    ("manual_run_prompt", "text added to the next run"), ("name", "renamed"), ("reasoning_effort", "max"),
    ("attach_to_session", True), ("wrap_response", False), ("state", "completed")])
def test_a_field_that_decides_when_or_what_a_job_runs_is_compared_and_put_back(box, field, value):  # noqa: F811
    home, state = _recorded(box)
    saved = _jobs(home)
    jobs = _jobs(home)
    jobs["edited"][field] = value
    _write(home, jobs)
    rows = H.diff(home, state)["rows"]
    assert [row["id"] for row in rows] == ["cron:edited"] and rows[0]["kind"] == "cron_changed"
    assert H.revert(home, state, "all")["reverted"] == ["cron:edited"]
    assert _jobs(home) == saved and H.diff(home, state)["rows"] == []


def test_what_the_scheduler_wrote_while_it_worked_is_no_row(box):  # noqa: F811
    home, state = _recorded(box, ["ran", "passed-over", "ended", "twin"])
    jobs = _jobs(home)
    jobs["ran"].update(last_run_at=_at(minutes=-5), last_status="ok", next_run_at=_at(minutes=175),
                       repeat={"times": 5, "completed": 1})
    jobs["passed-over"].update(next_run_at=_at(minutes=170))  # a run was missed: the next slot from now
    jobs["ended"].update(last_run_at=_at(minutes=-5), last_status="ok", next_run_at=None, state="completed",
                         enabled=False, repeat={"times": 5, "completed": 5})
    _write(home, jobs)
    view = H.diff(home, state)
    assert view["rows"] == [] and view["unanswered"] == 0


def test_a_job_that_ran_keeps_its_runs_and_gets_its_schedule_back_counted_from_the_last_run(box):  # noqa: F811
    home, state = _recorded(box)
    jobs = _jobs(home)
    ran_at = _at(minutes=-20)
    jobs["edited"].update(schedule={"kind": "interval", "minutes": 43200, "display": "every 43200m"},
                          schedule_display="every 43200m", next_run_at=_at(days=30), last_run_at=ran_at,
                          last_status="ok", repeat={"times": 1, "completed": 1}, state="completed", enabled=False)
    _write(home, jobs)
    assert [row["id"] for row in H.diff(home, state)["rows"]] == ["cron:edited"]
    H.revert(home, state, "all")
    after = _jobs(home)["edited"]
    assert after["schedule"]["minutes"] == 180 and after["schedule_display"] == "every 180m"
    assert after["repeat"] == {"times": 5, "completed": 1} and after["last_run_at"] == ran_at  # the run stays counted
    assert after["state"] == "scheduled" and after["enabled"] is True  # it ended only at the lowered limit
    assert datetime.fromisoformat(after["next_run_at"]) == datetime.fromisoformat(ran_at) + timedelta(minutes=180)
    assert H.diff(home, state)["rows"] == []


def test_a_job_that_was_removed_is_a_row_and_comes_back(box):  # noqa: F811
    home, state = _recorded(box)
    saved = _jobs(home)
    _write(home, {"twin": saved["twin"]})
    rows = H.diff(home, state)["rows"]
    assert [(row["id"], row["kind"], row["name"], row["detail"]) for row in rows] == [
        ("cron:edited", "cron_removed", "edited", "removed, runs a prompt")]
    assert H.revert(home, state, "all")["reverted"] == ["cron:edited"]
    assert _jobs(home) == saved and H.diff(home, state)["rows"] == []


def test_a_jobs_file_that_was_removed_is_a_row_and_comes_back(box):  # noqa: F811
    home, state = _recorded(box)
    data = (home / "cron" / "jobs.json").read_bytes()
    (home / "cron" / "jobs.json").unlink()
    rows = H.diff(home, state)["rows"]
    shown = [(row["id"], row["kind"], row["detail"]) for row in rows]
    assert shown == [("cronfile:cron/jobs.json", "cron_file", "removed")]
    assert H.revert(home, state, "all")["reverted"] == ["cronfile:cron/jobs.json"]
    assert (home / "cron" / "jobs.json").read_bytes() == data


@pytest.mark.parametrize("copy", [True, False], ids=["with the copy of the jobs file", "without a copy"])
def test_a_record_of_version_1_is_compared_by_the_copy_of_the_jobs_file_or_by_the_fields_it_holds(box, copy):  # noqa: F811
    home, state = _recorded(box)
    record = state / "handback" / "baseline.json"
    first = json.loads(record.read_text(encoding="utf-8"))
    first["version"] = 1
    first["cron"]["jobs"] = {name: H._payload(saved, v1=True) for name, saved in _jobs(home).items()}
    if not copy:
        del first["manifest"]["cron/jobs.json"]["copy"]
    record.write_text(json.dumps(first), encoding="utf-8")
    assert H.diff(home, state)["rows"] == []  # a job with a name and a run limit is no change
    jobs = _jobs(home)
    jobs["edited"]["prompt"] = "Another prompt"
    jobs["edited"]["repeat"] = {"times": 1, "completed": 0}
    _write(home, jobs)
    rows = H.diff(home, state)["rows"]
    assert [row["id"] for row in rows] == ["cron:edited"]
    fields = "prompt, repeat" if copy else "prompt"  # a record of version 1 without the copy has no run limit
    assert rows[0]["detail"] == f"changed ({fields}), runs a prompt"


def test_a_kept_job_stays_named_while_the_scheduler_runs_it(box):  # noqa: F811
    home, state = _recorded(box)
    jobs = _jobs(home)
    jobs["edited"]["prompt"] = "Another prompt"
    _write(home, jobs)
    assert H.keep(home, state, "all")["kept"] == ["cron:edited"]
    H.remember_kept(home, state, ["cron:edited"])
    jobs["edited"].update(last_run_at=_at(minutes=-1), next_run_at=_at(minutes=179),
                          repeat={"times": 5, "completed": 1})
    _write(home, jobs)
    assert [item["id"] for item in H.kept(home, state)] == ["cron:edited"]
    assert TH.by_id(H.diff(home, state))["cron:edited"]["answer"] == "keep"
    jobs["edited"]["prompt"] = "A third prompt"
    _write(home, jobs)
    assert H.kept(home, state) == [] and TH.by_id(H.diff(home, state))["cron:edited"]["answer"] is None


def test_very_long_hostile_job_values_are_listed_and_reverted_in_seconds(box):  # noqa: F811
    home, state = _recorded(box)
    saved = _jobs(home)
    hostile = ("'\"\\[{(:+-T " * 30000)[:200_000]
    jobs = _jobs(home)
    jobs["edited"].update(next_run_at=hostile, timezone=hostile, name=hostile, origin={hostile: [hostile]},
                          last_run_at=hostile, schedule={"kind": "interval", "minutes": 1e308, "display": hostile})
    _write(home, jobs)
    started = time.monotonic()
    rows = H.diff(home, state)["rows"]
    done = H.revert(home, state, "all")
    assert time.monotonic() - started < 5
    assert [row["id"] for row in rows] == ["cron:edited"] and done["reverted"] == ["cron:edited"]
    after = _jobs(home)
    assert after["twin"] == saved["twin"] and after["edited"]["schedule"] == saved["edited"]["schedule"]
    assert after["edited"]["name"] == "edited" and "timezone" not in after["edited"]
    assert "next_run_at" not in after["edited"]  # no readable last run to count from: Hermes works it out
