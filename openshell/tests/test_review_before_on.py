"""A switch-on never pins or records a home whose last sandbox session nobody reviewed (launcher/switch.py
``previous_session``).

A session that ended without its hand-back answered leaves its baseline open (a launcher that was killed and whose
marker was cleared by hand, a switch-off whose review could not run, a foreground serve that was killed). Before
this, the next switch-on pinned that home's ``secrets:`` block and model entries as the user's own, and the
launcher then ran what the sandbox had written there at every sandbox start. Now ``turn_on`` (the page's route
and ``hermes sandbox on``) and a foreground ``hermes sandbox serve`` run the switch-off's review first: rows that
need an answer stop the switch-on with the list and change nothing; ``revert`` and ``keep`` answer as at a
switch-off; with no rows it goes on. A foreground serve also records the home when it starts and compares when
it stops. Everything runs in temp folders with stand-ins for the service and the launcher.
"""
import argparse
import json
import time
from pathlib import Path

import pytest

import test_handback as TH
import test_settings_routes as SR
from openshell import launcher_cli as CLI
from openshell.launcher import handback as H
from openshell.launcher import layout as L
from openshell.launcher import pins as P
from openshell.launcher import switch as SW
from test_handback_wiring import LIST, _ids, _in_use, _text_and_settings, _the_report, _user_home
from test_pins import _serve_args, layout, serve  # noqa: F401  (fixtures: a layout, `sandbox serve` up to the launcher)
from test_switch_flow import FakeDriver, FakeRuntime, FakeService, _on, env  # noqa: F401  (the switch fixture)
from test_switch_flow import _runs_once_asked  # a launcher that takes a while to report its sandbox running

PLANTED = "sh -c 'id >> /tmp/markers/w.log'"  # the secret source the sandbox wrote (TH.plant_the_four)
NEEDS = "hermes sandbox: 7 changes need an answer. Run again with --revert or --keep.\n"


def _unanswered(env_, plant=TH.plant_the_four):
    """A profile whose last sandbox session ended without a review: the user's home recorded at that switch-on,
    its pin still there, then what the sandbox wrote, and nothing marked or running."""
    lay = env_["layout"]
    _user_home(lay)
    P.take(lay)
    assert H.take_baseline(lay.home, lay.state_dir)["taken"] is True
    env_["user"] = TH.tier1_state(lay.home)  # the settings and jobs that run here, as the user had them
    plant(lay.home)
    return lay


def _pinned_command(lay):
    return ((P.load(lay) or {}).get("secrets") or {}).get("command", {}).get("command")


# -- the switch-on stops for the review -----------------------------------------------------------------------

def test_a_switch_on_over_an_unanswered_session_stops_with_the_list_and_pins_nothing(env):  # noqa: F811
    lay = _unanswered(env)
    pin_before, home_before = P.load(lay), TH.tree_bytes(lay.home)
    with pytest.raises(SW.HandbackNeeded) as err:
        _on(env)
    assert err.value.status == 409 and str(err.value) == "7 changes need an answer."
    assert _ids(err.value.view) == TH.FOUR
    # nothing was changed: not the home, not the old pin, no spec, no service, no marker; the list is still there
    assert TH.tree_bytes(lay.home) == home_before and P.load(lay) == pin_before and _pinned_command(lay) is None
    assert not lay.spec_path.exists() and env["log"] == [] and env["services"] == []
    assert H.is_open(lay.state_dir) and _ids(H.diff(lay.home, lay.state_dir)) == TH.FOUR


def test_revert_and_turn_on_puts_the_changes_back_before_anything_is_pinned(env):  # noqa: F811
    lay = _unanswered(env)
    result = _on(env, handback_answer="revert")
    assert result["handback"]["reverted"] == TH.FOUR and result["handback"]["kept"] == []
    assert TH.tier1_state(lay.home) == env["user"] and not (lay.home / "scripts" / "hook-injected.sh").exists()
    assert _pinned_command(lay) is None and P.load(lay)["secrets"] == {}  # the planted source was never pinned
    held = lay.state_dir / "handback" / "held" / result["handback"]["held"]
    assert PLANTED.encode() in (held / "files" / "config.yaml").read_bytes()  # the sandbox's version is kept, host-only
    # the new session starts from the answered home: a fresh record with nothing to list
    view = H.diff(lay.home, lay.state_dir)
    assert view["open"] and view["rows"] == [] and "mark" in env["log"]


def test_keep_and_turn_on_takes_the_home_as_the_user_answered_it(env):  # noqa: F811
    lay = _unanswered(env)
    result = _on(env, handback_answer="keep")
    assert result["handback"]["kept"] == TH.FOUR and result["handback"]["reverted"] == []
    assert _pinned_command(lay) == PLANTED  # the user's answer, not a silent default
    assert H.diff(lay.home, lay.state_dir)["rows"] == []  # recorded anew: kept rows are the user's now


def test_a_keep_holds_only_for_the_rows_the_user_was_shown(env):  # noqa: F811
    lay = _unanswered(env)
    seen = {row["id"]: row["state"] for row in H.diff(lay.home, lay.state_dir)["rows"]}
    TH.put(lay.home / "scripts" / "late.sh", "#!/bin/sh\nid\n")  # after the list was shown
    result = _on(env, handback_answer="keep", handback_seen=seen)
    assert result["handback"]["kept"] == TH.FOUR and result["handback"]["reverted"] == ["file:scripts/late.sh"]
    assert not (lay.home / "scripts" / "late.sh").exists() and (lay.home / "scripts" / "hook-injected.sh").exists()


def test_a_session_whose_changes_ask_nothing_is_closed_and_the_switch_on_goes_on(env):  # noqa: F811
    lay = _unanswered(env, plant=_text_and_settings)  # only text the agent reads: no row
    first = json.loads((lay.state_dir / "handback" / "baseline.json").read_text(encoding="utf-8"))["manifest"]
    result = _on(env)
    assert result["handback"] == {"reverted": [], "kept": [], "held": None} and "mark" in env["log"]
    now = json.loads((lay.state_dir / "handback" / "baseline.json").read_text(encoding="utf-8"))["manifest"]
    assert now["SOUL.md"]["sha256"] != first["SOUL.md"]["sha256"]  # a new record, of the home as it is now
    assert H.diff(lay.home, lay.state_dir)["tier2"]["files"] == 0


def test_a_first_switch_on_has_nothing_to_review(env):  # noqa: F811
    lay = env["layout"]
    _user_home(lay)
    result = _on(env)
    assert result["handback"] is None and H.is_open(lay.state_dir) and P.present(lay)


def test_an_env_file_the_last_session_replaced_is_put_back_before_the_home_is_pinned_again(env):  # noqa: F811
    lay = _unanswered(env, plant=lambda home: TH.put(home / ".env", "A_KEY=replaced-inside\nPLANTED=1\n"))
    result = _on(env)  # an env file asks nothing: it is always put back
    assert result["handback"]["reverted"] == [] and (lay.home / ".env").read_bytes() == b"A_KEY=one\n"
    assert (P.pin_dir(lay) / ".env").read_bytes() == b"A_KEY=one\n" and P.secrets(lay) == {"A_KEY": "one"}
    [kept] = list((lay.state_dir / "quarantine").glob("*/.env"))
    assert kept.read_bytes() == b"A_KEY=replaced-inside\nPLANTED=1\n"


def test_a_pin_left_by_a_session_without_a_record_still_puts_its_env_file_back_first(env):  # noqa: F811
    """A session of a version that pinned but recorded no baseline, ended without a switch-off."""
    lay = env["layout"]
    _user_home(lay)
    P.take(lay)
    TH.put(lay.home / ".env", "A_KEY=replaced-inside\n")
    _on(env)
    assert (lay.home / ".env").read_bytes() == b"A_KEY=one\n" and P.secrets(lay) == {"A_KEY": "one"}


def test_a_row_that_cannot_be_put_back_refuses_the_switch_on_and_keep_goes_on(env, monkeypatch):  # noqa: F811
    lay = _unanswered(env)
    release = _in_use(monkeypatch, "cron-injected.sh")
    with pytest.raises(SW.SwitchError) as err:
        _on(env, handback_answer="revert")
    assert err.value.status == 409 and not isinstance(err.value, SW.HandbackNeeded)
    assert str(err.value) == ("Couldn't revert 1 change: scripts/cron-injected.sh. Close any app using this "
                              "profile's files, then turn on again.")
    assert not P.present(lay) and H.is_open(lay.state_dir) and "install" not in env["log"]
    # keep is never refused: the one change that could not be put back stays, as the user's answer
    result = _on(env, handback_answer="keep")
    assert result["handback"]["kept"] == ["file:scripts/cron-injected.sh"] and "mark" in env["log"]
    release()


def test_a_review_that_cannot_run_stops_the_switch_on_and_keep_is_the_way_past(env, monkeypatch):  # noqa: F811
    lay = _unanswered(env)
    pin_before = P.load(lay)
    diff = H.diff
    monkeypatch.setattr(H, "diff", lambda *a, **kw: (_ for _ in ()).throw(OSError("unreadable folder")))
    with pytest.raises(SW.SwitchError) as err:
        _on(env)
    assert err.value.status == 409
    assert str(err.value) == "Couldn't review the last sandbox session's changes (OSError: unreadable folder)."
    assert P.load(lay) == pin_before and env["log"] == [] and H.is_open(lay.state_dir)  # nothing was changed
    result = _on(env, handback_answer="keep")  # the user takes the home as it is
    assert result["handback"]["error"] == "OSError: unreadable folder" and _pinned_command(lay) == PLANTED
    monkeypatch.setattr(H, "diff", diff)
    assert H.diff(lay.home, lay.state_dir)["rows"] == []  # a new record, taken after the keep


def test_a_revert_that_cannot_run_is_answered_from_the_saved_copies_and_the_switch_on_goes_on(env, monkeypatch):  # noqa: F811
    lay = _unanswered(env)
    monkeypatch.setattr(H, "revert", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    done = _on(env, handback_answer="revert")["handback"]
    assert done["reverted"] == ["cfgfile:config.yaml", "cronfile:cron/jobs.json", "file:scripts/cron-injected.sh",
                                "file:scripts/hook-injected.sh"]
    assert done["problem"].startswith("Couldn't review the sandbox's changes (RuntimeError: boom). Reverted from the "
                                      "copies saved at switch-on: config.yaml, ")
    assert TH.tier1_state(lay.home) == env["user"] and _pinned_command(lay) is None and "mark" in env["log"]


def test_a_record_that_cannot_be_read_compares_with_nothing_and_is_dropped(env):  # noqa: F811
    lay = _unanswered(env)
    (lay.state_dir / "handback" / "baseline.json").write_text("{not json", encoding="utf-8")
    result = _on(env)
    assert "cannot be read" in result["handback"]["error"] and "mark" in env["log"]
    assert H.diff(lay.home, lay.state_dir)["rows"] == []


def test_a_switch_off_that_could_not_review_is_reviewed_by_the_next_switch_on(env, monkeypatch):  # noqa: F811
    """HANDBACK-READY's limit: a review that fails turns the sandbox off without one and leaves the record open."""
    lay = _unanswered(env)
    env["markers"].marked.add("work")
    diff = H.diff
    monkeypatch.setattr(H, "diff", lambda *a, **kw: (_ for _ in ()).throw(OSError("unreadable")))
    off = SW.turn_off_here(lay, runtime=env["runtime"], manager=env["manager"])
    assert off["marker_cleared"] is True and off["handback"]["error"] and H.is_open(lay.state_dir)
    monkeypatch.setattr(H, "diff", diff)
    env["log"].clear()
    with pytest.raises(SW.HandbackNeeded):
        _on(env)
    assert "install" not in env["log"] and not P.present(lay)


# -- a sandbox the last launcher left running -----------------------------------------------------------------

class LeftoverDriver(FakeDriver):
    """A driver with a sandbox still registered under the profile's name (its launcher was killed)."""

    def __init__(self, calls, fails=None):
        super().__init__()
        self.calls, self.fails = calls, fails

    def preflight(self):
        self.calls.append("preflight")
        return {}

    def drop_leftover(self, profile):
        self.calls.append(f"drop {profile}")
        if self.fails:
            raise RuntimeError(self.fails)
        return True


def test_a_sandbox_the_last_launcher_left_running_is_stopped_before_the_home_is_looked_at(env, monkeypatch):  # noqa: F811
    lay = _unanswered(env)
    calls = []
    review = SW.review
    monkeypatch.setattr(SW, "review", lambda layout_, **kw: (calls.append("review"), review(layout_, **kw))[1])
    with pytest.raises(SW.HandbackNeeded):
        _on(env, driver=LeftoverDriver(calls))
    assert calls == ["preflight", "drop work", "review"]  # stopped even when the switch-on then waits for the answer
    calls.clear()
    _on(env, driver=LeftoverDriver(calls), handback_answer="revert")
    assert calls[:3] == ["preflight", "drop work", "review"] and P.present(lay)


def test_a_leftover_sandbox_that_cannot_be_stopped_refuses_the_switch_on(env):  # noqa: F811
    lay = _unanswered(env)
    pin_before = P.load(lay)
    with pytest.raises(SW.SwitchError) as err:
        _on(env, driver=LeftoverDriver([], fails="gateway did not answer"), handback_answer="keep")
    assert err.value.status == 502
    assert str(err.value) == ("A sandbox from the last session is still running and couldn't be stopped: "
                              "RuntimeError: gateway did not answer")
    assert P.load(lay) == pin_before and H.is_open(lay.state_dir) and env["log"] == []  # nothing reviewed or pinned


def test_a_foreground_serve_stops_a_leftover_sandbox_first(layout, capsys):  # noqa: F811
    TH.put(layout.home / "config.yaml", TH.CONFIG)
    calls = []
    assert CLI._own_switch_on(layout, None, LeftoverDriver(calls)) == 0 and calls == ["drop work"]
    P.release(layout)
    assert CLI._own_switch_on(layout, "keep", LeftoverDriver([], fails="no gateway")) == 1
    assert "couldn't be stopped: RuntimeError: no gateway" in capsys.readouterr().err and not P.present(layout)


def test_the_drivers_delete_a_sandbox_left_under_the_profiles_name(tmp_path, monkeypatch):
    import test_openshell_driver as LD
    import test_openshell_windows as WD

    sup, api, _rec, lay = LD._supervisor(tmp_path / "linux", monkeypatch)
    assert sup.driver.drop_leftover(lay.name) is False  # none there: nothing is deleted
    api.sandboxes[f"hermes-{lay.name}"] = {"phase": "READY", "exit_code": None}
    assert sup.driver.drop_leftover(lay.name) is True and api.sandboxes == {}
    layout_, _runtime, cfg, _bb = WD._tree(tmp_path / "windows")
    fake = WD.FakeCli()
    driver = WD._driver(cfg, fake, tmp_path / "windows")
    assert driver.drop_leftover(layout_.name) is False
    fake.sandboxes[f"hermes-{layout_.name}"] = {"phase": "Ready"}
    assert driver.drop_leftover(layout_.name) is True and f"hermes-{layout_.name}" not in fake.sandboxes


# -- the page's route and the terminal ------------------------------------------------------------------------

def test_the_host_route_lists_the_last_session_and_switch_on_needs_the_answer(env, monkeypatch):  # noqa: F811
    lay = _unanswered(env)
    api = SR._plugin_api()
    monkeypatch.setattr(api._layout, "current_profile", lambda: lay)
    view = api.handback()
    assert view["open"] is True and _ids(view) == TH.FOUR and view["unanswered"] == 7 and "more" in view["tier2"]
    calls = []

    def turn_on(layout_, **kw):
        calls.append(kw)
        if kw["handback_answer"] is None:
            raise api._switch.HandbackNeeded(view)
        return {"profile": "work", "handback": {"reverted": TH.FOUR}}

    monkeypatch.setattr(api._switch, "turn_on", turn_on)
    refused = api.switch_on({})
    assert refused.status_code == 409
    assert json.loads(refused.body) == {"detail": "7 changes need an answer.", "code": "handback_needs_answer",
                                        "unanswered": 7}
    assert api.switch_on({"handback": "keep", "seen": {"a": "b"}})["handback"] == {"reverted": TH.FOUR}
    assert calls[-1] == {"handback_answer": "keep", "handback_seen": {"a": "b"}}
    assert api.switch_on(None)  # an older page sends no body
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as err:
        api.switch_on({"handback": "maybe"})
    assert err.value.status_code == 422
    # nothing to review: the route says so with an empty list
    H.close(lay.state_dir)
    assert api.handback() == {"open": False, "rows": [], "unanswered": 0, "kept": []}


@pytest.fixture
def cli(env, monkeypatch):  # noqa: F811
    """``hermes -p work sandbox ...`` for the fixture's profile, with no launcher running."""
    lay = env["layout"]
    monkeypatch.setattr(L, "current_profile", lambda: lay)
    on, off = SW.turn_on, SW.turn_off_here
    fakes = dict(runtime=env["runtime"], manager=env["manager"])
    monkeypatch.setattr(SW, "turn_on", lambda layout_, **kw: on(layout_, environ={}, sleep=lambda s: None,
                                                                make_driver=lambda spec: FakeDriver(), **fakes, **kw))
    monkeypatch.setattr(SW, "turn_off_here", lambda layout_, **kw: off(layout_, **fakes, **kw))
    parser = argparse.ArgumentParser(prog="hermes sandbox")
    CLI._setup(parser)
    return lambda *argv: CLI._dispatch(parser.parse_args(list(argv)))


def test_sandbox_on_lists_and_exits_3_until_it_has_an_answer(env, cli, capsys):  # noqa: F811
    lay = _unanswered(env, plant=lambda home: _the_report(env["layout"]))
    before = TH.tree_bytes(lay.home)
    assert cli("on") == 3
    out = capsys.readouterr()
    assert out.out == LIST and out.err == NEEDS
    assert TH.tree_bytes(lay.home) == before and env["log"] == [] and _pinned_command(lay) is None


def test_sandbox_on_revert(env, cli, capsys):  # noqa: F811
    lay = _unanswered(env)
    assert cli("on", "--revert") == 0
    out = capsys.readouterr()
    result = json.loads(out.out)
    assert result["state"] == "running" and result["handback"]["reverted"] == TH.FOUR
    held = lay.state_dir / "handback" / "held" / result["handback"]["held"]
    assert out.err == f"Reverted 7 changes. The sandbox's versions are in {held}.\n"
    assert TH.tier1_state(lay.home) == env["user"] and _pinned_command(lay) is None


def test_sandbox_on_keep(env, cli, capsys):  # noqa: F811
    lay = _unanswered(env)
    assert cli("on", "--keep") == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["handback"]["kept"] == TH.FOUR and out.err == "Kept 7 changes.\n"
    assert _pinned_command(lay) == PLANTED


def test_sandbox_on_with_nothing_to_review_prints_what_it_did_before(env, cli, capsys):  # noqa: F811
    _user_home(env["layout"])
    assert cli("on") == 0
    out = capsys.readouterr()
    assert sorted(json.loads(out.out)) == ["profile", "service", "state", "token_file", "url"] and out.err == ""


def test_sandbox_on_says_how_to_get_past_a_review_that_cannot_run(env, cli, capsys, monkeypatch):  # noqa: F811
    _unanswered(env)
    monkeypatch.setattr(H, "diff", lambda *a, **kw: (_ for _ in ()).throw(OSError("unreadable")))
    assert cli("on") == 1
    assert capsys.readouterr().err == ("hermes sandbox: Couldn't review the last sandbox session's changes "
                                       "(OSError: unreadable). Run again with --keep to turn on without a review.\n")


def test_revert_and_keep_together_is_a_usage_error_for_on_and_serve(cli, capsys):
    for verb in ("on", "serve"):
        with pytest.raises(SystemExit) as err:
            cli(verb, "--revert", "--keep")
        assert err.value.code == 2 and "not allowed with argument" in capsys.readouterr().err


# -- a foreground `hermes sandbox serve` is its own switch-on, and now its own switch-off ------------------------

@pytest.fixture
def foreground(layout, serve, monkeypatch):  # noqa: F811
    """``hermes -p work sandbox serve`` with a launcher stand-in that notes what it finds when it starts and can
    write into the home while it "runs" (what the sandbox does). Returns ``(run, seen)``."""
    TH.put(layout.home / "config.yaml", TH.CONFIG)
    TH.put(layout.home / "cron" / "jobs.json", TH.jobs_bytes(TH.JOB))
    seen = []

    def run(answer=None, sandbox_writes=lambda home: None, **args):
        async def fake_serve(lay, spec, driver, token, service=False, own_pin=False):
            seen.append({"own_pin": own_pin, "pinned": P.present(lay), "recorded": H.is_open(lay.state_dir),
                         "rows": _ids(H.diff(lay.home, lay.state_dir)), "command": _pinned_command(lay)})
            sandbox_writes(lay.home)
            return 0

        monkeypatch.setattr(CLI, "_serve", fake_serve)
        return CLI._cmd_serve(_serve_args(handback_answer=answer, **args))

    return run, seen


def test_a_foreground_serve_records_the_home_beside_its_pin_and_ends_the_record_when_nothing_changed(layout, foreground, capsys):  # noqa: F811
    run, seen = foreground
    assert run(sandbox_writes=lambda home: (_text_and_settings(home), TH.put(home / ".op.env", "PLANTED=1\n"))) == 0
    assert seen == [{"own_pin": True, "pinned": True, "recorded": True, "rows": [], "command": None}]
    # stopped: the env file made inside is put back (it asks nothing), the pin is released, the record ends
    assert not H.is_open(layout.state_dir) and not P.present(layout) and not (layout.home / ".op.env").exists()
    assert capsys.readouterr().err == ""


def test_a_foreground_serve_that_stops_with_changes_prints_them_and_off_answers(layout, foreground, capsys):  # noqa: F811
    run, seen = foreground
    user = TH.tier1_state(layout.home)
    assert run(sandbox_writes=TH.plant_the_four) == 0
    out = capsys.readouterr()
    assert out.out.startswith("Changed in the sandbox (profile work)\n")
    assert out.err == ("hermes sandbox: 7 changes need an answer. Run `hermes -p work sandbox off --revert` or "
                       "`hermes -p work sandbox off --keep`.\n")
    assert H.is_open(layout.state_dir) and not P.present(layout)  # the pin is released, the record waits
    assert TH.tier1_state(layout.home) != user  # nothing was reverted without an answer
    # `sandbox off --revert` answers it although nothing is running or marked
    result = SW.turn_off_here(layout, handback_answer="revert", runtime=FakeRuntime(Path("py.exe"), layout.root.parent),
                              manager=lambda defn: FakeService(defn, []))
    assert result["handback"]["reverted"] == TH.FOUR and not H.is_open(layout.state_dir)
    assert TH.tier1_state(layout.home) == user


def test_the_next_foreground_serve_reviews_a_session_that_was_not_answered(layout, foreground, capsys):  # noqa: F811
    run, seen = foreground
    user = TH.tier1_state(layout.home)
    assert run(sandbox_writes=TH.plant_the_four) == 0  # stops with 7 changes, not answered
    capsys.readouterr()
    assert run() == 3
    out = capsys.readouterr()
    assert out.out.startswith("Changed in the sandbox (profile work)\n") and out.err == NEEDS
    assert len(seen) == 1 and not P.present(layout)  # the launcher never started again, nothing was pinned
    assert run(answer="revert") == 0
    assert seen[-1] == {"own_pin": True, "pinned": True, "recorded": True, "rows": [], "command": None}
    assert TH.tier1_state(layout.home) == user
    # and kept: the planted source is pinned because the user said so
    TH.put(layout.home / "config.yaml", TH.CONFIG)
    assert run(sandbox_writes=TH.plant_the_four) == 0
    assert run(answer="keep") == 0 and seen[-1]["command"] == PLANTED


def test_a_serve_beside_a_switched_on_sandbox_reviews_and_records_nothing(layout, foreground, monkeypatch):  # noqa: F811
    from openshell.launcher import login_service as LS

    run, seen = foreground
    H.take_baseline(layout.home, layout.state_dir)  # the switched-on sandbox's own record
    TH.plant_the_four(layout.home)
    monkeypatch.setattr(LS, "switched_on", lambda lay: True)
    assert run() == 0 and seen[-1]["own_pin"] is False  # not its switch-on: no review, no stop
    assert H.is_open(layout.state_dir) and _ids(H.diff(layout.home, layout.state_dir)) == TH.FOUR  # untouched


def test_a_login_service_start_and_stop_reviews_nothing_and_releases_nothing(layout, foreground, capsys, monkeypatch):  # noqa: F811
    """`serve --service` is a restart at login: the switch-on's pin and record are not its to end."""
    from openshell.launcher import login_service as LS

    run, seen = foreground
    P.take(layout)
    H.take_baseline(layout.home, layout.state_dir)
    TH.plant_the_four(layout.home)  # what the sandbox wrote before the restart
    monkeypatch.setattr(LS, "switched_on", lambda lay: True)
    SW.mark(layout)  # and its profile is marked: a login service runs a sandbox for no other
    assert run(service=True) == 0 and seen[-1]["own_pin"] is False
    assert P.present(layout) and _pinned_command(layout) is None  # still the switch-on's pin
    assert H.is_open(layout.state_dir) and _ids(H.diff(layout.home, layout.state_dir)) == TH.FOUR
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


def test_the_default_profile_is_named_without_a_profile_flag(tmp_path, capsys):
    root = tmp_path / "root"
    lay = L.ProfileLayout(name="default", home=root, root=root)
    TH.put(root / "config.yaml", TH.CONFIG)
    assert CLI._own_switch_on(lay, None) == 0
    TH.put(root / "scripts" / "planted.sh", "#!/bin/sh\nid\n")
    CLI._own_switch_off(lay)
    assert capsys.readouterr().err == ("hermes sandbox: 1 change needs an answer. Run `hermes sandbox off --revert` "
                                       "or `hermes sandbox off --keep`.\n")


def test_a_review_that_cannot_run_when_a_foreground_serve_stops_is_said_and_the_record_stays(layout, capsys, monkeypatch):  # noqa: F811
    TH.put(layout.home / "config.yaml", TH.CONFIG)
    assert CLI._own_switch_on(layout, None) == 0
    monkeypatch.setattr(H, "diff", lambda *a, **kw: (_ for _ in ()).throw(OSError("unreadable")))
    CLI._own_switch_off(layout)
    assert capsys.readouterr().err == "hermes sandbox: Couldn't review the sandbox's changes (OSError: unreadable).\n"
    assert H.is_open(layout.state_dir) and not P.present(layout)


# -- the page's route answers in short requests (launcher/switch.py ``turn_on_within``) -------------------------

FINAL = {"profile", "plugin", "url", "token", "undo_ticket", "service", "status", "handback"}
MOVE_FIRST = "A key is written in config.yaml, where the sandbox could read it. Move it to .env first."


@pytest.fixture
def page(env, monkeypatch):  # noqa: F811
    """The page's route for the fixture's profile, with the fixture's stand-ins behind both ways of turning on."""
    lay = env["layout"]
    api = SR._plugin_api()
    monkeypatch.setattr(api._layout, "current_profile", lambda: lay)
    monkeypatch.setattr(api, "_switch", SW)
    fakes = dict(runtime=env["runtime"], manager=env["manager"], environ={}, make_driver=lambda spec: FakeDriver(),
                 sleep=lambda s: time.sleep(0.002))
    starts = SW.Starts(tick=0.01)
    on, within = SW.turn_on, SW.turn_on_within
    monkeypatch.setattr(SW, "turn_on", lambda layout_, **kw: on(layout_, **fakes, **kw))
    monkeypatch.setattr(SW, "turn_on_within",
                        lambda layout_, wait, **kw: within(layout_, wait, starts=starts, **fakes, **kw))
    return api


def _answer(response):
    return response.status_code, json.loads(response.body)


def test_the_route_answers_pending_while_the_sandbox_starts_and_marks_with_the_final_answer(env, page):  # noqa: F811
    env["launcher"]["state"] = "starting"
    code, body = _answer(page.switch_on({"wait": 0}))
    assert code == 202 and body["pending"] is True and not {"url", "token", "undo_ticket"} & set(body)
    assert "mark" not in env["log"] and not env["markers"].marked
    env["launcher"]["state"] = "running"
    final = page.switch_on({"wait": 5})
    assert isinstance(final, dict) and set(final) == FINAL
    assert final["url"].startswith("http://127.0.0.1:") and final["undo_ticket"] == "undo-ticket"
    assert final["profile"] == "work" and final["handback"] is None
    assert env["log"][-1] == "mark" and env["log"].count("install") == 1 and "work" in env["markers"].marked


def test_a_request_that_names_no_wait_is_held_until_the_sandbox_runs(env, page):  # noqa: F811
    _runs_once_asked(env)
    final = page.switch_on({})  # an older page: one request, and its answer is the final one
    assert isinstance(final, dict) and set(final) == FINAL and final["undo_ticket"] == "undo-ticket"
    assert env["log"][-1] == "mark" and env["log"].count("GET status") >= 3 and env["log"].count("install") == 1


def test_the_last_sessions_changes_are_asked_about_in_the_first_answer_and_nothing_starts(env, page):  # noqa: F811
    lay = _unanswered(env)
    pin_before, home_before = P.load(lay), TH.tree_bytes(lay.home)
    refused = _answer(page.switch_on({"wait": 5}))
    assert refused == (409, {"detail": "7 changes need an answer.", "code": "handback_needs_answer", "unanswered": 7})
    assert refused == _answer(page.switch_on({}))  # the same answer a request without a wait gets
    assert TH.tree_bytes(lay.home) == home_before and P.load(lay) == pin_before and _pinned_command(lay) is None
    assert not lay.spec_path.exists() and env["log"] == [] and env["services"] == []
    final = page.switch_on({"wait": 5, "handback": "revert"})
    assert isinstance(final, dict) and final["handback"]["reverted"] and "work" in env["markers"].marked


def test_a_refusal_the_page_can_act_on_keeps_its_code_and_keys_in_the_first_answer(env, page, monkeypatch):  # noqa: F811
    def refuse(layout_):
        error = SW.SwitchError(MOVE_FIRST, 422)
        error.code = "key_in_config"
        error.keys = [{"path": "model.api_key", "env": "MODEL_API_KEY", "value": "never sent"}]
        raise error

    monkeypatch.setattr(SW, "refuse_unready", refuse)
    refused = _answer(page.switch_on({"wait": 5}))
    assert refused == (422, {"detail": MOVE_FIRST, "code": "key_in_config",
                             "keys": [{"path": "model.api_key", "env": "MODEL_API_KEY"}]})
    assert refused == _answer(page.switch_on({}))
    assert env["services"] == [] and env["log"] == []


def test_a_plain_refusal_keeps_its_status_and_sentence_in_the_first_answer(env, page):  # noqa: F811
    from fastapi import HTTPException

    env["markers"].marked.add("work")
    seen = []
    for body in ({"wait": 5}, {}):
        with pytest.raises(HTTPException) as err:
            page.switch_on(body)
        seen.append((err.value.status_code, err.value.detail))
    assert seen[0] == seen[1] and seen[0][0] == 409 and "still switched on for this profile" in seen[0][1]
    with pytest.raises(HTTPException) as err:
        page.switch_on({"wait": "soon"})
    assert err.value.status_code == 422 and env["services"] == []


def test_a_start_that_fails_after_a_pending_answer_keeps_its_status_and_sentence(env, page):  # noqa: F811
    from fastapi import HTTPException

    env["launcher"]["state"] = "starting"
    assert page.switch_on({"wait": 0}).status_code == 202
    env["launcher"].update(state="failed", error="sandbox exited with 1")
    with pytest.raises(HTTPException) as err:
        page.switch_on({"wait": 5})
    assert (err.value.status_code, err.value.detail) == (502, "The sandbox didn't start: sandbox exited with 1")
    assert "mark" not in env["log"] and env["services"][0].state() == "absent"


def test_sandbox_on_in_a_terminal_still_waits_for_the_sandbox_in_one_call(env, cli, capsys):  # noqa: F811
    _runs_once_asked(env)
    assert cli("on") == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["profile"] == "work" and printed["url"].startswith("http://127.0.0.1:")
    assert printed["state"] == "running" and "pending" not in printed
    assert env["log"][-1] == "mark" and env["log"].count("install") == 1 and "work" in env["markers"].marked
