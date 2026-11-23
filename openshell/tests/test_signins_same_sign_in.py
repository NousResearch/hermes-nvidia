"""One Nous Portal sign-in used by the sandboxed profile and by the default profile at the same time
(launcher/signins.py).

The usual state of a computer: the default profile signed in to Nous Portal, and a named profile signed in
afterwards by taking Hermes's offer to import the sign-in it found. Hermes then keeps one grant in three places:
the default profile's ``auth.json`` (the Hermes root's), the named profile's ``auth.json`` and the shared store in
the root. Whichever Hermes renews writes the new pair to its own store and to the shared store; the others take it
from there at their next renewal instead of presenting their own, spent refresh token.

While the sandbox is on, the launcher's engine is one of those Hermes, over its copy of the profile's store. These
tests run it beside the default profile's Hermes against issuers that end a sign-in for good when a spent refresh
token is presented.
"""
import json
import shutil

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import signin_home  # noqa: E402
from signin_home import refresh_token_in, world  # noqa: E402,F401

from openshell.launcher import signins, standins  # noqa: E402

ROUNDS = 6
ID = "nous:agent_key"
ROTATED = {"provider": "nous", "step": "refresh", "presented": "current", "answer": "rotated"}


def finished(child) -> dict:
    out, err = child.communicate(timeout=300)
    assert child.returncode == 0, err[-2000:]
    return json.loads(out.strip().splitlines()[-1])


def _config(world):  # noqa: F811
    for home in (world.home, world.root):
        world.config({"model": {"provider": "nous", "default": "a-model"}}, home=home)


def both_signed_in(world):  # noqa: F811
    """In this process: the default profile signs in, then the named profile imports that sign-in."""
    world.sign_in("nous", home=world.root)
    with world.at(world.home):
        signin_home.import_shared_sign_in()
    _config(world)


def shared_refresh_token(world, production=False) -> str:  # noqa: F811
    folder = world.root / ("shared" if production else "shared-store")
    return str(json.loads((folder / "nous_auth.json").read_text(encoding="utf-8")).get("refresh_token") or "")


def _due(world, engine):  # noqa: F811
    (row,) = [row for row in engine.status() if row.get("id") == ID]
    world.clock.advance(max(0.0, row["renew_at"] - world.clock()) + 1.0)


def _stand_in(engine) -> dict:
    """The stand-in store a sandbox that starts now would get, and the variable of the Nous row's token."""
    template, names, left_out = standins.build(engine)
    assert template is not None and names == ("auth.json",) and left_out == (), (names, left_out)
    assert "nous" in template["files"]["auth.json"]["providers"]
    return template


def _changed_outside(world, before) -> set:  # noqa: F811
    """The files of the Hermes root that changed outside the profile's home and the launcher's own folder
    (lock files left out: whether one is new depends on who came first)."""
    after = signin_home.files_under(world.root)
    changed = {name for name in set(before) | set(after) if before.get(name) != after.get(name)}
    return {name for name in changed if not name.startswith(("profiles/", "openshell/")) and not name.endswith(".lock")}


def _switch_off(world):  # noqa: F811
    """The copy goes back under the profile's name, as the pins put it back."""
    with signins.settled(world.copy):
        shutil.copyfile(world.copy / "auth.json", world.home / "auth.json")


def test_an_ordinary_sign_in_of_a_named_profile_leaves_one_grant_in_three_stores(world):  # noqa: F811
    """What Hermes writes, pinned here because the engine's rules rest on it."""
    world.sign_in("nous", home=world.root)
    first = refresh_token_in(world.root, "nous")
    assert shared_refresh_token(world) == first and not (world.home / "auth.json").exists()
    with world.at(world.home):
        signin_home.import_shared_sign_in()
    current = world.issuers.current_refresh_token("nous")
    # The import renewed once: the profile's own row and the shared store hold the new pair, the root's row the
    # spent one, which the default profile's Hermes never presents again.
    assert refresh_token_in(world.home, "nous") == shared_refresh_token(world) == current != first
    assert refresh_token_in(world.root, "nous") == first
    assert world.issuers.refreshes("nous") == [ROTATED]
    world.renew_in_home("nous", home=world.root)
    assert world.issuers.refreshes("nous") == [ROTATED, ROTATED] and not world.issuers.ended("nous")
    assert refresh_token_in(world.root, "nous") == shared_refresh_token(world) == world.issuers.current_refresh_token("nous")


def test_the_engine_and_the_default_profiles_hermes_renew_in_turns_and_both_stay_signed_in(world):  # noqa: F811
    both_signed_in(world)
    world.take_copy()
    home_before = signin_home.files_under(world.home)
    engine = world.engine()
    (declared,) = engine.declare()
    assert declared.id == ID and not declared.shared
    seen = {world.sink.values[ID][0]}
    for turn in range(4):
        # The engine's turn: it renews over the copy, or takes the pair the other Hermes left in the shared store.
        _due(world, engine)
        assert engine.step() > 0
        token = world.sink.values[ID][0]
        assert world.issuers.valid("nous", token) and token not in seen, f"turn {turn}: the sandbox kept an old token"
        seen.add(token)
        assert shared_refresh_token(world) == world.issuers.current_refresh_token("nous")
        _stand_in(engine)  # a sandbox that starts now still finds itself signed in
        (row,) = [row for row in engine.status() if row.get("id") == ID]
        assert row["state"] == "works" and row["usable"]
        # The default profile's Hermes on the host renews next.
        world.clock.advance(5)
        theirs = world.renew_in_home("nous", home=world.root)
        assert world.issuers.valid("nous", theirs)
        assert shared_refresh_token(world) == world.issuers.current_refresh_token("nous")
        assert world.issuers.valid("nous", world.sink.values[ID][0]), "the other Hermes's renewal cut the sandbox's token"
        engine.catch_up()  # a sandbox that starts again now: its token is the one its stand-in is made for
        assert world.issuers.valid("nous", world.sink.values[ID][0])
        _stand_in(engine)
    calls = world.issuers.refreshes("nous")
    assert calls and all(call == ROTATED for call in calls), [c for c in calls if c != ROTATED]
    assert not world.issuers.ended("nous") and signin_home.files_under(world.home) == home_before
    engine.close()
    _switch_off(world)
    # Both are still signed in: each renews with what its own home holds now.
    assert world.issuers.valid("nous", world.renew_in_home("nous"))
    assert world.issuers.valid("nous", world.renew_in_home("nous", home=world.root))
    assert all(call == ROTATED for call in world.issuers.refreshes("nous")) and not world.issuers.ended("nous")


def test_when_hermes_folds_the_copys_grant_into_the_roots_the_sandbox_keeps_its_row(world):  # noqa: F811
    """Hermes keeps one grant per account. Once the copy and the root hold the same pair it drops the copy's row
    and the profile uses the root's from then on. The engine follows: the sign-in is the default profile's now,
    the stand-in keeps its row, and the row reads as it does for a profile that never had its own."""
    both_signed_in(world)
    world.take_copy()
    engine = world.engine()
    (declared,) = engine.declare()
    assert not declared.shared and refresh_token_in(world.copy, "nous")
    world.clock.advance(5)
    world.renew_in_home("nous", home=world.root)  # the root now holds the newest pair of the same grant
    touched = []
    for _ in range(3):
        _due(world, engine)
        before = signin_home.files_under(world.root)
        engine.step()
        touched.append(_changed_outside(world, before))
        _stand_in(engine)
        world.clock.advance(5)
    # What the engine's renewals wrote outside the copy: the shared store, and the root's own store from the
    # moment the grant was folded into it. Nothing else.
    assert set().union(*touched) == {"auth.json", "shared-store/nous_auth.json"}, touched
    assert refresh_token_in(world.copy, "nous") == "", "this Hermes did not fold the grant; the test proves nothing"
    assert refresh_token_in(world.root, "nous") == world.issuers.current_refresh_token("nous")
    (row,) = [row for row in engine.status() if row.get("id") == ID]
    assert row["state"] == "works" and row["reason"] == "signed_in_shared" and row["shared"] is True
    template = _stand_in(engine)
    assert template["credentials"], "the stand-in's token has no variable"
    assert all(call == ROTATED for call in world.issuers.refreshes("nous")) and not world.issuers.ended("nous")
    engine.close()
    _switch_off(world)
    assert world.issuers.valid("nous", world.renew_in_home("nous"))  # the profile, through the root's grant
    assert world.issuers.valid("nous", world.renew_in_home("nous", home=world.root))
    assert not world.issuers.ended("nous")


def test_renewing_at_the_same_time_in_two_processes_never_presents_a_spent_token(world):  # noqa: F811
    """As users have it: Hermes's own paths (the shared store in ``<root>/shared``), two processes, no pause."""
    finished(world.child("sign-in", "nous", home=world.root))
    finished(world.child("import", "nous"))
    _config(world)
    world.take_copy()
    assert refresh_token_in(world.copy, "nous") == shared_refresh_token(world, production=True)
    world.issuers.delay = 0.05
    engine = world.child("engine", world.copy, ROUNDS)
    host = world.child("host", "nous", ROUNDS, home=world.root)
    engine_out, host_out = finished(engine), finished(host)
    assert (engine_out["ok"], engine_out["errors"]) == (ROUNDS, [])
    assert (host_out["ok"], host_out["errors"]) == (ROUNDS, [])
    calls = world.issuers.refreshes("nous")
    assert calls and all(call == ROTATED for call in calls), [c for c in calls if c != ROTATED]
    assert not world.issuers.ended("nous")
    assert shared_refresh_token(world, production=True) == world.issuers.current_refresh_token("nous")
    world.issuers.delay = 0.0
    _switch_off(world)
    for side in (world.child("host", "nous", 1), world.child("host", "nous", 1, home=world.root)):
        assert finished(side)["errors"] == []
    assert not world.issuers.ended("nous") and all(call == ROTATED for call in world.issuers.refreshes("nous"))
