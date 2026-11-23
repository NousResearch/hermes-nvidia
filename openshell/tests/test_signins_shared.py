"""A profile without its own sign-in uses the default profile's, which the default profile's Hermes on this
computer renews as well. The engine leaves it where it is, in the Hermes root, and renews it there with Hermes's
own code and under Hermes's own lock, never from a copy: two holders of one refresh token would sign each other
out. Run with two processes against issuers that end a sign-in when a spent refresh token is presented.

The second process and the engine process of these tests run without the marks of a test run, so Hermes uses
the paths it uses for a user (the shared Nous store in ``<root>/shared``).
"""
import json

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import signin_home  # noqa: E402
from signin_home import files_under, world  # noqa: E402,F401

from openshell.launcher import signins  # noqa: E402

ROUNDS = 6


def finished(child) -> dict:
    out, err = child.communicate(timeout=300)
    assert child.returncode == 0, err[-2000:]
    return json.loads(out.strip().splitlines()[-1])


def default_profile_signed_in(world, provider):
    """The default profile signs in (its home is the root); the named profile has no sign-in of its own."""
    finished(world.child("sign-in", provider, home=world.root))
    world.config({"model": {"provider": provider, "default": "a-model"}})
    world.take_copy()


def changed_under_root(world, before) -> set:
    """The files that changed in the Hermes root outside the profile's home and the launcher's own folder.
    Lock files are listed apart (``locks_under_root``): whether one is new depends on who came first."""
    after = files_under(world.root)
    return {name for name in set(before) | set(after) if before.get(name) != after.get(name)
            and not name.startswith(("profiles/work/", "openshell/")) and not name.endswith(".lock")}


def locks_under_root(world) -> set:
    return {name for name in files_under(world.root)
            if name.endswith(".lock") and not name.startswith(("profiles/", "openshell/"))}


@pytest.mark.parametrize("provider", ["nous", "openai-codex"])
def test_the_default_profiles_sign_in_is_used_where_it_is(world, provider):
    default_profile_signed_in(world, provider)
    row = [r for r in signins.report(world.home) if r["provider"] == provider][0]
    assert (row["state"], row["shared"]) == ("works", True)
    assert row["sentence"].startswith("Signed in with the default profile's sign-in.")
    home_before, root_before = files_under(world.home), files_under(world.root)
    out = finished(world.child("engine", world.copy, 2))
    assert out["ok"] == 2 and out["errors"] == [] and out["states"] == ["works"]
    assert set(c["answer"] for c in world.issuers.refreshes(provider)) == {"rotated"}
    # The renewed sign-in is in the root, where the default profile's Hermes finds it; the copy never held it.
    assert signin_home.refresh_token_in(world.root, provider) == world.issuers.current_refresh_token(provider)
    assert signin_home.refresh_token_in(world.copy, provider) == ""
    assert files_under(world.home) == home_before
    shared_store = {"shared/nous_auth.json"} if provider == "nous" else set()
    assert changed_under_root(world, root_before) == {"auth.json"} | shared_store
    assert locks_under_root(world) == {"auth.lock"} | ({"shared/nous_auth.lock"} if provider == "nous" else set())
    # The default profile's Hermes goes on with the same sign-in.
    assert finished(world.child("host", provider, 1, home=world.root))["errors"] == []
    assert not world.issuers.ended(provider)


@pytest.mark.parametrize("provider", ["nous", "openai-codex"])
def test_two_hermes_renewing_one_sign_in_never_present_a_spent_refresh_token(world, provider):
    """The engine for the sandboxed profile and the default profile's Hermes renew the same sign-in at the same
    time, again and again. Neither signs the other out."""
    default_profile_signed_in(world, provider)
    world.issuers.delay = 0.05
    engine = world.child("engine", world.copy, ROUNDS)
    host = world.child("host", provider, ROUNDS, home=world.root)
    engine_out, host_out = finished(engine), finished(host)
    assert (engine_out["ok"], engine_out["errors"]) == (ROUNDS, [])
    assert (host_out["ok"], host_out["errors"]) == (ROUNDS, [])
    calls = world.issuers.refreshes(provider)
    assert calls and all(call == {"provider": provider, "step": "refresh", "presented": "current", "answer": "rotated"}
                         for call in calls), [c for c in calls if c["answer"] != "rotated"]
    assert not world.issuers.ended(provider)
    assert signin_home.refresh_token_in(world.root, provider) == world.issuers.current_refresh_token(provider)
    world.issuers.delay = 0.0
    for side in (world.child("host", provider, 1, home=world.root), world.child("engine", world.copy, 1)):
        assert finished(side)["errors"] == []
    assert not world.issuers.ended(provider)


def test_what_a_renewal_of_the_profiles_own_nous_sign_in_touches_in_the_root(world):
    """Not shared: the sign-in lives in the copy. Hermes still takes part in its shared Nous store, and takes
    the root store's lock to look for a copy of the default profile's sign-in."""
    world.config({"model": {"provider": "nous", "default": "a-model"}})
    finished(world.child("sign-in", "nous"))
    world.take_copy()
    home_before, root_before = files_under(world.home), files_under(world.root)
    out = finished(world.child("engine", world.copy, 2))
    assert out["ok"] == 2 and out["errors"] == []
    assert files_under(world.home) == home_before
    assert changed_under_root(world, root_before) == {"shared/nous_auth.json"}
    assert locks_under_root(world) == {"auth.lock", "shared/nous_auth.lock"}
    assert signin_home.refresh_token_in(world.copy, "nous") == world.issuers.current_refresh_token("nous")


@pytest.mark.parametrize("provider", ["xai-oauth", "minimax-oauth", "anthropic"])
def test_a_shared_sign_in_hermes_does_not_guard_with_the_roots_lock_is_not_carried(world, provider):
    """For these Hermes renews a sign-in of the default profile under the lock of the home it runs for, so two
    Hermes processes could present the same refresh token. The engine does not touch such a sign-in."""
    world.config({"model": {"provider": provider, "default": "a-model"}}, home=world.root)
    world.sign_in(provider, home=world.root)
    world.config({"model": {"provider": provider, "default": "a-model"}})
    world.take_copy()
    row = [r for r in signins.report(world.home) if r["provider"] == provider][0]
    assert (row["state"], row["reason"]) == ("needs_sign_in", "shared_not_carried")
    assert row["sentence"].endswith("Sign in for this profile with the sandbox off.")
    root_before = files_under(world.root)
    engine = world.engine()
    assert engine.declare() == [] and world.sink.declared == {}
    assert [r["reason"] for r in engine.status()] == ["shared_not_carried"]
    assert world.issuers.refreshes(provider) == []
    assert changed_under_root(world, root_before) == set()


@pytest.mark.parametrize("provider", ["nous", "openai-codex"])
def test_a_token_the_default_profiles_hermes_already_renewed_is_taken_as_it_is(world, provider):
    """The default profile's Hermes renews the shared sign-in on its own schedule. When the engine's turn comes
    the store already holds a newer token: it goes to the sink, and no refresh token is spent for it."""
    world.config({"model": {"provider": provider, "default": "a-model"}}, home=world.root)
    world.sign_in(provider, home=world.root)
    world.config({"model": {"provider": provider, "default": "a-model"}})
    world.take_copy()
    engine = world.engine()
    cred = engine.declare()[0].id
    world.clock.advance(engine.status()[0]["renew_at"] - world.clock())
    theirs = world.renew_in_home(provider, home=world.root)
    asked = len(world.issuers.refreshes(provider))
    engine.step()
    assert world.sink.values[cred][0] == theirs and len(world.sink.updates) == 1
    assert len(world.issuers.refreshes(provider)) == asked, "a refresh token was spent although a newer token was there"

    # A newer token with too little life left is not worth taking: the engine renews. Ours has 100 seconds
    # left here, theirs 200.
    world.clock.advance(engine.status()[0]["expires_at"] - 100 - world.clock())
    world.short_token(provider, seconds=200, home=world.root)
    asked = len(world.issuers.refreshes(provider))
    engine.step()
    if provider == "nous":
        # Hermes's own Nous renewal takes a token another Hermes left as long as it is usable at all. The
        # engine hands that one on and renews when it is due in its turn, which is soon.
        assert len(world.issuers.refreshes(provider)) == asked
        assert world.issuers.valid(provider, world.sink.values[cred][0])
        assert engine.status()[0]["renew_at"] - world.clock() < 200
        world.clock.advance(max(0.0, engine.status()[0]["renew_at"] - world.clock()))
        engine.step()
    assert len(world.issuers.refreshes(provider)) == asked + 1
    assert world.issuers.valid(provider, world.sink.values[cred][0])
    assert signin_home.refresh_token_in(world.root, provider) == world.issuers.current_refresh_token(provider)
