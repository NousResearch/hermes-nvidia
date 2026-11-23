"""Giving the sign-in back: while the sandbox is on, the launcher's copy is the live sign-in (every renewal
replaces the refresh token there), and at switch-off the copy's files go back into the profile, so the user is
still signed in. Run against issuers that end a sign-in when a spent refresh token is presented.

The pins own the files (launcher/pins.py): ``follow_copy`` records what the copy holds, ``release`` puts it back
and only then deletes the pins.
"""
import json
import threading
import time

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import signin_home  # noqa: E402
from signin_home import world  # noqa: E402,F401

from openshell.launcher import pins, signins  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402

CARRIED = ["nous", "openai-codex", "xai-oauth", "minimax-oauth", "anthropic"]


@pytest.fixture
def on(world, monkeypatch):
    """``on(provider)``: the profile signed in to *provider* and switched on through the pins, with what the
    engine needs added to the copy. Returns ``(layout, engine, credential id)``."""
    layout = ProfileLayout(name="work", home=world.home, root=world.root)
    assert pins.STORE_FILES == signins.SIGN_IN_FILES

    def switch_on(provider, **engine):
        world.config({"model": {"provider": provider, "default": "a-model"}})
        world.sign_in(provider)
        pins.take(layout)
        assert pins.pin_dir(layout) == world.copy and (world.copy / "config.yaml").is_file()
        made = world.engine(**engine)
        return layout, made, made.declare()[0].id

    return switch_on


def renew(world, engine, times=1):
    for _ in range(times):
        world.clock.advance(max(0.0, engine.status()[0]["renew_at"] - world.clock()))
        engine.step()


@pytest.mark.parametrize("provider", CARRIED)
def test_the_copy_goes_back_and_the_profile_is_still_signed_in(world, on, provider):
    layout, engine, cred = on(provider)
    at_switch_on = signin_home.refresh_token_in(world.home, provider)
    renew(world, engine, times=2)
    assert [call["answer"] for call in world.issuers.refreshes(provider)] == ["rotated", "rotated"]
    assert signin_home.refresh_token_in(world.home, provider) == at_switch_on, "the home changed while the sandbox was on"
    engine.close()
    name = signins._BY_PROVIDER[provider].file
    assert pins.release(layout) == [name]
    assert signin_home.refresh_token_in(world.home, provider) == world.issuers.current_refresh_token(provider)
    assert not world.copy.exists(), "the pins were not deleted"
    kept = list((layout.state_dir / "quarantine").rglob(name))
    assert len(kept) == 1, "the home's stale store was not kept"
    # Hermes on this computer, in the profile's own home, renews again: the user never signed in twice.
    assert world.issuers.valid(provider, world.renew_in_home(provider))
    assert world.issuers.refreshes(provider)[-1] == {"provider": provider, "step": "refresh", "presented": "current",
                                                     "answer": "rotated"}
    assert not world.issuers.ended(provider)


@pytest.mark.parametrize("provider", CARRIED)
def test_without_the_return_the_profile_is_signed_out(world, on, provider):
    """The copy is dropped at switch-off and the home keeps the store it had at switch-on: its refresh token
    was spent by the first renewal, and presenting it ends the sign-in."""
    layout, engine, cred = on(provider)
    renew(world, engine)
    engine.close()
    pins.remove(layout)
    if provider == "nous":
        # Hermes keeps every renewed Nous pair in its shared store as well (next test); here that is gone too.
        (world.root / "shared-store" / "nous_auth.json").unlink()
    with pytest.raises(Exception):
        world.renew_in_home(provider)
    assert world.issuers.refreshes(provider)[-1]["presented"] == "spent"
    assert world.issuers.ended(provider), "the profile's sign-in survived: the return is not needed after all"


def test_for_nous_hermes_shared_store_is_a_second_way_back(world, on):
    """Every Nous renewal the engine makes is also written to Hermes's shared Nous store, and a Hermes whose own
    store holds an older pair of the same account takes the newer one from there. So a Nous sign-in survives a
    switch-off that put nothing back. The return is still made: the other sign-ins have no such store."""
    layout, engine, cred = on("nous")
    renew(world, engine)
    engine.close()
    pins.remove(layout)
    assert signin_home.refresh_token_in(world.home, "nous") != world.issuers.current_refresh_token("nous")
    assert world.issuers.valid("nous", world.renew_in_home("nous"))
    assert world.issuers.refreshes("nous")[-1]["presented"] == "current" and not world.issuers.ended("nous")


def test_each_renewal_can_be_recorded_as_it_happens(world, on):
    layout, engine, cred = on("nous", on_change=lambda names: None)
    engine._on_change = lambda names: pins.follow_copy(layout)
    before = pins.load(layout)["stores"]["auth.json"]
    renew(world, engine)
    recorded = pins.load(layout)["stores"]["auth.json"]
    assert recorded != before
    assert recorded == signins.copy_states(world.copy)["auth.json"] == pins._file_state(world.copy / "auth.json")
    # Recorded or not, nothing at a restart of the sandbox may undo the renewal.
    assert pins.restore_stores(layout, replaceable=True) == ["auth.json"]
    assert signin_home.refresh_token_in(world.home, "nous") == world.issuers.current_refresh_token("nous")


@pytest.mark.parametrize("provider", ["nous", "openai-codex"])
def test_a_launcher_killed_right_after_the_issuer_answered_leaves_a_copy_that_signs_in(world, on, provider):
    """The process ends, with no cleanup, at the first thing the engine does after Hermes wrote the renewed
    sign-in: the sink never got the token and the pins recorded nothing."""
    layout, engine, cred = on(provider)
    engine.close()
    spent = signin_home.refresh_token_in(world.copy, provider)
    killed = world.child("killed", world.copy, production=False)
    killed.communicate(timeout=120)
    assert killed.returncode == 9
    assert [call["answer"] for call in world.issuers.refreshes(provider)] == ["rotated"]
    assert signin_home.refresh_token_in(world.copy, provider) == world.issuers.current_refresh_token(provider) != spent
    recorded = pins.load(layout)["stores"]["auth.json"]
    assert recorded != signins.copy_states(world.copy)["auth.json"], "nothing was left stale"

    # The launcher's next start: a new engine over the same copy has the renewed token and renews again.
    world.sink.declared.clear()
    again = world.engine()
    assert [d.id for d in again.declare()] == [cred]
    assert world.issuers.valid(provider, world.sink.values[cred][0])
    renew(world, again)
    assert [call["answer"] for call in world.issuers.refreshes(provider)] == ["rotated", "rotated"]
    again.close()
    # And the switch-off after it gives the profile a sign-in that works.
    pins.release(layout)
    assert world.issuers.valid(provider, world.renew_in_home(provider))
    assert not world.issuers.ended(provider)


def test_no_renewal_runs_while_the_copy_is_settled(world, on):
    layout, engine, cred = on("nous")
    world.clock.advance(engine.status()[0]["renew_at"] - world.clock())
    holding, release = threading.Event(), threading.Event()

    def hold():
        with signins.settled(world.copy):
            holding.set()
            release.wait(30)

    holder = threading.Thread(target=hold)
    holder.start()
    assert holding.wait(30)
    stepping = threading.Thread(target=engine.step)
    stepping.start()
    time.sleep(0.5)
    assert world.issuers.refreshes("nous") == [], "a renewal ran while the copy was being read"
    release.set()
    holder.join(30)
    stepping.join(60)
    assert [call["answer"] for call in world.issuers.refreshes("nous")] == ["rotated"]


def test_only_a_whole_store_is_a_state_to_record(world):
    assert signins.copy_states(world.copy) == {"auth.json": None, ".anthropic_oauth.json": None}
    (world.copy / "auth.json").write_text(json.dumps({"providers": {}}), encoding="utf-8")
    (world.copy / ".anthropic_oauth.json").write_text("{ half a file", encoding="utf-8")
    states = signins.copy_states(world.copy)
    assert states[".anthropic_oauth.json"] is None
    assert states["auth.json"] == pins._file_state(world.copy / "auth.json")
