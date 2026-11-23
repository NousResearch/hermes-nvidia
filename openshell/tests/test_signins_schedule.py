"""The sign-in engine's schedule: each token is renewed ahead of its expiry with Hermes's own refresh, the sink
gets the new value at a moment no reply is streaming, and at the last moment before the expiry it gets it anyway.
Time is the test's (signin_issuers.Clock): nothing here waits.
"""
import threading
import time

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import signin_home  # noqa: E402
from signin_home import files_under, world  # noqa: E402,F401

from openshell.launcher import signins  # noqa: E402

CARRIED = ["nous", "openai-codex", "xai-oauth", "minimax-oauth", "anthropic"]
# These issuers say how long a token lasts, not when it ends: Hermes adds that to its own clock, the real one.
STAMPED_HERE = ("minimax-oauth", "anthropic")


def switched_on(world, provider="nous", **engine):
    """A profile signed in to *provider*, its copy taken, its sign-in declared. ``(engine, credential id)``."""
    world.config({"model": {"provider": provider, "default": "a-model"}})
    world.sign_in(provider)
    world.take_copy()
    made = world.engine(**engine)
    return made, made.declare()[0].id


def held(world, cred):
    return world.sink.values[cred][0]


def answers(world, provider):
    return [call["answer"] for call in world.issuers.refreshes(provider)]


def renew_in(world, engine):
    """Seconds until the next renewal is due."""
    return engine.status()[0]["renew_at"] - world.clock()


def to_due(world, engine):
    """Move the clock to the moment the next renewal is due."""
    world.clock.advance(renew_in(world, engine))


def test_the_margins_are_hermes_keepalive_margins():
    assert (signins.lead(900), signins.last_moment(900)) == (345, 120)  # a fifteen-minute token
    assert (signins.lead(3600), signins.last_moment(3600)) == (1020, 120)  # an hour
    assert (signins.lead(6 * 3600), signins.last_moment(6 * 3600)) == (1020, 120)
    assert (signins.lead(120), signins.last_moment(120)) == (60, 30)  # never more than half a short life
    try:
        from hermes_cli import nous_auth_keepalive as keepalive
    except ImportError:
        return
    for lifetime in (900, 3600, 6 * 3600):
        look = keepalive._tick_seconds(keepalive.NOUS_AUTH_KEEPALIVE_INTERVAL_SECONDS, lifetime)
        horizon = keepalive._refresh_horizon_seconds(look, keepalive.NOUS_INVOKE_JWT_MIN_TTL_SECONDS)
        assert signins.lead(lifetime) == horizon


def test_nothing_is_renewed_before_a_token_is_due(world):
    engine, cred = switched_on(world)
    first = held(world, cred)
    assert renew_in(world, engine) == pytest.approx(900 - 345, abs=5)
    assert engine.step() == signins.LONGEST_SLEEP  # it looks again within a minute, whatever the plan says
    world.clock.advance(renew_in(world, engine) - 10)
    assert engine.step() == pytest.approx(10, abs=1)
    assert answers(world, "nous") == [] and world.sink.updates == [] and world.sink.asked_quiet == 0
    assert held(world, cred) == first


@pytest.mark.parametrize("provider", CARRIED)
def test_a_due_token_is_renewed_and_the_sink_gets_it_at_a_quiet_moment(world, provider):
    changed = []
    engine, cred = switched_on(world, provider, on_change=changed.append)
    first, home_before = held(world, cred), files_under(world.home)
    to_due(world, engine)
    engine.step()
    assert answers(world, provider) == ["rotated"]
    assert [(u["id"], u["quiet"]) for u in world.sink.updates] == [(cred, True)]
    value, expires_at = world.sink.values[cred]
    assert value != first and world.issuers.valid(provider, value)
    issued = time.time() if provider in STAMPED_HERE else world.clock()
    assert expires_at == pytest.approx(issued + world.issuers.ttl[provider], abs=5)
    # The copy holds the newest grant; the profile's home was not touched.
    assert signin_home.refresh_token_in(world.copy, provider) == world.issuers.current_refresh_token(provider)
    assert files_under(world.home) == home_before
    assert changed == [[signins._BY_PROVIDER[provider].file]]
    lifetime = expires_at - world.clock()
    assert renew_in(world, engine) == pytest.approx(lifetime - signins.lead(lifetime), abs=5)
    assert engine.status()[0]["state"] == "works" and engine.notes() == []


def test_while_a_reply_streams_nothing_is_renewed_and_nothing_replaced(world):
    engine, cred = switched_on(world)
    first = held(world, cred)
    to_due(world, engine)
    world.sink.busy = True
    for _ in range(5):
        assert engine.step() == signins.QUIET_POLL
        world.clock.advance(signins.QUIET_POLL)
    assert answers(world, "nous") == [] and world.sink.updates == [] and held(world, cred) == first
    world.sink.busy = False
    engine.step()
    assert answers(world, "nous") == ["rotated"] and [u["quiet"] for u in world.sink.updates] == [True]


@pytest.mark.parametrize("provider", ["nous", "openai-codex"])
def test_at_the_last_moment_the_value_is_replaced_whatever_streams(world, provider):
    """A reply streams from the moment the token is due until after it would have expired: one cut stream is
    better than every request failing."""
    engine, cred = switched_on(world, provider)
    expires = world.sink.values[cred][1]
    lifetime = world.issuers.ttl[provider]
    to_due(world, engine)
    world.sink.busy = True
    while not world.sink.updates:
        assert world.issuers.valid(provider, held(world, cred)), "the sink was left with an expired token"
        assert world.clock() < expires
        world.clock.advance(engine.step())
    update = world.sink.updates[0]
    assert update["quiet"] is False
    last = expires - signins.last_moment(lifetime)
    assert last <= update["at"] < last + signins.QUIET_POLL + 1
    assert answers(world, provider) == ["rotated"], "the token was renewed before the last moment, or twice"
    assert world.issuers.valid(provider, held(world, cred))


def test_a_reply_that_starts_during_the_renewal_is_not_cut(world):
    """Quiet when the renewal starts, streaming when it is back: the new value waits for the next quiet moment,
    and no second refresh token is spent."""
    engine, cred = switched_on(world)
    to_due(world, engine)
    said = iter([True, False, False, True])
    world.sink.quiet = lambda: next(said)
    assert engine.step() == signins.QUIET_POLL
    assert answers(world, "nous") == ["rotated"] and world.sink.updates == []
    assert engine.step() == signins.QUIET_POLL and world.sink.updates == []
    engine.step()
    assert len(world.sink.updates) == 1 and answers(world, "nous") == ["rotated"]
    assert world.issuers.valid("nous", held(world, cred))


def test_a_network_error_is_tried_again_with_growing_waits(world):
    engine, cred = switched_on(world)
    first = held(world, cred)
    to_due(world, engine)
    world.issuers.fail("nous", "server_error", "timeout", "server_error", "timeout", "server_error", "server_error")
    waits = []
    for _ in range(6):
        waits.append(engine.step())
        world.clock.advance(waits[-1])
    assert waits == pytest.approx([5, 10, 20, 40, 60, 60], abs=0.5)
    row = engine.status()[0]
    assert (row["state"], row["failures"]) == ("retrying", 6)
    assert row["sentence"] == "Couldn't reach Nous Portal to renew the sign-in. Trying again."
    assert world.sink.updates == [] and held(world, cred) == first
    engine.step()
    assert answers(world, "nous")[-1] == "rotated" and len(world.sink.updates) == 1
    assert engine.status()[0]["state"] == "works"
    # No refresh token was spent by a failed attempt: the copy still signs in.
    assert signin_home.refresh_token_in(world.copy, "nous") == world.issuers.current_refresh_token("nous")


def test_a_token_that_was_not_renewed_in_time_comes_back_when_the_issuer_answers(world):
    engine, cred = switched_on(world)
    expires = world.sink.values[cred][1]
    to_due(world, engine)
    world.issuers.fail("nous", *["server_error"] * 40)
    while world.clock() < expires + 30:
        world.clock.advance(engine.step())
    row = engine.status()[0]
    assert (row["state"], row["usable"]) == ("lapsed", False)
    assert engine.notes() == ["The Nous Portal sign-in could not be renewed in time. The model answers again once "
                              "it is renewed."]
    assert engine.notes() == []
    world.issuers.faults["nous"].clear()
    world.clock.advance(engine.step())
    engine.step()
    engine.step()
    assert world.issuers.valid("nous", held(world, cred))
    row = engine.status()[0]
    assert (row["state"], row["usable"]) == ("works", True)


@pytest.mark.parametrize("provider", CARRIED)
def test_a_grant_that_is_gone_stops_the_schedule_and_keeps_the_last_value(world, provider):
    engine, cred = switched_on(world, provider)
    first, expires = world.sink.values[cred]
    label = engine.status()[0]["label"]
    to_due(world, engine)
    world.issuers.fail(provider, "invalid_grant")
    engine.step()
    row = engine.status()[0]
    assert (row["state"], row["sentence"]) == ("needs_sign_in", "Sign-in expired. Sign in again.")
    assert row["action"] == f"Turn the sandbox off, sign in to {label}, then turn it on again."
    assert row["usable"] is True and row["renew_at"] is None
    assert engine.notes() == [f"The {label} sign-in expired on this computer. Turn the sandbox off, sign in to "
                              f"{label}, then turn it on again."]
    asked = len(world.issuers.refreshes(provider))
    while world.clock() < expires + 60:
        world.clock.advance(engine.step())
    assert len(world.issuers.refreshes(provider)) == asked, "a dead grant was presented again"
    assert world.sink.updates == [] and held(world, cred) == first
    assert engine.status()[0]["usable"] is False and engine.notes() == []
    if provider in ("nous", "xai-oauth", "minimax-oauth"):
        # Hermes took the dead tokens out of the store and left its verdict there: what goes back to the
        # profile says the same, and the page offers the sign-in. (For the other two Hermes leaves the store
        # as it was; the next renewal finds out again.)
        row = [r for r in signins.report(world.copy) if r["provider"] == provider][0]
        assert (row["state"], row["sentence"]) == ("needs_sign_in", "Sign-in expired. Sign in again.")


@pytest.mark.parametrize("provider", ["nous", "openai-codex"])
def test_a_value_the_sink_refuses_is_offered_again_without_a_second_renewal(world, provider):
    engine, cred = switched_on(world, provider)
    to_due(world, engine)
    world.sink.fail_updates = 2
    for _ in range(2):
        assert engine.step() == signins.UPDATE_RETRY
        world.clock.advance(signins.UPDATE_RETRY)
    assert world.sink.updates == []
    engine.step()
    assert len(world.sink.updates) == 1 and answers(world, provider) == ["rotated"]
    assert world.issuers.valid(provider, held(world, cred))


def test_three_lifetimes_of_running_never_leave_the_sink_with_a_dead_token(world):
    """``run`` with a reply streaming two looks out of three: the token in the sink is good at every look."""
    engine, cred = switched_on(world)
    end = world.clock() + 3 * 900
    looks = []

    def sleep(seconds):
        looks.append(seconds)
        assert world.issuers.valid("nous", held(world, cred)), "the sink was left with a dead token"
        world.sink.busy = len(looks) % 3 != 0
        world.clock.advance(seconds)

    engine._sleep = sleep
    engine.run(lambda: world.clock() >= end)
    assert set(answers(world, "nous")) == {"rotated"} and 3 <= len(answers(world, "nous")) <= 6
    assert len(world.sink.updates) == len(answers(world, "nous"))
    assert all(update["quiet"] for update in world.sink.updates), "a stream was cut although quiet moments came"
    assert signin_home.refresh_token_in(world.copy, "nous") == world.issuers.current_refresh_token("nous")


def test_two_passes_at_once_spend_one_refresh_token(world):
    engine, cred = switched_on(world)
    to_due(world, engine)
    world.issuers.delay = 0.2
    passes = [threading.Thread(target=engine.step) for _ in range(2)]
    for one in passes:
        one.start()
    for one in passes:
        one.join(30)
    assert answers(world, "nous") == ["rotated"] and len(world.sink.updates) == 1
    row = engine.status()[0]
    assert (row["state"], row["failures"]) == ("works", 0), "the second pass ran into the first one's renewal"


def test_a_token_that_does_not_say_when_it_expires_is_planned_as_a_short_one(world):
    world.issuers.plain.add("xai-oauth")
    engine, cred = switched_on(world, "xai-oauth")
    assert world.sink.values[cred][1] is None
    assumed = signins.ASSUMED_LIFETIME
    assert renew_in(world, engine) == pytest.approx(assumed - signins.lead(assumed), abs=2)
    to_due(world, engine)
    engine.step()
    assert answers(world, "xai-oauth") == ["rotated"] and len(world.sink.updates) == 1


def test_a_closed_engine_renews_nothing(world):
    engine, cred = switched_on(world)
    to_due(world, engine)
    engine.close()
    assert engine.step() == signins.LONGEST_SLEEP
    engine.run(lambda: False)  # returns at once
    assert answers(world, "nous") == [] and world.sink.updates == []


def test_a_renewal_that_hands_back_the_old_token_counts_as_failed(world, monkeypatch):
    engine, cred = switched_on(world)
    first = world.sink.values[cred]
    to_due(world, engine)
    nous = signins._BY_PROVIDER["nous"]
    monkeypatch.setattr(nous, "resolve", lambda core, *, renew, stale: signins.Token(first[0], first[1]))
    assert engine.step() == pytest.approx(signins.BACKOFF[0], abs=0.5)
    assert world.sink.updates == [] and engine.status()[0]["state"] == "retrying"


def test_a_sink_that_cannot_say_whether_a_reply_streams_is_not_taken_as_quiet(world):
    engine, cred = switched_on(world)
    to_due(world, engine)

    def unknown():
        raise RuntimeError("the driver is restarting")

    world.sink.quiet = unknown
    assert engine.step() == signins.QUIET_POLL
    assert answers(world, "nous") == [] and world.sink.updates == []


def test_between_two_attempts_the_issuer_is_left_alone(world):
    engine, cred = switched_on(world)
    to_due(world, engine)
    world.issuers.fail("nous", "server_error")
    assert engine.step() == pytest.approx(5, abs=0.5)
    world.clock.advance(2)
    assert engine.step() == pytest.approx(3, abs=0.5)
    assert answers(world, "nous") == ["server_error"]


def test_trouble_with_one_sign_in_does_not_stop_the_others(world, monkeypatch):
    world.config({"model": {"provider": "nous", "default": "a-model"}})
    world.sign_in("nous")
    world.sign_in("openai-codex")
    world.take_copy()
    engine = world.engine()
    assert [d.id for d in engine.declare()] == ["nous:agent_key", "openai-codex:access_token"]

    def broken():
        raise RuntimeError("something this module did not foresee")

    monkeypatch.setattr(engine._entries["nous:agent_key"], "plan", broken)
    world.clock.advance(3600)
    assert engine.step() == signins.BACKOFF[0]
    assert answers(world, "openai-codex") == ["rotated"]
    assert [update["id"] for update in world.sink.updates] == ["openai-codex:access_token"]
