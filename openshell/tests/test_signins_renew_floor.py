"""How often the sign-in engine asks an issuer does not rest on what a token says.

A token decides when it is due, and a token can be wrong: it can arrive already expired (an issuer's fault, or this
computer's clock ahead of the issuer's by more than the token lasts), last a few seconds, or be the one that was to
be replaced. An engine that renews when the token says so would then ask the issuer again at once, each time with
a new grant, for as long as the sandbox is on. Here: two renewals are never closer than a floor, the wait grows
while nothing usable comes back, past a count within an hour the sign-in is left alone and reads as expired, and a
value the sink refuses is offered with the same restraint. A healthy one-minute token is not in the way of any of it.

The loop of these tests is the launcher's: a pass, then a wait of what the pass answered. Time is the test's
(signin_issuers.Clock): nothing here waits.
"""
import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import signin_home  # noqa: E402
import signin_issuers  # noqa: E402
from signin_home import world  # noqa: E402,F401

from openshell.launcher import signins  # noqa: E402

# Hermes hands a renewed token of these back as the issuer sent it. A Nous token about to end it refuses itself,
# and that sign-in reads as expired after the one request.
AS_SENT = ["openai-codex", "xai-oauth", "minimax-oauth", "anthropic"]
# Their tokens carry their own end, on the clock the test's issuers and the engine both read.
OWN_END = ["openai-codex", "xai-oauth"]
LAPSED = "The {label} sign-in could not be renewed in time. The model answers again once it is renewed."


def switched_on(world, provider="openai-codex"):
    world.config({"model": {"provider": provider, "default": "a-model"}})
    world.sign_in(provider)
    world.take_copy()
    engine = world.engine()
    return engine, engine.declare()[0].id


def held(world, cred):
    return world.sink.values[cred][0]


def answers(world, provider):
    return [call["answer"] for call in world.issuers.refreshes(provider)]


def to_due(world, engine):
    world.clock.advance(max(0.0, engine.status()[0]["renew_at"] - world.clock()))


def asked_at(world, provider):
    """The moment of every renewal request the issuer of *provider* gets from here on."""
    times, inner = [], world.issuers._refresh

    def noted(asked, presented):
        if asked == provider:
            times.append(world.clock())
        return inner(asked, presented)

    world.issuers._refresh = noted
    return times


def offered_at(world):
    """The moment of every value the sink is offered from here on."""
    times, inner = [], world.sink.update

    def noted(cred_id, value, expires_at):
        times.append(world.clock())
        return inner(cred_id, value, expires_at)

    world.sink.update = noted
    return times


def gaps(times):
    return [later - earlier for earlier, later in zip(times, times[1:])]


def launcher_loop(world, engine, provider, seconds, most=400, before_pass=None):
    """The launcher's loop for *seconds* on the clock: a pass, then a wait of what the pass answered. It also
    ends once the issuer was asked *most* times, so that an engine that renews in a loop ends the test instead of
    keeping it. Returns what each pass answered."""
    end, waits = world.clock() + seconds, []
    while world.clock() < end and len(world.issuers.refreshes(provider)) < most:
        if before_pass is not None:
            before_pass()
        waits.append(engine.step())
        world.clock.advance(waits[-1])
    return waits


def test_the_numbers_fit_each_other():
    # A one-minute token is due thirty seconds after it arrived: the floor is below that, with room for a request.
    assert signins.lead(signins.SHORTEST_LOOK) == 30 and 20 <= signins.MIN_BETWEEN_RENEWALS < 30
    # Neither that token (120 an hour) nor the floor alone meets the ceiling.
    assert 3600 / 30 < 3600 / signins.MIN_BETWEEN_RENEWALS < signins.MOST_RENEWALS_PER_HOUR <= 180
    assert signins.MOST_UPDATES_PER_HOUR == signins.MOST_RENEWALS_PER_HOUR
    # The longest wait asks as often as a fifteen-minute token does by itself.
    assert signins.LONGEST_WAIT == 600 and 3600 / (900 - signins.lead(900)) > 3600 / signins.LONGEST_WAIT
    assert [signins.wait_after(n, 25.0) for n in range(8)] == [25, 25, 50, 100, 200, 400, 600, 600]
    assert 0 < signins.SHORTEST_PASS <= signins.QUIET_POLL


@pytest.mark.parametrize("provider", AS_SENT)
def test_a_token_that_arrives_expired_is_not_renewed_again_at_once(world, provider):
    engine, cred = switched_on(world, provider)
    label = engine.status()[0]["label"]
    times = asked_at(world, provider)
    to_due(world, engine)
    world.issuers.ttl[provider] = 0
    waits = launcher_loop(world, engine, provider, 3600)
    assert len(times) == 10, f"{len(times)} requests in an hour of tokens that arrive expired"
    assert gaps(times) == pytest.approx([25, 50, 100, 200, 400, 600, 600, 600, 600], abs=2)
    assert min(waits) >= signins.SHORTEST_PASS, "a pass answered that the next one is due at once"
    assert waits[0] == pytest.approx(signins.MIN_BETWEEN_RENEWALS, abs=1)  # the pass that renewed says how long
    assert set(answers(world, provider)) == {"rotated"}
    row = engine.status()[0]
    assert (row["state"], row["usable"], row["failures"]) == ("lapsed", False, 0)
    assert row["sentence"] == LAPSED.format(label=label)
    assert engine.notes() == [LAPSED.format(label=label)], "one note for the chat, not one per request"
    # Every answer was kept: the copy still signs in.
    assert signin_home.refresh_token_in(world.copy, provider) == world.issuers.current_refresh_token(provider)


@pytest.mark.parametrize("seconds", [10, 2])
def test_tokens_too_short_to_keep_alive_are_asked_for_less_and_less_often(world, seconds):
    provider = "openai-codex"
    engine, cred = switched_on(world, provider)
    times = asked_at(world, provider)
    to_due(world, engine)
    world.issuers.ttl[provider] = seconds
    launcher_loop(world, engine, provider, 3600)
    assert len(times) == 10 and gaps(times)[:6] == pytest.approx([25, 50, 100, 200, 400, 600], abs=2)


def test_the_first_token_that_lasts_ends_the_longer_waits(world):
    provider = "openai-codex"
    engine, cred = switched_on(world, provider)
    times = asked_at(world, provider)
    to_due(world, engine)
    world.issuers.ttl[provider] = 0
    launcher_loop(world, engine, provider, 200)
    assert gaps(times) == pytest.approx([25, 50, 100], abs=2)  # the next one is due 200 s after the last
    world.issuers.ttl[provider] = 3600
    launcher_loop(world, engine, provider, 400)
    assert len(times) == 5 and world.issuers.valid(provider, held(world, cred))
    row = engine.status()[0]
    assert row["state"] == "works" and row["renew_at"] - world.clock() > 2000
    # Trouble that comes back starts at the floor again.
    to_due(world, engine)
    world.issuers.ttl[provider] = 0
    launcher_loop(world, engine, provider, 100)
    assert gaps(times)[5:] == pytest.approx([25, 50], abs=2)
    assert len(engine.notes()) == 2  # one for each time the sandbox was left without a token that works


@pytest.mark.parametrize("provider, hours", [("openai-codex", 2), ("xai-oauth", 1)])
def test_a_one_minute_token_is_renewed_at_half_its_life_hour_after_hour(world, provider, hours):
    """Nothing here is in the way of a healthy short token: thirty seconds apart, 120 times an hour, never a
    dead one, and the count of an hour is the count of that hour only."""
    engine, cred = switched_on(world, provider)
    times = asked_at(world, provider)
    world.issuers.ttl[provider] = 60
    to_due(world, engine)
    looks = []

    def look():
        looks.append((world.issuers.valid(provider, held(world, cred)), engine.status()[0]["state"]))

    launcher_loop(world, engine, provider, hours * 3600, most=1000, before_pass=look)
    assert set(looks) == {(True, "works")}
    assert 115 * hours <= len(times) <= 124 * hours and gaps(times) == pytest.approx([30] * (len(times) - 1), abs=2)
    assert len(times) > signins.MOST_RENEWALS_PER_HOUR or hours == 1
    assert set(answers(world, provider)) == {"rotated"} and engine.notes() == []
    assert len(world.sink.updates) == len(times)


def test_two_renewals_are_never_closer_than_the_floor_whatever_the_token_says(world):
    """A thirty-second token says it is due after fifteen. It is renewed at the floor, which keeps it alive."""
    provider = "openai-codex"
    engine, cred = switched_on(world, provider)
    times = asked_at(world, provider)
    world.issuers.ttl[provider] = 30
    to_due(world, engine)
    looks = []
    launcher_loop(world, engine, provider, 3600,
                  before_pass=lambda: looks.append(world.issuers.valid(provider, held(world, cred))))
    assert min(gaps(times)) >= signins.MIN_BETWEEN_RENEWALS - 0.01
    assert len(times) <= 3600 / signins.MIN_BETWEEN_RENEWALS + 1 < signins.MOST_RENEWALS_PER_HOUR
    assert all(looks) and engine.status()[0]["state"] == "works"


def test_the_floor_counts_from_the_switch(world):
    """Hermes may have renewed a sign-in to answer the switch: a token that is due as it is declared waits too."""
    provider = "openai-codex"
    world.config({"model": {"provider": provider, "default": "a-model"}})
    world.sign_in(provider)
    world.take_copy()
    world.clock.advance(2 * 3600)  # the token is past its end on the engine's clock
    engine = world.engine()
    engine.declare()
    times = asked_at(world, provider)
    assert engine.status()[0]["renew_at"] - world.clock() == pytest.approx(signins.MIN_BETWEEN_RENEWALS, abs=0.5)
    assert engine.step() == pytest.approx(signins.MIN_BETWEEN_RENEWALS, abs=0.5) and times == []
    world.clock.advance(signins.MIN_BETWEEN_RENEWALS)
    engine.step()
    assert len(times) == 1 and engine.status()[0]["state"] == "works"


def test_the_same_token_again_is_asked_for_less_and_less_often(world, monkeypatch):
    engine, cred = switched_on(world, "nous")
    first = world.sink.values[cred]
    to_due(world, engine)
    calls = []
    nous = signins._BY_PROVIDER["nous"]
    monkeypatch.setattr(nous, "resolve",
                        lambda core, *, renew, stale: calls.append(world.clock()) or signins.Token(first[0], first[1]))
    end = world.clock() + 3600
    while world.clock() < end and len(calls) < 400:
        world.clock.advance(engine.step())
    assert gaps(calls) == pytest.approx([5, 10, 20, 40, 80, 160, 320, 600, 600, 600, 600], abs=2)
    assert world.sink.updates == [] and engine.status()[0]["failures"] == len(calls)


def test_past_the_hourly_ceiling_the_sign_in_reads_expired_and_is_left_alone(world):
    """Renewals at the floor with a failed attempt before each: 240 requests an hour, were they all made."""
    provider = "openai-codex"
    engine, cred = switched_on(world, provider)
    times = asked_at(world, provider)
    world.issuers.ttl[provider] = 40
    to_due(world, engine)
    start = world.clock()

    def trouble():
        if answers(world, provider)[-1:] == ["rotated"] and not world.issuers.faults.get(provider):
            world.issuers.fail(provider, "server_error")

    launcher_loop(world, engine, provider, 3 * 3600, most=1000, before_pass=trouble)
    assert len(times) == signins.MOST_RENEWALS_PER_HOUR, f"the issuer was asked {len(times)} times"
    assert times[-1] - start < 3600 and world.clock() - times[-1] > 2 * 3600
    row = engine.status()[0]
    assert (row["state"], row["reason"], row["renew_at"]) == ("needs_sign_in", "expired", None)
    assert row["sentence"] == "Sign-in expired. Sign in again."
    assert row["action"] == "Turn the sandbox off, sign in to OpenAI Codex, then turn it on again."
    assert row["error"] == ("OpenAI Codex was asked to renew the sign-in 150 times within an hour. It is not asked "
                            "again until the sandbox is turned off and on.")
    assert engine.notes() == ["The OpenAI Codex sign-in expired on this computer. Turn the sandbox off, sign in to "
                              "OpenAI Codex, then turn it on again."]
    assert engine.step() == signins.LONGEST_SLEEP
    # The grant is whole: the copy that goes back at switch-off still signs in, and so does the next switch-on.
    assert signin_home.refresh_token_in(world.copy, provider) == world.issuers.current_refresh_token(provider)
    world.issuers.ttl[provider] = 3600
    world.sink = signin_issuers.Sink(world.clock)
    again = world.engine()
    (declared,) = again.declare()
    launcher_loop(world, again, provider, 120, most=1000)
    assert len(times) == signins.MOST_RENEWALS_PER_HOUR + 1
    assert again.status()[0]["state"] == "works" and world.issuers.valid(provider, held(world, declared.id))


def test_a_value_the_sink_keeps_refusing_is_offered_less_and_less_often(world):
    provider = "openai-codex"
    engine, cred = switched_on(world, provider)
    to_due(world, engine)
    offers = offered_at(world)
    world.sink.fail_updates = 10 ** 9
    waits = launcher_loop(world, engine, provider, 3600)
    assert waits[:6] == [2, 2, 4, 8, 16, 32]  # what the pass of each refusal answered
    assert gaps(offers) == pytest.approx([2, 2, 4, 8, 16, 32, 64, 128, 256, 512, 600, 600, 600, 600], abs=1)
    assert answers(world, provider) == ["rotated"], "a refused value is no reason to ask the issuer again"
    assert engine.status()[0]["state"] == "lapsed"  # the value the sandbox has ran out meanwhile
    # The first offer that is taken ends it, and the schedule goes on.
    world.sink.fail_updates = 0
    launcher_loop(world, engine, provider, 700)
    assert engine.status()[0]["state"] == "works" and world.issuers.valid(provider, held(world, cred))
    # A value refused later on is a new story: it starts at the usual wait.
    to_due(world, engine)
    world.sink.fail_updates = 1
    assert engine.step() == signins.UPDATE_RETRY


def test_a_refused_value_is_not_offered_again_before_its_wait_is_over(world):
    engine, cred = switched_on(world)
    to_due(world, engine)
    offers = offered_at(world)
    world.sink.fail_updates = 10 ** 9
    assert engine.step() == signins.UPDATE_RETRY
    for _ in range(5):  # a caller that does not wait
        assert engine.step() == pytest.approx(signins.UPDATE_RETRY, abs=0.5)
    assert len(offers) == 1


def test_a_sink_offered_a_value_too_often_is_left_alone(world):
    """A sandbox that starts again and again has the waiting value offered before each start (``catch_up``)."""
    provider = "openai-codex"
    engine, cred = switched_on(world, provider)
    to_due(world, engine)
    offers = offered_at(world)
    world.sink.fail_updates = 10 ** 9
    engine.step()
    for _ in range(300):
        world.clock.advance(1)
        engine.catch_up()
    assert len(offers) == signins.MOST_UPDATES_PER_HOUR, f"the sink was offered the value {len(offers)} times"
    row = engine.status()[0]
    assert (row["state"], row["sentence"]) == ("needs_sign_in", "Sign-in expired. Sign in again.")
    assert row["error"] == ("The sandbox was offered a new OpenAI Codex token 150 times within an hour. It is not "
                            "offered again until the sandbox is turned off and on.")
    world.sink.fail_updates = 0
    assert engine.step() >= signins.SHORTEST_PASS and len(offers) == signins.MOST_UPDATES_PER_HOUR
    assert answers(world, provider) == ["rotated"]


def test_a_pass_never_answers_less_than_a_second(world):
    engine, cred = switched_on(world)
    world.sink.busy = True
    world.clock.advance(engine.status()[0]["last_moment"] - 0.3 - world.clock())
    assert engine.step() == signins.SHORTEST_PASS


def test_the_loop_ends_when_hermes_stamps_a_token_on_another_clock_than_the_engines(world, monkeypatch):
    """Three token lifetimes of running in a world whose engine reads a clock ahead of the one Hermes stamps a
    token's arrival with: from the engine's side every token arrives older than it is, and after one lifetime
    already expired. The engine once renewed in a loop here and the run never ended."""
    auth_nous = pytest.importorskip("hermes_cli.auth_nous")
    stamped = auth_nous.datetime
    if stamped.__name__ == "WorldDatetime":  # the test world's own stamp: back to the real clock for this test
        monkeypatch.setattr(auth_nous, "datetime", stamped.__mro__[1])
    engine, cred = switched_on(world, "nous")
    times = asked_at(world, "nous")
    end = world.clock() + 3 * 900
    waits = launcher_loop(world, engine, "nous", 3 * 900, most=60)
    assert world.clock() >= end, f"the issuer was asked {len(times)} times and the three lifetimes were not over"
    assert len(times) <= 15 and min(waits) >= signins.SHORTEST_PASS
    assert min(gaps(times)) >= signins.MIN_BETWEEN_RENEWALS - 0.01
    assert signin_home.refresh_token_in(world.copy, "nous") == world.issuers.current_refresh_token("nous")
