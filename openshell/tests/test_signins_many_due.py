"""Three or more sign-ins due at one last moment cost a streaming reply at most two of its attempts
(launcher/signins.py).

Replacing a value closes whatever streams in the sandbox, and Hermes asks the model again a moment later, three
times at most for one reply. A renewal takes a round trip to the provider's issuer. If each sign-in that is due
were renewed and handed over in turn, every hand-over would come a round trip after the one before and could cut
the attempt that had just started: three sign-ins could use the reply up. So no value is handed over with a renewal
in between: the sign-ins at their last moment are renewed and go in together, then every other one that is due is
renewed and those go in together.
"""
import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

from signin_home import world  # noqa: E402,F401

IDS = {"nous": "nous:agent_key", "openai-codex": "openai-codex:access_token", "xai-oauth": "xai-oauth:access_token"}


def _three(world, apart=(20, 20)):  # noqa: F811
    """Signed in to three providers, *apart* seconds after one another; declared; a reply streams from now on.
    Every refresh at an issuer and every value handed to the sink is listed in order."""
    world.config({"model": {"provider": "nous", "default": "m"},
                  "auxiliary": {"title_generation": {"provider": "openai-codex", "model": "x"},
                                "vision": {"provider": "xai-oauth", "model": "g"}}})
    for provider, wait in zip(IDS, (*apart, 20)):
        world.issuers.ttl[provider] = 900
        world.sign_in(provider)
        world.clock.advance(wait)
    world.take_copy()
    engine = world.engine()
    assert sorted(d.id for d in engine.declare()) == sorted(IDS.values())
    events = []
    refresh, update = world.issuers._refresh, world.sink.update

    def refreshed(provider, presented):
        events.append(("renewed", IDS[provider]))
        return refresh(provider, presented)

    def updated(cred_id, value, expires_at):
        update(cred_id, value, expires_at)
        events.append(("handed over", cred_id))

    world.issuers._refresh, world.sink.update = refreshed, updated
    world.sink.busy = True
    return engine, {row["id"]: row for row in engine.status()}, events


def _runs(events):
    """The hand-overs as runs with no renewal in between: each run closes what streams once."""
    runs, last = [], None
    for what, ident in events:
        if what == "handed over":
            if last != "handed over":
                runs.append([])
            runs[-1].append(ident)
        last = what
    return runs


def test_every_sign_in_that_is_due_is_renewed_before_the_others_values_go_in(world):  # noqa: F811
    engine, rows, events = _three(world)
    first = min(rows, key=lambda ident: rows[ident]["last_moment"])
    assert all(rows[ident]["renew_at"] < rows[first]["last_moment"] for ident in rows)  # all three are due by then
    world.clock.advance(rows[first]["last_moment"] - world.clock() - 5)
    engine.step()
    assert events == [], "a value was replaced under a streaming reply before any last moment"
    world.clock.advance(6)
    engine.step()
    runs = _runs(events)
    assert sorted(ident for run in runs for ident in run) == sorted(IDS.values())  # one pass renews everything due
    # what was at its last moment, then the two others together: two closes, whatever the number of sign-ins
    assert runs[0] == [first] and len(runs) == 2 and len(runs[1]) == 2, events
    assert [what for what, _ident in events].count("renewed") == 3
    assert all(world.issuers.valid(provider, world.sink.values[ident][0]) for provider, ident in IDS.items())
    # the other last moments come and go: every value is new, nothing is replaced again
    world.clock.advance(120)
    engine.step()
    assert len(_runs(events)) == 2 and all(len(world.issuers.refreshes(provider)) == 1 for provider in IDS)


def test_a_sign_in_whose_renewal_fails_in_that_pass_does_not_hold_the_others_back(world):  # noqa: F811
    engine, rows, events = _three(world)
    first = min(rows, key=lambda ident: rows[ident]["last_moment"])
    world.issuers.fail("xai-oauth", "server_error")
    world.clock.advance(rows[first]["last_moment"] - world.clock() + 1)
    engine.step()
    handed = [ident for run in _runs(events) for ident in run]
    assert sorted(handed) == sorted(ident for ident in IDS.values() if ident != IDS["xai-oauth"])
    assert len(_runs(events)) == 2
    assert {row["id"]: row["state"] for row in engine.status()}[IDS["xai-oauth"]] == "retrying"


def test_two_sign_ins_at_their_last_moment_together_go_in_together(world):  # noqa: F811
    engine, rows, events = _three(world, apart=(0, 60))
    nous, codex, xai = IDS.values()
    both = max(rows[nous]["last_moment"], rows[codex]["last_moment"])  # the same moment, give or take a second
    assert both - min(rows[nous]["last_moment"], rows[codex]["last_moment"]) <= 2 and both + 30 < rows[xai]["last_moment"]
    world.clock.advance(both - world.clock() + 1)
    engine.step()
    # both are renewed before either value is handed over; then the third, which is due, in a turn of its own
    assert events[:4] == [("renewed", nous), ("renewed", codex), ("handed over", nous), ("handed over", codex)], events
    assert _runs(events) == [[nous, codex], [xai]]
