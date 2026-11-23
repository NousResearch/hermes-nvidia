"""A long reply is cut once when sign-ins must be renewed, not once for each (launcher/signins.py).

Replacing a value closes whatever streams in the sandbox, whichever sign-in the value belongs to. A profile with
two sign-ins has two last moments. When one value goes in at its last moment, every other sign-in that is already
due is renewed and handed over in the same pass; one that is not due yet is left alone.
"""
import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

from signin_home import world  # noqa: E402,F401

NOUS, CODEX = "nous:agent_key", "openai-codex:access_token"


def _both(world, apart):  # noqa: F811
    """Signed in to Nous Portal, and *apart* seconds later to OpenAI Codex; declared; a reply streams from now on."""
    world.config({"model": {"provider": "nous", "default": "m"},
                  "auxiliary": {"title_generation": {"provider": "openai-codex", "model": "x"}}})
    world.issuers.ttl["nous"] = world.issuers.ttl["openai-codex"] = 900  # the same lifetime for both
    world.sign_in("nous")
    world.clock.advance(apart)
    world.sign_in("openai-codex")
    world.take_copy()
    engine = world.engine()
    assert sorted(d.id for d in engine.declare()) == [NOUS, CODEX]
    world.sink.busy = True
    return engine, {row["id"]: row for row in engine.status()}


def test_the_other_sign_in_that_is_due_goes_in_with_the_one_at_its_last_moment(world):  # noqa: F811
    engine, rows = _both(world, apart=60)
    assert rows[CODEX]["renew_at"] < rows[NOUS]["last_moment"] < rows[CODEX]["last_moment"]
    world.clock.advance(rows[NOUS]["last_moment"] - world.clock() - 5)
    engine.step()
    assert world.sink.updates == [], "a value was replaced under a streaming reply before any last moment"
    world.clock.advance(6)
    engine.step()
    assert [(u["id"], u["quiet"]) for u in world.sink.updates] == [(NOUS, False), (CODEX, False)]
    assert world.sink.updates[1]["at"] - world.sink.updates[0]["at"] < 30, "the two values did not go in together"
    assert all(world.issuers.valid(provider, world.sink.values[ident][0])
               for provider, ident in (("nous", NOUS), ("openai-codex", CODEX)))
    # Codex's own last moment comes and goes: its value is new, nothing is replaced a second time.
    world.clock.advance(rows[CODEX]["last_moment"] - world.clock() + 5)
    engine.step()
    assert len(world.sink.updates) == 2 and len(world.issuers.refreshes("openai-codex")) == 1


def test_a_sign_in_that_is_not_due_yet_is_left_alone(world):  # noqa: F811
    engine, rows = _both(world, apart=400)
    assert rows[NOUS]["last_moment"] < rows[CODEX]["renew_at"]
    world.clock.advance(rows[NOUS]["last_moment"] - world.clock() + 1)
    engine.step()
    assert [u["id"] for u in world.sink.updates] == [NOUS] and world.issuers.refreshes("openai-codex") == []


def test_between_replies_each_sign_in_keeps_its_own_time(world):  # noqa: F811
    engine, rows = _both(world, apart=60)
    world.sink.busy = False
    world.clock.advance(rows[NOUS]["renew_at"] - world.clock() + 1)
    engine.step()
    assert [(u["id"], u["quiet"]) for u in world.sink.updates] == [(NOUS, True)]
