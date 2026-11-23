"""The page asks for a restart for a sign-in that came back only while a restart would hand it in.

A sandbox that started without a sign-in (its token had run out) gets it at the next start once it is renewed, and
the Sandbox page's restart bar says so. A renewal can also bring a token that does not last: an issuer that keeps
answering with tokens of a second or two is what makes the engine wait longer after each answer. Such a token is
over before any restart could hand it in, and the sandbox that restarts for it starts without the sign-in again.
The bar is therefore up only while the renewed value lasts as the next start needs it (``SignIns.returned``), is
read anew at every look of the engine, and is down again once that value has run out.

``Gateway`` (``test_signins_ended``) is OpenShell as the launcher meets it when a credential's value has run out.
"""
import asyncio

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import test_signins_ended as SE  # noqa: E402
from signin_home import world  # noqa: E402,F401

MAIN, OTHER = SE.MAIN, SE.OTHER
CODEX = f"{OTHER}:access_token"


def looks(world, sup, seconds):  # noqa: F811
    """The launcher's own loop for *seconds* on the clock: a look of the engine, its rows and notes published, then
    the wait the look answered."""
    end = world.clock() + seconds
    while world.clock() < end:
        wait = sup.signins.step()
        sup._publish_sign_ins()
        world.clock.advance(wait)


async def started_without(world, sup, api):  # noqa: F811
    """A running sandbox that restarted while *OTHER*'s issuer answered with tokens that were over on arrival."""
    await sup.start()
    engine = sup.signins
    SE.passes_until(world, engine, SE.row_of(engine, OTHER)["renew_at"])
    usual, world.issuers.ttl[OTHER] = world.issuers.ttl[OTHER], 0
    engine.step()
    world.clock.advance(5)
    await sup.restart()
    assert SE.started_with(api)[0] == {MAIN} and sup.status()["restart_required"] is False
    return usual


def test_a_renewed_token_that_does_not_last_asks_for_no_restart(world, tmp_path, monkeypatch):  # noqa: F811
    SE.signed_in(world, MAIN, OTHER)
    sup, api, layout = SE.launcher(world, tmp_path, monkeypatch)

    async def scenario():
        usual = await started_without(world, sup, api)
        try:
            engine = sup.signins
            world.issuers.ttl[OTHER] = 2  # the issuer answers again, with tokens that last two seconds
            asked = len(world.issuers.refreshes(OTHER))
            looks(world, sup, 180)
            assert len(world.issuers.refreshes(OTHER)) > asked  # it was renewed, more than once
            world.clock.advance(3)
            sup._publish_sign_ins()
            assert engine.returned() == []  # nothing a restart could hand in
            status = sup.status()
            assert status["restart_required"] is False and status["pending"]["keys"] is False
            assert SE.page(sup)[f"sign_in:{OTHER}"] == ("expired", SE.LAPSED.format(label=SE.LABELS[OTHER]))
            await sup.restart()  # and a restart all the same starts without it, as before
            assert SE.started_with(api)[0] == {MAIN} and sup.status()["restart_required"] is False
            world.issuers.ttl[OTHER] = usual  # tokens that last again
            looks(world, sup, 700)
            assert engine.returned() == [CODEX]
            assert sup.status()["restart_required"] is True and sup.status()["pending"]["keys"] is True
            await sup.restart()
            assert SE.started_with(api)[0] == {MAIN, OTHER} and sup.status()["restart_required"] is False
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_bar_is_down_again_once_the_value_that_came_back_has_run_out(world, tmp_path, monkeypatch):  # noqa: F811
    """The token that came back lasted, the bar went up, nobody restarted, and the issuer then went back to
    tokens that are over on arrival: nothing is left to hand in."""
    SE.signed_in(world, MAIN, OTHER)
    sup, api, layout = SE.launcher(world, tmp_path, monkeypatch)

    async def scenario():
        usual = await started_without(world, sup, api)
        try:
            engine = sup.signins
            world.issuers.ttl[OTHER] = usual
            looks(world, sup, 700)
            assert engine.returned() == [CODEX] and sup.status()["restart_required"] is True
            world.issuers.ttl[OTHER] = 0
            end = SE.row_of(engine, OTHER)["expires_at"]
            looks(world, sup, end - world.clock() + 30)
            assert engine.returned() == [] and sup.status()["restart_required"] is False
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_key_saved_meanwhile_keeps_its_own_restart_bar(world, tmp_path, monkeypatch):  # noqa: F811
    """What else asks for a restart (a key saved while the sandbox is on, an endpoint the user allowed) is not
    taken down by the sign-ins' look."""
    SE.signed_in(world, MAIN, OTHER)
    sup, api, layout = SE.launcher(world, tmp_path, monkeypatch)

    async def scenario():
        await started_without(world, sup, api)
        try:
            sup.endpoint_allowed({"env": "A_KEY", "host": "example.test", "port": 443})
            assert sup.status()["pending"]["keys"] is True
            looks(world, sup, 60)
            assert sup.signins.returned() == [] and sup.status()["pending"]["keys"] is True
        finally:
            await sup.stop()

    asyncio.run(scenario())
