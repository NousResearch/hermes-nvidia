"""Three kinds of restart that meet: for a credential-named file, for a sign-in, for an approval.

The launcher restarts a running sandbox by itself when a credential-named file appears in the profile folder
(``Supervisor.hide_new_private``), and on the user's word for a folder or a tool approval or its removal. Before
every start the sign-in engine settles which sign-ins that sandbox gets (``SignIns.for_start``): one that has
ended, or whose token ran out, is left out, and when it is renewed later the page asks for the restart that hands
it in again. The engine spaces its renewals by its own clock and makes no request for a start.

Here these meet: the restart that hides a file while a sign-in has ended, while one is waiting to be renewed,
and while one is renewed under way; what the status says during each; and the count of restarts for such files
beside restarts of the other kinds.

``Gateway`` (``test_signins_ended``) is OpenShell as the launcher meets it when a credential's value has run out.
"""
import asyncio

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import test_private_entry_while_on as PE  # noqa: E402
import test_signins_ended as SE  # noqa: E402
from signin_home import world  # noqa: E402,F401

from openshell.launcher import supervisor as S  # noqa: E402

MAIN, OTHER = SE.MAIN, SE.OTHER
COPY = ".env.bak-20261120T224522Z"
HIDING = f"Restarting the sandbox to hide {COPY}"
STOPPED = "kept appearing in the profile folder while it ran. Turn the sandbox off, then on again."


def watched(sup):
    """What the status and the page say at the moment each restart takes the sandbox down."""
    seen = []
    sup.on_down.append(lambda why: seen.append({
        "why": why, "state": sup.status()["state"], "restarting": sup.status()["restarting"],
        "restart": sup.status()["restart"], "rows": SE.page(sup)}))
    return seen


def copy_appears(world, name=COPY):  # noqa: F811
    (world.home / name).write_text("MADE_UP_KEY=sk-made-up\n", encoding="utf-8")


def hidden(sup, name=COPY) -> bool:
    return any(path.name == name and path.parent == sup.layout.home for path in sup._grants.denied)


# -- the restart that hides a file, and the sign-ins ---------------------------------------------------------------

@pytest.mark.parametrize("ended", [OTHER, MAIN], ids=["another", "the-models"])
def test_the_restart_that_hides_a_file_goes_on_without_a_sign_in_that_ended(
        world, tmp_path, monkeypatch, ended):  # noqa: F811
    """Nobody is asked before this restart, and it must not be the one that takes the sandbox down."""
    SE.signed_in(world, MAIN, OTHER)
    sup, api, layout = SE.launcher(world, tmp_path, monkeypatch)
    monkeypatch.setattr(S, "PRIVATE_LOOK", 0.0)
    kept = MAIN if ended == OTHER else OTHER
    seen = watched(sup)

    async def scenario():
        await sup.start()
        try:
            last = SE.refused(world, sup.signins, ended)
            SE.passes_until(world, sup.signins, last + 1)  # its last token has run out
            asked = len(world.issuers.calls)
            copy_appears(world)
            assert await sup.hide_new_private() == [COPY]
            assert sup.state == "running" and api.step_errors == [] and sup._last_error is None
            assert SE.started_with(api)[0] == {kept} and SE.in_stand_in(layout) == [kept]
            assert hidden(sup)  # the new sandbox's start lists the file
            [down] = seen
            assert down["why"] == "restarting" and down["state"] == "restarting"
            assert down["restarting"]["label"] == HIDING and down["restarting"]["why"] == "hide"
            assert down["restart"] is None  # not a folder's restart: the page shows the status' line
            sentence = ("expired", SE.EXPIRED.format(label=SE.LABELS[ended]))
            assert down["rows"][f"sign_in:{ended}"] == sentence  # the same sentence before, during
            assert SE.page(sup)[f"sign_in:{ended}"] == sentence  # and after
            assert SE.page(sup)[f"sign_in:{kept}"][0] == "ready"
            assert sup.status()["restarting"] is None and sup.status()["restart_required"] is False
            assert len(world.issuers.calls) == asked  # the restart asked no issuer anything
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_restart_that_hides_a_file_inside_a_wait_leaves_the_sign_in_out_and_asks_no_one(
        world, tmp_path, monkeypatch):  # noqa: F811
    """A sign-in whose issuer answers with tokens that are over on arrival waits longer after each answer. A
    restart for a file inside such a wait starts the sandbox without it and does not bring the next try forward."""
    SE.signed_in(world, MAIN, OTHER)
    sup, api, layout = SE.launcher(world, tmp_path, monkeypatch)
    monkeypatch.setattr(S, "PRIVATE_LOOK", 0.0)
    seen = watched(sup)

    async def scenario():
        await sup.start()
        try:
            engine = sup.signins
            SE.passes_until(world, engine, SE.row_of(engine, OTHER)["renew_at"])
            world.issuers.ttl[OTHER] = 0
            engine.step()
            world.clock.advance(5)
            due = SE.row_of(engine, OTHER)["renew_at"]
            assert SE.row_of(engine, OTHER)["state"] == "lapsed" and due > world.clock()
            copy_appears(world)
            assert await sup.hide_new_private() == [COPY]
            assert sup.state == "running" and SE.started_with(api)[0] == {MAIN} and hidden(sup)
            assert seen[-1]["restarting"]["label"] == HIDING
            lapsed = ("expired", SE.LAPSED.format(label=SE.LABELS[OTHER]))
            assert seen[-1]["rows"][f"sign_in:{OTHER}"] == lapsed and SE.page(sup)[f"sign_in:{OTHER}"] == lapsed
            assert SE.row_of(engine, OTHER)["renew_at"] == due  # the wait is the one it was
            assert sup.status()["restart_required"] is False  # nothing to hand in yet
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_sign_in_renewed_while_such_a_restart_is_under_way_is_asked_for_once_the_sandbox_is_back(
        world, tmp_path, monkeypatch):  # noqa: F811
    """The restart settles the sign-ins before the new sandbox is created. One that is renewed after that moment
    is not in the sandbox that comes up: the page's restart bar is raised at the engine's next look, not lost,
    and the restart it asks for hands the sign-in in."""
    SE.signed_in(world, MAIN, OTHER)
    sup, api, layout = SE.launcher(world, tmp_path, monkeypatch)
    monkeypatch.setattr(S, "PRIVATE_LOOK", 0.0)

    async def scenario():
        await sup.start()
        try:
            engine = sup.signins
            SE.passes_until(world, engine, SE.row_of(engine, OTHER)["renew_at"])
            usual, world.issuers.ttl[OTHER] = world.issuers.ttl[OTHER], 0
            engine.step()
            world.clock.advance(5)
            await sup.restart()  # the sandbox runs without the sign-in that is waiting
            assert SE.started_with(api)[0] == {MAIN}

            def renewed_meanwhile():
                api.before_create = None
                world.issuers.ttl[OTHER] = usual
                world.clock.advance(max(0.0, SE.row_of(engine, OTHER)["renew_at"] - world.clock()))
                engine.step()
                sup._publish_sign_ins()  # as the engine's thread does after each look
                assert engine.returned() == [f"{OTHER}:access_token"] and sup.state == "starting"

            api.before_create = renewed_meanwhile
            copy_appears(world)
            assert await sup.hide_new_private() == [COPY]
            assert sup.state == "running" and SE.started_with(api)[0] == {MAIN} and hidden(sup)
            assert sup.status()["pending"]["keys"] is False  # the start's own end
            sup._publish_sign_ins()  # the engine's next look
            assert sup.status()["pending"]["keys"] is True and sup.status()["restart_required"] is True
            assert SE.page(sup)[f"sign_in:{OTHER}"] == ("expired", SE.LAPSED.format(label=SE.LABELS[OTHER]))
            await sup.restart()  # the restart the page asks for
            assert SE.started_with(api)[0] == {MAIN, OTHER} and sup.status()["restart_required"] is False
            assert SE.page(sup)[f"sign_in:{OTHER}"][0] == "ready" and hidden(sup)
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_restart_that_hides_a_file_hands_in_a_sign_in_that_came_back(world, tmp_path, monkeypatch):  # noqa: F811
    """The restart bar is up for a renewed sign-in when a file appears: the one restart does both."""
    SE.signed_in(world, MAIN, OTHER)
    sup, api, layout = SE.launcher(world, tmp_path, monkeypatch)
    monkeypatch.setattr(S, "PRIVATE_LOOK", 0.0)

    async def scenario():
        await sup.start()
        try:
            engine = sup.signins
            SE.passes_until(world, engine, SE.row_of(engine, OTHER)["renew_at"])
            usual, world.issuers.ttl[OTHER] = world.issuers.ttl[OTHER], 0
            engine.step()
            world.clock.advance(5)
            await sup.restart()
            world.issuers.ttl[OTHER] = usual
            world.clock.advance(max(0.0, SE.row_of(engine, OTHER)["renew_at"] - world.clock()))
            engine.step()
            sup._publish_sign_ins()
            assert sup.status()["pending"]["keys"] is True
            copy_appears(world)
            assert await sup.hide_new_private() == [COPY]
            assert SE.started_with(api)[0] == {MAIN, OTHER} and hidden(sup)
            assert sup.status()["restart_required"] is False and SE.page(sup)[f"sign_in:{OTHER}"][0] == "ready"
        finally:
            await sup.stop()

    asyncio.run(scenario())


# -- the count of restarts for such files, beside the other restarts -------------------------------------------------

def test_restarts_of_other_kinds_do_not_count_towards_the_limit_for_such_files(tmp_path, monkeypatch):
    sup, home, starts = PE._supervisor(tmp_path, monkeypatch)

    async def main():
        await sup.start()
        for n in range(S.PRIVATE_LIMIT):
            await sup.restart()  # a folder or a tool approval, a removal, the page's restart
            (home / f".env.bak{n}").write_text("x", encoding="utf-8")
            assert await sup.hide_new_private() == [f".env.bak{n}"]
            assert sup.state == "running"
        await sup.restart()
        assert sup.state == "running" and len(starts) == 2 + 2 * S.PRIVATE_LIMIT
        (home / ".env.bak-one-more").write_text("x", encoding="utf-8")
        await sup.hide_new_private()

    asyncio.run(main())
    assert sup.state == "failed" and sup._last_error.endswith(STOPPED) and ".env.bak-one-more" in sup._last_error
    assert len(starts) == 2 + 2 * S.PRIVATE_LIMIT  # the one more stopped the sandbox instead


def test_a_file_that_another_restart_listed_costs_no_restart_and_is_not_counted(tmp_path, monkeypatch):
    """A file that appears while a restart of another kind is under way is on the new start's list: nothing is
    restarted for it and it is not one of the three."""
    sup, home, starts = PE._supervisor(tmp_path, monkeypatch)

    async def main():
        await sup.start()
        for n in range(S.PRIVATE_LIMIT + 2):
            (home / f".env.bak{n}").write_text("x", encoding="utf-8")
            await sup.restart()
            assert await sup.hide_new_private() == []
        assert sup._private_restarts == [] and sup.state == "running"

    asyncio.run(main())
    assert len(starts) == 1 + S.PRIVATE_LIMIT + 2 and starts[-1] == sorted(
        [".env", *(f".env.bak{n}" for n in range(S.PRIVATE_LIMIT + 2))])


def test_a_sandbox_stopped_for_such_files_says_so_and_asks_no_restart(tmp_path, monkeypatch):
    sup, home, starts = PE._supervisor(tmp_path, monkeypatch)

    async def main():
        await sup.start()
        for n in range(S.PRIVATE_LIMIT + 1):
            (home / f".env.bak{n}").write_text("x", encoding="utf-8")
            await sup.hide_new_private()
        (home / ".env.bak-later").write_text("x", encoding="utf-8")
        assert await sup.hide_new_private() == []  # nothing runs: nothing is looked for

    asyncio.run(main())
    status = sup.status()
    assert status["state"] == "failed" and status["restarting"] is None and status["restart_required"] is False
    assert status["error"] == (f"The sandbox was stopped: credential files (.env.bak{S.PRIVATE_LIMIT}) " + STOPPED)
