"""A sandbox that starts again inside one launcher starts with the current sign-in values (launcher/supervisor.py,
signins.py, openshell_driver.py).

The sign-ins are declared to the driver once per launcher process. A folder grant restarts the sandbox in that
process, possibly after a renewal: the provider the new sandbox is created with must hold the token that is
current then, and the stand-in store must still have the sign-in's row. Sign-ins are made with Hermes's own steps
against loopback issuers; the gateway is a fake that keeps what it is given.
"""
import asyncio
import json
import threading

import pytest

pytest.importorskip("openshell.launcher.signins", reason="the sign-in engine is not in this tree")

import test_openshell_driver as LD  # noqa: E402
from signin_home import world  # noqa: E402,F401
from test_standins_wiring import _supervisor  # noqa: E402

from openshell.launcher import pins as P  # noqa: E402
from openshell.launcher import signins  # noqa: E402
from openshell.launcher.credential_sink import CredentialDecl, Endpoint  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402

NOUS = "HERMES_CRED_NOUS_AGENT_KEY"


def _on(world, tmp_path, monkeypatch, provider="nous", shared=False):  # noqa: F811
    """A supervisor over the fake gateway for the world's profile, signed in to *provider* (*shared*: through
    the default profile's sign-in), with an engine on the world's clock."""
    world.config({"model": {"provider": provider, "default": "m"}})
    if shared:
        world.config({"model": {"provider": provider, "default": "m"}}, home=world.root)
        world.sign_in(provider, home=world.root)
    else:
        world.sign_in(provider)
    layout = ProfileLayout(name="work", home=world.home, root=world.root)
    sup, api, _rec, layout = _supervisor(tmp_path, monkeypatch, layout)
    sup.signins = signins.SignIns(P.pin_dir(layout), sup.driver, clock=world.clock, sleep=world.clock.sleep,
                                  on_change=lambda names: P.follow_copy(layout))
    return sup, api, layout


def _held(api, variable=NOUS):
    """The value the gateway holds for *variable* (one provider registers it)."""
    (value,) = [row["credentials"][variable] for row in api.providers.values() if variable in row["credentials"]]
    return value


def _due(world, sup):  # noqa: F811
    """Move the clock to the moment the declared sign-in is due."""
    (row,) = [row for row in sup.signins.status() if row.get("id")]
    world.clock.advance(max(0.0, row["renew_at"] - world.clock()) + 1.0)


def _stand_in_rows(layout) -> dict:
    template = json.loads((layout.state_dir / "standin" / "template.json").read_text(encoding="utf-8"))
    return (template["files"].get("auth.json") or {}).get("providers") or {}


def test_a_restart_after_a_renewal_starts_with_the_renewed_token(world, tmp_path, monkeypatch):  # noqa: F811
    sup, api, layout = _on(world, tmp_path, monkeypatch)
    sup.driver.turns_idle = lambda: True  # no reply is streaming

    async def scenario():
        await sup.start()
        try:
            first = _held(api)
            assert world.issuers.valid("nous", first) and "nous" in _stand_in_rows(layout)
            _due(world, sup)
            sup.signins.step()  # the renewal, handed over at once: no reply is streaming
            renewed = _held(api)
            assert renewed != first and world.issuers.valid("nous", renewed)
            assert [call for call in api.calls if call[0] == "provider update"], "the value was not replaced in place"
            created = len([call for call in api.calls if call[0] == "create"])
            await sup.restart()
            assert len([call for call in api.calls if call[0] == "create"]) == created + 1
            assert _held(api) == renewed, "the sandbox started again with a token from before the renewal"
            assert "nous" in _stand_in_rows(layout), "the stand-in of the restart lost the sign-in's row"
            assert len(world.issuers.refreshes("nous")) == 1, "the restart renewed again"
            return first, renewed
        finally:
            sup.switching_off = True
            await sup.stop()

    first, renewed = asyncio.run(scenario())
    for path in layout.state_dir.rglob("*"):
        if path.is_file() and P.pin_dir(layout) not in path.parents:
            assert first.encode() not in path.read_bytes() and renewed.encode() not in path.read_bytes(), path


def test_a_renewed_token_that_waited_for_a_quiet_moment_goes_in_with_the_restart(world, tmp_path, monkeypatch):  # noqa: F811
    sup, api, layout = _on(world, tmp_path, monkeypatch)
    quiet = [True]  # quiet when the renewal is made; a reply streams from then on, so the new value waits
    sup.driver.turns_idle = lambda: quiet.pop(0) if quiet else False

    async def scenario():
        await sup.start()
        try:
            first = _held(api)
            _due(world, sup)
            sup.signins.step()
            assert len(world.issuers.refreshes("nous")) == 1 and _held(api) == first  # renewed, not handed over yet
            await sup.restart()
            current = _held(api)
            assert current != first and world.issuers.valid("nous", current)
            assert "nous" in _stand_in_rows(layout)
            assert len(world.issuers.refreshes("nous")) == 1
            (row,) = [row for row in sup.status()["providers"] if row["kind"] == "sign_in"]
            assert row["state"] == "ready" and row["main"] is True
        finally:
            sup.switching_off = True
            await sup.stop()

    asyncio.run(scenario())


def test_a_restart_after_another_hermes_renewed_a_shared_sign_in_starts_with_its_token(world, tmp_path, monkeypatch):  # noqa: F811
    """The profile uses the default profile's sign-in. That profile's Hermes renews it; the sandbox then starts
    again before the launcher's own schedule looked: the new sandbox gets the token that is in the store now,
    and the stand-in keeps the row."""
    sup, api, layout = _on(world, tmp_path, monkeypatch, shared=True)

    async def scenario():
        await sup.start()
        try:
            first = _held(api)
            assert "nous" in _stand_in_rows(layout)
            other = world.renew_in_home("nous", home=world.root)  # the default profile's Hermes, on the host
            assert other != first and _held(api) == first
            await sup.restart()
            assert _held(api) == other, "the sandbox started again with the token the other Hermes replaced"
            assert "nous" in _stand_in_rows(layout), "the stand-in of the restart lost the shared sign-in's row"
            assert len(world.issuers.refreshes("nous")) == 1, "the launcher renewed on top of the other Hermes"
        finally:
            sup.switching_off = True
            await sup.stop()

    asyncio.run(scenario())


def test_a_value_update_never_falls_between_a_start_reading_the_values_and_binding_them(tmp_path, monkeypatch):
    """The schedule's thread replaces a value while another thread registers the providers of a start. The
    update waits for the registration; without that it found nothing bound, returned, and the new sandbox ran
    on the old value with nobody left to replace it."""
    sup, api, _rec, _layout = _supervisor(tmp_path, monkeypatch, LD._layout(tmp_path))
    decl = CredentialDecl(id="nous:agent_key", label="Nous Portal", endpoints=(Endpoint("inference.example.com", 443),),
                          placement="bearer", expires=True)
    sup.driver.declare(decl, "old-" + "a" * 40, 2_000_000_000.0)
    upsert, late = api.upsert_provider, []

    def upsert_while_the_schedule_updates(name, profile_id, credentials):
        upsert(name, profile_id, credentials)
        if NOUS in credentials and not late:
            thread = threading.Thread(target=sup.driver.update,
                                      args=("nous:agent_key", "new-" + "b" * 40, 2_000_000_600.0))
            late.append(thread)
            thread.start()
            thread.join(0.5)  # it is still waiting when the registration goes on

    api.upsert_provider = upsert_while_the_schedule_updates

    async def scenario():
        await sup.start()
        try:
            late[0].join(10)
            assert not late[0].is_alive()
            assert _held(api) == "new-" + "b" * 40
        finally:
            await sup.stop()

    asyncio.run(scenario())
