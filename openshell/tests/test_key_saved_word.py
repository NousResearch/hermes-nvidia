"""A key saved on the Keys page while the sandbox is on: the launcher's answer says what that means for the sandbox,
so the page can say it in one line. ``in_use``: the running sandbox uses the new value now. ``after_restart``: it
does once the sandbox has restarted (a reply was running, or the key is new to the sandbox). ``not_used``: no model
of the profile names the key, so it is not handed in at all.
"""
import asyncio
import json

import test_openshell_driver as LD
from openshell.launcher import supervisor as S
from openshell.launcher.host_routes import HostRoutes


def test_the_keys_route_says_what_a_saved_key_means_for_the_running_sandbox(tmp_path, monkeypatch):
    sup, api, _rec, _layout = LD._supervisor(tmp_path, monkeypatch)
    routes = HostRoutes(sup, lambda: None)
    idle = [True]
    sup.driver.turns_idle = lambda: idle[0]
    secrets = {"LLAMA_API_KEY": LD.SECRET, "DECOY_TOKEN": LD.DECOY}
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: dict(secrets))
    header = {"X-Hermes-Sandbox-Restart-Required": "1"}

    async def written(_req, body):  # Hermes's own handler wrote the key; the launcher then looks at the sandbox
        name = json.loads(body)["key"]
        sup.keys_changed = True  # as the launcher marks every write of a credential
        return await routes._key_live((200, {"ok": True, "key": name, "sandbox_restart_required": True}, dict(header)))

    monkeypatch.setattr(routes, "_env_set", written)

    async def save(name, value):
        secrets[name] = value
        return await routes._key_set(None, json.dumps({"key": name, "value": value}).encode())

    async def scenario():
        await sup.start()
        try:
            (llama,) = api.providers
            # the model's key, replaced while no reply runs: one value-only update, in use now
            assert await save("LLAMA_API_KEY", "sk-replaced") == \
                (200, {"ok": True, "sandbox_restart_required": False, "sandbox": "in_use"}, {})
            assert api.providers[llama]["credentials"] == {"LLAMA_API_KEY": "sk-replaced"}
            # a key no model of the profile names: saved on this computer, the sandbox does not get it
            before = len(api.calls)
            assert await save("SOME_OTHER_TOKEN", "t-" + "o" * 20) == \
                (200, {"ok": True, "sandbox_restart_required": False, "sandbox": "not_used"}, {})
            assert len(api.calls) == before and sup.status()["pending"]["keys"] is False
            # the model's key again, while a reply runs: nothing is touched, the restart is still needed
            idle[0] = False
            assert await save("LLAMA_API_KEY", "sk-later") == \
                (200, {"ok": True, "sandbox_restart_required": True, "sandbox": "after_restart"}, header)
            assert api.providers[llama]["credentials"] == {"LLAMA_API_KEY": "sk-replaced"}
            assert sup.status()["pending"]["keys"] is True
        finally:
            await sup.stop()
        # no sandbox runs (stopped, or still starting): the next start has it
        assert sup.key_use("LLAMA_API_KEY", True) == "after_restart"

    asyncio.run(scenario())

    async def refused(_req, _body):
        return 422, {"detail": "Invalid key name."}, {}

    monkeypatch.setattr(routes, "_env_set", refused)
    assert asyncio.run(routes._key_set(None, b'{"key": "x y", "value": "v"}')) == (422, {"detail": "Invalid key name."}, {})


def test_a_body_that_names_no_key_gets_no_word_it_could_be_wrong_about(tmp_path, monkeypatch):
    sup, _api, _rec, _layout = LD._supervisor(tmp_path, monkeypatch)
    routes = HostRoutes(sup, lambda: None)

    async def written(_req, _body):
        return 200, {"ok": True, "sandbox_restart_required": False}, {}

    monkeypatch.setattr(routes, "_env_set", written)
    for body in (b"", b"[]", b'{"value": "v"}', b"not json"):
        assert asyncio.run(routes._key_set(None, body)) == (200, {"ok": True, "sandbox_restart_required": False}, {}), body
