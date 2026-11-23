"""A look at the sandbox's state while its start is under way (launcher/openshell_driver.py).

Seen on Linux: now and then a start failed with "sandbox exited with 1 before the backend was ready" although the
sandbox had come up healthy; the launcher then deleted it, and the next start worked. The supervisor's watch asks
the driver for the sandbox's state several times a second, from the event loop, while the driver's ``start`` runs
on a worker thread. Between the moment ``start`` records its request and the moment the sandbox exists on the
gateway, the gateway answers "not found". The driver took that for an exit and kept the answer for two seconds,
which is what the supervisor read when it asked right after ``start`` had returned: a start that took less than
those two seconds failed.
"""
import asyncio

import test_openshell_driver as LD
from openshell.launcher import supervisor as S


def _looks_during_start(api, driver) -> list:
    """Stand in for the watch: one look at the sandbox's state at each step of ``start`` that talks to the
    gateway before the sandbox exists there, and one right as it is created. Returns what the looks got."""
    seen = []
    upsert, create = api.upsert_provider, api.create_sandbox

    def upsert_provider(*args, **kwargs):
        seen.append(("before the sandbox exists", driver.exit_code()))
        return upsert(*args, **kwargs)

    def create_sandbox(name, spec, labels):
        seen.append(("as it is created", driver.exit_code()))
        return create(name, spec, labels)

    api.upsert_provider, api.create_sandbox = upsert_provider, create_sandbox
    return seen


def test_a_look_while_the_sandbox_starts_is_not_an_exit(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    seen = _looks_during_start(api, sup.driver)

    async def scenario():
        await sup.start()  # (it raised: sandbox exited with 1 before the backend was ready)
        try:
            assert sup.state == "running" and sup.driver.exit_code() is None
        finally:
            await sup.stop()

    asyncio.run(scenario())
    assert [what for what, _ in seen] == ["before the sandbox exists", "as it is created"]
    assert [code for _, code in seen] == [None, None]
    assert [c[0] for c in api.calls if c[0] in ("create", "delete")] == ["create", "delete"]  # one sandbox, kept


def test_a_look_while_the_sandbox_restarts_is_not_an_exit(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        try:
            seen = _looks_during_start(api, sup.driver)
            await sup.restart()  # the old sandbox is deleted first: the name is unknown to the gateway meanwhile
            assert sup.state == "running" and sup.driver.exit_code() is None
            assert [code for _, code in seen] == [None, None]
        finally:
            await sup.stop()

    asyncio.run(scenario())
    assert [c[0] for c in api.calls if c[0] in ("create", "delete")] == ["create", "delete", "create", "delete"]


def test_a_sandbox_that_is_gone_after_its_start_is_still_an_exit(tmp_path, monkeypatch):
    """The rule covers the start only: once ``start`` has returned, a sandbox the gateway does not know has ended,
    and a failed start leaves the driver answering its own state again."""
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        try:
            api.sandboxes.pop("hermes-work")
            sup.driver._checked = 0.0  # (the next look asks the gateway)
            assert sup.driver.exit_code() == 1
        finally:
            await sup.stop()
        api.create_sandbox = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("the gateway refused"))
        try:
            await sup.start()
        except Exception as exc:
            assert "the gateway refused" in str(exc)
        else:
            raise AssertionError("the start should have failed")
        assert sup.state == "failed" and sup.driver.exit_code() is not None

    asyncio.run(scenario())
