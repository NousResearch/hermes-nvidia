"""Four decisions in the provider support that each need a test of their own: the sign-in engine's calls into
Hermes ask no cloud metadata address, a Nous Portal model's request shape is worked out the way Hermes does it,
the page's ``GET /providers`` reads the profile now, and a key the sandbox was not given has no row while it is on.
"""
import asyncio
import importlib.util
import os
from contextlib import contextmanager
from pathlib import Path

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")
pytest.importorskip("openshell.launcher.signins", reason="the sign-in report is not in this tree")

import page_provider_fixtures as fx  # noqa: E402
import test_openshell_driver as LD  # noqa: E402
from page_provider_fixtures import write_env  # noqa: E402
from signin_home import world  # noqa: E402,F401

from openshell.launcher import openshell_driver as OD  # noqa: E402
from openshell.launcher import signins  # noqa: E402

OFF = "AWS_EC2_METADATA_DISABLED"
PLUGIN_DIR = Path(__file__).resolve().parent.parent


def test_every_call_of_the_engine_into_hermes_runs_with_the_metadata_lookup_off(world, monkeypatch):  # noqa: F811
    monkeypatch.delenv(OFF, raising=False)
    world.config({"model": {"provider": "nous", "default": "m"}})
    world.sign_in("nous")
    world.take_copy()
    engine = world.engine()
    assert [d.id for d in engine.declare()] == ["nous:agent_key"]
    core = signins._core()
    bind, seen = core.runtime_scope.bind_profile_scope, []

    @contextmanager
    def watched(home, **kwargs):
        seen.append(os.environ.get(OFF))
        with bind(home, **kwargs) as scope:
            yield scope

    monkeypatch.setattr(core.runtime_scope, "bind_profile_scope", watched)
    row = engine.status()[0]
    world.clock.advance(row["renew_at"] - world.clock() + 1)
    engine.step()  # a renewal: the engine binds its copy and calls Hermes's own refresh
    assert len(world.issuers.refreshes("nous")) == 1 and len(world.sink.updates) == 1
    engine.catch_up()  # and before a sandbox starts again
    assert len(seen) >= 2 and set(seen) == {"true"}, seen
    assert OFF not in os.environ and world.refused == []


def test_a_nous_portal_model_gets_the_request_shape_hermes_gives_it(world, monkeypatch):  # noqa: F811
    from hermes_cli import providers, runtime_provider

    fx.offline_catalog(monkeypatch)
    url = "https://inference-api.nousresearch.com/v1"
    monkeypatch.setattr(providers, "_nous_anthropic_wire", lambda: "native")
    # Portal serves its anthropic/* models on the Messages wire when the profile says so; every other model on chat
    assert OD._api_mode({"model": "anthropic/claude-x"}, "nous", url) == "anthropic_messages"
    assert OD._api_mode({"model": "some/other-model"}, "nous", url) == "chat_completions"
    monkeypatch.setattr(providers, "_nous_anthropic_wire", lambda: "chat")
    assert OD._api_mode({"model": "anthropic/claude-x"}, "nous", url) == "chat_completions"
    for wire in ("native", "chat"):
        monkeypatch.setattr(providers, "_nous_anthropic_wire", lambda wire=wire: wire)
        for provider in ("nous", "Nous", "nous-portal", "nousresearch"):
            for model in ("anthropic/claude-x", "some/other-model", ""):
                assert OD._api_mode({"model": model}, provider, url) == \
                    str(runtime_provider._fallback_api_mode(provider, url, model) or ""), (wire, provider, model)
    assert world.refused == []


def test_the_providers_route_reads_the_profile_now(world, monkeypatch):  # noqa: F811
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    fx.offline_catalog(monkeypatch)
    spec = importlib.util.spec_from_file_location("openshell_plugin_api_now", PLUGIN_DIR / "dashboard" / "plugin_api.py")
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    view = api._view
    view.forget_providers()
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/openshell")
    page = TestClient(app)
    fx.install(monkeypatch)
    world.config({"model": {"provider": "openrouter", "default": "m"}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    try:
        first = page.get("/api/plugins/openshell/providers").json()
        assert [row["id"] for row in first["providers"]] == ["key:OPENROUTER_API_KEY"]
        reads, host_rows = [], view._host_rows

        def counted(layout):
            reads.append(layout.name)
            return host_rows(layout)

        monkeypatch.setattr(view, "_host_rows", counted)
        # the page's poll of the config may reuse rows for a few seconds while the profile's files stay the same
        assert page.get("/api/plugins/openshell/config").json()["providers"] == first["providers"] and reads == []
        # this route is asked when the answer must be current (a sign-in made a moment ago lives outside those files)
        assert page.get("/api/plugins/openshell/providers").json() == first and len(reads) == 1
        assert page.get("/api/plugins/openshell/providers").json() == first and len(reads) == 2
    finally:
        view.forget_providers()


def test_a_key_the_sandbox_was_not_given_has_no_row_while_it_is_on(tmp_path, monkeypatch):
    sup, _api, _rec, _layout = LD._supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        try:
            given = [row for row in sup.provider_rows() if row.get("env") == "LLAMA_API_KEY"]
            assert len(given) == 1 and given[0]["state"] == "ready"
            # the discovery listed one more key than the driver registered (a sandbox takes a fixed number of
            # providers; a variable the launcher declared itself wins over the profile's key of that name)
            sup._key_rows = [*sup._key_rows, {**sup._key_rows[0], "id": "key:NOT_HANDED_IN", "env": "NOT_HANDED_IN",
                                              "label": "Another provider"}]
            ids = [row["id"] for row in sup.provider_rows()]
            assert given[0]["id"] in ids and "key:NOT_HANDED_IN" not in ids
        finally:
            await sup.stop()

    asyncio.run(scenario())
