"""The route that moves a key out of config.yaml, on the backend of a profile that is off (dashboard/plugin_api.py).

The Sandbox page's "Move to .env" posts the paths of the keys to move; the route answers what was moved and the
provider rows read again, or a refusal in plain words with its own status. All of its work is
``settings_view.move_keys``; these tests go through the router as the page does. The profile is a throwaway one,
and the module that finds and moves the keys is a stand-in (``page_provider_fixtures``).
"""
import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")
pytest.importorskip("openshell.launcher.signins", reason="the sign-in report is not in this tree")

import page_provider_fixtures as fx  # noqa: E402
from page_provider_fixtures import INLINE_KEY, INLINE_KEY_2, secrets_of, shown, write_env  # noqa: E402
from signin_home import world  # noqa: E402,F401

PLUGIN_DIR = Path(__file__).resolve().parent.parent
MOVE = "/api/plugins/openshell/providers/move"


@pytest.fixture
def page(world, monkeypatch):  # noqa: F811
    """The dashboard router of the throwaway profile, as the page of a profile that is off reaches it."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    fx.offline_catalog(monkeypatch)
    spec = importlib.util.spec_from_file_location("openshell_plugin_api_move", PLUGIN_DIR / "dashboard" / "plugin_api.py")
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    api._view.forget_providers()
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/openshell")
    client = TestClient(app)
    client.keys = fx.install(monkeypatch)
    world.config({"model": {"provider": "custom", "base_url": "https://llm.example.com/v1", "api_key": INLINE_KEY,
                            "default": "m"},
                  "providers": {"spare": {"base_url": "https://spare.example.com/v1", "api_key": INLINE_KEY_2}}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    yield client
    api._view.forget_providers()


def test_the_page_moves_a_key_and_gets_the_rows_read_again(page, world):  # noqa: F811
    before = page.get("/api/plugins/openshell/config").json()
    assert before["providers_block"]["code"] == "key_in_config" and before["sandboxed"] is False
    assert [row["path"] for row in before["providers"][:2]] == ["model.api_key", "providers.spare.api_key"]
    done = page.post(MOVE, json={"keys": ["model.api_key", "providers.spare.api_key"]})
    assert done.status_code == 200
    answer = done.json()
    assert answer["moved"] == [{"path": "model.api_key", "env": "MODEL_API_KEY"},
                               {"path": "providers.spare.api_key", "env": "SPARE_API_KEY"}] and answer["left"] == []
    assert answer["providers_block"] is None
    assert not [row for row in answer["providers"] if row["state"] == "key_in_config"]
    assert page.keys.moves == [(str(world.home), answer["moved"])]
    config = (world.home / "config.yaml").read_text(encoding="utf-8")
    assert INLINE_KEY not in config and INLINE_KEY_2 not in config
    assert f"MODEL_API_KEY={INLINE_KEY}" in (world.home / ".env").read_text(encoding="utf-8")
    after = page.get("/api/plugins/openshell/config").json()
    assert after["providers_block"] is None and after["providers"] == answer["providers"]
    secrets = secrets_of(world.home)
    for payload in (before, answer, after):
        assert [secret for secret in secrets if secret in shown(payload)] == []


def test_a_refusal_keeps_its_status_and_its_plain_words(page, world, monkeypatch):  # noqa: F811
    for body in ({"keys": []}, {"keys": [{"path": "model.api_key", "env": "PATH"}]}, None, ["model.api_key"]):
        refused = page.post(MOVE, json=body)
        assert refused.status_code == 422
        assert refused.json() == {"detail": 'Expected {"keys": [the path of each key to move]}.'}
    gone = page.post(MOVE, json={"keys": ["providers.gone.api_key"]})
    assert gone.status_code == 409 and gone.json()["detail"] == "config.yaml no longer has a key at providers.gone.api_key."
    assert gone.json()["providers_block"]["code"] == "key_in_config"  # the rows, read again
    page.keys.fail = PermissionError(13, "Permission denied")
    failed = page.post(MOVE, json={"keys": ["model.api_key"]})
    assert failed.status_code == 500 and failed.json()["detail"].startswith("Couldn't move model.api_key to .env: ")
    assert INLINE_KEY not in failed.text and "Traceback" not in failed.text
    fx.remove(monkeypatch)
    without = page.post(MOVE, json={"keys": ["model.api_key"]})
    assert without.status_code == 409 and without.json() == {
        "detail": "This version can't move keys. Take the key out of config.yaml and save it in .env yourself."}
    assert len(page.keys.moves) == 1  # only the move that failed was tried


def test_the_route_takes_a_post_only(page):
    assert page.get(MOVE).status_code == 405 and page.put(MOVE, json={"keys": ["model.api_key"]}).status_code == 405
    assert page.keys.moves == []
