"""No request leaves this computer for a look at a profile's providers (launcher/signins.py,
openshell_driver.py).

Two requests Hermes makes by itself are left out wherever this plugin asks it about a profile: the cloud metadata
address (169.254.169.254) that the AWS credential chain ends with when a profile names no provider, and the
download of Hermes's public model catalog when the process has none. The rows are read on the page's poll, at the
switch and at every sandbox start. ``world`` refuses, and lists, every connection and name lookup that is not
loopback; the catalog's download is replaced by a recorder that fails it.
"""
import os
import threading

import pytest

pytest.importorskip("openshell.launcher.signins", reason="the sign-in report is not in this tree")

from signin_home import world  # noqa: E402,F401

from openshell.launcher import openshell_driver as OD  # noqa: E402
from openshell.launcher import pins as P  # noqa: E402
from openshell.launcher import provider_rows as R  # noqa: E402
from openshell.launcher import settings_view as SV  # noqa: E402
from openshell.launcher import signins  # noqa: E402
from openshell.launcher import switch as SW  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402

OFF = "AWS_EC2_METADATA_DISABLED"
KEYS = {"ANTHROPIC_API_KEY": "made-up-anthropic-" + "a" * 24, "OPENROUTER_API_KEY": "made-up-openrouter-" + "b" * 24,
        "GEMINI_API_KEY": "made-up-gemini-" + "c" * 24, "DEEPSEEK_API_KEY": "made-up-deepseek-" + "d" * 24,
        "LOCAL_KEY": "made-up-local-" + "e" * 24}


def _layout(world):  # noqa: F811
    return ProfileLayout(name="work", home=world.home, root=world.root)


@pytest.fixture
def no_catalog(monkeypatch):
    """A process that has no model catalog, in memory or on disk, and a download that is recorded and fails."""
    models_dev = pytest.importorskip("agent.models_dev")
    asked = []

    def download(*args, **kwargs):
        asked.append("models.dev")
        raise OSError("a test downloads nothing")

    monkeypatch.setattr(models_dev, "_fetch_models_dev_from_network", download)
    monkeypatch.setattr(models_dev, "_models_dev_cache", {})
    monkeypatch.setattr(models_dev, "_models_dev_cache_time", 0)
    monkeypatch.setattr(models_dev, "_models_dev_retry_after", 0)
    monkeypatch.setattr(models_dev, "_load_disk_cache", lambda *a, **k: {})
    return asked


# -- the cloud metadata address ------------------------------------------------------------------------------

@pytest.mark.parametrize("config", [{}, {"model": {"provider": "auto"}}, {"model": {"default": "some-model"}}])
def test_the_report_of_a_profile_that_names_no_provider_asks_no_metadata_address(world, monkeypatch, no_catalog, config):  # noqa: F811
    monkeypatch.delenv(OFF, raising=False)
    world.config(config)
    assert signins.report(world.home) == []
    assert world.refused == [] and OFF not in os.environ


def test_neither_do_the_page_the_switch_the_terminal_and_the_launcher(world, monkeypatch, no_catalog):  # noqa: F811
    monkeypatch.delenv(OFF, raising=False)
    layout = _layout(world)
    SV.forget_providers()
    assert SV.provider_view(layout) == {"providers": [], "providers_block": None}  # the page's poll
    assert R.host_rows(layout) == [] and R.refusal(layout) is None  # the terminal's check
    SW.refuse_unready(layout)  # the switch
    world.take_copy()  # the launcher: the sign-ins at a sandbox's start, and the routes of that start
    engine = world.engine()
    assert engine.declare() == [] and engine.step() > 0 and signins.report(world.copy) == []
    engine.catch_up()
    assert world.refused == [] and OFF not in os.environ
    SV.forget_providers()


def test_the_users_own_setting_is_put_back_also_when_two_threads_ask_at_once(monkeypatch):
    for before in (None, "false"):
        monkeypatch.delenv(OFF, raising=False) if before is None else monkeypatch.setenv(OFF, before)
        inside, release, seen = threading.Event(), threading.Event(), []

        def long_look():
            with signins.no_metadata_lookup():
                inside.set()
                release.wait(10)
                seen.append(os.environ.get(OFF))

        thread = threading.Thread(target=long_look)
        thread.start()
        assert inside.wait(10)
        with signins.no_metadata_lookup():
            assert os.environ[OFF] == "true"
        assert os.environ[OFF] == "true", "the first look lost the setting when the second ended"
        release.set()
        thread.join(10)
        assert seen == ["true"] and os.environ.get(OFF) == before


# -- the model catalog ----------------------------------------------------------------------------------------

def test_the_key_discovery_makes_no_request(world, monkeypatch, no_catalog):  # noqa: F811
    world.config({"model": {"provider": "anthropic", "default": "claude-x"},
                  "fallback_model": {"provider": "openrouter", "model": "some/model"},
                  "auxiliary": {"vision": {"provider": "gemini", "model": "gemini-x"}},
                  "providers": {"local": {"base_url": "http://127.0.0.1:18500/v1", "key_env": "LOCAL_KEY"}}})
    (world.home / ".env").write_text("".join(f"{name}={value}\n" for name, value in KEYS.items()), encoding="utf-8")
    layout = _layout(world)
    found = OD.discover_routes(world.home, dict(KEYS), {"models": P.model_entries(SV._read_config(layout)), "allowed": []})
    by_env = {route["env"]: route for route in found.routes}
    assert {"ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY"} <= set(by_env)
    assert by_env["ANTHROPIC_API_KEY"]["placement"] == "header" and by_env["OPENROUTER_API_KEY"]["placement"] == "bearer"
    assert by_env["GEMINI_API_KEY"]["placement"] == "header" and by_env["GEMINI_API_KEY"]["name"] == "x-goog-api-key"
    rows = R.host_rows(layout)  # the page, the switch and the terminal go through the same discovery
    assert {row["id"] for row in rows} >= {"key:ANTHROPIC_API_KEY", "key:OPENROUTER_API_KEY", "key:GEMINI_API_KEY"}
    assert no_catalog == [] and world.refused == []


def test_the_request_shape_is_the_one_hermes_works_out_itself(world, monkeypatch, no_catalog):  # noqa: F811
    """The discovery reads a provider's request shape without the network. It must be Hermes's own answer: here
    Hermes's function runs with its download failing, as on a computer without a network."""
    from hermes_cli import runtime_provider
    from hermes_cli.auth import PROVIDER_REGISTRY

    cases = [(provider, str(getattr(row, "inference_base_url", "") or ""), model)
             for provider, row in sorted(PROVIDER_REGISTRY.items()) for model in ("", "claude-sonnet-x", "gpt-x")]
    cases += [("custom", "https://llm.example.com/v1", ""), ("custom", "https://api.anthropic.com", ""),
              ("anthropic", "https://relay.example.com/v1", "claude-x"), ("minimax", "https://api.minimax.io/v1", ""),
              ("minimax", "https://api.minimax.io/anthropic", ""), ("nous", "https://inference.example.com/v1", "claude-x"),
              ("bedrock", "", ""), ("no-such-provider", "https://x.example.com/v1", ""), ("openrouter", "", "")]
    assert len(cases) > 30
    for provider, url, model in cases:
        ours = OD._api_mode({"model": model}, provider, url)
        assert ours == str(runtime_provider._fallback_api_mode(provider, url, model) or ""), (provider, url, model)
    assert world.refused == []
    assert OD._api_mode({"api_mode": "anthropic_messages"}, "custom", "https://llm.example.com/v1") == "anthropic_messages"
