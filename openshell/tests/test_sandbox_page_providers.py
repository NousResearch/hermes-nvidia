"""The provider rows of the Sandbox page (launcher/settings_view.py) and the host routes around them.

Before the switch the page lists the profile's providers, one row each, with what each will do in the sandbox,
and says what keeps the switch from turning on: a key written in config.yaml, or the profile's model on a
provider that is not available in the sandbox or needs a sign-in first. While the sandbox is on the launcher's
status carries the rows, and they reach the page reduced to what it reads. A key written in config.yaml can be
moved to ``.env`` from the page.

The profiles here are throwaway ones (``signin_home.world``): their sign-ins are made through Hermes's own steps
against loopback issuers, their keys are made up, and the module that finds and moves keys written in
config.yaml is a stand-in (``page_provider_fixtures``).
"""
import asyncio
import json

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")
pytest.importorskip("openshell.launcher.signins", reason="the sign-in report is not in this tree")

import page_provider_fixtures as fx  # noqa: E402
from page_provider_fixtures import INLINE_KEY, INLINE_KEY_2, KEYS, secrets_of, shown, write_env  # noqa: E402
from signin_home import world  # noqa: E402,F401

from openshell.launcher import host_routes as HR  # noqa: E402
from openshell.launcher import pins, signins  # noqa: E402
from openshell.launcher import settings_view as SV  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402
from openshell.launcher.proxy import parse_head  # noqa: E402

WORKS_KEY = "Works in the sandbox. The key stays on this computer and is used only at {}."
SIGNED_IN = "Works in the sandbox. Stays signed in on this computer."
SIGNED_IN_AT = "Works in the sandbox. Stays signed in on this computer and is used only at {}."
INLINE = "Written in config.yaml, where the sandbox could read it."
ONE_KEY = "A key is written in config.yaml, where the sandbox could read it. Move it to .env first."
TWO_KEYS = "Keys are written in config.yaml, where the sandbox could read them. Move them to .env first."
CAPS = {"driver": "openshell", "model_endpoints": "provider", "credentials": "placeholders", "host_loopback": "open"}


@pytest.fixture(autouse=True)
def _fresh_rows():
    SV.forget_providers()
    yield
    SV.forget_providers()



@pytest.fixture(autouse=True)
def _no_catalog_download(monkeypatch):
    fx.offline_catalog(monkeypatch)


def _layout(world):  # noqa: F811
    return ProfileLayout(name="work", home=world.home, root=world.root)


def _view(world):  # noqa: F811
    SV.forget_providers()
    return SV.provider_view(_layout(world))


def _by_id(view) -> dict:
    return {row["id"]: row for row in view["providers"]}


def _reported(monkeypatch, *rows):
    """A sign-in report with these rows, whatever the home holds."""
    monkeypatch.setattr(signins, "report", lambda home: [dict(row) for row in rows])


def _report_row(provider, label, state, reason, used_by=("model",), kind="sign_in"):
    return {"provider": provider, "label": label, "kind": kind, "shared": False, "state": state, "reason": reason,
            "used_by": list(used_by), "sentence": "the report's own words"}


# -- before the switch: the rows ------------------------------------------------------------------------

def test_a_profile_with_no_provider_credentials_lists_nothing_and_holds_nothing(world):  # noqa: F811
    view = _view(world)
    assert view == {"providers": [], "providers_block": None}


def test_a_profile_that_names_no_provider_is_read_without_asking_the_cloud_metadata_address(world, monkeypatch):  # noqa: F811
    """Hermes finds such a profile's provider by looking at what the computer has; the last place it looks asks
    an address outside this computer and waits. The rows are read on a poll: that step is left out, and only
    for the length of the call. (``world`` fails a test that reaches for an address that is not loopback.)"""
    import os

    seen = []
    resolve = signins._core().auth.resolve_provider
    monkeypatch.setattr(signins._core().auth, "resolve_provider",
                        lambda name, *a, **k: (seen.append(os.environ.get("AWS_EC2_METADATA_DISABLED")),
                                               resolve(name, *a, **k))[1])
    monkeypatch.delenv("AWS_EC2_METADATA_DISABLED", raising=False)
    assert _view(world)["providers"] == [] and seen == ["true"]
    assert "AWS_EC2_METADATA_DISABLED" not in os.environ and world.refused == []
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "false")  # the user's own setting is put back as it was
    world.config({"model": {"provider": "auto"}})
    assert _view(world)["providers"] == [] and seen == ["true", "true"]
    assert os.environ["AWS_EC2_METADATA_DISABLED"] == "false"


def test_a_model_whose_key_is_not_in_the_profile_is_named_and_does_not_hold_the_switch(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "default": "some/model"}})
    view = _view(world)
    assert view["providers"] == [{
        "id": "key:openrouter", "label": "OpenRouter", "kind": "key", "state": "no_key", "main": True,
        "env": "OPENROUTER_API_KEY", "detail": ("No key found: OPENROUTER_API_KEY is not set in this profile's .env. "
                                                "The model won't answer in the sandbox without it.")}]
    assert view["providers_block"] is None  # a key may be kept elsewhere: the switch is the user's call


def test_a_profile_with_only_an_api_key_has_one_row_that_says_where_the_key_is_used(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "default": "some/model"}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    view = _view(world)
    assert view["providers"] == [{
        "id": "key:OPENROUTER_API_KEY", "label": "OpenRouter", "kind": "key", "state": "ready", "main": True,
        "env": "OPENROUTER_API_KEY", "detail": WORKS_KEY.format("openrouter.ai")}]
    assert view["providers_block"] is None


def test_every_key_with_a_registered_address_gets_a_row_used_by_a_model_or_not(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "default": "some/model"}})
    write_env(world.home, ["OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "TAVILY_API_KEY"])
    rows = _by_id(_view(world))
    assert [row["id"] for row in rows.values()][0] == "key:OPENROUTER_API_KEY"  # the model's provider comes first
    assert rows["key:ANTHROPIC_API_KEY"]["detail"] == WORKS_KEY.format("api.anthropic.com")
    assert rows["key:ANTHROPIC_API_KEY"]["main"] is False and rows["key:ANTHROPIC_API_KEY"]["state"] == "ready"
    assert rows["key:TAVILY_API_KEY"]["label"] == "Tavily"
    assert rows["key:TAVILY_API_KEY"]["detail"] == ("Used in the sandbox once Web search or Web extract is allowed in "
                                                    "a chat. The key stays on this computer.")


def test_a_fallback_that_uses_a_key_is_listed_with_its_key_or_without_one(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "default": "some/model"},
                  "fallback_providers": [{"provider": "anthropic", "model": "claude"}]})
    write_env(world.home, ["OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"])
    view = _view(world)
    assert {row["id"]: (row["state"], row["main"]) for row in view["providers"]} == {
        "key:OPENROUTER_API_KEY": ("ready", True), "key:ANTHROPIC_API_KEY": ("ready", False)}
    write_env(world.home, ["OPENROUTER_API_KEY"])  # the fallback's key is gone
    view = _view(world)
    assert {row["id"]: (row["state"], row["main"]) for row in view["providers"]} == {
        "key:OPENROUTER_API_KEY": ("ready", True), "key:anthropic": ("no_key", False)}
    assert _by_id(view)["key:anthropic"]["detail"] == "No key found: ANTHROPIC_API_KEY is not set in this profile's .env."
    assert view["providers_block"] is None


def test_a_model_server_on_this_computer_is_named_as_this_computer(world):  # noqa: F811
    world.config({"model": {"provider": "custom", "base_url": "http://127.0.0.1:8080/v1", "key_env": "LOCAL_MODEL_KEY",
                            "default": "local"}})
    write_env(world.home, ["LOCAL_MODEL_KEY"])
    row = _by_id(_view(world))["key:LOCAL_MODEL_KEY"]
    assert row["detail"] == WORKS_KEY.format("localhost:8080") and row["main"] is True
    assert row["label"] == "Custom endpoint" and "openshell.internal" not in json.dumps(row)


def test_one_key_at_two_addresses_names_both(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "default": "some/model"},
                  "fallback_providers": [{"provider": "custom", "base_url": "https://llm.example.com:8443/v1",
                                          "key_env": "OPENROUTER_API_KEY", "model": "m"}]})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    row = _by_id(_view(world))["key:OPENROUTER_API_KEY"]
    assert row["detail"] == WORKS_KEY.format("llm.example.com:8443 and openrouter.ai")  # the user's own entry first


def test_a_sign_in_of_the_profile_is_kept_signed_in_on_this_computer(world):  # noqa: F811
    world.config({"model": {"provider": "nous", "default": "hermes-4"}})
    world.sign_in("nous")
    view = _view(world)
    assert view["providers"] == [{"id": "sign_in:nous", "label": "Nous Portal", "kind": "sign_in", "state": "ready",
                                  "main": True, "detail": SIGNED_IN_AT.format("inference-api.nousresearch.com")}]
    assert view["providers_block"] is None


def test_a_sign_in_no_model_uses_is_listed_and_is_not_the_models(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "default": "some/model"}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    world.sign_in("openai-codex")
    rows = _by_id(_view(world))
    assert rows["sign_in:openai-codex"]["state"] == "ready" and rows["sign_in:openai-codex"]["main"] is False
    assert rows["sign_in:openai-codex"]["detail"] == SIGNED_IN_AT.format("chatgpt.com")


def test_the_models_sign_in_is_needed_first_and_the_switch_says_so(world):  # noqa: F811
    world.config({"model": {"provider": "openai-codex", "default": "gpt-5"}})
    view = _view(world)
    assert view["providers"] == [{
        "id": "sign_in:openai-codex", "label": view["providers"][0]["label"], "kind": "sign_in",
        "state": "needs_sign_in", "main": True,
        "detail": f"Not signed in. Sign in to {view['providers'][0]['label']} first."}]
    label = view["providers"][0]["label"]
    assert view["providers_block"] == {
        "code": "model_needs_sign_in", "rows": ["sign_in:openai-codex"],
        "reason": f"This profile's model uses {label}, which needs a sign-in first."}
    # Signed in: the next look says it works, and nothing holds the switch.
    world.sign_in("openai-codex")
    view = SV.provider_view(_layout(world))  # no forgetting: the sign-in file changed
    assert view["providers"][0]["state"] == "ready" and view["providers_block"] is None


def test_a_fallback_that_needs_a_sign_in_is_named_and_does_not_hold_the_switch(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "default": "some/model"},
                  "fallback_providers": [{"provider": "nous", "model": "hermes-4"}]})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    view = _view(world)
    row = _by_id(view)["sign_in:nous"]
    assert row["state"] == "needs_sign_in" and row["main"] is False
    assert row["detail"] == "Not signed in. Sign in to Nous Portal first."
    assert view["providers_block"] is None


WHY = {
    "own_program": "Not available in the sandbox: {} signs in through its own program.",
    "outside_profile": "Not available in the sandbox: {} keeps its sign-in outside this profile.",
    "claude_code": "Not available in the sandbox: {} is signed in through Claude Code, outside this profile.",
    "cloud_sdk": "Not available in the sandbox: {} signs in through a cloud SDK on this computer.",
    "not_carried": "Not available in the sandbox yet: the {} sign-in stays on this computer.",
    "unknown": "Not available in the sandbox: Hermes doesn't know the provider \"{}\".",
}


@pytest.mark.parametrize("provider, label, reason", [
    ("copilot-acp", "GitHub Copilot ACP", "own_program"), ("qwen-oauth", "Qwen OAuth", "outside_profile"),
    ("anthropic", "Anthropic", "claude_code"), ("bedrock", "AWS Bedrock", "cloud_sdk"),
    ("vertex", "Google Vertex AI", "cloud_sdk"), ("azure-foundry", "Azure Foundry", "cloud_sdk"),
    ("some-oauth", "Some OAuth", "not_carried"), ("mystery", "mystery", "unknown")])
def test_a_provider_that_cannot_work_in_the_sandbox_says_why_and_holds_the_switch_when_it_is_the_models(
        world, monkeypatch, provider, label, reason):  # noqa: F811
    _reported(monkeypatch, _report_row(provider, label, "not_available", reason))
    view = _view(world)
    assert view["providers"] == [{"id": f"sign_in:{provider}", "label": label, "kind": "sign_in",
                                  "state": "unavailable", "main": True, "detail": WHY[reason].format(label)}]
    why = WHY[reason].format(label).split(": ", 1)[1]  # the bar's second line: why, without the reason's words
    assert view["providers_block"] == {
        "code": "model_unavailable", "rows": [f"sign_in:{provider}"], "detail": why[:1].upper() + why[1:],
        "reason": f"This profile's model uses {label}, which isn't available in the sandbox."}
    # The same provider as a fallback or an auxiliary model: named, and the switch is free.
    _reported(monkeypatch, _report_row(provider, label, "not_available", reason, used_by=("fallback 1", "auxiliary title")))
    view = _view(world)
    assert view["providers"][0]["main"] is False and view["providers_block"] is None


@pytest.mark.parametrize("reason, sentence", [
    ("not_signed_in", "Not signed in. Sign in to Nous Portal first."),
    ("expired", "Sign-in expired. Sign in to Nous Portal again first."),
    ("shared_not_carried", "Signed in for the default profile only. Sign in to Nous Portal for this profile first."),
])
def test_each_way_a_sign_in_is_needed_first_has_its_sentence(world, monkeypatch, reason, sentence):  # noqa: F811
    _reported(monkeypatch, _report_row("nous", "Nous Portal", "needs_sign_in", reason))
    view = _view(world)
    assert view["providers"][0]["detail"] == sentence and view["providers"][0]["state"] == "needs_sign_in"
    assert view["providers_block"]["code"] == "model_needs_sign_in"


def test_a_sign_in_shared_with_the_default_profile_says_so(world, monkeypatch):  # noqa: F811
    _reported(monkeypatch, _report_row("nous", "Nous Portal", "works", "signed_in_shared"))
    row = _view(world)["providers"][0]
    assert row["state"] == "ready"
    assert row["detail"] == ("Works in the sandbox with the default profile's sign-in. Stays signed in on this "
                             "computer.")


def test_a_report_with_a_reason_this_page_does_not_know_still_gets_a_plain_sentence(world, monkeypatch):  # noqa: F811
    _reported(monkeypatch, _report_row("p1", "One", "not_available", "something_new"),
              _report_row("p2", "Two", "needs_sign_in", "something_new", used_by=()),
              _report_row("p3", "Three", "works", "something_new", used_by=()),
              _report_row("p4", "Four", "a_state_of_tomorrow", "x", used_by=()))
    rows = _by_id(_view(world))
    assert rows["sign_in:p1"]["detail"] == "Not available in the sandbox."
    assert rows["sign_in:p2"]["detail"] == "Not signed in. Sign in to Two first."
    assert rows["sign_in:p3"]["detail"] == SIGNED_IN
    assert "sign_in:p4" not in rows  # a state the report does not have today is not guessed at


# -- before the switch: a key written in config.yaml ----------------------------------------------------

def test_a_key_written_in_config_yaml_is_the_first_row_and_holds_the_switch(world, monkeypatch):  # noqa: F811
    fx.install(monkeypatch)
    world.config({"model": {"provider": "custom", "base_url": "https://llm.example.com/v1", "api_key": INLINE_KEY,
                            "default": "m"}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    view = _view(world)
    assert view["providers"][0] == {"id": "config:model.api_key", "label": "Key in config.yaml", "kind": "key",
                                    "state": "key_in_config", "main": False, "env": "MODEL_API_KEY",
                                    "path": "model.api_key", "detail": INLINE}
    assert view["providers_block"] == {"code": "key_in_config", "reason": ONE_KEY, "rows": ["config:model.api_key"]}
    assert view["providers"][1]["id"] == "key:OPENROUTER_API_KEY"


def test_two_keys_in_config_yaml_are_two_rows_and_one_reason(world, monkeypatch):  # noqa: F811
    fx.install(monkeypatch)
    world.config({"model": {"provider": "custom", "base_url": "https://llm.example.com/v1", "api_key": INLINE_KEY},
                  "providers": {"spare": {"base_url": "https://spare.example.com/v1", "api_key": INLINE_KEY_2}}})
    view = _view(world)
    assert [row["path"] for row in view["providers"][:2]] == ["model.api_key", "providers.spare.api_key"]
    assert view["providers_block"] == {"code": "key_in_config", "reason": TWO_KEYS,
                                       "rows": ["config:model.api_key", "config:providers.spare.api_key"]}


def test_a_key_in_config_yaml_is_said_before_a_model_that_cannot_work(world, monkeypatch):  # noqa: F811
    fx.install(monkeypatch)
    world.config({"model": {"provider": "copilot-acp", "api_key": INLINE_KEY}})
    _reported(monkeypatch, _report_row("copilot-acp", "GitHub Copilot ACP", "not_available", "own_program"))
    view = _view(world)
    assert view["providers_block"]["code"] == "key_in_config"
    assert [row["state"] for row in view["providers"]] == ["key_in_config", "unavailable"]


def test_a_plugin_without_the_module_lists_no_such_key_and_still_lists_the_rest(world, monkeypatch):  # noqa: F811
    fx.remove(monkeypatch)
    world.config({"model": {"provider": "openrouter", "api_key": INLINE_KEY}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    view = _view(world)
    assert [row["id"] for row in view["providers"]] == ["key:OPENROUTER_API_KEY"] and view["providers_block"] is None


def test_a_listing_that_fails_or_answers_nonsense_lists_no_such_key(world, monkeypatch):  # noqa: F811
    keys = fx.install(monkeypatch)
    world.config({"model": {"provider": "openrouter", "api_key": INLINE_KEY}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    for answer in (lambda config: 1 / 0, lambda config: "model.api_key",
                   lambda config: [{"path": "model.api_key"}, {"env": "X"}, "model.api_key", {"path": 3, "env": "X"}]):
        keys.inline_keys = answer
        fx.install(monkeypatch, keys)
        assert [row["id"] for row in _view(world)["providers"]] == ["key:OPENROUTER_API_KEY"]  # and the rest stays


# -- before the switch: what is not said -----------------------------------------------------------------

def test_no_missing_key_is_claimed_where_the_page_cannot_know(world):  # noqa: F811
    # A secret source may supply the key when the sandbox starts.
    world.config({"model": {"provider": "openrouter"}, "secrets": {"onepassword": {"enabled": True}}})
    assert _view(world)["providers"] == []
    # A model entry that names its own key variable or its own address is not its provider's registered key.
    world.config({"model": {"provider": "openrouter", "key_env": "MY_OWN_KEY"}})
    assert _view(world)["providers"] == []
    world.config({"model": {"provider": "deepseek", "base_url": "http://127.0.0.1:9000/v1"}})
    assert _view(world)["providers"] == []


def test_a_hermes_that_cannot_be_asked_about_sign_ins_still_lists_the_keys(world, monkeypatch):  # noqa: F811
    world.config({"model": {"provider": "openrouter"}})
    write_env(world.home, ["OPENROUTER_API_KEY"])

    def unavailable(home):
        raise signins.Unavailable("Hermes is not importable")

    monkeypatch.setattr(signins, "report", unavailable)
    view = _view(world)
    assert [row["id"] for row in view["providers"]] == ["key:OPENROUTER_API_KEY"] and view["providers_block"] is None


def test_rows_that_cannot_be_built_never_fail_the_page(world, monkeypatch):  # noqa: F811
    monkeypatch.setattr(SV, "_host_rows", lambda layout: 1 / 0)
    payload = SV.config_payload(_layout(world), {}, CAPS, sandboxed=False, restart_required=False, resolve=lambda h: [])
    assert payload["providers"] == [] and payload["providers_block"] is None and payload["sandboxed"] is False


def test_a_home_a_sandbox_session_still_holds_is_not_read_for_keys_or_sign_ins(world, monkeypatch):  # noqa: F811
    """While the launcher's copy exists the home's files may be the sandbox's, and the copy's secret sources are
    the launcher's to run."""
    fx.install(monkeypatch)
    world.config({"model": {"provider": "openrouter", "api_key": INLINE_KEY}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    world.sign_in("nous")
    (world.copy / pins.PIN_FILE).write_text(json.dumps({"version": pins.VERSION, "models": [], "allowed": []}), encoding="utf-8")
    monkeypatch.setattr(pins, "secrets", lambda layout: 1 / 0)
    monkeypatch.setattr(signins, "report", lambda home: 1 / 0)
    view = _view(world)
    assert [row["state"] for row in view["providers"]] == ["key_in_config"]


# -- before the switch: the page's data --------------------------------------------------------------------

def test_the_config_of_a_profile_that_is_off_carries_the_rows_and_the_one_of_a_sandbox_does_not(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter"}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    off = SV.config_payload(_layout(world), {}, CAPS, sandboxed=False, restart_required=False, resolve=lambda h: [])
    on = SV.config_payload(_layout(world), {}, CAPS, sandboxed=True, restart_required=False, resolve=lambda h: [])
    assert [row["id"] for row in off["providers"]] == ["key:OPENROUTER_API_KEY"] and off["providers_block"] is None
    assert "providers" not in on and "providers_block" not in on  # the launcher's status carries them
    assert {k: v for k, v in off.items() if not k.startswith("providers")} == {**on, "sandboxed": False}


def test_a_row_follows_the_profiles_files_at_the_next_look_and_is_not_read_again_in_between(world, monkeypatch):  # noqa: F811
    layout = _layout(world)
    world.config({"model": {"provider": "openrouter"}})
    looks = []
    built = SV._host_rows
    monkeypatch.setattr(SV, "_host_rows", lambda layout: (looks.append(1), built(layout))[1])
    first = SV.provider_view(layout)
    assert first["providers"][0]["state"] == "no_key"
    assert SV.provider_view(layout) is first and len(looks) == 1  # nothing changed: not read again
    write_env(world.home, ["OPENROUTER_API_KEY"])  # the key is saved
    assert SV.provider_view(layout)["providers"][0]["state"] == "ready" and len(looks) == 2
    world.sign_in("nous")  # a sign-in appears
    assert "sign_in:nous" in _by_id(SV.provider_view(layout)) and len(looks) == 3
    # What lives outside the profile (a sign-in shared with the default profile) is looked at again after a while.
    now = SV.time.monotonic()
    monkeypatch.setattr(SV.time, "monotonic", lambda: now + SV._PROVIDERS_TTL + 1)
    SV.provider_view(layout)
    assert len(looks) == 4


def test_nothing_the_page_receives_before_the_switch_carries_a_key_a_token_or_a_grant(world, monkeypatch):  # noqa: F811
    fx.install(monkeypatch)
    world.config({"model": {"provider": "nous", "default": "hermes-4", "api_key": INLINE_KEY},
                  "fallback_providers": [{"provider": "openai-codex", "model": "gpt-5"},
                                         {"provider": "custom", "base_url": "http://127.0.0.1:8080/v1",
                                          "key_env": "LOCAL_MODEL_KEY", "model": "local"}],
                  "providers": {"spare": {"base_url": "https://spare.example.com/v1", "api_key": INLINE_KEY_2}}})
    write_env(world.home, list(KEYS))
    for provider in ("nous", "openai-codex", "xai-oauth", "minimax-oauth", "anthropic"):
        world.sign_in(provider)
    secrets = secrets_of(world.home)
    assert len(secrets) > len(KEYS) + 2, "the sign-in files hold tokens and grants to look for"
    layout = _layout(world)
    payload = SV.config_payload(layout, {}, CAPS, sandboxed=False, restart_required=False, resolve=lambda h: [])
    states = {row["id"]: row["state"] for row in payload["providers"]}
    assert states["config:model.api_key"] == "key_in_config" and states["sign_in:nous"] == "ready"
    assert states["key:OPENROUTER_API_KEY"] == "ready" and states["key:LOCAL_MODEL_KEY"] == "ready"
    assert len(states) >= 10
    env_rows = {name: {"is_set": True, "redacted_value": value[:4] + "...", "value": value} for name, value in KEYS.items()}
    pages = {"config": payload, "keys": SV.key_rows(env_rows),
             "move": SV.move_keys(layout, {"keys": ["model.api_key", "providers.spare.api_key"]}),
             "after": SV.config_payload(layout, {}, CAPS, sandboxed=False, restart_required=False, resolve=lambda h: [])}
    assert pages["move"][0] == 200
    for name, page in pages.items():
        text = shown(page)
        assert [secret for secret in secrets if secret in text] == [], name
    assert {tuple(sorted(row)) for row in payload["providers"]} <= {
        ("detail", "id", "kind", "label", "main", "state"), ("detail", "env", "id", "kind", "label", "main", "state"),
        ("detail", "env", "id", "kind", "label", "main", "path", "state"),
        ("detail", "fallback", "id", "kind", "label", "main", "state"),
        ("detail", "env", "fallback", "id", "kind", "label", "main", "state")}


# -- while the sandbox is on: the launcher's rows as the page gets them -------------------------------------

def test_a_launcher_row_keeps_what_the_page_reads_and_nothing_else():
    rows = SV.page_rows([
        {"id": "nous:agent_key", "label": "Nous Portal", "kind": "sign_in", "state": "ready", "reason": "signed_in",
         "detail": "x", "value": "tok-1", "token": "tok-2", "refresh_token": "grant-1", "expires_at": 1.0, "error": "tok-3",
         "claims": {"sub": "u"}, "main": True},
        {"id": "key:OPENROUTER_API_KEY", "label": "OpenRouter", "kind": "key", "state": "ready",
         "hosts": [{"host": "openrouter.ai", "port": 443}], "env": "OPENROUTER_API_KEY", "placeholder": "ph-1"},
    ])
    assert rows == [
        {"id": "nous:agent_key", "label": "Nous Portal", "kind": "sign_in", "state": "ready", "main": True,
         "detail": SIGNED_IN},
        {"id": "key:OPENROUTER_API_KEY", "label": "OpenRouter", "kind": "key", "state": "ready", "main": False,
         "env": "OPENROUTER_API_KEY", "detail": WORKS_KEY.format("openrouter.ai")},
    ]


@pytest.mark.parametrize("row, sentence", [
    ({"kind": "key", "state": "ready"}, "Works in the sandbox. The key stays on this computer."),
    ({"kind": "key", "state": "ready", "hosts": ["api.x.ai", "127.0.0.1:8080", "llm.example.com:8443"]},
     WORKS_KEY.format("api.x.ai, localhost:8080 and llm.example.com:8443")),
    ({"kind": "sign_in", "state": "ready", "reason": "signed_in_shared"},
     "Works in the sandbox with the default profile's sign-in. Stays signed in on this computer."),
    ({"kind": "sign_in", "state": "ready", "reason": "retrying"},
     "Couldn't reach Nous Portal to renew the sign-in. Trying again."),
    ({"kind": "sign_in", "state": "needs_sign_in"},
     "Not signed in. Turn the sandbox off, sign in to Nous Portal, then turn it on."),
    ({"kind": "sign_in", "state": "needs_sign_in", "reason": "shared_not_carried"},
     "Signed in for the default profile only. Turn the sandbox off, sign in to Nous Portal for this profile, "
     "then turn it on."),
    ({"kind": "sign_in", "state": "expired", "reason": "expired", "detail": "the launcher's words"},
     "Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on."),
    ({"kind": "sign_in", "state": "expired"}, "Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on."),
    ({"kind": "sign_in", "state": "expired", "reason": "lapsed"},
     "The Nous Portal sign-in wasn't renewed in time. The model answers again once it is."),
    ({"kind": "sign_in", "state": "unavailable", "reason": "own_program"},
     "Not available in the sandbox: Nous Portal signs in through its own program."),
    ({"kind": "sign_in", "state": "unavailable", "detail": "Not available: the launcher says why."},
     "Not available: the launcher says why."),
    ({"kind": "sign_in", "state": "unavailable"}, "Not available in the sandbox."),
    ({"kind": "key", "state": "withheld", "detail": "x"}, "Model endpoint changed in the sandbox. Key withheld."),
    ({"kind": "key", "state": "key_in_config", "path": "model.api_key"},
     "Written in config.yaml, where the sandbox can read it. Turn the sandbox off, then move it to .env."),
    ({"kind": "sign_in", "state": "renewing", "detail": "A state of a later launcher."}, "A state of a later launcher."),
])
def test_each_state_of_a_launcher_row_has_the_pages_sentence(row, sentence):
    out = SV.page_rows([{"id": "r", "label": "Nous Portal", **row}])
    assert out[0]["detail"] == sentence and out[0]["state"] == row["state"]


def test_a_launcher_row_without_a_reason_is_read_by_the_sign_in_engines_own_sentence():
    """A launcher that sends the engine's sentence as a row's detail, and no reason, gets the page's words for
    it all the same; words this page does not recognise are shown as they are."""
    def row(state, reason, **more):
        text = signins._SENTENCES[reason].format(label="Nous Portal")
        return {"id": reason, "label": "Nous Portal", "kind": "sign_in", "state": state, "detail": text + more.pop("tail", ""),
                **more}

    rows = {r["id"]: r for r in SV.page_rows([
        row("ready", "signed_in", used_by=["model", "fallback 1"]), row("ready", "signed_in_shared"),
        row("ready", "retrying"), row("needs_sign_in", "not_signed_in", used_by=["auxiliary title"]),
        row("expired", "expired", tail=" Turn the sandbox off, sign in to Nous Portal, then turn it on again."),
        row("expired", "lapsed"), row("unavailable", "own_program"), row("unavailable", "claude_code"),
        {"id": "odd", "label": "Nous Portal", "kind": "sign_in", "state": "expired", "detail": "Words of a later launcher."},
        {"id": "bare", "label": "Nous Portal", "kind": "sign_in", "state": "expired"},
        {"id": "key", "label": "OpenRouter", "kind": "key", "state": "ready", "detail": "In the sandbox as a placeholder."},
    ])}
    assert rows["signed_in"]["detail"] == SIGNED_IN and rows["signed_in"]["main"] is True
    assert rows["signed_in_shared"]["detail"].startswith("Works in the sandbox with the default profile's sign-in.")
    assert rows["retrying"]["detail"] == "Couldn't reach Nous Portal to renew the sign-in. Trying again."
    assert rows["not_signed_in"]["detail"] == "Not signed in. Turn the sandbox off, sign in to Nous Portal, then turn it on."
    assert rows["not_signed_in"]["main"] is False
    assert rows["expired"]["detail"] == "Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on."
    assert rows["lapsed"]["detail"] == "The Nous Portal sign-in wasn't renewed in time. The model answers again once it is."
    assert rows["own_program"]["detail"] == "Not available in the sandbox: Nous Portal signs in through its own program."
    assert rows["claude_code"]["detail"].endswith("is signed in through Claude Code, outside this profile.")
    assert rows["odd"]["detail"] == "Words of a later launcher."
    assert rows["bare"]["detail"] == "Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on."
    assert rows["key"]["detail"] == "Works in the sandbox. The key stays on this computer."
    assert "placeholder" not in json.dumps(list(rows.values()))


def test_a_launcher_row_for_a_key_in_config_yaml_is_drawn_like_the_hosts():
    rows = SV.page_rows([{"id": "config:model.api_key", "label": "model.api_key", "kind": "key", "state": "key_in_config",
                          "detail": "Written in config.yaml as model.api_key, which the sandbox can read. Move it to .env."}])
    assert rows == [{"id": "config:model.api_key", "label": "Key in config.yaml", "kind": "key", "state": "key_in_config",
                     "main": False, "path": "model.api_key",
                     "detail": ("Written in config.yaml, where the sandbox can read it. Turn the sandbox off, then move "
                                "it to .env.")}]


def test_launcher_rows_that_are_not_rows_are_left_out_and_long_text_is_cut():
    rows = SV.page_rows([None, "ready", 7, {"label": "no state"}, {"id": "a", "state": "Not A State!"},
                         {"id": "b", "state": "READY", "kind": "other", "label": "L" * 300,
                          "detail": "ignored for a ready row"},
                         {"state": "unavailable", "detail": "line one\nline two   " + "d" * 600}])
    assert [row["id"] for row in rows] == ["row:6", "b"]  # what needs attention first; a row without an id gets one
    assert rows[1]["kind"] == "sign_in" and rows[1]["state"] == "ready" and len(rows[1]["label"]) == 80
    assert rows[0]["detail"].startswith("line one line two d") and len(rows[0]["detail"]) == 400
    assert SV.page_rows(None) == [] and SV.page_rows({"id": "x"}) == []


def test_a_withheld_key_gets_a_row_when_the_launcher_sent_none():
    changed = [{"label": "Model", "host": "evil.example", "port": 443, "env": "OPENAI_API_KEY"}]
    ready = {"id": "k", "label": "OpenAI", "kind": "key", "state": "ready"}
    rows = SV.page_rows([ready], endpoint_changed=changed)
    assert rows[0] == {"id": "withheld:OPENAI_API_KEY:evil.example:443", "label": "OPENAI_API_KEY", "kind": "key",
                       "state": "withheld", "main": False, "env": "OPENAI_API_KEY",
                       "detail": "Model endpoint changed in the sandbox. Key withheld."}
    sent = {"id": "w", "label": "OpenAI", "kind": "key", "state": "withheld"}
    assert [row["id"] for row in SV.page_rows([ready, sent], endpoint_changed=changed)] == ["w", "k"]


def test_the_order_is_keys_to_move_then_the_models_provider_then_what_needs_attention():
    rows = SV.page_rows([{"id": "ok", "state": "ready", "kind": "key"}, {"id": "gone", "state": "unavailable"},
                         {"id": "main", "state": "ready", "main": True}, {"id": "cfg", "state": "key_in_config"},
                         {"id": "exp", "state": "expired"}])
    assert [row["id"] for row in rows] == ["cfg", "main", "gone", "exp", "ok"]


def test_a_status_without_rows_is_passed_on_as_it_is():
    assert SV.status_providers({"state": "running"}) == {}
    assert SV.status_providers({"providers": "soon"}) == {} and SV.status_providers(None) == {}
    assert SV.status_providers({"providers": []}) == {"providers": []}


class _Sup:
    """A supervisor whose status carries what a launcher's does, and more than the page may see."""

    def __init__(self, layout, rows=None, changed=()):
        self.layout, self.rows, self.changed, self.restarts = layout, rows, list(changed), 0
        self.outer_port = 47999

    def status(self):
        out = {"profile": "work", "sandboxed": True, "state": "running", "endpoint_changed": list(self.changed)}
        return out if self.rows is None else {**out, "providers": [dict(row) for row in self.rows]}

    async def restart(self):
        self.restarts += 1


def _call(routes, method, path, body=b""):
    handler = routes.match(method, path)
    assert handler is not None, path
    return asyncio.run(handler(parse_head(f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode()), body))


def _launcher(world, monkeypatch, rows=None, changed=()):  # noqa: F811
    monkeypatch.setattr(HR, "switch_view", lambda layout, sandboxed: {"available": True, "reason": None, "on": True})
    sup = _Sup(_layout(world), rows, changed)
    return HR.HostRoutes(sup, lambda: None), sup


def test_the_status_route_hands_the_page_the_launchers_rows_and_nothing_a_row_must_not_show(world, monkeypatch):  # noqa: F811
    write_env(world.home, list(KEYS))
    for provider in ("nous", "openai-codex"):
        world.sign_in(provider)
    secrets = sorted(secrets_of(world.home))
    rows = [{"id": "nous:agent_key", "label": "Nous Portal", "kind": "sign_in", "state": "expired", "main": True,
             "reason": "expired", "detail": "the launcher's words", "value": secrets[0], "error": f"refused: {secrets[1]}",
             "token": secrets[2], "refresh_token": secrets[3], "claims": {"sub": secrets[4]}},
            {"id": "key:OPENROUTER_API_KEY", "label": "OpenRouter", "kind": "key", "state": "ready",
             "hosts": ["openrouter.ai"], "env": "OPENROUTER_API_KEY", "placeholder": KEYS["OPENROUTER_API_KEY"]}]
    routes, sup = _launcher(world, monkeypatch, rows)
    code, status, _ = _call(routes, "GET", "/api/plugins/openshell/status")
    assert code == 200 and status["sandboxed"] is True and status["switch"]["on"] is True
    assert [(row["id"], row["state"]) for row in status["providers"]] == [
        ("nous:agent_key", "expired"), ("key:OPENROUTER_API_KEY", "ready")]
    assert status["providers"][0]["detail"] == "Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on."
    code, restarted, _ = _call(routes, "POST", "/api/plugins/openshell/restart")
    assert code == 200 and sup.restarts == 1 and restarted["providers"] == status["providers"]
    for page in (status, restarted):
        assert [secret for secret in secrets if secret in shown(page)] == []


def test_the_status_of_a_launcher_without_rows_has_none_and_the_withheld_bar_keeps_its_list(world, monkeypatch):  # noqa: F811
    changed = [{"label": "Model", "host": "evil.example", "port": 443, "env": "OPENAI_API_KEY"}]
    routes, _ = _launcher(world, monkeypatch, None, changed)
    status = _call(routes, "GET", "/api/plugins/openshell/status")[1]
    assert "providers" not in status and status["endpoint_changed"] == changed
    routes, _ = _launcher(world, monkeypatch, [], changed)
    status = _call(routes, "GET", "/api/plugins/openshell/status")[1]
    assert [row["state"] for row in status["providers"]] == ["withheld"] and status["endpoint_changed"] == changed


# -- signing in while the sandbox is on --------------------------------------------------------------------

def test_signing_in_or_out_while_the_sandbox_is_on_is_refused_with_what_to_do(world, monkeypatch):  # noqa: F811
    routes, _ = _launcher(world, monkeypatch)
    for method, path in (("POST", "/api/providers/oauth/nous/start"), ("DELETE", "/api/providers/oauth/openai-codex"),
                         ("POST", "/api/providers/oauth/nous/poll/abc")):
        code, payload, _ = _call(routes, method, path)
        assert code == 409 and payload["sandboxed"] is True
        assert payload["detail"] == ("Sign in or out with the sandbox off: turn the sandbox off for this profile, then "
                                     "turn it back on afterwards. The Sandbox page shows which sign-ins the sandbox can use.")
    code, payload, _ = _call(routes, "POST", "/api/mcp/servers/github/auth")
    assert code == 409 and payload["detail"] == ("An MCP server's sign-in stays on this computer: the sandbox can't use "
                                                 "it yet. Turn the sandbox off for this profile to sign in.")
    for text in (HR._SIGN_IN_REFUSED, HR._MCP_SIGN_IN_REFUSED):
        assert "cannot hold" not in text and "placeholder" not in text


# -- the move to .env ----------------------------------------------------------------------------------------

def _inline_profile(world, monkeypatch):  # noqa: F811
    keys = fx.install(monkeypatch)
    world.config({"model": {"provider": "custom", "base_url": "https://llm.example.com/v1", "api_key": INLINE_KEY,
                            "default": "m"},
                  "providers": {"spare": {"base_url": "https://spare.example.com/v1", "api_key": INLINE_KEY_2}}})
    return keys, _layout(world)


def test_moving_a_key_takes_it_out_of_config_yaml_and_the_rows_say_so_at_once(world, monkeypatch):  # noqa: F811
    keys, layout = _inline_profile(world, monkeypatch)
    before = SV.provider_view(layout)
    assert before["providers_block"]["code"] == "key_in_config"
    code, answer = SV.move_keys(layout, {"keys": ["model.api_key"]})
    assert code == 200 and answer["moved"] == [{"path": "model.api_key", "env": "MODEL_API_KEY"}] and answer["left"] == []
    assert keys.moves == [(str(world.home), [{"path": "model.api_key", "env": "MODEL_API_KEY"}])]
    states = {row["id"]: row["state"] for row in answer["providers"]}
    assert states == {"config:providers.spare.api_key": "key_in_config", "key:MODEL_API_KEY": "ready"}
    assert answer["providers_block"] == {"code": "key_in_config", "reason": ONE_KEY, "rows": ["config:providers.spare.api_key"]}
    moved = next(row for row in answer["providers"] if row["id"] == "key:MODEL_API_KEY")
    assert moved["detail"] == WORKS_KEY.format("llm.example.com") and moved["main"] is True
    code, answer = SV.move_keys(layout, {"keys": ["providers.spare.api_key"]})
    assert code == 200 and answer["providers_block"] is None
    assert SV.provider_view(layout)["providers_block"] is None  # the switch is free
    assert INLINE_KEY not in shown(answer) and INLINE_KEY_2 not in shown(answer)


def test_the_variable_a_key_moves_to_is_never_the_callers_choice(world, monkeypatch):  # noqa: F811
    keys, layout = _inline_profile(world, monkeypatch)
    for body in ({"keys": [{"path": "model.api_key", "env": "PATH"}]}, {"keys": []}, {"keys": "model.api_key"},
                 {"keys": ["model.api_key", ""]}, {"keys": ["model.api_key", 3]}, {}, None, ["model.api_key"]):
        code, answer = SV.move_keys(layout, body)
        assert code == 422 and answer == {"detail": 'Expected {"keys": [the path of each key to move]}.'}
    assert keys.moves == []
    code, _ = SV.move_keys(layout, {"keys": ["model.api_key", "model.api_key"], "env": "PATH"})
    assert code == 200 and keys.moves[0][1] == [{"path": "model.api_key", "env": "MODEL_API_KEY"}]


def test_a_key_that_is_no_longer_there_is_not_moved_and_the_rows_are_read_again(world, monkeypatch):  # noqa: F811
    keys, layout = _inline_profile(world, monkeypatch)
    code, answer = SV.move_keys(layout, {"keys": ["model.api_key", "providers.gone.api_key", "auth.secret"]})
    assert code == 409 and answer["detail"] == "config.yaml no longer has a key at providers.gone.api_key and auth.secret."
    assert keys.moves == [] and answer["providers_block"]["code"] == "key_in_config"


def test_a_move_that_fails_says_so_in_plain_words_and_shows_no_key(world, monkeypatch):  # noqa: F811
    keys, layout = _inline_profile(world, monkeypatch)
    keys.fail = PermissionError(13, "Permission denied")
    code, answer = SV.move_keys(layout, {"keys": ["model.api_key"]})
    assert code == 500 and answer["detail"].startswith("Couldn't move model.api_key to .env: ")
    assert "Permission denied" in answer["detail"] and "Traceback" not in answer["detail"]
    assert answer["providers_block"]["code"] == "key_in_config"  # still there, still said
    keys.fail = RuntimeError(f"could not write {INLINE_KEY}\nsecond line")
    code, answer = SV.move_keys(layout, {"keys": ["model.api_key"]})
    assert code == 500 and "second line" not in answer["detail"]
    keys.fail = None
    keys.skip = {"model.api_key", "providers.spare.api_key"}
    code, answer = SV.move_keys(layout, {"keys": ["model.api_key", "providers.spare.api_key"]})
    assert code == 500 and answer["detail"] == ("Couldn't move model.api_key and providers.spare.api_key to .env. "
                                                "config.yaml is unchanged.")


def test_a_move_that_moved_only_some_keys_names_the_rest(world, monkeypatch):  # noqa: F811
    keys, layout = _inline_profile(world, monkeypatch)
    keys.skip = {"providers.spare.api_key"}
    code, answer = SV.move_keys(layout, {"keys": ["model.api_key", "providers.spare.api_key"]})
    assert code == 200 and [item["path"] for item in answer["moved"]] == ["model.api_key"]
    assert answer["left"] == ["providers.spare.api_key"] and answer["providers_block"]["rows"] == ["config:providers.spare.api_key"]


def test_a_plugin_without_the_module_cannot_move_and_says_what_to_do(world, monkeypatch):  # noqa: F811
    fx.remove(monkeypatch)
    code, answer = SV.move_keys(_layout(world), {"keys": ["model.api_key"]})
    assert code == 409 and answer == {"detail": "This version can't move keys. Take the key out of config.yaml and "
                                                "save it in .env yourself."}


def test_nothing_is_moved_while_a_sandbox_session_holds_the_home(world, monkeypatch):  # noqa: F811
    keys, layout = _inline_profile(world, monkeypatch)
    (world.copy / pins.PIN_FILE).write_text(json.dumps({"version": pins.VERSION, "models": [], "allowed": []}), encoding="utf-8")
    code, answer = SV.move_keys(layout, {"keys": ["model.api_key"]})
    assert code == 409 and answer == {"detail": "Turn the sandbox off for this profile first."} and keys.moves == []
    # The launcher's own route says the same: the route that moves belongs to the backend of a profile that is off.
    routes, _ = _launcher(world, monkeypatch)
    code, payload, _ = _call(routes, "POST", "/api/plugins/openshell/providers/move", b'{"keys": ["model.api_key"]}')
    assert code == 409 and payload["detail"] == "Turn the sandbox off for this profile first." and keys.moves == []
