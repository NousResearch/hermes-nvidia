"""What the sandbox did with each credential, asked after it starts.

The Windows driver reads the answer from the CLI's ``sandbox provider status``; the fixture is that command's real
output. The wait ends as soon as every credential is ready, and a credential the gateway withheld, or one that
never becomes ready, fails the start with the reason.
"""
import asyncio
import json

import pytest

import provider_status_output as PS
import test_credential_placement as CP
import test_openshell_driver as LD
import test_openshell_windows as WD
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_windows as W
from openshell.launcher.driver import DriverUnavailable

SANDBOX, PROVIDER = "hermes-work", "hermes-work-model-key-70bb24d9"


def _status_calls(fake):
    return [argv for argv, _env in fake.calls if argv[1:4] == ["sandbox", "provider", "status"]]


@pytest.fixture
def no_sleep(monkeypatch):
    """The wait between two questions, recorded instead of slept."""
    slept = []
    monkeypatch.setattr(OD.time, "sleep", slept.append)
    return slept


# --- the CLI's output ------------------------------------------------------------------------------------

def test_the_state_is_read_from_the_target_of_the_real_output():
    doc = json.loads(PS.READY_OUTPUT)
    assert "state" not in doc and "status" not in doc and len(doc["targets"]) == 1
    assert W.parse_provider_status(doc, SANDBOX, PROVIDER) == ("READY", "UNSPECIFIED")


def test_the_gateway_reads_the_real_output_through_the_cli(tmp_path):
    _layout, _runtime, cfg, _bb = WD._tree(tmp_path)
    asked = []

    def run(argv, **kw):
        asked.append(argv[1:])
        return WD.Done(0, PS.READY_OUTPUT)

    assert W.CliGateway(cfg, run=run).provider_state(SANDBOX, PROVIDER) == ("READY", "UNSPECIFIED")
    assert asked == [["sandbox", "provider", "status", SANDBOX, PROVIDER, "-o", "json"]]


@pytest.mark.parametrize("state, reason, want", [
    ("pending", "waiting_for_supervisor", ("PENDING", "WAITING_FOR_SUPERVISOR")),
    ("persisted", "unspecified", ("PERSISTED", "UNSPECIFIED")),
    ("withheld", "credentials_withheld", ("WITHHELD", "CREDENTIALS_WITHHELD")),
    ("withheld", "unsupported_supervisor", ("WITHHELD", "UNSUPPORTED_SUPERVISOR")),
    ("failed", "credential_install_failed", ("FAILED", "CREDENTIAL_INSTALL_FAILED")),
    ("unknown", "unknown", (None, None)),  # a number this CLI has no word for
])
def test_a_target_that_is_not_ready_says_so(state, reason, want):
    doc = json.loads(PS.status_output(SANDBOX, PROVIDER, state, reason))
    assert W.parse_provider_status(doc, SANDBOX, PROVIDER) == want


def test_no_target_and_other_shapes_are_not_taken_for_an_answer():
    assert W.parse_provider_status({"mutation_id": "m", "targets": []}, SANDBOX, PROVIDER) == (None, None)
    assert W.parse_provider_status({"mutation_id": "m"}, SANDBOX, PROVIDER) == (None, None)
    assert W.parse_provider_status({"targets": "ready"}, SANDBOX, PROVIDER) == (None, None)
    assert W.parse_provider_status({"targets": [None, "ready", {"receipt": None}]}, SANDBOX, PROVIDER) == (None, None)
    assert W.parse_provider_status([], SANDBOX, PROVIDER) == (None, None)


def test_of_several_targets_the_one_of_this_sandbox_and_provider_counts():
    def target(sandbox, provider, state, reason="unspecified"):
        return json.loads(PS.status_output(sandbox, provider, state, reason))["targets"][0]

    mine = target(SANDBOX, PROVIDER, "pending", "waiting_for_credentials")
    doc = {"mutation_id": "m", "targets": [target("hermes-other", PROVIDER, "ready"), mine,
                                           target(SANDBOX, "hermes-work-other-key-00000000", "ready")]}
    assert W.parse_provider_status(doc, SANDBOX, PROVIDER) == ("PENDING", "WAITING_FOR_CREDENTIALS")
    # nothing names this sandbox and provider: no answer, whatever the others say
    doc["targets"].remove(mine)
    assert W.parse_provider_status(doc, SANDBOX, PROVIDER) == (None, None)
    # two answers for the same pair: the one that is not ready counts
    doc["targets"] = [target(SANDBOX, PROVIDER, "ready"), target(SANDBOX, PROVIDER, "withheld", "local_policy")]
    assert W.parse_provider_status(doc, SANDBOX, PROVIDER) == ("WITHHELD", "LOCAL_POLICY")


def test_the_forms_an_earlier_reading_expected_are_still_read():
    assert W.parse_provider_status({"state": "ready", "reason": "unspecified"}, SANDBOX, PROVIDER) == ("READY", "UNSPECIFIED")
    doc = {"status": {"state": "PROVIDER_READINESS_STATE_WITHHELD", "reason": "PROVIDER_READINESS_REASON_UNSUPPORTED_SUPERVISOR"}}
    assert W.parse_provider_status(doc, SANDBOX, PROVIDER) == ("WITHHELD", "UNSUPPORTED_SUPERVISOR")


def test_an_error_of_the_cli_is_an_error_and_text_after_the_output_is_not(tmp_path):
    _layout, _runtime, cfg, _bb = WD._tree(tmp_path)
    refused = W.CliGateway(cfg, run=lambda argv, **kw: WD.Done(1, "", "Error:   x status: NotFound, message: \"sandbox not found\""))
    with pytest.raises(W.CliError, match="sandbox provider status failed"):
        refused.provider_state(SANDBOX, PROVIDER)
    # a line the CLI writes beside its answer does not hide the answer
    noisy = W.CliGateway(cfg, run=lambda argv, **kw: WD.Done(0, PS.READY_OUTPUT, "warning: a newer version is available {1}"))
    assert noisy.provider_state(SANDBOX, PROVIDER) == ("READY", "UNSPECIFIED")


def test_a_profile_the_gateway_refuses_fails_with_what_the_import_said(tmp_path):
    _layout, _runtime, cfg, _bb = WD._tree(tmp_path)
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"id": "some-profile", "credentials": []}), encoding="utf-8")

    def run(argv, **kw):
        if argv[1:4] == ["provider", "profile", "import"]:
            return WD.Done(1, "", "Error: endpoint host is not valid")
        assert argv[1:4] == ["provider", "profile", "export"]  # it is not there to be updated
        return WD.Done(1, "", "Error: provider profile 'some-profile' not found")

    with pytest.raises(W.CliError, match="provider profile import failed.*endpoint host is not valid"):
        W.CliGateway(cfg, run=run).upsert_profile(path, "some-profile")


def test_a_provider_that_cannot_be_made_fails_with_what_the_create_said(tmp_path):
    _layout, _runtime, cfg, _bb = WD._tree(tmp_path)

    def run(argv, **kw):
        if argv[1:3] == ["provider", "create"]:
            return WD.Done(1, "", "Error: unknown provider type 'some-profile'")
        assert argv[1:3] == ["provider", "update"]
        return WD.Done(1, "", "Error: provider 'some-provider' not found")

    with pytest.raises(W.CliError, match="provider update.*not found.*provider create said: .*unknown provider type") as failed:
        W.CliGateway(cfg, run=run).upsert_provider("some-provider", "some-profile", {"SOME_KEY": "made-up-value"})
    assert "made-up-value" not in str(failed.value)


# --- the wait after a start ------------------------------------------------------------------------------

def test_a_windows_start_asks_once_per_credential_when_all_are_ready(tmp_path, monkeypatch, no_sleep):
    sup, fake, driver, _layout = CP._windows(tmp_path, monkeypatch)
    assert driver.declare(CP.NOUS, "first-token", 1900000000.5) == "HERMES_CRED_NOUS_AGENT_KEY"

    async def scenario():
        await sup.start()
        try:
            names = sorted(p["name"] for p in driver.policy()["providers"])
            assert len(names) == 2
            assert sorted(argv[5] for argv in _status_calls(fake)) == names  # one question each, no more
            assert no_sleep == []  # nothing to wait for
            assert {p["state"] for p in driver.policy()["providers"]} == {"READY"}
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_wait_ends_as_soon_as_the_last_credential_is_ready(tmp_path, monkeypatch, no_sleep):
    sup, fake, driver, _layout = CP._windows(tmp_path, monkeypatch)
    driver.declare(CP.NOUS, "first-token", 1900000000.5)
    answers = {}

    class Later(dict):
        def get(self, provider, default=None):
            answers[provider] = answers.get(provider, 0) + 1
            if "nous" in provider and answers[provider] < 3:
                return ("PENDING", "WAITING_FOR_CREDENTIALS")
            return ("READY", "UNSPECIFIED")

    fake.provider_states = Later()

    async def scenario():
        await sup.start()
        try:
            nous = next(n for n in answers if "nous" in n)
            model = next(n for n in answers if "nous" not in n)
            assert answers == {nous: 3, model: 1}  # a credential that is ready is not asked about again
            assert len(no_sleep) == 2 and all(0 < pause <= 0.5 for pause in no_sleep)
        finally:
            await sup.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize("state, reason, words", [
    ("WITHHELD", "CREDENTIALS_WITHHELD", "the gateway withheld Model .TEST_MODEL_KEY. from the sandbox .credentials withheld."),
    ("WITHHELD", "LOCAL_POLICY", "the gateway withheld Model .TEST_MODEL_KEY. from the sandbox .local policy."),
    ("FAILED", "CREDENTIAL_INSTALL_FAILED", "the sandbox could not take Model .TEST_MODEL_KEY. .credential install failed."),
    ("REVOKED", "UNSPECIFIED", "the sandbox could not take Model .TEST_MODEL_KEY. .revoked."),
])
def test_a_credential_the_sandbox_does_not_get_fails_the_windows_start_with_the_reason(tmp_path, monkeypatch, no_sleep,
                                                                                    state, reason, words):
    sup, fake, _driver, _layout = CP._windows(tmp_path, monkeypatch)

    class Refused(dict):
        def get(self, provider, default=None):
            return (state, reason)

    fake.provider_states = Refused()

    async def scenario():
        with pytest.raises(DriverUnavailable, match=words):
            await sup.start()
        assert len(_status_calls(fake)) == 1 and no_sleep == []  # the answer is final: nothing is waited for
        assert not fake.sandboxes  # the sandbox that came up is taken down again

    asyncio.run(scenario())


def test_a_credential_that_never_becomes_ready_fails_the_start_after_the_limit(tmp_path, monkeypatch):
    sup, fake, _driver, _layout = CP._windows(tmp_path, monkeypatch)
    clock = [1000.0]
    monkeypatch.setattr(OD.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(OD.time, "sleep", lambda pause: clock.__setitem__(0, clock[0] + pause))

    class Never(dict):
        def get(self, provider, default=None):
            return ("PENDING", "WAITING_FOR_SUPERVISOR")

    fake.provider_states = Never()

    async def scenario():
        with pytest.raises(DriverUnavailable, match=r"Model .TEST_MODEL_KEY. was not ready in the sandbox after 20 s "
                                                    r".pending: waiting for supervisor."):
            await sup.start()
        assert OD._READINESS_WAIT == 20.0 and clock[0] - 1000.0 >= OD._READINESS_WAIT
        assert 20 <= len(_status_calls(fake)) <= 90
        assert not fake.sandboxes

    asyncio.run(scenario())


def test_an_answer_that_cannot_be_had_or_read_is_noted_once_and_the_start_goes_on(tmp_path, monkeypatch, no_sleep):
    sup, fake, driver, _layout = CP._windows(tmp_path, monkeypatch)
    driver.declare(CP.NOUS, "first-token", 1900000000.5)
    notes = []
    monkeypatch.setattr(driver, "_note", notes.append)
    real = fake.__call__

    def cli(argv, env=None, **kw):
        if argv[1:4] == ["sandbox", "provider", "status"]:
            fake.calls.append((list(argv), dict(env or {})))
            if "nous" in argv[5]:
                return WD.Done(2, "", "error: unrecognized subcommand 'provider'")
            return WD.Done(0, json.dumps({"mutation_id": "m", "targets": []}))
        return real(argv, env=env, **kw)

    driver.gw._run = cli

    async def scenario():
        await sup.start()
        try:
            assert len(_status_calls(fake)) == 2 and no_sleep == []  # asked once each: asking again says no more
            assert sum("could not ask what the sandbox did with provider" in note for note in notes) == 1
            assert sum("did not say what the sandbox did with provider" in note for note in notes) == 1
            assert {p["state"] for p in driver.policy()["providers"]} == {None}
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_linux_driver_keeps_the_same_rules(tmp_path, monkeypatch, no_sleep):
    sup, api, _rec, _layout = LD._supervisor(tmp_path, monkeypatch)
    asked = []

    class Later(dict):
        def get(self, provider, default=None):
            asked.append(provider)
            return ("PERSISTED", "UNSPECIFIED") if len(asked) < 2 else ("READY", "UNSPECIFIED")

    api.provider_states = Later()

    async def ready():
        await sup.start()
        try:
            assert len(asked) == 2 and len(no_sleep) == 1
        finally:
            await sup.stop()

    asyncio.run(ready())

    class Failed(dict):
        def get(self, provider, default=None):
            return ("FAILED", "POLICY_ACTIVATION_FAILED")

    api.provider_states = Failed()

    async def failed():
        with pytest.raises(DriverUnavailable, match="the sandbox could not take .*LLAMA_API_KEY.* .policy activation failed."):
            await sup.start()
        assert ("delete", "hermes-work") in api.calls

    asyncio.run(failed())
