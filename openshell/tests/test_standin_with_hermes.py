"""Hermes itself, unchanged, on a stand-in sign-in store.

For each provider a profile can be signed in to: Hermes's own sign-in code writes the store on the "host" (against
a loopback issuer), ``build_template`` takes the secrets out, the sandbox's start-up step fills the stand-in into
another home from placeholders, and Hermes then runs a turn, an auxiliary request, the model list, the
context-length probe and the signed-in status there. Every request goes to a loopback server that records the
KIND of credential it received (``standin_stub.py``); a guard refuses any other connection. Fabricated values
only. The module is skipped when no Hermes checkout is on the import path.

Set ``STANDIN_RECORD_DIR`` to a folder to get one JSON record per case (where each request carried a credential,
and of what kind).
"""
import json
import os
import stat
import subprocess
import sys
import time
from argparse import Namespace
from pathlib import Path

import pytest

pytest.importorskip("hermes_cli.auth", reason="needs a Hermes checkout on the import path")
pytest.importorskip("run_agent", reason="needs a Hermes checkout on the import path")

import standin_stub
from openshell.inside import standin
from test_standin_template import strings_of

TREE = Path(__file__).resolve().parents[2]
PACKAGE = Path(__file__).resolve().parents[1].name


def core(module: str, name: str):
    """A function of Hermes's own sign-in code, or a skip when this Hermes does not have it under that name."""
    try:
        return getattr(__import__(module, fromlist=[name]), name)
    except (ImportError, AttributeError):
        pytest.skip(f"this Hermes has no {module}.{name}")


def sign_in_nous():
    state = core("hermes_cli.auth_nous", "_nous_device_code_login")(open_browser=False)
    core("hermes_cli.auth_nous", "persist_nous_credentials")(state)


def sign_in_codex():
    creds = core("hermes_cli.auth_codex", "_codex_device_code_login")()
    core("hermes_cli.auth_codex", "_save_codex_tokens")(creds["tokens"], creds.get("last_refresh"))


def sign_in_xai():
    creds = core("hermes_cli.auth_xai", "_xai_oauth_device_code_login")(open_browser=False)
    core("hermes_cli.auth_xai", "_save_xai_oauth_tokens")(
        creds["tokens"], discovery=creds.get("discovery"), redirect_uri=creds.get("redirect_uri", ""),
        last_refresh=creds.get("last_refresh"), auth_mode="oauth_device_code")


def sign_in_minimax():
    core("hermes_cli.auth_minimax", "_minimax_oauth_login")(open_browser=False)


def sign_in_anthropic_file():
    """Hermes's own Anthropic sign-in, kept in the file Hermes keeps it in (``.anthropic_oauth.json``)."""
    creds = core("agent.anthropic_credentials", "run_hermes_oauth_login_pure")()
    core("agent.anthropic_credentials", "_write_hermes_oauth_credentials")(
        creds["access_token"], creds["refresh_token"], creds["expires_at_ms"])


def sign_in_anthropic_row():
    """The same sign-in as ``hermes auth add anthropic --type oauth`` keeps it: a row of the credential pool."""
    core("hermes_cli.auth_commands", "auth_add_command")(Namespace(provider="anthropic", auth_type="oauth"))


SIGN_INS = {"nous": sign_in_nous, "openai-codex": sign_in_codex, "xai-oauth": sign_in_xai,
            "minimax-oauth": sign_in_minimax, "anthropic-file": sign_in_anthropic_file,
            "anthropic-row": sign_in_anthropic_row}

# name: (the sign-ins made on the host, token variables, the model block, the credential the main request uses,
#        the host and path of the main request)
CASES = {
    "nous": (["nous"], {}, {"provider": "nous", "default": "hermes-4-405b"}, "nous:agent_key",
             ("inference-api.nousresearch.com:443", "/v1/chat/completions")),
    "openai-codex": (["openai-codex"], {}, {"provider": "openai-codex", "default": "gpt-5.1-codex"},
                     "openai-codex:access_token", ("chatgpt.com:443", "/backend-api/codex/responses")),
    "xai-oauth": (["xai-oauth"], {}, {"provider": "xai-oauth", "default": "grok-4"}, "xai-oauth:access_token",
                  ("api.x.ai:443", "/v1/responses")),
    "minimax-oauth": (["minimax-oauth"], {}, {"provider": "minimax-oauth", "default": "MiniMax-M2"},
                      "minimax-oauth:access_token", ("api.minimax.io:443", "/anthropic/v1/messages")),
    "anthropic-file": (["anthropic-file"], {}, {"provider": "anthropic", "default": "claude-sonnet-4-5"},
                       "anthropic:accessToken", ("api.anthropic.com:443", "/v1/messages")),
    "anthropic-row": (["anthropic-row"], {}, {"provider": "anthropic", "default": "claude-sonnet-4-5"},
                      None, ("api.anthropic.com:443", "/v1/messages")),
    "anthropic-variable": ([], {"ANTHROPIC_TOKEN": "anthropic"}, {"provider": "anthropic", "default": "claude-sonnet-4-5"},
                           "env:ANTHROPIC_TOKEN", ("api.anthropic.com:443", "/v1/messages")),
}


@pytest.fixture
def stub(monkeypatch):
    import webbrowser

    upstream = standin_stub.Stub()
    standin_stub.install_redirect(monkeypatch, upstream.port)
    upstream.escaped = standin_stub.install_netguard(monkeypatch)
    upstream.opened = []
    for name in ("open", "open_new", "open_new_tab"):  # a sign-in must never open the user's browser from a test
        monkeypatch.setattr(webbrowser, name, lambda url=None, *a, **k: upstream.opened.append(url) or True)
    monkeypatch.setattr(webbrowser, "get", lambda *a, **k: webbrowser)
    # A program a client may start for a version string: never needed here.
    monkeypatch.setattr("agent.anthropic_adapter._claude_code_version_cache", "0.0.0", raising=False)
    yield upstream
    upstream.close()


class Homes:
    """The profile on the host (where Hermes signs in) and the same profile as the sandbox sees it."""

    def __init__(self, tmp_path, monkeypatch, stub):
        self.tmp, self.patch, self.stub = tmp_path, monkeypatch, stub
        self.host = tmp_path / "host" / "profiles" / "sb"
        self.inside = tmp_path / "sandbox" / "profiles" / "sb"
        for folder in (self.host, self.inside, tmp_path / "user"):
            folder.mkdir(parents=True)
        for name in ("HOME", "USERPROFILE"):  # no sign-in of another program on this computer is in reach
            monkeypatch.setenv(name, str(tmp_path / "user"))
        for name in list(os.environ):
            if name.endswith(("_API_KEY", "_TOKEN", "_BASE_URL")) or name.startswith(("AWS_", "HERMES_SANDBOX_")):
                monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(standin.TEMPLATE_ENV, raising=False)
        monkeypatch.setenv("HERMES_HOME", str(self.host))

    def sign_in(self, *names: str) -> None:
        import secrets

        made, real = [], secrets.token_urlsafe
        with self.patch.context() as patch:
            patch.setattr(time, "sleep", lambda seconds: None)  # the polls of a device-code sign-in
            # The Anthropic sign-in asks for the code its page shows, which ends in the state it made up.
            patch.setattr(secrets, "token_urlsafe", lambda n=32: made.append(real(n)) or made[-1])
            patch.setattr("builtins.input", lambda prompt="": f"code-fabricated#{made[-1]}")
            for name in names:
                SIGN_INS[name]()

    def stores(self, home=None) -> dict:
        out = {}
        for name in standin.STORE_FILES:
            path = (home or self.host) / name
            out[name] = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
        return out

    def enter(self, model: dict, env_tokens=(), stores=None, without_grants=()):
        """Switch the sandbox on: the template from the host's stores, the launcher's part (one variable and one
        placeholder per credential), then the start-up step in the sandbox's home."""
        template, credentials = standin.build_template(stores or self.stores(), env_tokens, without_grants=without_grants)
        for number, credential in enumerate(credentials):
            variable = credential["field"] if credential["id"].startswith("env:") else f"HERMES_SANDBOX_CRED_{number}"
            template["credentials"][credential["id"]]["env"] = variable
            self.patch.setenv(variable, standin_stub.placeholder(variable, stable=number % 2 == 0))
        path = self.tmp / "standin-template.json"
        path.write_text(json.dumps(template), encoding="utf-8")
        self.patch.setenv(standin.TEMPLATE_ENV, str(path))
        self.patch.setenv("HERMES_HOME", str(self.inside))
        lines = ["model:"] + [f"  {key}: {value}" for key, value in model.items()]
        (self.inside / "config.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
        for name, value in standin.prepare().items():
            self.patch.setenv(name, value)
        self.host_calls = list(self.stub.token_calls)
        self.stub.clear()
        return template, credentials


@pytest.fixture
def homes(tmp_path, monkeypatch, stub):
    made = Homes(tmp_path, monkeypatch, stub)
    yield made
    assert stub.opened in ([], [None]) or all("claude.ai" in str(url) for url in stub.opened)
    assert not stub.escaped, stub.escaped


def record(name: str, payload) -> None:
    folder = os.environ.get("STANDIN_RECORD_DIR")
    if folder:
        Path(folder).mkdir(parents=True, exist_ok=True)
        (Path(folder) / f"{name}.json").write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")


def outcome(fn, *args, **kwargs) -> str:
    try:
        fn(*args, **kwargs)
        return "ok"
    except BaseException as exc:  # noqa: BLE001 - every outcome is reported
        return f"{type(exc).__name__}: {str(exc).splitlines()[0][:200] if str(exc) else ''}"


def agent_for(model: str):
    import run_agent
    from hermes_cli.runtime_provider import resolve_runtime_provider

    runtime = resolve_runtime_provider(target_model=model)
    agent = run_agent.AIAgent(
        api_key=runtime["api_key"], base_url=runtime["base_url"], provider=runtime["provider"],
        api_mode=runtime["api_mode"], model=model, credential_pool=runtime.get("credential_pool"),
        requested_provider=runtime.get("requested_provider"), quiet_mode=True, skip_context_files=True,
        skip_memory=True, enabled_toolsets=[], max_iterations=1)
    return runtime, agent


def everything(stub, model_cfg: dict) -> dict:
    """A main turn, an auxiliary request, the model list, the context-length probe and the signed-in status."""
    from agent.auxiliary_client import call_llm
    from agent.model_metadata import get_model_context_length
    from hermes_cli.auth import get_auth_status
    from hermes_cli.models import provider_model_ids

    model, result, held = model_cfg["default"], {}, {}

    def turn():
        held["runtime"], agent = agent_for(model)
        held["result"] = agent.run_conversation("ping", conversation_history=[], task_id="t")

    result["main"] = outcome(turn)
    runtime = held.get("runtime") or {}
    key = runtime.get("api_key")
    result["runtime"] = {"provider": runtime.get("provider"), "api_mode": runtime.get("api_mode"),
                         "base_url": runtime.get("base_url"), "source": str(runtime.get("source")),
                         "api_key_kind": stub.kinds.kind(key) if isinstance(key, str) else type(key).__name__}
    result["turn_failed"] = bool((held.get("result") or {}).get("failed"))
    result["main_rows"] = stub.rows()
    stub.requests.clear()
    result["aux"] = outcome(call_llm, messages=[{"role": "user", "content": "ping"}], max_tokens=8)
    result["aux_rows"] = stub.rows()
    stub.requests.clear()
    result["model_list"] = outcome(provider_model_ids, model_cfg["provider"], force_refresh=True)
    result["context_length"] = outcome(get_model_context_length, model, base_url=runtime.get("base_url") or "",
                                       api_key=key if isinstance(key, str) else "", provider=runtime.get("provider") or "")
    result["probe_rows"] = stub.rows()
    try:
        status = get_auth_status(model_cfg["provider"])
        result["status"] = {k: status.get(k) for k in ("logged_in", "configured", "source", "error") if k in status}
    except Exception as exc:  # noqa: BLE001 - reported, and asserted on by the caller
        result["status"] = {"raised": type(exc).__name__}
    result["token_endpoint_calls"] = list(stub.token_calls)
    result["escaped"] = sorted(set(stub.escaped))
    return result


def kinds_in(rows) -> set:
    return {kind for row in rows for kind in row["cred"].values()}


def assert_no_issued_value(stub, template, credentials) -> None:
    """Nothing the issuers ever handed out is in the template, and no long string outside the known-safe keys."""
    text = json.dumps([template, credentials])
    assert stub.kinds.issued() and not [kind for kind in stub.kinds.inside(text) if kind in ("real", "refresh-token")]
    for doc in template["files"].values():
        for kind, key, top, found in strings_of(doc):
            if kind == "value" and key not in standin.SAFE_KEYS and not (key == "" and top in standin.SAFE_LISTS):
                assert len(found) <= standin.VALUE_BOUND, (key, found)
            if kind == "key":
                assert len(found) <= standin.KEY_BOUND


# -- one provider at a time --------------------------------------------------------------------------------------

def needs_its_client(name: str) -> None:
    """The providers that speak the Anthropic wire need Anthropic's client library, which Hermes installs on
    first use; a test environment without it skips them."""
    if name.startswith("anthropic") or name == "minimax-oauth":
        pytest.importorskip("anthropic", reason="the Anthropic client library is not installed here")


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_signed_in_provider_works_on_its_alias(name, homes, stub):
    needs_its_client(name)
    sign_ins, env_tokens, model_cfg, credential, (host, path) = CASES[name]
    homes.sign_in(*sign_ins)
    template, credentials = homes.enter(model_cfg, env_tokens)
    if sign_ins:
        assert_no_issued_value(stub, template, credentials)
    if credential:
        assert credential in template["credentials"], sorted(template["credentials"])
    result = everything(stub, model_cfg)
    record(f"alias_{name}", {**result, "credentials": credentials, "sign_in_calls": homes.host_calls})
    assert result["main"] == "ok" and not result["turn_failed"], result["main"]
    assert result["runtime"]["api_key_kind"] == "alias" and result["runtime"]["provider"] == model_cfg["provider"]
    sent = [row for row in result["main_rows"] if (row["host"], row["path"]) == (host, path)]
    assert sent and all(row["cred"] == {"authorization:bearer": "alias"} for row in sent), result["main_rows"]
    assert result["aux"] == "ok" and result["model_list"] == "ok" and result["context_length"] == "ok"
    assert result["status"].get("logged_in") is True, result["status"]
    assert result["token_endpoint_calls"] == []  # nothing inside signs in or refreshes
    seen = kinds_in(result["main_rows"] + result["aux_rows"] + result["probe_rows"])
    assert seen <= {"alias", "absent"}, seen  # never a real token, a refresh grant, or the fixed word
    if name == "openai-codex":  # the account header comes from the alias's claims
        assert all(row["account_header"] for row in sent)


def test_the_claims_in_an_alias_are_the_ones_hermes_reads(homes, stub):
    homes.sign_in("nous", "openai-codex")
    template, credentials = homes.enter({"provider": "nous", "default": "hermes-4-405b"})
    by_id = {c["id"]: c for c in credentials}
    assert by_id["nous:agent_key"]["claims"] == {key: standin_stub.NOUS_CLAIMS[key] for key in
                                                 ("scope", "sub", "org_id", "paid_access", "tool_access")}
    assert by_id["openai-codex:access_token"]["claims"] == {
        "sub": "user-fabricated", "https://api.openai.com/auth": {"chatgpt_account_id": "acct-fabricated"}}
    for credential in credentials:  # the expiry the launcher needs is the real token's
        assert time.time() < credential["expires_at"] <= time.time() + 3700
    doc = json.loads((homes.inside / "auth.json").read_text(encoding="utf-8"))
    claims = standin_stub.claims_of(doc["providers"]["nous"]["agent_key"])
    assert claims["exp"] > time.time() + 9 * 365 * 24 * 3600 and "email" not in claims and "jti" not in claims
    from hermes_cli.nous_account import get_nous_portal_account_info

    info = outcome(get_nous_portal_account_info)
    assert info == "ok" and stub.token_calls == []


# -- several sign-ins, a pool, an older shape --------------------------------------------------------------------

def test_a_store_holding_several_sign_ins_and_a_pool(homes, stub):
    homes.sign_in("nous", "openai-codex", "xai-oauth", "minimax-oauth", "anthropic-row", "anthropic-file")
    key = stub.kinds.new_real("sk-or-v1-")
    core("hermes_cli.auth_commands", "auth_add_command")(
        Namespace(provider="openrouter", auth_type="api-key", api_key=key, label="a second key"))
    stores = homes.stores()
    pool = stores["auth.json"]["credential_pool"]
    assert {"anthropic", "openrouter"} <= set(pool), sorted(pool)
    template, credentials = homes.enter({"provider": "openai-codex", "default": "gpt-5.1-codex"})
    assert_no_issued_value(stub, template, credentials)
    ids = {c["id"] for c in credentials}
    assert {"nous:agent_key", "openai-codex:access_token", "xai-oauth:access_token", "minimax-oauth:access_token",
            "anthropic:accessToken"} <= ids, sorted(ids)
    manual = [c for c in credentials if c["provider"] == "openrouter"]
    assert len(manual) == 1 and manual[0]["auth_type"] == "api_key" and standin.credential_value(stores, manual[0]) == key
    # Every secret of the store is one credential: the values read back are all different, and all were issued.
    values = [standin.credential_value(stores, c) for c in credentials]
    assert len(set(values)) == len(values) and set(values) <= stub.kinds.issued()
    filled = json.loads((homes.inside / "auth.json").read_text(encoding="utf-8"))
    row = [r for r in filled["credential_pool"]["openrouter"] if r.get("source") == "manual"][0]
    assert stub.kinds.kind(row["access_token"]) == "placeholder"  # a key row: the placeholder itself
    assert all(stub.kinds.kind(r["access_token"]) == "alias" for r in filled["credential_pool"]["anthropic"])
    result = everything(stub, {"provider": "openai-codex", "default": "gpt-5.1-codex"})
    record("alias_several_sign_ins", {**result, "credentials": credentials})
    assert result["main"] == "ok" and not result["turn_failed"] and result["token_endpoint_calls"] == []
    from hermes_cli.auth import get_auth_status

    for provider in ("nous", "openai-codex", "xai-oauth", "minimax-oauth", "anthropic"):
        assert get_auth_status(provider).get("logged_in") is True, provider
    assert stub.token_calls == [] and kinds_in(stub.rows()) <= {"alias", "absent", "placeholder"}


def test_a_store_in_the_older_shape_is_read_by_hermes_as_before(homes, stub):
    """Hermes still reads the ``systems`` shape an early version wrote; the stand-in keeps the shape it was given."""
    homes.sign_in("nous")
    row = homes.stores()["auth.json"]["providers"]["nous"]
    older = {"auth.json": {"systems": {"nous_portal": row}}, ".anthropic_oauth.json": None}
    template, credentials = homes.enter({"provider": "nous", "default": "hermes-4-405b"}, stores=older)
    assert_no_issued_value(stub, template, credentials)
    assert [c["id"] for c in credentials] == ["nous_portal:agent_key"]
    assert list(json.loads((homes.inside / "auth.json").read_text(encoding="utf-8"))) == ["systems"]
    from hermes_cli.auth import get_auth_status
    from hermes_cli.runtime_provider import resolve_runtime_provider

    assert get_auth_status("nous").get("logged_in") is True
    runtime = resolve_runtime_provider(target_model="hermes-4-405b")
    assert (runtime["provider"], stub.kinds.kind(runtime["api_key"])) == ("nous", "alias") and stub.token_calls == []


def test_the_stand_in_follows_a_refresh_made_on_the_host(homes, stub):
    """The host keeps the sign-in fresh with Hermes's own code; a template built afterwards holds neither the old
    pair nor the new one, and the turn inside makes no token call of its own."""
    homes.sign_in("nous", "openai-codex")
    before = homes.stores()["auth.json"]
    core("hermes_cli.auth", "resolve_nous_runtime_credentials")(force_refresh=True)
    tokens = dict(before["providers"]["openai-codex"]["tokens"])
    refreshed = core("hermes_cli.auth_codex", "refresh_codex_oauth_pure")(tokens["access_token"], tokens["refresh_token"])
    core("hermes_cli.auth_codex", "_save_codex_tokens")(
        {"access_token": refreshed["access_token"], "refresh_token": refreshed["refresh_token"]}, refreshed.get("last_refresh"))
    after = homes.stores()["auth.json"]
    assert after["providers"]["nous"]["refresh_token"] != before["providers"]["nous"]["refresh_token"]
    assert after["providers"]["openai-codex"]["tokens"]["refresh_token"] != tokens["refresh_token"]
    assert [call["presented"] for call in stub.refreshes()] == ["refresh-token", "refresh-token"]
    for provider, model in (("nous", "hermes-4-405b"), ("openai-codex", "gpt-5.1-codex")):
        template, credentials = homes.enter({"provider": provider, "default": model})
        assert_no_issued_value(stub, template, credentials)
        result = everything(stub, {"provider": provider, "default": model})
        record(f"after_host_refresh_{provider}", {**result, "host_calls": homes.host_calls})
        assert result["main"] == "ok" and not result["turn_failed"] and result["runtime"]["api_key_kind"] == "alias"
        assert result["token_endpoint_calls"] == []
        homes.patch.setenv("HERMES_HOME", str(homes.host))


# -- the store as a file -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["nous", "openai-codex"])
def test_a_store_the_sandbox_cannot_write(name, homes, stub):
    """Hermes rewrites the store when it may (it normalises a row); with the file read-only everything still works."""
    sign_ins, env_tokens, model_cfg, _, _ = CASES[name]
    homes.sign_in(*sign_ins)
    homes.enter(model_cfg, env_tokens)
    path = homes.inside / "auth.json"
    before = path.read_bytes()
    os.chmod(path, stat.S_IREAD)
    try:
        result = everything(stub, model_cfg)
    finally:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    record(f"read_only_{name}", result)
    assert result["token_endpoint_calls"] == [] and kinds_in(result["main_rows"] + result["aux_rows"]) <= {"alias", "absent"}
    assert result["main"] == "ok" and not result["turn_failed"] and result["aux"] == "ok", result
    if os.name == "nt" and name == "nous":
        # A read-only file cannot be replaced on Windows, and Hermes saves the Nous row whenever it resolves it:
        # the status then fails. The launcher must leave the stand-in writable for the sandbox.
        assert path.read_bytes() == before and result["status"] == {"raised": "PermissionError"}
    else:
        assert result["status"].get("logged_in") is True, result["status"]


def test_the_nous_tool_gateway_takes_the_same_alias(homes, stub):
    """Tools the Nous subscription pays for go through ``<vendor>-gateway.nousresearch.com`` with the Portal token."""
    homes.sign_in("nous")
    homes.enter({"provider": "nous", "default": "hermes-4-405b"})
    from tools import managed_tool_gateway as gateway

    assert stub.kinds.kind(gateway.read_nous_access_token() or "") == "alias" and stub.token_calls == []
    assert gateway.build_vendor_gateway_url("firecrawl") == "https://firecrawl-gateway.nousresearch.com"


# -- a placeholder that no longer resolves -----------------------------------------------------------------------

DEAD = {"error": {"message": "stub: the credential placeholder did not resolve", "type": "authentication_error",
                  "code": "credential_unresolved"}}
# What OpenShell's proxy answers for a placeholder it cannot resolve (expired, revoked or unknown).
UNAVAILABLE = {"error": "credential_unavailable", "message": "Credential placeholder could not be resolved"}
DENIED = (403, {"error": "policy_denied", "message": "stub: this address is not allowed"})
# name: (case, the model host's answer, what a refresh gets, providers without a grant in the stand-in,
#        what the user reads, the fewest and the most refresh attempts made inside,
#        whether Hermes is signed in by itself again once the value behind the placeholder is fresh)
DEAD_CASES = {
    # The model host answers 401 or 403 and the token endpoint can be reached and answers: one refresh attempt
    # with the fixed word, the issuer says the grant is no good, and Hermes clears the stand-in's row. The
    # provider then reads as signed out until the start-up step writes the store again.
    "nous-401": ("nous", (401, DEAD), None, (), "Nous Portal rejected your sign-in", 1, 1, False),
    "nous-403": ("nous", (403, DEAD), None, (), "Nous Portal rejected your sign-in", 1, 1, False),
    "codex-401": ("openai-codex", (401, DEAD), None, (), "rejected your sign-in", 1, 1, False),
    # The same with a token endpoint the sandbox cannot use (refused by a proxy, or not reachable at all): the
    # row stays, and the next turn works as soon as the value is fresh.
    "nous-401-refresh-refused": ("nous", (401, DEAD), DENIED, (), "Nous Portal rejected your sign-in", 1, 3, True),
    "nous-401-refresh-unreachable": ("nous", (401, DEAD), "unreachable", (), "Nous Portal rejected your sign-in", 1, 3, True),
    "codex-401-refresh-refused": ("openai-codex", (401, DEAD), DENIED, (), "rejected your sign-in", 1, 3, True),
    "codex-401-refresh-unreachable": ("openai-codex", (401, DEAD), "unreachable", (), "rejected your sign-in", 1, 3, True),
    # A stand-in without the Nous refresh grant: nothing to try, nothing cleared.
    "nous-401-no-grant-inside": ("nous", (401, DEAD), None, ("nous",), "Nous Portal rejected your sign-in", 0, 0, True),
    "anthropic-401": ("anthropic-variable", (401, DEAD), None, (), "Anthropic rejected your API key", 0, 0, True),
    # The other sign-ins with the fixed word and an issuer that answers: xAI is signed out as Nous and Codex are,
    # Hermes's own Anthropic sign-in tries once and stays.
    "xai-401": ("xai-oauth", (401, DEAD), None, (), "rejected your sign-in", 1, 1, False),
    "anthropic-file-401": ("anthropic-file", (401, DEAD), None, (), "Anthropic rejected your API key", 1, 1, True),
    # Without a grant in the stand-in, which is what the launcher builds for every sign-in it carries: nothing to
    # try with, no request to any token address, and the row stays signed in.
    "codex-401-no-grant-inside": ("openai-codex", (401, DEAD), None, ("openai-codex",), "rejected your sign-in", 0, 0, True),
    "xai-401-no-grant-inside": ("xai-oauth", (401, DEAD), None, ("xai-oauth",), "rejected your sign-in", 0, 0, True),
    "anthropic-file-401-no-grant-inside": ("anthropic-file", (401, DEAD), None, ("anthropic",),
                                           "Anthropic rejected your API key", 0, 0, True),
    # OpenShell's own answer for a placeholder it cannot resolve: no refresh is tried, nothing is cleared.
    "nous-500": ("nous", (500, UNAVAILABLE), None, (), "returned a server error", 0, 0, True),
    "codex-500": ("openai-codex", (500, UNAVAILABLE), None, (), "returned a server error", 0, 0, True),
}


@pytest.mark.parametrize("case", sorted(DEAD_CASES))
def test_what_the_user_reads_when_a_placeholder_stops_resolving(case, homes, stub):
    name, answer, refresh_answer, without_grants, said, fewest, most, signed_in_after = DEAD_CASES[case]
    needs_its_client(name)
    sign_ins, env_tokens, model_cfg, _, _ = CASES[name]
    homes.sign_in(*sign_ins)
    homes.enter(model_cfg, env_tokens, without_grants=without_grants)
    stub.inference_error, stub.refresh_answer = answer, refresh_answer
    _, agent = agent_for(model_cfg["default"])
    pause = time.sleep
    with homes.patch.context() as patch:  # the waits between Hermes's retries
        patch.setattr(time, "sleep", lambda seconds: pause(min(seconds, 0.01)))
        patch.setattr("agent.retry_utils.jittered_backoff", lambda *a, **k: 0.0, raising=False)
        result = agent.run_conversation("ping", conversation_history=[], task_id="t")
    calls, requests = list(stub.token_calls), stub.table()
    # Then the launcher has put a fresh value behind the same placeholder: is Hermes signed in by itself again?
    stub.inference_error = None
    again = everything(stub, model_cfg)
    after = {k: again[k] for k in ("main", "turn_failed", "aux", "status")}
    record(f"dead_{case}", {
        "failed": result.get("failed"), "final_response": str(result.get("final_response"))[:900],
        "error": str(result.get("error"))[:600], "requests": requests, "token_endpoint_calls": calls,
        "after_the_value_is_fresh_again": after, "token_endpoint_calls_afterwards": again["token_endpoint_calls"][len(calls):]})
    assert result.get("failed") and said in str(result.get("final_response")), result.get("final_response")
    if "sign-in" in said:
        assert "Sign in again" in str(result.get("final_response"))  # Hermes's own advice, wrong in a sandbox
    # What a refresh attempt presents is the fixed word of the stand-in, never a grant an issuer handed out.
    assert fewest <= len(calls) <= most and all((c["grant"], c["presented"]) == ("refresh", "fixed-word") for c in calls), calls
    assert kinds_in(stub.rows()) <= {"alias", "absent", "fixed-word"}
    assert (again["main"] == "ok" and again["status"].get("logged_in") is True) is signed_in_after, after


# -- the start-up step and Hermes in one process of their own ----------------------------------------------------

STATUS_MODULE = '''
"""Print what this Hermes says about a provider's sign-in. No connection but loopback is let through."""
import json, socket, sys

def refuse(self, address, *args):
    raise ConnectionRefusedError("no network in this check")

socket.socket.connect = refuse
from hermes_cli.auth import get_auth_status
from hermes_cli.runtime_provider import resolve_runtime_provider

status = get_auth_status(sys.argv[1])
runtime = resolve_runtime_provider(target_model=sys.argv[2])
key = runtime["api_key"]
print(json.dumps({"logged_in": status.get("logged_in"), "provider": runtime["provider"],
                  "alias": key.count(".") == 2 and key.split(".")[2].startswith("OPENSHELL-RESOLVE-ENV-"),
                  "argv": sys.argv[1:], "leftover": sorted(m for m in sys.modules if m.split(".")[0] == "PACKAGE")}))
sys.exit(6)
'''


@pytest.mark.parametrize("name", ["nous", "openai-codex"])
def test_the_start_command_with_the_step_in_front(name, homes, stub, tmp_path):
    """``python -m <package>.inside.standin -- python -m <module> ...`` in a process of its own, the way this
    system runs it: the store is written from the template, then Hermes finds itself signed in."""
    sign_ins, _, model_cfg, _, _ = CASES[name]
    homes.sign_in(*sign_ins)
    template, credentials = standin.build_template(homes.stores())
    env = {k: v for k, v in os.environ.items()}
    for number, credential in enumerate(credentials):
        template["credentials"][credential["id"]]["env"] = f"HERMES_SANDBOX_CRED_{number}"
        env[f"HERMES_SANDBOX_CRED_{number}"] = standin_stub.placeholder(f"HERMES_SANDBOX_CRED_{number}")
    (tmp_path / "template.json").write_text(json.dumps(template), encoding="utf-8")
    (tmp_path / "standin_status.py").write_text(STATUS_MODULE.replace("PACKAGE", PACKAGE), encoding="utf-8")
    (homes.inside / "config.yaml").write_text(
        f"model:\n  provider: {model_cfg['provider']}\n  default: {model_cfg['default']}\n", encoding="utf-8")
    env.update({standin.TEMPLATE_ENV: str(tmp_path / "template.json"), "HERMES_HOME": str(homes.inside),
                "PYTHONPATH": os.pathsep.join([str(tmp_path), str(TREE), env.get("PYTHONPATH", "")])})
    done = subprocess.run([sys.executable, "-m", f"{PACKAGE}.inside.standin", "--", sys.executable, "-m",
                           "standin_status", model_cfg["provider"], model_cfg["default"]],
                          env=env, capture_output=True, text=True, timeout=300)
    assert done.returncode == 6, done.stderr[-2000:]
    said = json.loads(done.stdout.strip().splitlines()[-1])
    assert said == {"logged_in": True, "provider": model_cfg["provider"], "alias": True,
                    "argv": [model_cfg["provider"], model_cfg["default"]], "leftover": []}
    assert stub.token_calls == [call for call in stub.token_calls if call["grant"] == "sign-in"]
