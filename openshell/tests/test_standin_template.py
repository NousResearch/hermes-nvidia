"""The stand-in sign-in store: the template built on the host, and what it is filled with inside the sandbox.

Fabricated values only. These tests need nothing but the module itself; the ones that run Hermes are in
``test_standin_with_hermes.py``.
"""
import ast
import base64
import json
import random
import string
import sys
from pathlib import Path

import pytest

from openshell.inside import standin

NOW = 1_800_000_000
HEX = "0123456789abcdef"


def placeholder(env: str, handle: str = "") -> str:
    return f"openshell:resolve:env:{handle or 's' + 'ab' * 32}_{env}"


def jwt(claims: dict, signature: str = "SIGNED-BY-THE-ISSUER") -> str:
    def part(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{part({'alg': 'RS256', 'typ': 'JWT'})}.{part(claims)}.{signature}"


def decoded(segment: str):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


ACCESS = jwt({"scope": "inference:invoke", "sub": "user-1", "org_id": "org-1", "email": "someone@example.test",
              "exp": 1_700_000_900, "iat": 1_700_000_000, "tool_access": {"enabled": True, "coverage": {"web": True}}})
CODEX = jwt({"https://api.openai.com/auth": {"chatgpt_account_id": "acct-1", "chatgpt_plan_type": "plus",
                                             "chatgpt_user_id": "user-1"}, "sub": "user-1", "exp": 1_700_003_600})
REFRESH, CODEX_REFRESH, MANUAL_KEY, ENV_KEY = "RT-nous-0123456789", "RT-codex-0123456789", "sk-manual-0123456789", "sk-env-0123456789"


def store() -> dict:
    """An ``auth.json`` in the shape Hermes writes: two sign-ins, the pool rows that mirror them, two key rows."""
    nous = {"access_token": ACCESS, "refresh_token": REFRESH, "client_id": "hermes-cli", "token_type": "Bearer",
            "portal_base_url": "https://portal.example.test", "inference_base_url": "https://inference.example.test/v1",
            "scope": "inference:invoke", "obtained_at": "2025-01-01T00:00:00+00:00",
            "expires_at": "2025-01-01T00:15:00+00:00", "expires_in": 899, "agent_key": ACCESS,
            "agent_key_expires_at": "2025-01-01T00:15:00+00:00", "agent_key_expires_in": 899, "agent_key_id": None,
            "agent_key_reused": False, "agent_key_obtained_at": "2025-01-01T00:00:00+00:00",
            "tls": {"insecure": False, "ca_bundle": "/etc/ssl/own-ca.pem"}, "added_later": "a field of a later Hermes"}
    codex = {"tokens": {"access_token": CODEX, "refresh_token": CODEX_REFRESH, "id_token": jwt({"email": "x@example.test"})},
             "last_refresh": "2025-01-01T00:00:00Z", "auth_mode": "chatgpt"}
    pool = {"nous": [{"id": "a1b2c3", "label": "someone@example.test", "auth_type": "oauth", "priority": 0,
                      "source": "device_code", "access_token": ACCESS, "refresh_token": REFRESH, "agent_key": ACCESS,
                      "expires_at": "2025-01-01T00:15:00+00:00", "request_count": 4, "last_status": "exhausted",
                      "last_error_message": "the provider said something", "last_error_code": 429,
                      "secret_fingerprint": "f" * 40}],
            "openrouter": [{"id": "d4e5f6", "label": "OPENROUTER_API_KEY", "auth_type": "api_key", "priority": 0,
                            "source": "env:OPENROUTER_API_KEY", "access_token": ENV_KEY},
                           {"id": "0a0b0c", "label": "second key", "auth_type": "api_key", "priority": 1,
                            "source": "manual", "access_token": MANUAL_KEY, "base_url": "https://openrouter.example.test/api/v1"}]}
    return {"version": 1, "providers": {"nous": nous, "openai-codex": codex}, "credential_pool": pool,
            "active_provider": "nous", "updated_at": "2025-01-01T00:00:01+00:00",
            "suppressed_sources": {"xai-oauth": ["device_code"]}}


def built(env_tokens=()):
    template, credentials = standin.build_template({"auth.json": store()}, env_tokens)
    for number, (ident, entry) in enumerate(sorted(template["credentials"].items())):
        entry["env"] = f"CRED_{number}"
    environ = {entry["env"]: placeholder(entry["env"]) for entry in template["credentials"].values()}
    return template, credentials, environ


# -- the alias ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("handle", ["s" + "0f" * 32, "v12"])
def test_the_alias_keeps_the_issued_placeholder_in_its_signature_segment(handle):
    issued = placeholder("NOUS_TOKEN", handle)
    token = standin.alias(issued, {"scope": "inference:invoke", "exp": 5})
    header, claims, signature = token.split(".")
    assert decoded(header) == {"alg": "RS256", "typ": "JWT"}
    assert decoded(claims) == {"scope": "inference:invoke", "exp": 5}
    assert signature == "OPENSHELL-RESOLVE-ENV-" + issued[len("openshell:resolve:env:"):]
    assert signature.endswith(f"{handle}_NOUS_TOKEN")
    assert set(token) <= set(string.ascii_letters + string.digits + "-_.")
    assert token.startswith("eyJ")  # what Hermes takes for an OAuth token by its shape


@pytest.mark.parametrize("value", [
    "openshell:resolve:env:NOUS_TOKEN",  # a bare environment key: never issued for a workload
    "openshell:resolve:env:s" + "ab" * 31 + "_NOUS_TOKEN",  # a handle of another length
    "openshell:resolve:env:sXYZ_NOUS_TOKEN", "openshell:resolve:env:v_NOUS_TOKEN", "openshell:resolve:env:",
    "resolve:env:v1_NOUS_TOKEN", "sk-a-real-looking-key", "", None,
    "openshell:resolve:env:v1_NOUS TOKEN", "openshell:resolve:env:v1_NOUS_TOKEN\n",
])
def test_no_alias_of_anything_openshell_did_not_issue(value):
    with pytest.raises(ValueError):
        standin.alias(value, {})


# -- the template ------------------------------------------------------------------------------------------------

def test_the_template_keeps_the_shape_and_no_secret():
    template, credentials, _ = built()
    doc = template["files"]["auth.json"]
    nous = doc["providers"]["nous"]
    marker = nous["agent_key"]
    assert marker.startswith("@@alias:") and nous["access_token"] == marker  # one secret, one credential
    assert nous["refresh_token"] == "held-on-the-host"
    assert nous["expires_at"] == nous["agent_key_expires_at"] == "@@far:iso@@"
    assert nous["expires_in"] == nous["agent_key_expires_in"] == "@@far:seconds@@"
    assert (nous["client_id"], nous["token_type"], nous["scope"]) == ("hermes-cli", "Bearer", "inference:invoke")
    assert nous["portal_base_url"] == "https://portal.example.test"
    assert nous["obtained_at"] == "2025-01-01T00:00:00+00:00"
    assert nous["agent_key_id"] is None and nous["agent_key_reused"] is False
    assert nous["tls"] == {"insecure": False}  # a path on the host is not a known-safe string
    assert "added_later" not in nous  # a string under a key nobody vouched for
    codex = doc["providers"]["openai-codex"]
    assert set(codex["tokens"]) == {"access_token", "refresh_token"}  # the id token is left out
    assert codex["tokens"]["refresh_token"] == "held-on-the-host" and codex["auth_mode"] == "chatgpt"
    row = doc["credential_pool"]["nous"][0]
    assert row["access_token"] == row["agent_key"] == marker  # the pool row mirrors the sign-in: the same credential
    assert (row["id"], row["label"], row["source"], row["priority"]) == ("a1b2c3", "someone@example.test", "device_code", 0)
    assert (row["request_count"], row["last_error_code"]) == (4, 429)
    assert not {"last_status", "last_error_message", "secret_fingerprint"} & set(row)
    keys = doc["credential_pool"]["openrouter"]
    assert [r["id"] for r in keys] == ["0a0b0c"]  # the row that mirrors an environment variable is left out
    assert keys[0]["access_token"].startswith("@@placeholder:")  # a key row: its client does not parse the key
    assert doc["suppressed_sources"] == {"xai-oauth": ["device_code"]} and doc["active_provider"] == "nous"
    text = json.dumps([template, credentials])
    for secret in (ACCESS, CODEX, REFRESH, CODEX_REFRESH, MANUAL_KEY, ENV_KEY, "SIGNED-BY-THE-ISSUER", "own-ca.pem",
                   "a field of a later Hermes", "the provider said something", "f" * 40):
        assert secret not in text


def test_the_credentials_say_what_the_launcher_needs():
    _, credentials, _ = built()
    by_id = {c["id"]: c for c in credentials}
    assert sorted(by_id) == ["nous:agent_key", "openai-codex:access_token", "openrouter:0a0b0c:access_token"]
    nous = by_id["nous:agent_key"]
    assert (nous["provider"], nous["field"], nous["expires_at"]) == ("nous", "agent_key", 1_700_000_900.0)
    # Only what Hermes reads: no e-mail address, and the real expiry is not copied into the alias.
    assert nous["claims"] == {"scope": "inference:invoke", "sub": "user-1", "org_id": "org-1",
                              "tool_access": {"enabled": True, "coverage": {"web": True}}}
    codex = by_id["openai-codex:access_token"]
    assert codex["claims"] == {"sub": "user-1", "https://api.openai.com/auth": {"chatgpt_account_id": "acct-1"}}
    assert codex["expires_at"] == 1_700_003_600.0
    key = by_id["openrouter:0a0b0c:access_token"]
    assert (key["claims"], key["expires_at"], key["source"], key["auth_type"]) == ({}, None, "manual", "api_key")
    stores = {"auth.json": store()}
    assert [standin.credential_value(stores, by_id[i]) for i in sorted(by_id)] == [ACCESS, CODEX, MANUAL_KEY]
    assert standin.credential_value({"auth.json": {}}, nous) is None


def test_the_expiry_of_a_token_that_is_not_a_jwt_comes_from_its_row():
    doc = {"providers": {"minimax-oauth": {"access_token": "opaque-token-0123456789", "refresh_token": "RT-0123456789",
                                           "expires_at": "2025-01-01T01:00:00+00:00"}}}
    file = {"accessToken": "sk-ant-oat01-0123456789", "refreshToken": "RT-anthropic-0123", "expiresAt": 1_735_693_200_000}
    template, credentials = standin.build_template({"auth.json": doc, ".anthropic_oauth.json": file})
    by_id = {c["id"]: c for c in credentials}
    assert by_id["minimax-oauth:access_token"]["expires_at"] == 1_735_693_200.0
    assert by_id["anthropic:accessToken"]["expires_at"] == 1_735_693_200.0
    assert by_id["anthropic:accessToken"]["provider"] == "anthropic"
    assert template["files"][".anthropic_oauth.json"] == {
        "accessToken": f"@@alias:{template['credentials']['anthropic:accessToken']['marker']}@@",
        "refreshToken": "held-on-the-host", "expiresAt": "@@far:ms@@"}


def test_two_secrets_in_one_row_are_two_credentials():
    doc = {"providers": {"nous": {"access_token": ACCESS, "agent_key": "agent-key-of-its-own-0123",
                                  "agent_key_expires_at": "2025-01-01T00:30:00+00:00"}}}
    template, credentials = standin.build_template({"auth.json": doc})
    by_id = {c["id"]: c for c in credentials}
    assert sorted(by_id) == ["nous:access_token", "nous:agent_key"]
    assert by_id["nous:agent_key"]["expires_at"] == 1_735_691_400.0
    row = template["files"]["auth.json"]["providers"]["nous"]
    assert row["access_token"] != row["agent_key"]


def test_a_provider_can_be_left_without_its_refresh_grant():
    template, credentials = standin.build_template({"auth.json": store()}, without_grants=["nous"])
    doc = template["files"]["auth.json"]
    assert "refresh_token" not in doc["providers"]["nous"] and "refresh_token" not in doc["credential_pool"]["nous"][0]
    assert doc["providers"]["openai-codex"]["tokens"]["refresh_token"] == "held-on-the-host"
    assert [c["id"] for c in credentials] == [c["id"] for c in standin.build_template({"auth.json": store()})[1]]


def test_a_store_in_the_older_shape_keeps_that_shape():
    doc = {"systems": {"nous_portal": {"access_token": ACCESS, "refresh_token": REFRESH, "scope": "inference:invoke"}}}
    template, credentials = standin.build_template({"auth.json": doc})
    assert [c["id"] for c in credentials] == ["nous_portal:access_token"]
    assert template["files"]["auth.json"] == {"systems": {"nous_portal": {
        "access_token": "@@alias:1@@", "refresh_token": "held-on-the-host", "scope": "inference:invoke"}}}


def test_a_file_the_profile_does_not_have_is_to_be_absent_inside():
    template, credentials = standin.build_template({"auth.json": None, ".anthropic_oauth.json": None})
    assert template["files"] == {"auth.json": None, ".anthropic_oauth.json": None} and credentials == []
    assert standin.fill(template, {}) == ({"auth.json": None, ".anthropic_oauth.json": None}, {})


def test_only_sign_in_files_are_templated():
    with pytest.raises(ValueError, match="config.yaml"):
        standin.build_template({"config.yaml": {"model": {"api_key": "sk-in-a-config-0123456789"}}})
    with pytest.raises(ValueError, match="JSON object"):
        standin.build_template({"auth.json": ["not", "a", "store"]})


def test_a_known_safe_key_keeps_only_the_shape_it_is_known_for():
    row = {"access_token": ACCESS,
           "base_url": "https://user:" + MANUAL_KEY + "@api.example.test/v1",  # user information
           "inference_base_url": "https://api.example.test/v1?key=abcdef0123456789",  # a query
           "portal_base_url": "file:///etc/passwd", "obtained_at": "not a time at all",
           "last_refresh": "sk-shaped-like-a-key-0123", "token_type": "Bearer\nX-Injected: 1",
           "label": "the token is " + ACCESS, "scope": "@@alias:1@@", "source": "x" * 200, "region": "global"}
    template, _ = standin.build_template({"auth.json": {"providers": {"p": row}}})
    assert template["files"]["auth.json"]["providers"]["p"] == {"access_token": "@@alias:1@@", "region": "global"}
    # A copy of a token or of a refresh grant is caught under any known-safe key, whatever its shape.
    copies = {"access_token": "token-0123456789", "refresh_token": "grant-0123456789", "label": "token-0123456789",
              "source": "see grant-0123456789", "client_id": "token-0123456789", "scope": "a token-0123456789 b"}
    template, _ = standin.build_template({"auth.json": {"providers": {"p": copies}}})
    assert template["files"]["auth.json"]["providers"]["p"] == {"access_token": "@@alias:1@@", "refresh_token": "held-on-the-host"}


def test_the_known_safe_keys_are_these():
    """A change here is a decision: every key added must be argued in the module's table."""
    assert sorted(standin.SAFE_KEYS) == [
        "active_provider", "agent_key_obtained_at", "auth_method", "auth_mode", "auth_type", "base_url", "client_id",
        "id", "inference_base_url", "label", "last_refresh", "obtained_at", "portal_base_url", "provider", "region",
        "scope", "source", "token_type", "updated_at"]
    assert standin.SAFE_LISTS == {"suppressed_sources": "word"}
    assert standin.TOKEN_KEYS == ("agent_key", "access_token", "accessToken")
    assert standin.GRANT_KEYS == ("refresh_token", "refreshToken", "anon_token")
    table = standin.__doc__
    for key in standin.SAFE_KEYS:
        assert f"``{key}``" in table, key


def test_a_token_variable_gets_an_alias_exported():
    template, credentials = standin.build_template({}, {"ANTHROPIC_TOKEN": "anthropic"})
    assert credentials == [{"id": "env:ANTHROPIC_TOKEN", "provider": "anthropic", "field": "ANTHROPIC_TOKEN",
                            "claims": {}, "expires_at": None, "file": None, "path": []}]
    template["credentials"]["env:ANTHROPIC_TOKEN"]["env"] = "ANTHROPIC_TOKEN"
    issued = placeholder("ANTHROPIC_TOKEN")
    files, exports = standin.fill(template, {"ANTHROPIC_TOKEN": issued}, now=NOW)
    assert files == {} and list(exports) == ["ANTHROPIC_TOKEN"]
    assert exports["ANTHROPIC_TOKEN"].endswith("." + "OPENSHELL-RESOLVE-ENV-" + issued.split("env:")[1])
    assert decoded(exports["ANTHROPIC_TOKEN"].split(".")[1]) == {"iat": NOW, "exp": NOW + standin.FAR_SECONDS}
    names_only, _ = standin.build_template({}, ["CLAUDE_CODE_OAUTH_TOKEN"])
    assert names_only["credentials"]["env:CLAUDE_CODE_OAUTH_TOKEN"]["provider"] is None
    with pytest.raises(ValueError):
        standin.build_template({}, ["NOT A NAME"])


# -- filling it inside -------------------------------------------------------------------------------------------

def test_every_marker_becomes_the_alias_of_its_own_placeholder():
    template, _, environ = built()
    files, exports = standin.fill(template, environ, now=NOW)
    doc = files["auth.json"]
    nous = doc["providers"]["nous"]
    issued = environ[template["credentials"]["nous:agent_key"]["env"]]
    header, claims, signature = nous["agent_key"].split(".")
    assert signature == "OPENSHELL-RESOLVE-ENV-" + issued[len("openshell:resolve:env:"):]
    assert decoded(claims) == {"scope": "inference:invoke", "sub": "user-1", "org_id": "org-1",
                               "tool_access": {"enabled": True, "coverage": {"web": True}},
                               "iat": NOW, "exp": NOW + standin.FAR_SECONDS}
    assert nous["access_token"] == nous["agent_key"] == doc["credential_pool"]["nous"][0]["access_token"]
    assert nous["expires_in"] == standin.FAR_SECONDS and nous["agent_key_expires_in"] == standin.FAR_SECONDS
    assert nous["expires_at"] == "2037-01-12T08:00:00+00:00" == nous["agent_key_expires_at"]
    codex = doc["providers"]["openai-codex"]["tokens"]["access_token"]
    assert decoded(codex.split(".")[1])["https://api.openai.com/auth"] == {"chatgpt_account_id": "acct-1"}
    assert codex.split(".")[2].endswith(template["credentials"]["openai-codex:access_token"]["env"])
    # A key row gets the placeholder itself.
    assert doc["credential_pool"]["openrouter"][0]["access_token"] == environ[
        template["credentials"]["openrouter:0a0b0c:access_token"]["env"]]
    assert exports == {} and "@@" not in json.dumps(files)


def test_far_expiries_keep_the_type_the_store_had():
    doc = {"providers": {"p": {"access_token": "opaque-token-0123456789", "expires_at": 1_700_000_000,
                               "expires_at_ms": 1_700_000_000_000, "expires_in": 60, "expiresAt": None}}}
    template, _ = standin.build_template({"auth.json": doc})
    template["credentials"]["p:access_token"]["env"] = "P_TOKEN"
    files, _ = standin.fill(template, {"P_TOKEN": placeholder("P_TOKEN")}, now=NOW)
    row = files["auth.json"]["providers"]["p"]
    assert (row["expires_at"], row["expires_at_ms"], row["expires_in"], row["expiresAt"]) == (
        NOW + standin.FAR_SECONDS, (NOW + standin.FAR_SECONDS) * 1000, standin.FAR_SECONDS, None)


@pytest.mark.parametrize("damage,said", [
    (lambda t, e: e.pop(t["credentials"]["nous:agent_key"]["env"]), "sign-in for nous (nous:agent_key)"),
    (lambda t, e: e.update({t["credentials"]["nous:agent_key"]["env"]: ""}), "sign-in for nous"),
    (lambda t, e: e.update({t["credentials"]["openai-codex:access_token"]["env"]: "sk-a-real-looking-key"}),
     "sign-in for openai-codex (openai-codex:access_token)"),
    (lambda t, e: e.update({t["credentials"]["nous:agent_key"]["env"]: "openshell:resolve:env:" + t["credentials"]["nous:agent_key"]["env"]}),
     "does not hold a placeholder OpenShell issued for it"),
    (lambda t, e: e.update({t["credentials"]["nous:agent_key"]["env"]: placeholder("ANOTHER_VARIABLE")}),
     "does not hold a placeholder OpenShell issued for it"),
    (lambda t, e: t["credentials"]["nous:agent_key"].pop("env"), "named no environment variable"),
    (lambda t, e: t["credentials"]["nous:agent_key"].update(marker=99), "does not list"),
    (lambda t, e: t["credentials"]["nous:agent_key"].update(claims=None), "damaged at sign-in for nous"),
    (lambda t, e: t.update(version=2), "not one this version reads"),
    (lambda t, e: t["files"].update({"../outside.json": {}}), "not a sign-in file"),
    (lambda t, e: t["files"].update({"config.yaml": {}}), "not a sign-in file"),
    (lambda t, e: t.pop("credentials"), "incomplete"),
])
def test_a_store_is_never_half_filled(damage, said):
    template, _, environ = built()
    damage(template, environ)
    with pytest.raises(standin.StandinError) as refused:
        standin.fill(template, environ, now=NOW)
    assert said in str(refused.value)
    for value in filter(None, environ.values()):  # the message names the provider and the variable, never a value
        assert value not in str(refused.value)


def test_a_placeholder_is_matched_to_its_variable_whatever_the_case():
    template, _, environ = built()
    name = template["credentials"]["nous:agent_key"]["env"]
    environ[name] = placeholder(name.lower())
    assert standin.fill(template, environ, now=NOW)[0]["auth.json"]["providers"]["nous"]["agent_key"].endswith(name.lower())


def test_a_credential_that_is_not_handed_in_takes_its_rows_out():
    template, _, _ = built(["ANTHROPIC_TOKEN"])
    file_template, _ = standin.build_template({".anthropic_oauth.json": {"accessToken": "sk-ant-oat01-0123456789"}})
    pruned = standin.without(template, ["nous:agent_key", "openrouter:0a0b0c:access_token", "env:ANTHROPIC_TOKEN"])
    doc = pruned["files"]["auth.json"]
    assert list(doc["providers"]) == ["openai-codex"]
    assert doc["credential_pool"] == {"nous": [], "openrouter": []}
    assert sorted(pruned["credentials"]) == ["openai-codex:access_token"] and pruned["env"] == {}
    assert "nous" in template["files"]["auth.json"]["providers"]  # the template given is not changed
    assert standin.without(file_template, ["anthropic:accessToken"])["files"] == {".anthropic_oauth.json": None}
    assert standin.without(template, ["no-such-credential"]) == template
    pruned["credentials"]["openai-codex:access_token"]["env"] = "CODEX"
    files, _ = standin.fill(pruned, {"CODEX": placeholder("CODEX")}, now=NOW)
    assert "@@" not in json.dumps(files)


# -- properties over stores of any shape -------------------------------------------------------------------------

class Maker:
    """Stores of random shape that hold secrets in every kind of place a store could hold one."""

    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.secrets: list[str] = []
        self.held: list[str] = []  # the ones under a token or grant key

    def secret(self, low: int = 9, high: int = 300) -> str:
        alphabet = string.ascii_letters + string.digits + "-_.~+/="
        text = "".join(self.rng.choice(alphabet) for _ in range(self.rng.randint(low, high)))
        text = self.rng.choice(["", "sk-", "eyJ", "RT-"]) + text + f"#{len(self.secrets)}"
        self.secrets.append(text)
        return text

    def value(self, depth: int):
        roll = self.rng.random()
        if roll < 0.35:
            return self.secret()
        if roll < 0.5:
            return self.rng.choice([None, True, False, 0, 17, -3, 2.5, 1_700_000_000, 1_700_000_000_000])
        if roll < 0.6 and depth < 4:
            return [self.value(depth + 1) for _ in range(self.rng.randint(0, 3))]
        if depth < 4:
            return self.row(depth + 1)
        return self.secret()

    def row(self, depth: int) -> dict:
        out: dict = {}
        for _ in range(self.rng.randint(1, 7)):
            roll = self.rng.random()
            if roll < 0.3:
                key = self.rng.choice(standin.TOKEN_KEYS if roll < 0.2 else standin.GRANT_KEYS)
                out[key] = self.secret()
                self.held.append(out[key])
            elif roll < 0.45:  # a known-safe key holding something of the wrong shape, or a copy of a token
                key = self.rng.choice(sorted(standin.SAFE_KEYS))
                shapes = [lambda: self.secret(130, 300), lambda: "\n" + self.secret(), lambda: "@@alias:1@@",
                          lambda: "seen: " + self.held[-1] if self.held else self.secret(130, 300)]
                if standin.SAFE_KEYS[key] != "text":  # free text is free: only its length and a copy are caught
                    shapes += [lambda: "https://user:" + self.secret(9, 40) + "@host.example.test/v1",
                               lambda: "https://host.example.test/v1?token=" + self.secret(9, 40)]
                out[key] = self.rng.choice(shapes)()
            elif roll < 0.55:
                out[self.rng.choice(standin.EXPIRY_KEYS)] = self.rng.choice([self.secret(), 1_700_000_000, "2025-01-01T00:00:00+00:00"])
            elif roll < 0.65:  # a secret as a dictionary key
                out[self.secret(standin.KEY_BOUND + 1, 200)] = self.value(depth)
            elif roll < 0.72:
                out["a key with spaces " + self.secret(9, 20)] = self.value(depth)
            else:
                out[self.rng.choice(["tokens", "extra", "tls", "session", "cookie", "api_key", "password", "id_token",
                                     "nested", "model_cooldowns", "discovery"])] = self.value(depth)
        return out

    def store(self) -> dict:
        return {"version": 1, "providers": {f"provider-{n}": self.row(0) for n in range(self.rng.randint(0, 3))},
                "credential_pool": {f"provider-{n}": [self.row(1) for _ in range(self.rng.randint(0, 3))]
                                    for n in range(self.rng.randint(0, 3))},
                "active_provider": self.secret(), self.rng.choice(["later", "systems"]): self.value(0)}


def strings_of(node, key="", top="", depth=0):
    """Every string of a document with the key it is under: ``(kind, key, top-level key, text)``."""
    if isinstance(node, dict):
        for name, value in node.items():
            yield "key", key, top, name
            yield from strings_of(value, name, top if depth else name, depth + 1)
    elif isinstance(node, list):
        for value in node:
            yield from strings_of(value, "" if isinstance(value, str) else key, top, depth + 1)
    elif isinstance(node, str):
        yield "value", key, top, node


@pytest.mark.parametrize("seed", range(60))
def test_no_secret_and_no_long_string_survives_in_a_template(seed):
    maker = Maker(seed)
    stores = {"auth.json": maker.store(), ".anthropic_oauth.json": maker.row(0)}
    template, credentials = standin.build_template(stores, ["SOME_TOKEN"])
    text = json.dumps([template, credentials])
    leaked = [n for n, secret in enumerate(maker.secrets) if secret in text]
    assert not leaked, [maker.secrets[n][:12] for n in leaked]
    for name, doc in template["files"].items():
        for kind, key, top, found in strings_of(doc):
            if kind == "key":
                assert len(found) <= standin.KEY_BOUND and " " not in found
            elif key not in standin.SAFE_KEYS and not (key == "" and top in standin.SAFE_LISTS):
                assert len(found) <= standin.VALUE_BOUND, (name, key, found)
                assert found == "held-on-the-host" or found.startswith("@@") or found == "", (name, key, found)
    assert standin.build_template(stores, ["SOME_TOKEN"]) == (template, credentials)  # the same stores, the same result
    for number, entry in enumerate(template["credentials"].values()):
        entry["env"] = f"CRED_{number}"
    environ = {entry["env"]: placeholder(entry["env"]) for entry in template["credentials"].values()}
    files, exports = standin.fill(template, environ, now=NOW)
    filled = json.dumps([files, exports])
    assert "@@" not in filled and not [s for s in maker.secrets if s in filled]
    # Every credential listed can be read back from the stores it came from.
    for credential in credentials:
        if credential["file"]:
            assert standin.credential_value(stores, credential) in maker.secrets


def test_the_module_imports_the_standard_library_only():
    def nodes(node):
        yield node
        for child in ast.iter_child_nodes(node):
            yield from nodes(child)

    imported = set()
    for node in nodes(ast.parse(Path(standin.__file__).read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            imported |= {name.name.split(".")[0] for name in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "a relative import would pull in the plugin's other modules"
            imported.add((node.module or "").split(".")[0])
    assert imported <= set(sys.stdlib_module_names), imported - set(sys.stdlib_module_names)
    package = Path(standin.__file__).with_name("__init__.py").read_text(encoding="utf-8")
    assert not [n for n in nodes(ast.parse(package)) if isinstance(n, (ast.Import, ast.ImportFrom))]
