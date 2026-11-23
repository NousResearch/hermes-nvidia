"""The sign-in engine: which providers of a profile work in the sandbox, and what each sign-in hands to the
driver's credential sink. Hermes's own code answers every question, over the launcher's host-only copy, against
loopback issuers (signin_issuers.py).
"""
import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import signin_home  # noqa: E402
from signin_home import files_under, world  # noqa: E402,F401
from signin_issuers import claims_of  # noqa: E402

from openshell.launcher import signins  # noqa: E402

CARRIED = ["nous", "openai-codex", "xai-oauth", "minimax-oauth", "anthropic"]
IDS = {"nous": "nous:agent_key", "openai-codex": "openai-codex:access_token", "xai-oauth": "xai-oauth:access_token",
       "minimax-oauth": "minimax-oauth:access_token", "anthropic": "anthropic:oauth_token"}
MODEL_HOST = {"nous": "inference-api.nousresearch.com", "openai-codex": "chatgpt.com", "xai-oauth": "api.x.ai",
              "minimax-oauth": "api.minimax.io", "anthropic": "api.anthropic.com"}


def signed_in(world, provider, about_to_expire=False):
    """The profile signed in to *provider* and switched on. *about_to_expire*: its stored token has a minute
    left, which is inside the two minutes Hermes's own resolver renews ahead of."""
    world.config({"model": {"provider": provider, "default": "a-model"}})
    world.sign_in(provider)
    if about_to_expire:
        world.short_token(provider)
    world.take_copy()


def rows_by_provider(rows):
    return {row["provider"]: row for row in rows}


# -- the report before the switch ---------------------------------------------------------------------

def test_the_report_has_one_row_per_provider_the_profile_uses(world):
    """Main model on a sign-in, a fallback on another sign-in, an auxiliary task on a sign-in that is missing,
    and routes to providers the sandbox cannot carry and to one that uses a key."""
    world.config({"model": {"provider": "nous", "default": "a-model"},
                  "fallback_providers": [{"provider": name, "model": "another-model"} for name in
                                         ("openai-codex", "qwen-oauth", "bedrock", "deepseek", "vertex")],
                  "auxiliary": {"vision": {"provider": "xai-oauth", "model": "g"},
                                "compression": {"provider": "no-such-provider", "model": "h"}}})
    world.sign_in("nous")
    world.sign_in("openai-codex")
    before = files_under(world.root)
    rows = rows_by_provider(signins.report(world.home))
    assert files_under(world.root) == before, "the report wrote something"
    assert world.issuers.refreshes("nous") == [] and world.issuers.refreshes("openai-codex") == []

    assert rows["nous"]["state"] == "works" and rows["nous"]["used_by"] == ["model"]
    assert rows["nous"]["sentence"] == "Signed in. Kept signed in on this computer; the sandbox holds a placeholder."
    assert rows["openai-codex"]["state"] == "works" and rows["openai-codex"]["used_by"] == ["fallback 1"]
    assert rows["xai-oauth"]["state"] == "needs_sign_in" and rows["xai-oauth"]["used_by"] == ["auxiliary vision"]
    assert rows["xai-oauth"]["sentence"].startswith("Not signed in. Sign in to xAI")
    assert rows["qwen-oauth"]["state"] == "not_available"
    assert rows["qwen-oauth"]["sentence"] == ("Not available in the sandbox: Qwen OAuth keeps its sign-in in a file "
                                              "outside this profile.")
    for cloud in ("bedrock", "vertex"):
        assert rows[cloud]["state"] == "not_available" and "signs in through a cloud SDK" in rows[cloud]["sentence"]
    assert rows["deepseek"]["state"] == "key" and rows["deepseek"]["sentence"] == ""
    unknown = rows["no-such-provider"]
    assert unknown["state"] == "not_available" and "does not know" in unknown["sentence"]
    assert set(rows) == {"nous", "openai-codex", "xai-oauth", "qwen-oauth", "bedrock", "vertex", "deepseek",
                         "no-such-provider"}


def test_a_sign_in_no_route_uses_is_listed_too(world):
    """Switching models inside the sandbox works for every sign-in the profile has."""
    world.config({"model": {"provider": "nous", "default": "a-model"}})
    world.sign_in("nous")
    world.sign_in("minimax-oauth")
    rows = rows_by_provider(signins.report(world.home))
    assert rows["minimax-oauth"]["state"] == "works" and rows["minimax-oauth"]["used_by"] == []


def test_the_report_names_a_program_with_its_own_sign_in(world, monkeypatch):
    from hermes_cli import auth

    row = auth.ProviderConfig("pair-program", "Pair Program", "external_process")
    monkeypatch.setattr(auth, "_registry_lookup", lambda name, _real=auth._registry_lookup:
                        row if name == "pair-program" else _real(name))
    world.config({"model": {"provider": "pair-program", "default": "a-model"}})
    rows = rows_by_provider(signins.report(world.home))
    assert rows["pair-program"]["state"] == "not_available"
    assert rows["pair-program"]["sentence"] == ("Not available in the sandbox: Pair Program signs in through its "
                                                "own program.")


def test_anthropic_through_claude_code_is_not_available_and_its_file_is_not_read(world, monkeypatch):
    world.config({"model": {"provider": "anthropic", "default": "a-model"}})
    kept = world.user / "claude" / ".credentials.json"
    kept.parent.mkdir(parents=True)
    kept.write_text("not json: a reader would fail on it", encoding="utf-8")
    rows = rows_by_provider(signins.report(world.home))
    assert rows["anthropic"]["state"] == "not_available"
    assert "signed in through Claude Code" in rows["anthropic"]["sentence"]
    # With a key in the env file the provider is the key discovery's.
    (world.home / ".env").write_text("ANTHROPIC_API_KEY=made-up-key\n", encoding="utf-8")
    assert rows_by_provider(signins.report(world.home))["anthropic"]["state"] == "key"


def test_a_sign_in_whose_grant_is_gone_reads_as_expired(world):
    signed_in(world, "nous")
    world.issuers.fail("nous", "invalid_grant")
    with pytest.raises(Exception):
        world.renew_in_home("nous")
    row = rows_by_provider(signins.report(world.home))["nous"]
    assert (row["state"], row["sentence"]) == ("needs_sign_in", "Sign-in expired. Sign in again.")
    assert row["action"] == "Turn the sandbox off, sign in to Nous Portal, then turn it on again."


# -- declaring ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("provider", CARRIED)
def test_declare_hands_the_current_token_to_the_sink(world, provider):
    signed_in(world, provider)
    home_before = files_under(world.home)
    engine = world.engine()
    declared = engine.declare()
    assert [d.id for d in declared] == [IDS[provider]]
    one = declared[0]
    held = world.sink.declared[one.id]
    value, expires_at = world.sink.values[one.id]
    assert world.issuers.valid(provider, value), "the sink holds a token the issuer does not accept"
    assert held["decl"].expires is True and held["decl"].placement == "bearer"
    assert expires_at == pytest.approx(world.clock() + world.issuers.ttl[provider], abs=5)
    assert one.env == "SANDBOX_" + one.id.replace(":", "_").replace("-", "_").upper() and one.expires_at == expires_at
    assert MODEL_HOST[provider] in [e.host for e in held["decl"].endpoints]
    assert all(e.port == 443 and e.path_prefix is None for e in held["decl"].endpoints)
    assert files_under(world.home) == home_before, "declaring wrote into the profile's home"
    assert world.issuers.refreshes(provider) == [], "a fresh token was renewed"
    assert [row["state"] for row in engine.status()] == ["works"]


def test_nous_travels_to_the_inference_host_only_at_switch_on(world):
    """The model's host and no other: not the Portal, and no host of the tool gateway (a tool category's host
    is bound once the user approved the category, test_tool_categories.py)."""
    signed_in(world, "nous")
    hosts = [e.host for e in world.engine().declare()[0].endpoints]
    assert hosts == ["inference-api.nousresearch.com"]


def test_the_category_table_names_every_vendor_hermes_asks_for():
    """The tool gateway's vendors are spread over Hermes's sources; each is a category's, or is listed here as
    one that stays closed because no tool of a category asks for it."""
    import re
    from pathlib import Path

    from openshell.launcher import categories

    try:
        import tools.managed_tool_gateway as gateway
    except ImportError:
        pytest.skip("no Hermes checkout is importable")
    core = Path(gateway.__file__).resolve().parent.parent
    asked = set()
    pattern = re.compile(r"(?:resolve_managed_tool_gateway|is_managed_tool_gateway_ready|build_vendor_gateway_url|"
                         r"_vendor_gateway)\(\s*\"([a-z0-9-]+)\"")
    for folder in ("tools", "agent", "hermes_cli", "plugins"):
        for path in (core / folder).rglob("*.py"):
            if "tests" not in path.parts:
                asked.update(pattern.findall(path.read_text(encoding="utf-8", errors="replace")))
    assert asked, "no gateway vendor found in this Hermes"
    in_table = {vendor for category in categories.CATEGORIES for vendor in category.gateways}
    closed = {"tool"}  # only trusted as an origin for a request another service names; no tool asks for it
    assert asked <= in_table | closed, f"in no category: {sorted(asked - in_table - closed)}"
    assert not in_table & closed


def test_an_operator_address_in_the_copy_is_the_one_declared(world):
    """The copy's env file is the secret scope of every call: an inference address set there is honoured."""
    world.config({"model": {"provider": "nous", "default": "a-model"}})
    world.sign_in("nous")
    (world.home / ".env").write_text("NOUS_INFERENCE_BASE_URL=https://inference.example.test/v1\n", encoding="utf-8")
    world.take_copy()
    hosts = [e.host for e in world.engine().declare()[0].endpoints]
    assert hosts[0] == "inference.example.test"


@pytest.mark.parametrize("provider", ["nous", "openai-codex", "xai-oauth"])
def test_only_the_claims_hermes_reads_are_passed_on(world, provider):
    signed_in(world, provider)
    one = world.engine().declare()[0]
    real = claims_of(world.sink.values[one.id][0])
    assert "email" in real and "email" not in one.claims and "jti" not in one.claims
    assert one.claims["exp"] == real["exp"]
    if provider == "nous":
        assert one.claims["scope"] == "inference:invoke" and one.claims["tool_access"] == {"web": True}
    if provider == "openai-codex":
        assert one.claims["https://api.openai.com/auth"] == {"chatgpt_account_id": "account-1"}


def test_a_token_about_to_expire_is_renewed_at_declare_and_the_copy_holds_the_new_grant(world):
    signed_in(world, "nous", about_to_expire=True)
    first = signin_home.refresh_token_in(world.copy, "nous")
    changed = []
    world.engine(on_change=changed.append).declare()
    assert [c["answer"] for c in world.issuers.refreshes("nous")] == ["rotated", "rotated"]  # the setup's, then this one
    assert signin_home.refresh_token_in(world.copy, "nous") == world.issuers.current_refresh_token("nous") != first
    assert signin_home.refresh_token_in(world.home, "nous") == first, "the profile's home was written"
    assert changed == [["auth.json"]]
    assert world.issuers.valid("nous", world.sink.values["nous:agent_key"][0])


def test_a_gone_grant_is_reported_and_never_declared(world):
    signed_in(world, "openai-codex", about_to_expire=True)
    world.issuers.fail("openai-codex", "invalid_grant")
    engine = world.engine()
    assert engine.declare() == [] and world.sink.declared == {}
    row = engine.status()[0]
    assert (row["provider"], row["state"]) == ("openai-codex", "needs_sign_in")
    assert row["sentence"] == "Sign-in expired. Sign in again."


def test_an_issuer_that_does_not_answer_at_declare_leaves_the_stored_token_declared(world):
    signed_in(world, "nous", about_to_expire=True)
    world.issuers.fail("nous", "server_error")
    engine = world.engine()
    declared = engine.declare()
    assert [d.id for d in declared] == ["nous:agent_key"]
    assert world.issuers.valid("nous", world.sink.values["nous:agent_key"][0])
    assert engine.status()[0]["state"] == "retrying"


def test_every_sign_in_of_the_profile_is_declared_once(world):
    world.config({"model": {"provider": "anthropic", "default": "a-model"}})
    for provider in CARRIED:
        world.sign_in(provider)
    world.take_copy()
    declared = world.engine().declare()
    assert sorted(d.id for d in declared) == sorted(IDS.values())
    assert len({d.env for d in declared}) == len(CARRIED)


def test_a_renewal_never_runs_bound_to_a_profile_home(world):
    signed_in(world, "nous")
    for folder in (world.home, world.root):
        with pytest.raises(signins.NotACopy):
            signins.SignIns(folder, world.sink).declare()
    assert world.sink.declared == {}


def test_the_copy_config_holds_the_routes_and_keeps_other_programs_sign_ins_out(world):
    import hermes_yaml

    world.config({"model": {"provider": "openai-codex", "default": "a-model"}, "terminal": {"backend": "local"},
                  "secrets": {"op": {"enabled": True}}, "auth": {"adopt_external_logins": True},
                  "auxiliary": {"vision": {"provider": "nous"}}})
    signins.write_copy_config(world.home, world.copy)
    doc = hermes_yaml.safe_load((world.copy / "config.yaml").read_text(encoding="utf-8"))
    assert doc == {"model": {"provider": "openai-codex", "default": "a-model"},
                   "auxiliary": {"vision": {"provider": "nous"}}, "auth": {"adopt_external_logins": False}}


def test_a_codex_cli_sign_in_is_not_taken_over_while_the_copy_is_bound(world):
    """Hermes on the host adopts the Codex CLI's sign-in when its own is refused. Bound to the copy it must not:
    that file is another program's, outside the profile."""
    signed_in(world, "openai-codex", about_to_expire=True)
    cli = world.user / "codex" / "auth.json"
    cli.parent.mkdir(parents=True)
    cli.write_text('{"tokens": {"access_token": "another-programs-token", "refresh_token": "another-programs-grant"}}',
                   encoding="utf-8")
    world.issuers.fail("openai-codex", "invalid_grant")
    engine = world.engine()
    assert engine.declare() == []
    assert "another-programs" not in (world.copy / "auth.json").read_text(encoding="utf-8")


def test_hermes_own_anthropic_sign_in_stays_out_beside_a_key(world):
    """With a key or a token for Anthropic in the env file Hermes does not use its sign-in: the key goes into
    the sandbox as a key, and the sign-in is neither declared nor renewed."""
    world.config({"model": {"provider": "anthropic", "default": "a-model"}})
    world.sign_in("anthropic")
    (world.home / ".env").write_text("ANTHROPIC_API_KEY=made-up-key\n", encoding="utf-8")
    world.take_copy()
    assert rows_by_provider(signins.report(world.home))["anthropic"]["state"] == "key"
    engine = world.engine()
    assert engine.declare() == [] and engine.status() == []


def test_tokens_are_in_the_sign_in_files_and_nowhere_else(world, monkeypatch):
    """After a switch-on, a renewal of every sign-in and a refused one: no token is in a log line, and in the
    launcher's copy tokens are in the sign-in files only, so those are the files to give back."""
    import logging

    lines = []

    class Keep(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    root_logger = logging.getLogger()
    keep = Keep(level=logging.DEBUG)
    root_logger.addHandler(keep)
    monkeypatch.setattr(root_logger, "level", logging.DEBUG)
    world.config({"model": {"provider": "anthropic", "default": "a-model"}})
    for provider in CARRIED:
        world.sign_in(provider)
    world.take_copy()
    engine = world.engine()
    engine.declare()
    for _ in range(2):
        world.clock.advance(max(0.0, max(row["renew_at"] for row in engine.status()) - world.clock()))
        engine.step()
    world.issuers.fail("openai-codex", "invalid_grant")
    world.issuers.fail("nous", "server_error")
    world.clock.advance(3600)
    engine.step()
    assert {row["state"] for row in engine.status()} >= {"needs_sign_in"}
    tokens = [token for token in world.issuers.issued if token]
    assert len(tokens) > 20
    root_logger.removeHandler(keep)
    assert any("sign-in" in line for line in lines), "nothing was logged at all"
    said = "\n".join(lines) + "".join(engine.notes()) + repr(engine.status())
    assert not [token for token in tokens if token in said], "a token was written to a log line or a status row"
    holding = set()
    for path in world.copy.rglob("*"):
        if path.is_file():
            text = path.read_bytes().decode("utf-8", "replace")
            if any(token in text for token in tokens):
                holding.add(path.relative_to(world.copy).as_posix())
    assert holding == set(signins.SIGN_IN_FILES)


def test_the_engine_works_while_the_profile_is_marked_as_run_elsewhere(world):
    """While the sandbox is on the profile is marked, and Hermes on this computer loads no env file from its
    home. The copy is another folder: its env file is read, its sign-in is renewed, the home is not touched."""
    elsewhere = pytest.importorskip("hermes_cli.profiles_run_elsewhere")
    world.config({"model": {"provider": "nous", "default": "a-model"}})
    world.sign_in("nous")
    (world.home / ".env").write_text("NOUS_INFERENCE_BASE_URL=https://inference.example.test/v1\n", encoding="utf-8")
    world.take_copy()
    elsewhere.mark_profile_run_elsewhere("work", "openshell", root=world.root)
    assert elsewhere.run_elsewhere("work", root=world.root) is not None
    home_before = files_under(world.home)
    engine = world.engine()
    declared = engine.declare()
    assert declared[0].endpoints[0].host == "inference.example.test"
    world.clock.advance(engine.status()[0]["renew_at"] - world.clock())
    engine.step()
    assert [call["answer"] for call in world.issuers.refreshes("nous")] == ["rotated"]
    assert len(world.sink.updates) == 1 and world.issuers.valid("nous", world.sink.values["nous:agent_key"][0])
    assert files_under(world.home) == home_before


def test_a_test_folder_inside_the_computers_own_hermes_folder_is_refused(tmp_path, monkeypatch):
    """The tests' Hermes root must be the throwaway one. Below the computer's own Hermes folder Hermes would take
    that folder as the root, and a test would renew its sign-ins against the issuers of the test."""
    if not signin_home.hermes_importable():
        pytest.skip("no Hermes checkout is importable")
    import hermes_constants

    monkeypatch.setattr(hermes_constants, "_get_platform_default_hermes_home", lambda: tmp_path)
    with pytest.raises(RuntimeError, match="refusing to run"):
        signin_home.World(tmp_path, monkeypatch)
