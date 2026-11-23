"""A sign-in that has ended does not keep the sandbox from starting.

OpenShell's gateway hands a sandbox no credential whose value has run out: the sandbox starts without that
variable, and asked what the sandbox did with it the gateway answers that it was withheld because it expired. A
launcher that still declared such a sign-in then failed every start: the start-up step names a credential in the
stand-in sign-in store that holds no placeholder and ends, and the question after the start fails it too. A sign-in
ends that way whenever its provider refuses a renewal and its last token passes its expiry, so the next restart
(a folder or a tool approval, or its removal) took the whole sandbox down, the models on other sign-ins included.

Here: a sign-in that has ended, one this computer is no longer signed in to, and one whose token ran out with
nothing newer at hand are left out of the sandbox that starts. It starts, the other sign-ins work, the stand-in
store has no row for the one left out (Hermes inside reads as not signed in to it) and its row keeps its sentence.
One that is renewed later is handed over at the next start, which the page asks for. A credential the launcher did
declare and the gateway withholds still fails the start with the reason.

``Gateway`` is OpenShell as the launcher meets it in this case. Issuers, clock and tokens are the tests' own.
"""
import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import signin_home  # noqa: E402,F401
import test_credential_placement as CP  # noqa: E402
import test_openshell_driver as LD  # noqa: E402
from signin_home import world  # noqa: E402,F401

from openshell.inside import standin  # noqa: E402
from openshell.launcher import categories  # noqa: E402
from openshell.launcher import layout as L  # noqa: E402
from openshell.launcher import openshell_driver as OD  # noqa: E402
from openshell.launcher import pins as P  # noqa: E402
from openshell.launcher import signins, standins  # noqa: E402
from openshell.launcher import supervisor as S  # noqa: E402
from openshell.launcher.driver import DriverUnavailable  # noqa: E402

MAIN, OTHER = "nous", "openai-codex"
LABELS = {"nous": "Nous Portal", "openai-codex": "OpenAI Codex"}
EXPIRED = "Sign-in expired. Turn the sandbox off, sign in to {label}, then turn it on."
LAPSED = "The {label} sign-in wasn't renewed in time. The model answers again once it is."
TOOLS = next(category.id for category in categories.CATEGORIES if categories.gateway_endpoints(category))


class Gateway(LD.FakeApi):
    """OpenShell's gateway and sandbox as the launcher meets them when a credential's value has run out.

    The gateway leaves such a value out of what it hands the sandbox, so the sandbox starts without that
    variable. Its command then runs: the start-up step, which ends at once when a variable its template names
    holds no placeholder, and the sandbox is in its error phase. Asked what the sandbox did with that provider,
    the gateway answers that the credential was withheld because it expired."""

    def __init__(self, clock):
        super().__init__()
        self.clock, self.handed, self.skipped, self.step_errors = clock, {}, {}, []
        self.before_create = None

    def create_sandbox(self, name, spec, labels):
        if self.before_create is not None:
            self.before_create()
        super().create_sandbox(name, spec, labels)
        environment, skipped = {}, []
        for provider in spec["providers"]:
            row = self.providers[provider]
            for variable in row["credentials"]:
                expires = (row.get("expires") or {}).get(variable)
                if expires is not None and expires <= self.clock():
                    skipped.append(provider)
                else:
                    environment[variable] = "openshell:resolve:env:s" + "0" * 64 + "_" + variable
        self.handed[name], self.skipped[name] = environment, skipped
        template = spec["environment"].get(standin.TEMPLATE_ENV)
        if template:
            try:
                standin.fill(json.loads(Path(template).read_text(encoding="utf-8")), environment)
            except standin.StandinError as exc:
                self.step_errors.append(str(exc))
                self.sandboxes[name]["phase"] = "ERROR"

    def wait_ready(self, name, timeout):
        if self.sandboxes[name]["phase"] == "ERROR":
            raise RuntimeError(f"sandbox {name} entered error phase")

    def provider_state(self, sandbox, provider):
        if provider in self.skipped.get(sandbox, ()):
            return ("WITHHELD", "CREDENTIAL_EXPIRED")
        return ("READY", "UNSPECIFIED")


def signed_in(world, *providers):
    world.config({"model": {"provider": providers[0], "default": "a-model"}})
    for provider in providers:
        world.sign_in(provider)


def launcher(world, tmp_path, monkeypatch):
    """A supervisor for the world's profile over ``Gateway``, with the real sign-in engine on the world's clock.
    The test makes the engine's passes itself."""
    from openshell.launcher.spec import load_spec, save_spec

    layout = L.ProfileLayout(name="work", home=world.home, root=world.root)
    spec = load_spec(layout)
    spec.update(driver="openshell", folders=LD._folders(tmp_path), network={"egress": "deny", "allow": []})
    save_spec(layout, spec)
    P.take(layout)
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {})
    api, rec = Gateway(world.clock), LD.Recorder()
    driver = OD.OpenShellDriver(LD._cfg(tmp_path), api=api, run=rec.run, popen=rec.popen)
    driver.turns_idle = lambda: True  # no chat turn runs: a value is replaced when its renewal is due
    sup = S.Supervisor(layout, LD._runtime(tmp_path), load_spec(layout), driver, outer_port=1)
    sup.signins = signins.SignIns(P.pin_dir(layout), driver, clock=world.clock, sleep=world.clock.sleep,
                                  on_change=lambda names: P.follow_copy(layout), approved=sup.approved_tools)
    monkeypatch.setattr(sup, "_keep_sign_ins_current", lambda: None)
    return sup, api, layout


def row_of(engine, provider):
    return next(row for row in engine.status() if row["provider"] == provider)


def passes_until(world, engine, moment):
    """The launcher's loop until *moment* on the clock: a pass, then a wait of what the pass answered."""
    while world.clock() < moment:
        world.clock.advance(engine.step())


def refused(world, engine, provider):
    """The issuer refuses the next renewal of *provider*: the sign-in has ended. Returns when its last token ends."""
    world.issuers.fail(provider, "invalid_grant")
    end = row_of(engine, provider)["expires_at"]
    while row_of(engine, provider)["reason"] != "expired":
        assert world.clock() < end, "the renewal was never tried"
        world.clock.advance(engine.step())
    return end


def started_with(api):
    """What the sandbox that was created last got: the providers by sign-in, and the variables."""
    (_, name, spec) = [call for call in api.calls if call[0] == "create"][-1]
    return {p for p in (MAIN, OTHER) for n in spec["providers"] if p in n}, sorted(api.handed[name])


def page(sup):
    sup._publish_sign_ins()
    return {row["id"]: (row["state"], row["detail"]) for row in sup.provider_rows()}


def template_of(layout):
    path = layout.state_dir / "standin" / "template.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def in_stand_in(layout):
    template = template_of(layout)
    return sorted({entry["provider"] for entry in (template or {}).get("credentials", {}).values()})


# -- a restart after a sign-in ended ------------------------------------------------------------------------------

@pytest.mark.parametrize("ended", [(OTHER,), (MAIN,), (MAIN, OTHER)], ids=["another", "the-models", "both"])
def test_a_restart_goes_on_without_a_sign_in_that_ended(world, tmp_path, monkeypatch, ended):
    signed_in(world, MAIN, OTHER)
    sup, api, layout = launcher(world, tmp_path, monkeypatch)
    kept = [p for p in (MAIN, OTHER) if p not in ended]

    async def scenario():
        await sup.start()
        try:
            assert started_with(api)[0] == {MAIN, OTHER} and in_stand_in(layout) == sorted([MAIN, OTHER])
            last = max(refused(world, sup.signins, provider) for provider in ended)
            passes_until(world, sup.signins, last + 1)  # the last token of each has run out; the others are kept current
            await sup.restart()  # what a folder or a tool approval, or its removal, does
            assert sup.state == "running" and api.step_errors == []
            providers, variables = started_with(api)
            assert providers == set(kept) and len(variables) == len(kept)
            assert in_stand_in(layout) == sorted(kept)  # no row inside for the one that ended
            assert sup._standin.names == (("auth.json",) if kept else ())
            rows = page(sup)
            for provider in ended:
                assert rows[f"sign_in:{provider}"] == ("expired", EXPIRED.format(label=LABELS[provider]))
                assert not [name for name in api.providers if provider in name]  # its last token left the gateway
            for provider in kept:
                assert rows[f"sign_in:{provider}"][0] == "ready"
            bound = {host for host, _port in sup.bound_hosts()}
            assert ("chatgpt.com" in bound) == (OTHER in kept)
            assert ("inference-api.nousresearch.com" in bound) == (MAIN in kept)
            assert bool(sup.tool_services(TOOLS)["bound"]) == (MAIN in kept)  # the tool gateway's hosts
            await sup.restart()  # and again: nothing about it changes
            assert sup.state == "running" and started_with(api)[0] == set(kept)
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_token_that_ran_out_inside_a_wait_is_left_out_and_is_back_after_the_restart_the_page_asks_for(
        world, tmp_path, monkeypatch):
    signed_in(world, MAIN, OTHER)
    sup, api, layout = launcher(world, tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        try:
            engine = sup.signins
            passes_until(world, engine, row_of(engine, OTHER)["renew_at"])
            world.issuers.ttl[OTHER] = 0  # the issuer answers with tokens that are over when they arrive
            engine.step()
            world.clock.advance(5)
            assert row_of(engine, OTHER)["state"] == "lapsed" and row_of(engine, OTHER)["renew_at"] > world.clock()
            await sup.restart()
            assert sup.state == "running" and started_with(api)[0] == {MAIN} and in_stand_in(layout) == [MAIN]
            assert page(sup)[f"sign_in:{OTHER}"] == ("expired", LAPSED.format(label=LABELS[OTHER]))
            assert sup.status()["restart_required"] is False
            # The issuer is well again. The engine renews on its schedule; the sandbox that runs has no
            # placeholder for the new token, so nothing is offered to it and the page asks for the restart.
            world.issuers.ttl[OTHER] = 3600
            updates = len([call for call in api.calls if call[0] == "provider update"])
            asked = len(world.issuers.refreshes(OTHER))
            passes_until(world, engine, row_of(engine, OTHER)["renew_at"])
            engine.step()
            assert len(world.issuers.refreshes(OTHER)) == asked + 1
            row = row_of(engine, OTHER)
            assert (row["state"], row["usable"], row["failures"], row["error"]) == ("lapsed", False, 0, "")
            assert not [c for c in api.calls[:] if c[0] == "provider update" and OTHER in c[1]][updates:]
            assert page(sup)[f"sign_in:{OTHER}"] == ("expired", LAPSED.format(label=LABELS[OTHER]))
            assert sup.status()["restart_required"] is True and sup.status()["pending"]["keys"] is True
            await sup.restart()
            assert started_with(api)[0] == {MAIN, OTHER} and in_stand_in(layout) == sorted([MAIN, OTHER])
            rows = page(sup)
            assert rows[f"sign_in:{OTHER}"][0] == "ready" and rows[f"sign_in:{MAIN}"][0] == "ready"
            assert sup.status()["restart_required"] is False
            held = api.providers[next(name for name in api.providers if OTHER in name)]
            assert world.issuers.valid(OTHER, next(iter(held["credentials"].values())))
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_first_start_goes_on_without_a_sign_in_whose_token_is_over_while_its_issuer_does_not_answer(
        world, tmp_path, monkeypatch):
    signed_in(world, MAIN, OTHER)
    world.short_token(OTHER, seconds=30)
    world.clock.advance(40)  # the token in the profile's store is over
    sup, api, layout = launcher(world, tmp_path, monkeypatch)
    world.issuers.fail(OTHER, *["server_error"] * 6)

    async def scenario():
        await sup.start()  # the switch-on, and a launcher that starts again while the sandbox is on
        try:
            assert sup.state == "running" and api.step_errors == []
            assert started_with(api)[0] == {MAIN} and in_stand_in(layout) == [MAIN]
            assert page(sup)[f"sign_in:{OTHER}"] == ("expired", LAPSED.format(label=LABELS[OTHER]))
            assert not world.issuers.ended(OTHER)  # the grant was not spent: the schedule renews it later
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_token_that_runs_out_while_the_sandbox_starts_costs_one_attempt_not_the_sandbox(world, tmp_path, monkeypatch):
    signed_in(world, MAIN, OTHER)
    sup, api, _layout = launcher(world, tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        try:
            end = row_of(sup.signins, OTHER)["expires_at"]
            world.issuers.fail(OTHER, *["server_error"] * 400)  # its issuer does not answer: nothing newer comes
            passes_until(world, sup.signins, end - 2 * signins.START_MARGIN)
            assert row_of(sup.signins, OTHER)["state"] == "retrying"
            api.before_create = lambda: world.clock.advance(end - world.clock() + 1)  # one slow start
            with pytest.raises(Exception, match="entered error phase"):
                await sup.restart()  # the value was handed over and ran out before the sandbox asked for it
            assert api.step_errors and "holds no placeholder" in api.step_errors[-1]
            api.before_create = None
            await sup.restart()  # the launcher's second try, two seconds later
            assert sup.state == "running" and started_with(api)[0] == {MAIN}
            assert page(sup)[f"sign_in:{OTHER}"] == ("expired", LAPSED.format(label=LABELS[OTHER]))
        finally:
            await sup.stop()

    asyncio.run(scenario())


# -- the engine ------------------------------------------------------------------------------------------------

def switched_on(world, *providers):
    signed_in(world, *providers)
    world.take_copy()
    engine = world.engine()
    return engine, {row.provider: row for row in engine.declare()}


def test_the_margin_covers_a_start_and_spares_a_value_the_schedule_keeps_current():
    from openshell.launcher.openshell_driver import _READINESS_WAIT

    assert _READINESS_WAIT < signins.START_MARGIN <= signins.REFRESH_LEAD / 2
    assert [signins.start_margin(lifetime) for lifetime in (30, 60, 480, 900, 3600)] == [3.75, 7.5, 60, 60, 60]
    for lifetime in (30.0, 60.0, 300.0, 900.0, 3600.0):
        margin = signins.start_margin(lifetime)
        assert margin < signins.last_moment(lifetime)  # replaced whatever streams before the margin is met
        assert margin < lifetime - max(signins.lead(lifetime), min(lifetime, signins.MIN_BETWEEN_RENEWALS))


def test_a_token_is_left_out_from_the_margin_before_its_end_and_not_before(world):
    engine, declared = switched_on(world, MAIN, OTHER)
    web = TOOLS
    assert engine.tool_hosts(web) and {row["label"] for row in engine.tool_hosts(web)} == {LABELS[MAIN]}
    world.issuers.fail(MAIN, *["server_error"] * 400)  # its issuer does not answer: nothing newer comes
    end = row_of(engine, MAIN)["expires_at"]
    passes_until(world, engine, end - signins.START_MARGIN - 30)
    assert row_of(engine, MAIN)["state"] == "retrying"
    assert engine.for_start() == [] and engine.tool_hosts(web)  # half a minute more than the margin: handed over
    world.clock.advance(35)
    assert world.clock() < end and row_of(engine, MAIN)["state"] == "retrying"  # not over yet
    assert engine.for_start() == [declared[MAIN].id]
    assert engine.tool_hosts(web) == []  # no tool's host is bound for a sign-in the sandbox does not get
    row = row_of(engine, MAIN)
    assert (row["state"], row["usable"]) == ("lapsed", False)
    assert row["sentence"] == "The Nous Portal sign-in could not be renewed in time. The model answers again once it is renewed."


def test_sign_ins_that_are_kept_current_are_all_handed_over(world):
    engine, declared = switched_on(world, MAIN, OTHER)
    assert engine.for_start() == [] and world.sink.withdrawn == []
    passes_until(world, engine, world.clock() + 2 * 3600)  # renewed many times over
    world.sink.busy = True
    passes_until(world, engine, row_of(engine, OTHER)["renew_at"] + 1)  # due, and waiting for a quiet moment
    engine.catch_up()
    assert engine.for_start() == [] and world.sink.withdrawn == [] and engine.returned() == []
    assert sorted(world.sink.declared) == sorted(row.id for row in declared.values())
    template, names, left_out = standins.build(engine, {})
    assert names == ("auth.json",) and left_out == ()
    assert sorted(entry["provider"] for entry in template["credentials"].values()) == sorted([MAIN, OTHER])


def test_a_sign_in_that_ended_is_withdrawn_and_has_no_variable_and_keeps_its_sentence(world):
    engine, declared = switched_on(world, MAIN, OTHER)
    last = world.sink.values[declared[OTHER].id][0]
    refused(world, engine, OTHER)
    assert engine.variable_of(last) == declared[OTHER].env  # the sandbox that runs still has it
    before = row_of(engine, OTHER)
    assert engine.for_start() == [declared[OTHER].id]  # ended: left out whatever its last token has left
    assert world.sink.withdrawn == [declared[OTHER].id] and declared[OTHER].id not in world.sink.declared
    assert engine.variable_of(last) is None
    template, _names, left_out = standins.build(engine, {})
    assert [entry["provider"] for entry in template["credentials"].values()] == [MAIN]
    assert OTHER not in template["files"]["auth.json"]["providers"] and len(left_out) == 1
    row = row_of(engine, OTHER)
    assert (row["state"], row["reason"], row["sentence"]) == ("needs_sign_in", "expired", before["sentence"])
    assert row["action"] == "Turn the sandbox off, sign in to OpenAI Codex, then turn it on again."
    assert row["usable"] is False and row_of(engine, MAIN)["usable"] is True
    asked = len(world.issuers.refreshes(OTHER))
    passes_until(world, engine, world.clock() + 3600)
    assert len(world.issuers.refreshes(OTHER)) == asked and engine.returned() == []
    assert engine.for_start() == [declared[OTHER].id]  # until the sandbox is turned off and on


def test_removing_a_tool_approval_still_finds_the_hosts_an_ended_sign_in_has_bound_in_the_running_sandbox(world):
    signed_in(world, MAIN, OTHER)
    world.take_copy()
    approved = {TOOLS}
    engine = world.engine(approved=lambda: set(approved))
    declared = {row.provider: row for row in engine.declare()}
    other = next(c.id for c in categories.CATEGORIES if c.id != TOOLS and categories.gateway_endpoints(c)
                 and not set(categories.gateway_endpoints(c)) & set(categories.gateway_endpoints(categories.by_id(TOOLS))))
    gateway = [{"host": host, "port": port, "label": LABELS[MAIN]}
               for host, port in categories.gateway_endpoints(categories.by_id(TOOLS))]
    assert engine.tool_hosts(TOOLS) == gateway
    refused(world, engine, MAIN)
    # The sandbox that runs has the approved category's hosts bound to the ended sign-in: removing the approval
    # finds them (and restarts to close them). A category that was not approved gets no address for it.
    assert engine.tool_hosts(TOOLS) == gateway and engine.tool_hosts(other) == []
    assert engine.for_start() == [declared[MAIN].id]
    assert engine.tool_hosts(TOOLS) == []  # the sandbox that starts now has none of them


def test_a_sign_in_stopped_at_the_ceiling_is_left_out_like_one_that_ended(world, monkeypatch):
    monkeypatch.setattr(signins, "MOST_RENEWALS_PER_HOUR", 2)
    world.issuers.ttl[OTHER] = 60
    engine, declared = switched_on(world, MAIN, OTHER)
    passes_until(world, engine, world.clock() + 200)
    row = row_of(engine, OTHER)
    assert row["reason"] == "expired" and "times within an hour" in row["error"]
    assert engine.for_start() == [declared[OTHER].id]
    assert not world.issuers.ended(OTHER)  # the grant is kept: off and on is enough


def test_a_shared_sign_in_the_user_signed_out_of_is_left_out(world):
    world.config({"model": {"provider": MAIN, "default": "a-model"}})
    world.config({"model": {"provider": OTHER, "default": "a-model"}}, home=world.root)
    world.sign_in(MAIN)
    world.sign_in(OTHER, home=world.root)  # the default profile's sign-in, which the profile uses
    world.take_copy()
    engine = world.engine()
    declared = {row.provider: row for row in engine.declare()}
    assert declared[OTHER].shared is True and engine.for_start() == []
    store = world.root / "auth.json"
    doc = json.loads(store.read_text(encoding="utf-8"))
    doc["providers"].pop(OTHER)  # what signing out of it for the default profile leaves
    store.write_text(json.dumps(doc), encoding="utf-8")
    assert engine.for_start() == [declared[OTHER].id]
    row = row_of(engine, OTHER)
    assert (row["state"], row["reason"]) == ("needs_sign_in", "expired")
    assert row["error"] == "Not signed in. Sign in to OpenAI Codex with the sandbox off."
    assert engine.notes() == ["The OpenAI Codex sign-in expired on this computer. Turn the sandbox off, sign in to "
                              "OpenAI Codex, then turn it on again."]
    assert world.issuers.refreshes(OTHER) == []  # nothing was asked of the issuer to find out
    template, _names, _left = standins.build(engine, {})
    assert [entry["provider"] for entry in template["credentials"].values()] == [MAIN]


# -- the rule for a credential that should be there stays ----------------------------------------------------------

class Expiring(dict):
    """The Windows build's answer about a provider, from the expiry its CLI was given for it."""

    def __init__(self, fake, now):
        super().__init__()
        self.fake, self.now = fake, now

    def get(self, provider, default=None):
        over = [name for name, at in (self.fake.expiries.get(provider) or {}).items() if int(at) <= self.now * 1000]
        return ("WITHHELD", "CREDENTIAL_EXPIRED") if over else default


def test_on_windows_a_declared_credential_that_is_withheld_fails_the_start_and_a_withdrawn_one_is_not_asked_about(
        tmp_path, monkeypatch):
    monkeypatch.setattr(OD.time, "sleep", lambda seconds: None)
    sup, fake, driver, _layout = CP._windows(tmp_path, monkeypatch)
    fake.provider_states = Expiring(fake, now=2000000000)
    driver.declare(CP.NOUS, "a-token-that-is-over", 1900000000.5)

    async def scenario():
        with pytest.raises(DriverUnavailable, match="the gateway withheld Nous Portal from the sandbox .credential expired."):
            await sup.start()
        assert not fake.sandboxes
        driver.withdraw(CP.NOUS.id)  # what the launcher does with a sign-in that ended, before a start
        calls = len(fake.calls)
        await sup.start()
        try:
            names = [p["name"] for p in driver.policy()["providers"]]
            assert len(names) == 1 and "nous" not in names[0]
            later = [argv for argv, _env in fake.calls[calls:]]
            about = [argv for argv in later if any("nous-agent-key" in str(part).lower() for part in argv[1:])]
            assert about and all("delete" in argv for argv in about)  # its last token leaves the gateway, no more
            assert [argv[5] for argv in later if argv[1:4] == ["sandbox", "provider", "status"]] == names
        finally:
            await sup.stop()
        assert driver.declare(CP.NOUS, "a-new-token", 2100000000.0) == "HERMES_CRED_NOUS_AGENT_KEY"  # signed in again
        await sup.start()
        try:
            assert len(driver.policy()["providers"]) == 2
        finally:
            await sup.stop()

    asyncio.run(scenario())
