"""The stand-in sign-in store at a sandbox start (launcher/standins.py, supervisor.py, both drivers).

For a profile that is signed in to a provider: the start-up step goes in front of the command, started by its
path; the template is where the sandbox reads it; exactly the sign-in file's name leaves the hidden and the held
files, and every other credential file stays hidden. For a profile with no sign-in nothing about the start
changes. Every token here is made up.
"""
import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import test_openshell_driver as LD
from openshell.inside import standin
from openshell.launcher import cards as C
from openshell.launcher import held
from openshell.launcher import layout as L
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_windows as W
from openshell.launcher import pins as P
from openshell.launcher import standins
from openshell.launcher import supervisor as S

ACCESS = "made-up-access-" + "a" * 40
OTHER = "made-up-other-" + "b" * 40
GRANT = "made-up-grant-" + "c" * 40
VARIABLE = "HERMES_CRED_OPENAI_CODEX_ACCESS_TOKEN"
STORE = {"version": 1, "active_provider": "openai-codex", "providers": {
    "openai-codex": {"tokens": {"access_token": ACCESS, "refresh_token": GRANT}, "auth_mode": "chatgpt",
                     "last_refresh": "2030-01-01T00:00:00+00:00"},
    "xai-oauth": {"tokens": {"access_token": OTHER, "refresh_token": GRANT + "x"}}}}


class Engine:
    """The sign-in engine as the supervisor uses it, with one declared sign-in and no network."""

    def __init__(self, copy: Path, known=None):
        self.copy, self.pending, self.closed, self.steps = copy, [], False, 0
        self.known = {ACCESS: VARIABLE} if known is None else known

    def stores(self):
        out = {}
        for name in standin.STORE_FILES:
            try:
                out[name] = json.loads((self.copy / name).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                out[name] = None
        return out

    def variable_of(self, value):
        return self.known.get(value)

    def status(self):
        return [{"id": "openai-codex:access_token", "provider": "openai-codex", "label": "OpenAI Codex", "state": "works",
                 "sentence": "Signed in.", "kind": "sign_in"}]

    def notes(self):
        notes, self.pending = self.pending, []
        return notes

    def step(self):
        self.steps += 1
        return 60.0

    def catch_up(self):
        self.caught_up = getattr(self, "caught_up", 0) + 1

    def close(self):
        self.closed = True


def _signed_in(tmp_path, monkeypatch, store=STORE):
    """A supervisor over the fake gateway whose profile holds a sign-in store, switched on (pinned)."""
    layout = LD._layout(tmp_path)
    (layout.home / "auth.json").write_text(json.dumps(store), encoding="utf-8")
    P.remove(layout)
    sup, api, rec, layout = _supervisor(tmp_path, monkeypatch, layout)
    sup.signins, sup._declared = Engine(P.pin_dir(layout)), [SimpleNamespace(provider="openai-codex")]
    return sup, api, layout


def _supervisor(tmp_path, monkeypatch, layout):
    from openshell.launcher.spec import load_spec, save_spec

    spec = load_spec(layout)
    spec.update(driver="openshell", folders=LD._folders(tmp_path), network={"egress": "deny", "allow": []})
    save_spec(layout, spec)
    P.take(layout)
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"LLAMA_API_KEY": LD.SECRET})
    api, rec = LD.FakeApi(), LD.Recorder()
    driver = OD.OpenShellDriver(LD._cfg(tmp_path), api=api, run=rec.run, popen=rec.popen)
    return S.Supervisor(layout, LD._runtime(tmp_path), load_spec(layout), driver, outer_port=1), api, rec, layout


def _hidden(sup, plan=None):
    request, _folders = sup._launch_request({"LLAMA_API_KEY": LD.SECRET}, plan)
    return request, {os.path.normcase(str(p)) for p in request.grants.denied}


SERVE = ["-m", "hermes_cli.main", "serve", "--isolated", "--host", "127.0.0.1"]


# -- the template ---------------------------------------------------------------------------------------------------

def test_a_file_gets_a_stand_in_only_for_a_credential_that_was_handed_in(tmp_path):
    (tmp_path / "auth.json").write_text(json.dumps(STORE), encoding="utf-8")
    template, names, left_out = standins.build(Engine(tmp_path))
    assert names == ("auth.json",) and left_out == ("xai-oauth:access_token",)
    assert template["credentials"] == {"openai-codex:access_token": {
        "marker": template["credentials"]["openai-codex:access_token"]["marker"], "provider": "openai-codex",
        "field": "access_token", "claims": {}, "env": VARIABLE}}
    assert "xai-oauth" not in template["files"]["auth.json"]["providers"]  # its row is left out with it
    text = json.dumps(template)
    assert ACCESS not in text and OTHER not in text and GRANT not in text
    # nothing was handed in: the file gets no stand-in and stays hidden
    assert standins.build(Engine(tmp_path, known={})) == (None, (), ("openai-codex:access_token", "xai-oauth:access_token"))
    # no sign-in file at all
    assert standins.build(Engine(tmp_path / "empty")) == (None, (), ())
    assert standins.build(None) == (None, (), ())


def test_a_token_kept_in_the_env_file_gets_an_alias_and_no_file(tmp_path):
    template, names, left_out = standins.build(Engine(tmp_path), {"ANTHROPIC_TOKEN": "anthropic"})
    assert names == () and left_out == () and template["files"] == {}
    assert template["credentials"]["env:ANTHROPIC_TOKEN"]["env"] == "ANTHROPIC_TOKEN" and "ANTHROPIC_TOKEN" in template["env"]


def test_no_row_of_a_stand_in_holds_a_refresh_grant_or_a_word_in_its_place(tmp_path):
    store = {"version": 1, "providers": {
        "nous": {"access_token": ACCESS, "agent_key": ACCESS, "refresh_token": GRANT},
        "openai-codex": {"tokens": {"access_token": OTHER, "refresh_token": GRANT + "x"}},
        "xai-oauth": {"tokens": {"access_token": OTHER + "y", "refresh_token": GRANT + "y"}},
        "minimax-oauth": {"access_token": OTHER + "z", "refresh_token": GRANT + "z"}}}
    (tmp_path / "auth.json").write_text(json.dumps(store), encoding="utf-8")
    (tmp_path / ".anthropic_oauth.json").write_text(json.dumps({"accessToken": ACCESS + "a", "refreshToken": GRANT + "a",
                                                                "expiresAt": 1900000000000}), encoding="utf-8")
    known = {ACCESS: "A", OTHER: "B", OTHER + "y": "C", OTHER + "z": "D", ACCESS + "a": "E"}
    template, names, left_out = standins.build(Engine(tmp_path, known=known))
    assert names == (".anthropic_oauth.json", "auth.json") and left_out == ()
    text = json.dumps(template["files"])
    assert "refresh_token" not in text and "refreshToken" not in text and standin.NO_REFRESH not in text
    assert set(standins.WITHOUT_GRANTS) == {"nous", "openai-codex", "xai-oauth", "minimax-oauth", "anthropic"}


def test_the_step_and_the_template_are_written_where_the_sandbox_reads_them(tmp_path):
    layout = LD._layout(tmp_path)
    (tmp_path / "auth.json").write_text(json.dumps(STORE), encoding="utf-8")
    template, names, left_out = standins.build(Engine(tmp_path))
    plan = standins.write(layout, template, names, left_out)
    assert plan.folder == layout.state_dir / "standin" and plan.names == ("auth.json",)
    assert json.loads(plan.template.read_text(encoding="utf-8")) == template
    assert plan.step.read_bytes() == Path(standin.__file__).read_bytes()
    assert standins.environment(plan) == {"HERMES_OPENSHELL_STANDIN": str(plan.template)}
    assert standins.command(plan, ["/py", "-m", "x"]) == ["/py", str(plan.step), "--", "/py", "-m", "x"]
    # nothing to stand in for: the folder goes, the command and the environment are the ones given
    none = standins.write(layout, None)
    assert not (layout.state_dir / "standin").exists() and none.names == () and none.folder is None
    assert standins.command(none, ["/py", "-m", "x"]) == ["/py", "-m", "x"] and standins.environment(none) == {}


# -- a profile with no sign-in: nothing changes ---------------------------------------------------------------------

def test_a_profile_with_no_sign_in_starts_exactly_as_before(tmp_path, monkeypatch):
    sup, api, _rec, layout = LD._supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        try:
            (_, _, spec), = [c for c in api.calls if c[0] == "create"]
            python = str(sup.runtime.python)
            assert spec["command"][:len(SERVE) + 1] == [python, *SERVE]
            assert "HERMES_OPENSHELL_STANDIN" not in spec["environment"]
            assert not any("standin" in m["target"] for m in spec["template"]["driver_config"]["docker"]["mounts"])
            assert not (layout.state_dir / "standin").exists()
            assert sup._standin == standins.Plan() and sup._signin_thread is None and sup._declared == []
            assert P.load(layout)["standin"] == [] and (layout.home / "auth.json").exists()
            assert [row for row in sup.status()["providers"] if row["kind"] == "sign_in"] == []
        finally:
            await sup.stop()

    asyncio.run(scenario())
    request, hidden = _hidden(sup)
    assert request.standin == () and request.step == () and request.argv[1:len(SERVE) + 1] == SERVE
    listed = {os.path.normcase(str(p)) for p in L.credential_paths(layout.home)}
    assert listed <= hidden and {os.path.normcase(str(layout.home / name)) for name in
                                 ("auth.json", ".anthropic_oauth.json", ".env", ".op.env")} <= listed


# -- a profile with a sign-in ---------------------------------------------------------------------------------------

def test_a_signed_in_profile_starts_through_the_step_with_exactly_its_file_left_out(tmp_path, monkeypatch):
    sup, api, layout = _signed_in(tmp_path, monkeypatch)
    _request, before = _hidden(sup)

    async def scenario():
        await sup.start()
        try:
            (_, _, spec), = [c for c in api.calls if c[0] == "create"]
            python, folder = str(sup.runtime.python), layout.state_dir / "standin"
            assert spec["command"][:3] == [python, str(folder / "standin.py"), "--"]
            assert spec["command"][3:4 + len(SERVE)] == [python, *SERVE]
            assert spec["environment"]["HERMES_OPENSHELL_STANDIN"] == str(folder / "template.json")
            mounts = {m["target"]: m for m in spec["template"]["driver_config"]["docker"]["mounts"]}
            assert mounts[str(folder)] == {"type": "bind", "source": str(folder), "target": str(folder), "read_only": True}
            assert str(layout.home / "auth.json") not in mounts  # no mask on the name the stand-in goes under
            for path in layout.state_dir.rglob("*"):
                if path.is_file() and P.pin_dir(layout) not in path.parents:
                    assert ACCESS.encode() not in path.read_bytes() and GRANT.encode() not in path.read_bytes(), path
            assert ACCESS not in json.dumps(spec) and GRANT not in json.dumps(spec)
            assert sup._standin.names == ("auth.json",)
            return spec
        finally:
            await sup.stop()

    asyncio.run(scenario())
    # The real file left its name only after the copy was recorded; the copy is the only real one now.
    assert not (layout.home / "auth.json").exists() and P.load(layout)["standin"] == ["auth.json"]
    assert json.loads((P.pin_dir(layout) / "auth.json").read_text(encoding="utf-8")) == STORE
    request, hidden = _hidden(sup, sup._standin)
    assert before - hidden == {os.path.normcase(str(layout.home / "auth.json"))} and hidden - before == set()
    assert request.standin == ("auth.json",) and list(request.step) == request.argv[:3]
    assert sup._standin.folder in request.grants.readonly  # what the Windows driver's policy lists read-only
    assert request.argv[0] == str(sup.runtime.python) and "--port" in request.argv
    # The switch-off: the copy is back under the name.
    P.release(layout)
    assert json.loads((layout.home / "auth.json").read_text(encoding="utf-8")) == STORE and not P.present(layout)


def test_the_windows_driver_hides_everything_but_that_name(tmp_path, monkeypatch):
    """The deny list the Windows driver sends with the sandbox (``driver_config.mxc.denied_paths``), with and
    without the stand-in: the one difference is the sign-in file's own path."""
    sup, _api, layout = _signed_in(tmp_path, monkeypatch)
    network, binaries = {"egress": "deny", "allow": []}, [str(sup.runtime.python)]
    request, _hidden_before = _hidden(sup)
    _policy, without, _notes = W.build_windows_policy(request.grants, network, binaries, home=layout.home)
    plan = asyncio.run(asyncio.to_thread(sup._prepare_sign_ins, {"LLAMA_API_KEY": LD.SECRET}))
    request, _hidden_after = _hidden(sup, plan)
    policy, with_stand_in, _notes = W.build_windows_policy(request.grants, network, binaries, home=layout.home)
    # the template and the step are read-only inside, as the launcher's other folders for the sandbox are
    assert W.native(plan.folder) in policy["filesystem_policy"]["read_only"]
    assert W.native(plan.folder) not in policy["filesystem_policy"]["read_write"]
    name = W.native(layout.home / "auth.json")
    assert name in without and set(without) - set(with_stand_in) == {name} and set(with_stand_in) <= set(without)
    for other in (".env", ".op.env", ".anthropic_oauth.json"):
        assert W.native(layout.home / other) in with_stand_in
    assert W._with_port(request.argv, 4321)[:3] == [str(sup.runtime.python), str(plan.step), "--"]
    assert W.leaf_python(Path(request.argv[0])) == W.leaf_python(sup.runtime.python)


@pytest.mark.skipif(os.name == "nt", reason="the held folder is made of links")
def test_the_held_folder_leaves_exactly_that_name_out(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    for name in (".env", "auth.json", "bws_cache.json"):
        (home / name).write_text("x", encoding="utf-8")
    taken = []
    linked = held.hold(home, [".env", "auth.json", "bws_cache.json"], taken.append, leave=("auth.json",))
    assert linked == [".env", "bws_cache.json", ".op.env"] and taken == []
    assert not held.is_link(home / "auth.json") and (home / "auth.json").read_text(encoding="utf-8") == "x"
    assert held.is_link(home / ".env") and held.is_link(home / ".op.env") and held.is_link(home / "bws_cache.json")
    # what stands under that name is the sandbox's: the every-second look leaves it alone
    (home / "auth.json").write_text("a stand-in", encoding="utf-8")
    assert held.guard(home, taken.append) == [] and taken == []
    assert held.release(home, taken.append)["restored"] == [".env", "bws_cache.json"]
    assert (home / "auth.json").read_text(encoding="utf-8") == "a stand-in"
    # without the argument: as before
    assert "auth.json" in held.hold(home, [".env"], taken.append)
    held.release(home, taken.append)


def test_a_sign_in_whose_copy_is_not_the_recorded_file_stops_the_start(tmp_path, monkeypatch):
    sup, api, layout = _signed_in(tmp_path, monkeypatch)
    before = (layout.home / "auth.json").read_bytes()
    P._save(layout, {**P.load(layout), "stores": {**P.load(layout)["stores"], "auth.json": {"sha256": "0" * 64, "link": None}}})
    monkeypatch.setattr(P, "follow_copy", lambda _layout: [])

    async def scenario():
        with pytest.raises(P.PinError, match="not the file that was recorded"):
            await sup.start()

    asyncio.run(scenario())
    assert sup.state == "failed" and not [c for c in api.calls if c[0] == "create"]
    assert (layout.home / "auth.json").read_bytes() == before


# -- keeping fresh: the thread, the rows, the notes -------------------------------------------------------------------

def test_the_schedule_runs_in_one_thread_and_its_rows_and_notes_reach_the_launcher(tmp_path, monkeypatch):
    sup, _api, layout = _signed_in(tmp_path, monkeypatch)
    engine, said = sup.signins, []
    sup.on_signin_note = said.append
    engine.pending = ["The OpenAI Codex sign-in expired on this computer. Turn the sandbox off, sign in to OpenAI "
                      "Codex, then turn it on again."]
    sup._publish_sign_ins()
    assert len(said) == 1 and "expired on this computer" in said[0]
    sup._publish_sign_ins()
    assert len(said) == 1, "the note was said twice"

    async def scenario():
        await sup.start()
        try:
            thread = sup._signin_thread
            assert thread is not None and thread.name == "sign-ins" and thread.daemon
            for _ in range(200):
                if engine.steps:
                    break
                await asyncio.sleep(0.01)
            assert engine.steps == 1
            rows = sup.status()["providers"]
            assert {"id": "sign_in:openai-codex", "label": "OpenAI Codex", "kind": "sign_in", "state": "ready",
                    "detail": "Works in the sandbox. Stays signed in on this computer.", "main": False, "reason": "",
                    "used_by": []} in rows
            assert any(row["id"] == "key:LLAMA_API_KEY" and row["state"] == "ready" for row in rows)
            caught_up = engine.caught_up
            await sup.restart()
            assert sup._signin_thread is thread, "a restart of the sandbox started a second schedule"
            assert engine.caught_up == caught_up + 1, "a restart did not bring the driver's values up to date"
            sup.switching_off = True
        finally:
            await sup.stop()
        assert engine.closed and not thread.is_alive(), "a renewal could still start after the switch-off"

    asyncio.run(scenario())


def test_the_quiet_question_is_answered_on_the_launchers_loop_whoever_asks():
    from openshell import launcher_cli as CLI

    async def scenario():
        import threading

        loop, asked_on = asyncio.get_running_loop(), []

        def question():
            asked_on.append(threading.get_ident())
            return True

        ask = CLI._asked_on_loop(loop, question)
        assert ask() is True
        assert await asyncio.to_thread(ask) is True
        assert asked_on == [threading.get_ident()] * 2

    asyncio.run(scenario())


# -- the backend's own refresh attempt is not a website to ask about ---------------------------------------------------

def test_a_refusal_at_a_declared_sign_ins_token_address_raises_no_card(tmp_path):
    assert standins.token_hosts(["openai-codex", "nous"]) == {"auth.openai.com", "portal.nousresearch.com"}
    assert standins.token_hosts([]) == set() and standins.token_hosts(["openrouter"]) == set()
    rejected = []
    driver = SimpleNamespace(backend_binaries=lambda: ["/env/bin/python3"], can=lambda _f: True,
                             reject=lambda pid, reason: rejected.append((pid, reason)))
    sup = SimpleNamespace(driver=driver, layout=None, running=lambda: True,
                          sign_in_token_hosts=lambda: standins.token_hosts(["openai-codex"]))
    cards = C.Cards(sup, None, tmp_path / "cards.jsonl")
    draft = {"id": "d1", "status": "pending", "binary": "/env/bin/python3", "hit_count": 1,
             "endpoints": [{"host": "auth.openai.com", "port": 443}]}
    assert cards._sign_in_renewal(draft, [("auth.openai.com", 443)])
    assert not cards._sign_in_renewal({**draft, "binary": "/usr/bin/curl"}, [("auth.openai.com", 443)])  # the agent's own
    assert not cards._sign_in_renewal(draft, [("auth.openai.com", 443), ("example.com", 443)])
    assert not cards._sign_in_renewal(draft, [("example.com", 443)])
    asyncio.run(cards._on_proposals([draft]))
    assert cards.open == {} and rejected == [("d1", "Sign-ins are renewed on this computer, not in the sandbox.")]
    asyncio.run(cards._on_proposals([draft]))
    assert len(rejected) == 1
    sup.sign_in_token_hosts = lambda: set()  # no sign-in declared: the host is a website like any other
    assert not cards._sign_in_renewal(draft, [("auth.openai.com", 443)])


def test_a_note_of_the_launcher_waits_for_the_first_chat_that_writes(tmp_path):
    cards = C.Cards(None, None, tmp_path / "cards.jsonl")
    asyncio.run(cards.note("The OpenAI Codex sign-in expired on this computer."))
    assert cards._unplaced_notes == ["The OpenAI Codex sign-in expired on this computer."] and cards.notices == {}


# -- providers an earlier version registered ----------------------------------------------------------------------------

def test_providers_of_an_earlier_version_are_deleted_once_by_their_exact_names(tmp_path):
    forgotten, notes = [], []

    class Driver(OD.CredentialSinkMixin):
        def _gw_forget(self, name):
            forgotten.append(name)
            if name == "hermes-work-broken-key":
                raise RuntimeError("the gateway did not answer")

        def _note(self, text):
            notes.append(text)

    driver = Driver()
    secrets = {"OPENROUTER_API_KEY": "k", "BROKEN_KEY": "k", "KEPT_KEY": "k"}
    driver._forget_first_names(tmp_path, "hermes-work", secrets, ["hermes-work-kept-key"])
    assert forgotten == ["hermes-work-broken-key", "hermes-work-openrouter-api-key"]  # never a name in use now
    assert json.loads((tmp_path / "providers-first-names.json").read_text(encoding="utf-8")) == ["hermes-work-broken-key"]
    driver._forget_first_names(tmp_path, "hermes-work", {**secrets, "NEW_KEY": "k"}, [])
    assert forgotten[2:] == ["hermes-work-broken-key"]  # only what could not be deleted is tried again
    forgotten.clear()
    (tmp_path / "providers-first-names.json").write_text("[]", encoding="utf-8")
    driver._forget_first_names(tmp_path, "hermes-work", secrets, [])
    assert forgotten == []
