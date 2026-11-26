"""The names the plugin makes from a profile's name: the sandbox's name on the gateway, its labels, its providers.

A profile id is 1 to 64 characters of ``a-z 0-9 _ -``. OpenShell takes a sandbox name of 19 characters at most
that is a DNS label without ``--``, and a label value of 63 characters at most with a letter or digit at both
ends. So the sandbox's name is the profile's alone and always one the gateway takes (``sandbox_name``), and no
start, switch-off or provider cleanup of one profile deletes what belongs to another. A sandbox that stands
under the folded form of a name (``folded_sandbox_name``, which two profiles can share) is ended at the next
start and at a switch-off, but only when it is this profile's.

The gateway rules are restated here from OpenShell 0.1.9. The gateways are the suite's fakes.
"""
import asyncio
import hashlib
import itertools
import json
import random
import re
from types import SimpleNamespace

import pytest

import test_openshell_driver as LD
import test_openshell_windows as WD
import test_switch_off_ends_the_sandbox as OFF
from openshell.launcher import layout as L
from openshell.launcher import login_service as LS
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_windows as W
from openshell.launcher import pins
from openshell.launcher import supervisor as S
from openshell.launcher import switch as SW
from openshell.launcher.credential_sink import CredentialDecl, Endpoint
from openshell.launcher.driver import DriverUnavailable
from openshell.launcher.spec import load_spec, save_spec
from openshell.launcher.layout import ProfileLayout
from test_switch_flow import FakeMarkers, FakeRuntime, FakeService

PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
LONG_A, LONG_B = "p" * 56 + "aaaaaaaa", "p" * 56 + "bbbbbbbb"


def name_refusal(name):
    """Why OpenShell refuses a sandbox name; None when it takes it."""
    if len(name) > 19:
        return f"name exceeds maximum length ({len(name)} > 19)"
    if not re.fullmatch(r"[a-z0-9-]+", name):
        return "name must contain only lowercase alphanumeric characters or hyphens"
    if name.startswith("-") or name.endswith("-"):
        return "name must not start or end with a hyphen"
    if "--" in name:
        return "name must not contain consecutive hyphens"
    return None


def label_refusal(value):
    """Why OpenShell refuses a label value; None when it takes it."""
    if len(value) > 63:
        return "label value exceeds 63 characters"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        return "label value contains invalid characters"
    if not (value[0].isalnum() and value[-1].isalnum()):
        return "label value must start and end with an alphanumeric character"
    return None


def _ids():
    """Every profile id over ``a b 1 - _`` up to 5 characters, and 20,000 ids of 1 to 64 characters."""
    ids = ["".join(t) for n in range(1, 6) for t in itertools.product("ab1-_", repeat=n)]
    rng = random.Random(20261125)
    chars = "abcdefghijklmnopqrstuvwxyz0123456789-_"
    for _ in range(20_000):
        ids.append(rng.choice(chars[:36]) + "".join(rng.choice(chars) for _ in range(rng.randint(1, 64) - 1)))
    return sorted({i for i in ids if PROFILE_ID.match(i)})


# -- the rule --------------------------------------------------------------------------------------------------

def test_no_two_profiles_share_a_sandbox_name_and_the_gateway_takes_every_name():
    ids = _ids()
    assert len(ids) > 20_000
    by_name = {}
    for profile in ids:
        by_name.setdefault(OD.sandbox_name(profile), []).append(profile)
    shared = {name: profiles for name, profiles in by_name.items() if len(profiles) > 1}
    refused = {profile: name_refusal(OD.sandbox_name(profile)) for profile in ids}
    refused = {profile: why for profile, why in refused.items() if why}
    assert not shared, f"{len(shared)} names are shared, e.g. {list(shared.items())[:3]}"
    assert not refused, f"{len(refused)} names are refused, e.g. {list(refused.items())[:3]}"
    assert all(OD.sandbox_name(profile) == name for name, (profile,) in by_name.items())  # the same answer again


@pytest.mark.parametrize("a, b", [("d-x", "d_x"), ("x", "x-"), ("x", "x_"), ("default", "default_"),
                                  ("a--b", "a-_b"), ("a__b", "a-b"), (LONG_A, LONG_B)])
def test_profiles_that_shared_a_name_have_one_each(a, b):
    assert OD.sandbox_name(a) != OD.sandbox_name(b)
    assert name_refusal(OD.sandbox_name(a)) is None and name_refusal(OD.sandbox_name(b)) is None


def test_a_profile_that_is_a_short_dns_label_keeps_the_name_it_can_be_read_from():
    for profile in ("work", "default", "d-x", "x", "qa25b630594"):  # 11 characters at most, no underscore
        assert OD.sandbox_name(profile) == f"hermes-{profile}"
    for profile in ("qa25b630594x", "qa25b630594xx", "research-agent", "p" * 64):  # 12, 13, 14, 64 characters
        name = OD.sandbox_name(profile)
        assert len(name) == 19 and name.startswith(f"hermes-{profile[:3]}-") and name_refusal(name) is None


def test_two_profiles_whose_names_differ_by_an_underscore_have_providers_of_their_own():
    decl = CredentialDecl(id="env:OPENROUTER_API_KEY", label="OpenRouter", endpoints=(Endpoint("openrouter.ai", 443),),
                          placement="bearer", name=None)
    ids = {OD.provider_id(OD.sandbox_name(profile), [(decl, "OPENROUTER_API_KEY")], True) for profile in ("d-x", "d_x")}
    assert len(ids) == 2 and all(len(i) <= 63 for i in ids)


# -- a Linux sandbox of any profile, on the fake gateway --------------------------------------------------------

class Api(LD.FakeApi):
    """The fake gateway, which also keeps the labels a sandbox is created with and returns them."""

    def create_sandbox(self, name, spec, labels):
        super().create_sandbox(name, spec, labels)
        self.sandboxes[name]["labels"] = dict(labels)


def _linux(tmp_path, monkeypatch, profile, api=None):
    root = tmp_path / "root"
    home = root / "profiles" / profile
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text("model:\n  provider: custom\n  base_url: http://127.0.0.1:18500/v1\n"
                                      "  key_env: LLAMA_API_KEY\n", encoding="utf-8")
    (home / ".env").write_text(f"LLAMA_API_KEY={LD.SECRET}\n", encoding="utf-8")
    (home / "auth.json").write_text("{}", encoding="utf-8")
    layout = L.ProfileLayout(name=profile, home=home, root=root)
    spec = load_spec(layout)
    spec.update(driver="openshell", folders=[], network={"egress": "deny", "allow": []})
    save_spec(layout, spec)
    pins.take(layout)
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"LLAMA_API_KEY": LD.SECRET})
    api, rec = api or Api(), LD.Recorder()
    driver = OD.OpenShellDriver(LD._cfg(tmp_path), api=api, run=rec.run, popen=rec.popen)
    return S.Supervisor(layout, LD._runtime(tmp_path), load_spec(layout), driver, outer_port=1), api, layout


def _others(monkeypatch, profiles):
    """The other profiles that are switched on in this Hermes root, as both drivers ask for them."""
    for module in (OD, W):
        monkeypatch.setattr(module, "other_profiles", lambda profile: profiles, raising=False)


def _box(label=None, **more):
    """A sandbox as a gateway returns it: ``labels`` at the top, in the CLI's JSON and in the API's answer."""
    labels = {"hermes.profile": label} if label else {}
    return {"name": "x", "phase": "READY", "exit_code": None, "labels": {**labels, **more}}


def _deleted(api):
    return [call[1] for call in api.calls if call[0] == "delete"]


@pytest.mark.parametrize("profile", ["work", "x_", "a--b", "p" * 64])
def test_a_sandbox_is_created_under_a_name_and_with_labels_the_gateway_takes(tmp_path, monkeypatch, profile):
    sup, api, _layout = _linux(tmp_path, monkeypatch, profile)

    async def scenario():
        await sup.start()
        try:
            (name,) = api.sandboxes
            labels = api.sandboxes[name]["labels"]
            assert name == OD.sandbox_name(profile) and name_refusal(name) is None
            assert labels and all(label_refusal(value) is None for value in labels.values()), labels
            # Every sandbox says whose it is: the profile where that is a label value, a digest of it always.
            assert labels.get("hermes.profile", profile) == profile
            assert labels["hermes.profile-id"] == hashlib.sha256(profile.encode()).hexdigest()[:32]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_starting_a_profile_leaves_the_sandbox_of_a_profile_with_a_similar_name(tmp_path, monkeypatch):
    api = Api()
    api.sandboxes["hermes-d-x"] = _box("d-x")  # profile d-x is switched on and runs
    _others(monkeypatch, ["d-x"])
    sup, api, _layout = _linux(tmp_path, monkeypatch, "d_x", api)

    async def scenario():
        await sup.start()
        assert _deleted(api) == [] and sorted(api.sandboxes) == sorted(["hermes-d-x", OD.sandbox_name("d_x")])
        await sup.stop()
        assert _deleted(api) == [OD.sandbox_name("d_x")] and list(api.sandboxes) == ["hermes-d-x"]

    asyncio.run(scenario())


def test_a_sandbox_under_the_folded_form_of_the_name_is_replaced_at_the_next_start(tmp_path, monkeypatch):
    api = Api()
    api.sandboxes["hermes-d-x"] = _box("d_x")  # this profile's own, under the folded form of its name
    sup, api, layout = _linux(tmp_path, monkeypatch, "d_x", api)
    audit = layout.state_dir / "audit"
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "ocsf-hermes-d-x-2026-11-20.jsonl").write_text("{}\n", encoding="utf-8")

    async def scenario():
        await sup.start()
        try:
            assert _deleted(api) == ["hermes-d-x"] and list(api.sandboxes) == [OD.sandbox_name("d_x")]
            # The audit files under the folded form are read under the name the sandbox has.
            assert [p.name[-16:] for p in OD.archive_files(audit, OD.sandbox_name("d_x"))] == ["2026-11-20.jsonl"]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_api_returns_the_labels_the_sdk_holds_for_a_sandbox():
    """The SDK answers ``get`` with a reference that holds ``labels`` beside ``status``."""
    labels = {"hermes.profile": "d_x", "hermes.profile-id": hashlib.sha256(b"d_x").hexdigest()[:32]}
    reference = SimpleNamespace(id="s-1", name="hermes-d-x", workspace="default", labels=labels,
                                status=SimpleNamespace(phase=2, current_policy_version=3, exit_code=None))
    api = OD.GatewayApi.__new__(OD.GatewayApi)  # without the SDK: its client and its messages are stand-ins
    api.cfg = SimpleNamespace(workspace="default")
    api.grpc = SimpleNamespace(RpcError=RuntimeError)
    api.pb = SimpleNamespace(SandboxPhase=SimpleNamespace(Name=lambda phase: "SANDBOX_PHASE_READY"))
    api.client = SimpleNamespace(get=lambda name, workspace: reference)
    state = api.sandbox_state("hermes-d-x")
    assert state == {"phase": "READY", "exit_code": None, "policy_version": 3, "labels": labels}
    assert OD.owner_says(OD.sandbox_labels(state), "d_x") is True
    assert OD.owner_says(OD.sandbox_labels(state), "d-x") is False
    reference.labels = {}  # a sandbox created without labels says nothing of its profile
    assert OD.owner_says(OD.sandbox_labels(api.sandbox_state("hermes-d-x")), "d_x") is None


# -- the leftover of one profile, on both drivers ---------------------------------------------------------------

@pytest.fixture(params=["windows", "linux"])
def gateway(request, tmp_path):
    side = OFF.Side(request.param, tmp_path, [])
    side.sandboxes.clear()
    yield side
    side.listener.end()


FOLDED = "hermes-d-x"  # the folded form of the name of profile d_x, and the name of profile d-x


@pytest.mark.parametrize("box, others, gone", [
    (_box("d_x"), ["d-x"], True),  # labelled for this profile
    (_box(**{"hermes.profile-id": "d_x"}), ["d-x"], True),  # (the digest is put in below)
    (_box("d-x"), [], False),  # labelled for the other profile
    (_box(), [], True),  # no label, and no other profile that is switched on has that name
    (_box(), ["work"], True),
    (_box(), ["d-x"], False),  # no label, and the name is also profile d-x's
    (_box(), None, False),  # no label, and the other profiles cannot be listed
])
def test_a_sandbox_under_the_folded_name_is_deleted_only_when_it_is_this_profiles(gateway, monkeypatch, box, others,
                                                                                   gone):
    box = json.loads(json.dumps(box))
    if "hermes.profile-id" in box["labels"]:
        box["labels"]["hermes.profile-id"] = hashlib.sha256(b"d_x").hexdigest()[:32]
    gateway.sandboxes[FOLDED] = box
    _others(monkeypatch, others)
    assert gateway.driver.drop_leftover("d_x") is gone
    assert (FOLDED not in gateway.sandboxes) is gone


def test_a_sandbox_under_this_profiles_name_that_is_anothers_is_left_and_said(gateway, monkeypatch):
    gateway.sandboxes[OD.sandbox_name("d_x")] = _box("someone-else")
    with pytest.raises(DriverUnavailable) as err:
        gateway.driver.drop_leftover("d_x")
    assert "belongs to another profile" in str(err.value) and len(gateway.sandboxes) == 1


@pytest.mark.parametrize("kind", ["windows", "linux"])
def test_switching_one_profile_off_leaves_the_sandbox_of_the_profile_with_a_similar_name(tmp_path, monkeypatch, kind):
    """Profiles ``d_x`` and ``d-x`` are switched on and no launcher answers. ``d_x`` is switched off: the
    sandbox of ``d-x`` stays, and a sandbox of ``d_x`` under the folded name is told apart by its label."""
    root, log = tmp_path / "root", []
    markers = FakeMarkers(log)
    monkeypatch.setattr(SW, "marker_api", lambda: markers)
    monkeypatch.setattr(SW, "launcher_call", lambda *a, **kw: (0, None))
    runtime, layouts = FakeRuntime(tmp_path / "py.exe", tmp_path), {}
    for name in ("d_x", "d-x"):
        (root / "profiles" / name).mkdir(parents=True)
        layouts[name] = ProfileLayout(name=name, home=root / "profiles" / name, root=root)
        LS.write_definition(LS.define(layouts[name], runtime, {}))
        markers.marked.add(name)
    side = OFF.Side(kind, tmp_path, log)
    monkeypatch.setattr("openshell.launcher_cli.make_driver", lambda spec: side.driver)
    _others(monkeypatch, ["d-x"])

    def off():
        return SW.turn_off_here(layouts["d_x"], runtime=runtime, manager=lambda defn: FakeService(defn, log),
                                sleep=lambda s: None)

    try:
        side.sandboxes.clear()
        side.sandboxes.update({OD.sandbox_name("d_x"): _box("d_x"), "hermes-d-x": _box("d-x")})
        assert off()["marker_cleared"] is True
        assert list(side.sandboxes) == ["hermes-d-x"] and markers.marked == {"d-x"}
        # A sandbox of this profile under the folded name is ended by the same command.
        markers.marked.add("d_x")
        LS.write_definition(LS.define(layouts["d_x"], runtime, {}))
        side.sandboxes["hermes-d-x"] = _box("d_x")
        assert off()["marker_cleared"] is True and side.sandboxes == {}
    finally:
        side.listener.end()


# -- providers --------------------------------------------------------------------------------------------------

def test_a_start_under_a_new_name_leaves_the_provider_another_profiles_sandbox_uses(tmp_path, monkeypatch):
    theirs, mine = "hermes-d-x-llama-api-key-0000aaaa", "hermes-d-x-other-key-1111bbbb"
    sup, api, layout = _linux(tmp_path, monkeypatch, "d_x")
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    (layout.state_dir / "providers.json").write_text(json.dumps([theirs, mine]), encoding="utf-8")
    forgotten = lambda: [call[1] for call in api.calls if call[0] == "provider delete"]  # noqa: E731

    async def scenario():
        _others(monkeypatch, ["d-x"])  # d-x is switched on: a provider under the shared name can be its own
        await sup.start()
        await sup.stop()
        assert theirs not in forgotten() and mine not in forgotten()
        assert all(name.startswith(OD.sandbox_name("d_x") + "-") for name in api.providers)
        _others(monkeypatch, [])  # d-x is switched off: the folded name is this profile's alone
        await sup.start()
        await sup.stop()
        assert {theirs, mine} <= set(forgotten())

    asyncio.run(scenario())


# -- the state folder -------------------------------------------------------------------------------------------

def test_a_profile_named_like_the_runtimes_folder_is_refused_on_the_page_too(tmp_path, monkeypatch):
    monkeypatch.setattr(SW, "_hermes_too_old", lambda: False)
    home = tmp_path / "root" / "profiles" / "runtime"
    home.mkdir(parents=True)
    layout = L.ProfileLayout(name="runtime", home=home, root=tmp_path / "root")
    assert SW.availability(layout, check_host=False) == {"available": False,
                                                         "reason": "Not available for a profile named runtime."}
    log = []
    with pytest.raises(SW.SwitchError) as err:
        SW.turn_on(layout, runtime=FakeRuntime(tmp_path / "py.exe", tmp_path), environ={}, sleep=lambda s: None,
                   manager=lambda defn: FakeService(defn, log), make_driver=lambda spec: None)
    assert str(err.value) == "Not available for a profile named runtime." and log == []  # nothing was registered
