"""Hermes itself, unchanged, in a sandbox that started without the sign-in its model needs.

A sign-in that has ended is left out of a sandbox start: the sandbox gets no credential for it. Hermes inside
then looks for that provider's sign-in wherever it looks on a computer that is not signed in. One of those places
is outside everything a sandbox may open: the Nous Portal sign-in that every profile of this computer shares is
kept below the Hermes root (``<root>/shared``), and Hermes takes a lock file there before it looks. A sandbox
can neither open nor make that folder, and a chat turn ended with ``[Errno 13] Permission denied:
'<root>/shared'`` in place of Hermes's sentence for a provider that is not signed in.

The launcher therefore gives every sandbox a shared sign-in folder of its own, empty at every start, and names it
to Hermes inside (``HERMES_SHARED_AUTH_DIR``; ``layout.fresh_shared_sign_in_dir``, ``Supervisor._launch_request``).

Here: what the launch request carries on both drivers; then, for every provider a profile can be signed in to and
for a provider that uses a key, Hermes's own code asked for the model of a chat in a home whose stand-in store
has nothing for that provider, with the Hermes root closed as it is to a sandbox. Every path below the root that
Hermes tried to open, list or make is recorded. What the chat shows is Hermes's own sentence for the error.

Fabricated values only; every request goes to the loopback stub of ``standin_stub.py``. The cases that run
Hermes are skipped without a Hermes checkout on the import path.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("hermes_cli.auth", reason="needs a Hermes checkout on the import path")
pytest.importorskip("run_agent", reason="needs a Hermes checkout on the import path")

import standin_stub  # noqa: E402
import test_openshell_driver as LD  # noqa: E402
from test_standin_with_hermes import CASES, Homes, agent_for, record, stub  # noqa: E402,F401

from openshell.inside import standin  # noqa: E402
from openshell.launcher import layout as L  # noqa: E402
from openshell.launcher import supervisor as S  # noqa: E402
from openshell.launcher.driver import SandboxDriver  # noqa: E402
from openshell.launcher.spec import load_spec  # noqa: E402

SHARED_ENV = "HERMES_SHARED_AUTH_DIR"
# The provider of each case as Hermes names it in its store, and what the chat shows for a model on it once the
# sandbox has started without that sign-in: after the provider refused a renewal, and with nothing of it inside.
PROVIDER = {"nous": "nous", "openai-codex": "openai-codex", "xai-oauth": "xai-oauth",
            "minimax-oauth": "minimax-oauth", "anthropic-file": "anthropic", "anthropic-row": "anthropic"}
OTHER = {"nous": "openai-codex"}  # a second sign-in the profile keeps (Nous Portal for every other case)
NOT_SIGNED_IN = {
    "nous": ("No access token found for Nous Portal login.", "Hermes is not logged into Nous Portal."),
    "openai-codex": ("No Codex credentials stored.",) * 2,
    "xai-oauth": ("xAI OAuth state is missing access_token.", "No xAI OAuth credentials stored."),
    "minimax-oauth": ("Not logged into MiniMax OAuth.",) * 2,
    "anthropic-file": ("No Anthropic credentials found.",) * 2,
    "anthropic-row": ("No Anthropic credentials found.",) * 2,
}


# -- the Hermes root as a sandbox meets it -----------------------------------------------------------------------

_FENCE = {"root": None, "open": (), "refused": []}
_FENCED_EVENTS = frozenset(("open", "os.mkdir", "os.listdir", "os.scandir", "os.remove", "os.rename", "os.rmdir",
                            "os.chmod", "os.utime", "os.link", "os.symlink", "os.truncate"))


def _fence_hook(event, args):
    root = _FENCE["root"]
    if root is None or event not in _FENCED_EVENTS:
        return
    for arg in args[:2]:
        if not isinstance(arg, (str, bytes, os.PathLike)):
            continue
        path = os.path.normcase(os.path.abspath(os.fsdecode(arg)))
        if (path == root or path.startswith(root + os.sep)) and not any(
                path == ok or path.startswith(ok + os.sep) for ok in _FENCE["open"]):
            _FENCE["refused"].append((event, os.path.relpath(path, root).replace(os.sep, "/")))
            raise PermissionError(13, "Permission denied", os.fsdecode(arg))


@pytest.fixture
def fence():
    """``fence(root, open)``: from then on nothing below *root* can be opened, listed, made, changed or removed,
    except below the folders *open*; what was tried is ``fence.refused()``. One hook for the process (a hook
    cannot be taken off again); it does nothing outside this fixture."""
    if not getattr(sys, "_openshell_test_fence", False):
        sys.addaudithook(_fence_hook)
        sys._openshell_test_fence = True

    def close(root, open_dirs):
        _FENCE.update(root=os.path.normcase(os.path.abspath(root)), refused=[],
                      open=tuple(os.path.normcase(os.path.abspath(folder)) for folder in open_dirs))

    close.refused = lambda: sorted(set(_FENCE["refused"]))
    try:
        yield close
    finally:
        _FENCE.update(root=None, open=(), refused=[])


class NoSandbox(SandboxDriver):
    name = "fake"
    uses_host_shell = False
    capabilities_info = {"label": "Fake"}

    def preflight(self):
        return {}

    def start(self, request):
        pass

    def exit_code(self):
        return None

    def stop(self, timeout=20.0):
        pass

    def policy(self):
        return {}


def launch(home: Path, tmp_path: Path):
    """The launch request the launcher makes for the profile at *home* (a named profile of the root two folders
    up): what the sandbox may write, and the variables Hermes inside starts with."""
    layout = L.ProfileLayout(name=home.name, home=home, root=home.parent.parent)
    runtime = L.Runtime(python=tmp_path / "python.exe", code_dir=tmp_path, env_dir=tmp_path, base_python=tmp_path,
                        store=None)
    sup = S.Supervisor(layout, runtime, load_spec(layout), NoSandbox(), outer_port=1)
    request, _folders = sup._launch_request({})
    return layout, request


def _profile(tmp_path) -> Path:
    home = tmp_path / "root" / "profiles" / "work"
    home.mkdir(parents=True)
    (home / "config.yaml").write_text("{}\n", encoding="utf-8")
    return home


# -- what the launcher hands the sandbox -------------------------------------------------------------------------

def test_the_sandbox_gets_a_shared_sign_in_folder_of_its_own(tmp_path):
    home = _profile(tmp_path)
    real = tmp_path / "root" / "shared"
    real.mkdir()
    (real / "nous_auth.json").write_text('{"access_token": "made-up", "refresh_token": "x"}', encoding="utf-8")
    layout, request = launch(home, tmp_path)
    folder = Path(request.env[SHARED_ENV])
    assert folder == L.shared_sign_in_dir(layout) and folder.is_dir() and list(folder.iterdir()) == []
    assert layout.box in folder.parents  # in the sandbox's own scratch,
    assert folder in request.grants.readwrite  # which it may write (Hermes keeps a lock file there),
    assert folder != real and real not in folder.parents and home not in folder.parents  # never the real one
    assert sorted(p.name for p in real.iterdir()) == ["nous_auth.json"]  # which nothing here touched


def test_the_folder_is_empty_again_at_every_start(tmp_path):
    """Hermes inside may write there (its lock, a copy of the stand-in sign-in). A sandbox that starts without a
    sign-in must not find what an earlier one left."""
    home = _profile(tmp_path)
    layout, request = launch(home, tmp_path)
    folder = Path(request.env[SHARED_ENV])
    (folder / "nous_auth.json").write_text('{"access_token": "left by the sandbox before"}', encoding="utf-8")
    (folder / "nous_auth.lock").write_text(" ", encoding="utf-8")
    (folder / "deeper" / "still").mkdir(parents=True)
    (folder / "deeper" / "still" / "file").write_text("x", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "kept.txt").write_text("the user's", encoding="utf-8")
    linked = True
    try:
        os.symlink(outside, folder / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        linked = False  # this computer does not let the test make a link
    _, again = launch(home, tmp_path)
    assert Path(again.env[SHARED_ENV]) == folder and list(folder.iterdir()) == []
    assert (outside / "kept.txt").read_text(encoding="utf-8") == "the user's", linked  # a link is taken off, not followed


def test_a_file_under_the_folders_name_is_replaced_by_the_folder(tmp_path):
    home = _profile(tmp_path)
    layout = L.ProfileLayout(name="work", home=home, root=home.parent.parent)
    L.shared_sign_in_dir(layout).parent.mkdir(parents=True)
    L.shared_sign_in_dir(layout).write_text("not a folder", encoding="utf-8")
    assert L.fresh_shared_sign_in_dir(layout).is_dir() and list(L.shared_sign_in_dir(layout).iterdir()) == []


def test_a_folder_that_cannot_be_emptied_stops_the_start(tmp_path, monkeypatch):
    home = _profile(tmp_path)
    layout, request = launch(home, tmp_path)
    (Path(request.env[SHARED_ENV]) / "nous_auth.json").write_text("{}", encoding="utf-8")

    def held(path, *args, **kwargs):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(os, "unlink", held)
    monkeypatch.setattr(os, "remove", held)
    with pytest.raises(S.SandboxStartError, match="sign-in folder of its own could not be emptied"):
        launch(home, tmp_path)


def test_the_linux_sandbox_is_handed_the_folder_and_its_name(tmp_path, monkeypatch):
    """The Linux driver builds the sandbox's variables and mounts itself: the folder is mounted read & write at
    its own path, it is among the paths the sandbox may write, and Hermes inside is told its name."""
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        try:
            (_, _, spec), = [call for call in api.calls if call[0] == "create"]
            folder = spec["environment"][SHARED_ENV]
            assert Path(folder) == L.shared_sign_in_dir(layout) and Path(folder).is_dir()
            mounts = {m["target"]: m for m in spec["template"]["driver_config"]["docker"]["mounts"]}
            assert mounts[folder]["read_only"] is False and mounts[folder]["source"] == folder
            assert folder in sup.driver._plan.read_write
            assert folder in spec["environment"]["HERMES_WRITE_SAFE_ROOT"].split(os.pathsep)
            assert not [target for target in mounts if Path(target) == layout.root / "shared"]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_windows_sandbox_is_handed_the_folder_and_its_name(tmp_path):
    from types import SimpleNamespace

    import test_openshell_windows as WT
    from openshell.launcher import openshell_driver as OD
    from openshell.launcher import openshell_windows as W

    home = _profile(tmp_path)
    layout, request = launch(home, tmp_path)
    folder = request.env[SHARED_ENV]
    cfg = OD.OpenShellConfig(gateway="hermes-oswin", config_home=tmp_path / "xdg", cli=tmp_path / "openshell.exe")
    driver = WT._driver(cfg, WT.FakeCli(), tmp_path)
    env, _ = driver._sandbox_env(SimpleNamespace(env=dict(request.env), home=str(home), config_dir=layout.state_dir))
    assert env[SHARED_ENV] == folder
    policy, denied, _notes = W.build_windows_policy(request.grants, {"egress": "deny", "allow": []}, [])
    assert W.native(Path(folder)) in policy["filesystem_policy"]["read_write"]
    assert W.native(Path(folder)) not in denied and W.native(layout.root / "shared") not in denied


# -- Hermes inside, without the sign-in --------------------------------------------------------------------------

@pytest.fixture
def homes(tmp_path, monkeypatch, stub):  # noqa: F811
    made = Homes(tmp_path, monkeypatch, stub)
    monkeypatch.delenv(SHARED_ENV, raising=False)
    yield made
    assert not stub.escaped, stub.escaped


def refused_on_the_host(homes, provider: str) -> None:  # noqa: F811
    """The provider refuses to renew the sign-in, met by Hermes's own renewal in the host's home: the store is
    left as Hermes leaves it then (for Nous Portal: the row without its tokens)."""
    import signin_home

    asked = len(homes.stub.refreshes())
    homes.stub.refresh_answer = (400, {"error": "invalid_grant", "error_description": "the sign-in has ended"})
    try:
        with pytest.raises(Exception):  # noqa: B017,PT011 - whatever Hermes raises for a refused renewal
            signin_home.renew_in_home(provider)
    finally:
        homes.stub.refresh_answer = None
    assert len(homes.stub.refreshes()) > asked, "the renewal was never tried"


def enter_without(homes, tmp_path, model: dict, gone: str) -> list:  # noqa: F811
    """Switch the sandbox on as the launcher does when the sign-in *gone* is left out of the start
    (``standins.build`` with ``SignIns.for_start``): no credential of that provider gets a variable, its rows
    leave the stand-in store, a sign-in file with nothing handed in gets no stand-in at all; the variables are
    the launch request's. Returns the folders the sandbox may write."""
    template, credentials = standin.build_template(homes.stores(), ())
    left_out = [c["id"] for c in credentials if c["provider"] == gone]
    for number, credential in enumerate(credentials):
        if credential["id"] not in left_out:
            variable = f"HERMES_SANDBOX_CRED_{number}"
            template["credentials"][credential["id"]]["env"] = variable
            homes.patch.setenv(variable, standin_stub.placeholder(variable, stable=number % 2 == 0))
    template = standin.without(template, left_out)
    for name in sorted(template["files"]):
        doc = template["files"][name]
        if doc is None or "@@alias:" not in json.dumps(doc) and "@@placeholder:" not in json.dumps(doc):
            del template["files"][name]
    path = homes.tmp / "standin-template.json"
    path.write_text(json.dumps(template), encoding="utf-8")
    homes.patch.setenv(standin.TEMPLATE_ENV, str(path))
    homes.patch.setenv("HERMES_HOME", str(homes.inside))
    lines = ["model:"] + [f"  {key}: {value}" for key, value in model.items()]
    (homes.inside / "config.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for name, value in standin.prepare().items():
        homes.patch.setenv(name, value)
    _layout, request = launch(homes.inside, tmp_path)
    if SHARED_ENV in request.env:
        homes.patch.setenv(SHARED_ENV, request.env[SHARED_ENV])
    homes.stub.clear()
    return [homes.inside, *request.grants.readwrite]


def the_rest_of_the_root(homes) -> Path:  # noqa: F811
    """The Hermes root of the sandbox's profile with what a real one holds outside the profile: the shared Nous
    Portal sign-in and the default profile's own store, signed in. Present, and closed to the sandbox."""
    root = homes.inside.parent.parent
    host = homes.stores()["auth.json"] or {}
    (root / "shared").mkdir(exist_ok=True)
    (root / "shared" / "nous_auth.json").write_text(
        json.dumps({"access_token": "made-up-access", "refresh_token": "made-up-refresh"}), encoding="utf-8")
    (root / "auth.json").write_text(json.dumps(host), encoding="utf-8")
    return root


def a_chat(homes, model_cfg: dict) -> dict:  # noqa: F811
    """The model of a new chat as Hermes resolves it, then a turn. Returns what Hermes raised and the sentence
    the chat shows for it. Hermes keeps a process that runs under a test runner away from the shared store's
    usual place by a check of its own; a sandbox has no such check, so the runner's mark is taken off here."""
    from tui_gateway.user_messages import agent_init_failed_message

    homes.patch.delenv("PYTEST_CURRENT_TEST", raising=False)
    out = {"error": None, "says": None}
    try:
        _, agent = agent_for(model_cfg["default"])
        result = agent.run_conversation("ping", conversation_history=[], task_id="t")
        out["reply"] = str(result.get("final_response") or "")[:200]
    except Exception as exc:  # noqa: BLE001 - what Hermes raises is what is looked at
        out["error"] = f"{type(exc).__name__}: {' '.join(str(exc).split())[:300]}"
        out["says"] = agent_init_failed_message(exc)
    return out


# "refused": the provider refused a renewal, as Hermes's own renewal on this computer met it (the Anthropic
# sign-in has no renewal this kit can call: its cases are the second kind only). "ran-out": the sign-in is as it
# was and none of its credentials is handed in (its token ran out before it could be renewed).
ENDED = [(name, how) for name in sorted(PROVIDER) for how in ("refused", "ran-out")
         if how == "ran-out" or not name.startswith("anthropic")]


@pytest.mark.parametrize(("name", "how"), ENDED, ids=[f"{name}-{how}" for name, how in ENDED])
def test_a_model_whose_sign_in_the_sandbox_started_without_says_so(
        name, how, homes, stub, fence, tmp_path):  # noqa: F811
    sign_ins, _env_tokens, model_cfg, _, _ = CASES[name]
    homes.sign_in(*sign_ins, OTHER.get(name, "nous"))
    if how == "refused":
        refused_on_the_host(homes, PROVIDER[name])
    root = the_rest_of_the_root(homes)
    writable = enter_without(homes, tmp_path, model_cfg, PROVIDER[name])
    fence(root, writable)
    result = a_chat(homes, model_cfg)
    result.update(refused=fence.refused(), how=how)
    record(f"signed_out_{name}_{how}", result)
    assert result["error"] and result["says"], result  # the model does not answer: its sign-in is not there
    assert "Permission denied" not in result["says"] and "Errno" not in result["says"], result["says"]
    assert NOT_SIGNED_IN[name][how == "ran-out"] in result["says"], result["says"]
    assert "shared" not in {path.split("/")[0] for _event, path in result["refused"]}, result["refused"]
    assert stub.token_calls == [] and not stub.rows()  # nothing inside signs in, renews or asks a model


def test_a_model_whose_key_the_sandbox_did_not_get_says_so(homes, stub, fence, tmp_path):  # noqa: F811
    """A provider that uses a key: the key is in the profile's ``.env`` on this computer, the sandbox's ``.env``
    is an empty stand-in and the variable was not handed in."""
    homes.sign_in("nous")
    (homes.host / ".env").write_text("OPENROUTER_API_KEY=sk-or-v1-made-up\n", encoding="utf-8")
    model_cfg = {"provider": "openrouter", "default": "a/model"}
    root = the_rest_of_the_root(homes)
    (root / ".env").write_text("OPENROUTER_API_KEY=sk-or-v1-made-up-too\n", encoding="utf-8")
    writable = enter_without(homes, tmp_path, model_cfg, "openrouter")
    (homes.inside / ".env").write_text("", encoding="utf-8")
    fence(root, writable)
    result = a_chat(homes, model_cfg)
    result.update(refused=fence.refused())
    record("signed_out_a_key", result)
    assert result["error"] and "Permission denied" not in result["says"] and "Errno" not in result["says"], result
    assert "No LLM provider configured." in result["says"], result["says"]
    assert {kind for row in stub.rows() for kind in row["cred"].values()} <= {"absent"}  # the public model list
