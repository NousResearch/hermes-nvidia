"""The busybox terminal backend against the Hermes it is loaded into.

``BusyboxEnvironment`` subclasses Hermes's local terminal backend and replaces some of its internal steps: the
per-command wrapper, the shell start, the reading of a command's cwd marker. Hermes calls those steps with its own
arguments, under its own names, and both change between Hermes releases. A step that no longer takes what Hermes
passes fails every terminal command in the sandbox; a step Hermes renamed is skipped without any error. So the
first tests here read the Hermes that is on the path, not a stand-in of it, and run on every platform:

* every step the backend replaces takes what Hermes's own version of the step takes;
* every Hermes method the backend calls on itself is there;
* the step Hermes runs to read a command's cwd marker is one the backend replaces.

The rest drive a real busybox-w32 on a Windows host through ``execute()``, the way the terminal and file tools do.
"""
import ast
import inspect
import sys
from pathlib import Path

import pytest

from openshell import busybox_env as bb
from tools.environments.base import BaseEnvironment

WINDOWS = sys.platform == "win32"
BUSYBOX = bb.find_busybox() if WINDOWS else None
needs_busybox = pytest.mark.skipif(not BUSYBOX, reason="needs Windows and busybox-w32 (OPENSHELL_BUSYBOX or PATH)")

_HERMES_PACKAGES = ("tools", "agent")
_KIND = inspect.Parameter


def _hermes_bases(cls):
    return [base for base in cls.__mro__[1:] if base.__module__.split(".")[0] in _HERMES_PACKAGES]


def _function(member):
    return member.__func__ if isinstance(member, (staticmethod, classmethod)) else member


def _replaced_steps(cls):
    """(name, the backend's function, Hermes's function) for every method *cls* defines that Hermes also defines."""
    for name, member in vars(cls).items():
        mine = _function(member)
        if not inspect.isfunction(mine):
            continue
        owner = next((base for base in _hermes_bases(cls) if name in vars(base)), None)
        if owner is not None and inspect.isfunction(_function(vars(owner)[name])):
            yield name, mine, _function(vars(owner)[name])


# --- the Hermes on the path: every platform ----------------------------------------------------------

def test_every_step_the_backend_replaces_takes_what_hermes_passes():
    """Hermes calls a replaced step with the arguments of its own version. A parameter Hermes has and the
    backend lacks is a TypeError the first time Hermes passes it (``cwd_fallback`` on every command)."""
    checked, missing = [], []
    for name, mine, theirs in _replaced_steps(bb.BusyboxEnvironment):
        if name == "__init__":  # built by the plugin's own provider, never by Hermes
            continue
        got = inspect.signature(mine).parameters
        any_keyword = any(p.kind is _KIND.VAR_KEYWORD for p in got.values())
        any_positional = any(p.kind is _KIND.VAR_POSITIONAL for p in got.values())
        for param in inspect.signature(theirs).parameters.values():
            if param.kind in (_KIND.VAR_POSITIONAL, _KIND.VAR_KEYWORD):
                continue
            if param.name in got:
                if param.kind is _KIND.KEYWORD_ONLY and got[param.name].kind is _KIND.POSITIONAL_ONLY:
                    missing.append(f"{name}({param.name}=...)")
                continue
            if not (any_keyword or (any_positional and param.kind is not _KIND.KEYWORD_ONLY)):
                missing.append(f"{name}({param.name})")
        checked.append(name)
    assert not missing, f"Hermes passes what the busybox backend does not take: {missing}"
    assert {"_wrap_command", "_run_bash", "_wait_for_process", "_kill_process"} <= set(checked), checked


def _calls_on_self(cls):
    """Names of the methods *cls*'s own source calls as ``self.<name>(...)`` or ``super().<name>(...)``."""
    tree = ast.parse(Path(inspect.getsourcefile(cls)).read_text(encoding="utf-8"))
    body = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == cls.__name__)
    names = set()
    for node in ast.walk(body):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        target = node.func.value
        if isinstance(target, ast.Name) and target.id == "self":
            names.add(node.func.attr)
        elif isinstance(target, ast.Call) and isinstance(target.func, ast.Name) and target.func.id == "super":
            names.add(node.func.attr)
    return names


def test_every_hermes_step_the_backend_calls_is_there():
    """A step Hermes removed (``_recover_cwd``) is an AttributeError at the first shell start. A name that only
    some Hermes versions have is asked for with ``getattr``, which this test does not count."""
    called = _calls_on_self(bb.BusyboxEnvironment)
    assert {"_update_cwd", "_snapshot_script_kwargs", "get_temp_dir"} <= called, called
    gone = sorted(name for name in called if not hasattr(bb.BusyboxEnvironment, name))
    assert not gone, f"the busybox backend calls steps this Hermes does not have: {gone}"


def test_the_step_hermes_runs_for_a_cwd_marker_is_the_backends():
    """Hermes reads a command's cwd marker in one step, called from ``_update_cwd``; the backend replaces that
    step to put the path in native form. If Hermes runs a step the backend does not replace, the native-form
    rule is skipped and nothing fails."""
    known = ("_parse_cwd_marker", "_extract_cwd_from_output")
    source = inspect.getsource(BaseEnvironment._update_cwd)
    run = [name for name in known if f"self.{name}(" in source]
    assert len(run) == 1, f"Hermes's _update_cwd reads the marker in a step this backend does not know: {source}"
    assert run[0] in vars(bb.BusyboxEnvironment), f"the backend does not replace {run[0]}"
    for name in known:  # what the backend replaces, it replaces with the result argument Hermes passes
        if name in vars(bb.BusyboxEnvironment):
            assert list(inspect.signature(vars(bb.BusyboxEnvironment)[name]).parameters) == ["self", "result"]


def test_the_wrapper_is_the_same_script_whether_or_not_hermes_allows_a_cwd_fallback(tmp_path):
    """The directory is checked and swapped before the wrapper is built (``_usable_cwd``, where this Hermes has
    it: the shell and the backend see the same files), so the wrapper needs no fallback of its own."""
    env = bb.BusyboxEnvironment.__new__(bb.BusyboxEnvironment)
    env.cwd = str(tmp_path)
    env._session_id = "abc"
    env._cwd_marker = "__HERMES_CWD_abc__"
    env._snapshot_path = str(tmp_path / "hermes-snap-abc.sh")
    env._snapshot_ready = False
    env._snapshot_passthrough_names = frozenset()
    env.env = {}
    plain = env._wrap_command("echo hi", str(tmp_path))
    assert "echo hi" in plain
    assert env._wrap_command("echo hi", str(tmp_path), cwd_fallback=True) == plain
    assert env._wrap_command("echo hi", str(tmp_path), cwd_fallback=False) == plain


# --- a real busybox ------------------------------------------------------------------------------------

@pytest.fixture
def env(tmp_path):
    e = bb.BusyboxEnvironment(cwd=str(tmp_path), timeout=60, busybox=BUSYBOX)
    yield e
    e.cleanup()


def _terminal_keywords():
    """What the terminal tool adds to its own commands on this Hermes."""
    return {"allow_cwd_fallback": True} if "allow_cwd_fallback" in inspect.signature(BaseEnvironment.execute).parameters else {}


# Hermes with ``_update_cwd(result, move_session=...)`` moves the session only for a command that may move it;
# before that, every command's marker moved it and a missing session directory was swapped for its parent.
_ONLY_A_SESSION_COMMAND_MOVES = "move_session" in inspect.signature(BaseEnvironment._update_cwd).parameters


@needs_busybox
def test_a_terminal_command_runs_with_the_keywords_the_terminal_tool_passes(env, tmp_path):
    assert env._snapshot_ready
    r = env.execute("export BB_KEPT=yes && echo ok", **_terminal_keywords())
    assert r["returncode"] == 0 and r["output"].strip() == "ok", r
    r = env.execute('echo "v=$BB_KEPT"', **_terminal_keywords())
    assert r["returncode"] == 0 and r["output"].strip() == "v=yes", r


@needs_busybox
def test_cd_moves_the_session_in_native_form_and_a_one_off_directory_does_not(env, tmp_path):
    (tmp_path / "sub dir").mkdir()
    other = tmp_path / "other"
    other.mkdir()
    r = env.execute("cd 'sub dir'", **_terminal_keywords())
    assert r["returncode"] == 0, r
    assert env.cwd == str(tmp_path / "sub dir")  # C:\...\sub dir, not the shell's C:/.../sub dir
    assert r.get("cwd") in (None, str(tmp_path / "sub dir")), r
    r = env.execute("pwd", cwd=str(other))  # a file tool's command in a directory of its own
    assert r["returncode"] == 0 and Path(r["output"].strip()) == other, r
    assert env.cwd == str(tmp_path / "sub dir" if _ONLY_A_SESSION_COMMAND_MOVES else other)


@needs_busybox
def test_a_marker_that_names_no_directory_here_moves_nothing(env, tmp_path, monkeypatch):
    (tmp_path / "sub").mkdir()
    monkeypatch.setattr(bb, "native_path", lambda path: str(tmp_path / "gone"))
    r = env.execute("cd sub && echo there", **_terminal_keywords())
    assert r["returncode"] == 0 and r["output"].strip() == "there", r
    assert env.cwd == str(tmp_path)
    assert "cwd" not in r and "cwd_observed" not in r, r


@needs_busybox
def test_the_shell_still_starts_when_the_session_directory_is_gone(env, tmp_path):
    """A command that deleted the session's directory leaves a cwd no process can start in. The shell is started
    in a directory that exists. On this Hermes the wrapper's own ``cd`` then refuses the missing one (126) for a
    command that may not move the session (its rule for the file tools) and the session stays where it was; an
    earlier Hermes moved the session to the parent and ran the command there."""
    sub = tmp_path / "sub"
    sub.mkdir()
    assert env.execute("cd sub", **_terminal_keywords())["returncode"] == 0
    assert env.cwd == str(sub)
    sub.rmdir()  # nothing holds it: every command is a shell of its own
    r = env.execute("echo started")
    if _ONLY_A_SESSION_COMMAND_MOVES:
        assert r["returncode"] == 126 and "started" not in r["output"], r
        assert env.cwd == str(sub)
    else:
        assert r["returncode"] == 0 and r["output"].strip() == "started", r
        assert env.cwd == str(tmp_path)


@needs_busybox
def test_a_terminal_command_falls_back_from_a_session_directory_that_is_gone(env, tmp_path):
    if not _terminal_keywords():
        pytest.skip("this Hermes has no cwd fallback for terminal commands")
    sub = tmp_path / "sub"
    sub.mkdir()
    assert env.execute("cd sub", allow_cwd_fallback=True)["returncode"] == 0
    assert env.cwd == str(sub)
    sub.rmdir()
    r = env.execute("pwd", allow_cwd_fallback=True)
    assert r["returncode"] == 0 and Path(r["output"].strip().splitlines()[-1]) == tmp_path, r
    assert r.get("cwd_fallback") == {"requested": str(sub), "used": str(tmp_path)}, r
    assert env.cwd == str(tmp_path)  # the command's own marker moved the session to where it ran
