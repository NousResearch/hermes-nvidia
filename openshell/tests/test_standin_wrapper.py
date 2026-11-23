"""The sandbox's start-up step: ``python -m <plugin package>.inside.standin -- <command...>``.

It writes the stand-in sign-in files into the profile home, exports the aliases of token variables and then runs
the command so that the sandbox holds the same processes, with the same exit code, as without the step.
Fabricated values only; no Hermes code runs here.
"""
import errno
import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from openshell.inside import standin

TREE = Path(__file__).resolve().parents[2]  # the folder that holds the plugin package
PACKAGE = Path(__file__).resolve().parents[1].name
MODULE = f"{PACKAGE}.inside.standin"
POSIX = os.name != "nt"

# What the command under the step reports about the process it runs in.
REPORT = r'''
import json, os, sys
home = os.environ.get("HERMES_HOME") or ""
store = os.path.join(home, "auth.json")
print(json.dumps({
    "pid": os.getpid(), "ppid": os.getppid(), "argv": sys.argv, "name": __name__,
    "store": open(store, encoding="utf-8").read() if home and os.path.isfile(store) else None,
    "token": os.environ.get("SOME_TOKEN"), "template": os.environ.get("HERMES_OPENSHELL_STANDIN"),
    "modules": sorted(m for m in sys.modules if m.split(".")[0] in ("PACKAGE", "hermes_cli", "agent", "hermes_constants")),
    "path0": sys.path[0],
}), flush=True)
sys.exit(int(sys.argv[1]) if len(sys.argv) > 1 else 0)
'''.replace("PACKAGE", PACKAGE)


def placeholder(env: str) -> str:
    return f"openshell:resolve:env:s{'5c' * 32}_{env}"


def template_for(doc=None, env_tokens=("SOME_TOKEN",)):
    doc = doc or {"version": 1, "providers": {"nous": {"access_token": "REAL-token-0123456789", "scope": "inference:invoke",
                                                      "refresh_token": "RT-0123456789", "expires_in": 900}},
                  "active_provider": "nous"}
    template, _ = standin.build_template({"auth.json": doc, ".anthropic_oauth.json": None}, list(env_tokens))
    environ = {}
    for ident, entry in template["credentials"].items():
        entry["env"] = entry["field"] if ident.startswith("env:") else "CRED_NOUS"
        environ[entry["env"]] = placeholder(entry["env"])
    return template, environ


@pytest.fixture
def home(tmp_path):
    folder = tmp_path / "profile"
    folder.mkdir()
    return folder


def leftovers(home: Path) -> list:
    return sorted(p.name for p in home.iterdir() if p.name.endswith(".new"))


# -- writing the files -------------------------------------------------------------------------------------------

def test_the_files_are_written_with_the_aliases_and_private(home):
    template, environ = template_for()
    exports = standin.install(template, home, environ, now=1_800_000_000)
    doc = json.loads((home / "auth.json").read_text(encoding="utf-8"))
    token = doc["providers"]["nous"]["access_token"]
    assert token.split(".")[2] == "OPENSHELL-RESOLVE-ENV-" + environ["CRED_NOUS"].split("env:")[1]
    assert doc["providers"]["nous"]["refresh_token"] == "held-on-the-host"
    assert exports["SOME_TOKEN"].split(".")[2] == "OPENSHELL-RESOLVE-ENV-" + environ["SOME_TOKEN"].split("env:")[1]
    assert not (home / ".anthropic_oauth.json").exists() and leftovers(home) == []
    if POSIX:
        assert stat.S_IMODE((home / "auth.json").stat().st_mode) == 0o600


def test_whatever_stands_at_the_name_is_replaced(home):
    template, environ = template_for()
    (home / "auth.json").write_text('{"providers": {"nous": {"access_token": "an earlier one"}}}', encoding="utf-8")
    os.chmod(home / "auth.json", stat.S_IREAD)
    (home / ".anthropic_oauth.json").write_text("{}", encoding="utf-8")  # the template says: absent
    standin.install(template, home, environ)
    assert "an earlier one" not in (home / "auth.json").read_text(encoding="utf-8")
    assert not (home / ".anthropic_oauth.json").exists()
    (home / "auth.json").unlink()
    (home / "auth.json").mkdir()  # a folder planted under the file's name
    (home / "auth.json" / "inner.txt").write_text("x", encoding="utf-8")
    standin.install(template, home, environ)
    assert (home / "auth.json").is_file() and "OPENSHELL-RESOLVE-ENV-" in (home / "auth.json").read_text(encoding="utf-8")


def _link(target: Path, name: Path, folder: bool = False) -> None:
    try:
        os.symlink(target, name, target_is_directory=folder)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"this account cannot create a symbolic link: {exc}")


def test_a_planted_link_is_replaced_and_never_followed(home, tmp_path):
    template, environ = template_for()
    outside = tmp_path / "outside.json"
    outside.write_text("the sandbox wanted this overwritten", encoding="utf-8")
    other = tmp_path / "other.json"
    other.write_text("and this one removed", encoding="utf-8")
    _link(outside, home / "auth.json")
    _link(other, home / ".anthropic_oauth.json")
    standin.install(template, home, environ)
    assert outside.read_text(encoding="utf-8") == "the sandbox wanted this overwritten"
    assert other.read_text(encoding="utf-8") == "and this one removed"
    assert not (home / "auth.json").is_symlink() and (home / "auth.json").is_file()
    assert not os.path.lexists(home / ".anthropic_oauth.json")


def test_a_planted_link_to_a_folder_is_replaced_and_the_folder_left_alone(home, tmp_path):
    template, environ = template_for()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "kept.txt").write_text("kept", encoding="utf-8")
    for name in ("auth.json", ".anthropic_oauth.json"):  # one name is written, the other is to be absent
        if POSIX:
            _link(outside, home / name, folder=True)
        else:
            import _winapi
            _winapi.CreateJunction(str(outside), str(home / name))
    standin.install(template, home, environ)
    assert (outside / "kept.txt").read_text(encoding="utf-8") == "kept" and sorted(p.name for p in outside.iterdir()) == ["kept.txt"]
    assert (home / "auth.json").is_file() and not (home / "auth.json").is_symlink()
    assert not os.path.lexists(home / ".anthropic_oauth.json")
    if POSIX:  # a link that points nowhere is taken away as well
        _link(home / "nowhere", home / ".anthropic_oauth.json")
        standin.install(template, home, environ)
        assert not os.path.lexists(home / ".anthropic_oauth.json")


def test_nothing_is_written_outside_the_home(home, tmp_path):
    template, environ = template_for()
    template["files"]["../escaped.json"] = {"x": 1}
    with pytest.raises(standin.StandinError, match="not a sign-in file"):
        standin.install(template, home, environ)
    assert not (tmp_path / "escaped.json").exists() and list(home.iterdir()) == []
    with pytest.raises(standin.StandinError, match="not a folder"):
        standin.install(template_for()[0], home / "missing", environ)


def test_a_missing_placeholder_leaves_the_home_as_it_was(home):
    template, environ = template_for()
    (home / "auth.json").write_text("what was there", encoding="utf-8")
    del environ["CRED_NOUS"]
    with pytest.raises(standin.StandinError, match=r"sign-in for nous \(nous:access_token\).*CRED_NOUS holds no placeholder"):
        standin.install(template, home, environ)
    assert (home / "auth.json").read_text(encoding="utf-8") == "what was there" and leftovers(home) == []


def test_a_file_mounted_at_the_name_is_rewritten_in_place(home, monkeypatch):
    """A mounted file cannot be replaced (the system answers 'busy'): its content is rewritten, and only when it
    is a plain file with no second name."""
    template, environ = template_for()
    (home / "auth.json").write_text("{}", encoding="utf-8")
    real_replace = os.replace

    def busy(src, dst, **kwargs):
        if os.path.basename(dst) == "auth.json":
            raise OSError(errno.EBUSY, "Device or resource busy")
        return real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", busy)
    before = (home / "auth.json").stat().st_ino
    standin.install(template, home, environ)
    assert "OPENSHELL-RESOLVE-ENV-" in (home / "auth.json").read_text(encoding="utf-8")
    assert (home / "auth.json").stat().st_ino == before and leftovers(home) == []
    try:
        os.link(home / "auth.json", home / "second-name.json")
    except OSError as exc:
        pytest.skip(f"no hard links here: {exc}")
    (home / "auth.json").write_text("{}", encoding="utf-8")
    with pytest.raises(standin.StandinError, match="could not write auth.json"):
        standin.install(template, home, environ)
    assert (home / "second-name.json").read_text(encoding="utf-8") == "{}" and leftovers(home) == []


# -- reading the template ----------------------------------------------------------------------------------------

def test_without_the_variable_nothing_is_read_or_written(home):
    assert standin.prepare({"HERMES_HOME": str(home)}) == {}
    assert standin.prepare({"HERMES_HOME": str(home), standin.TEMPLATE_ENV: ""}) == {}
    assert list(home.iterdir()) == []


def test_a_template_that_cannot_be_read_stops_the_start(home, tmp_path):
    template, environ = template_for()
    path = tmp_path / "template.json"
    with pytest.raises(standin.StandinError, match="could not read the sign-in template"):
        standin.prepare({standin.TEMPLATE_ENV: str(path), "HERMES_HOME": str(home), **environ})
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(standin.StandinError, match="could not read the sign-in template"):
        standin.prepare({standin.TEMPLATE_ENV: str(path), "HERMES_HOME": str(home), **environ})
    path.write_text(json.dumps(template), encoding="utf-8")
    with pytest.raises(standin.StandinError, match="HERMES_HOME is not set"):
        standin.prepare({standin.TEMPLATE_ENV: str(path), **environ})
    assert list(home.iterdir()) == []
    assert set(standin.prepare({standin.TEMPLATE_ENV: str(path), "HERMES_HOME": str(home), **environ})) == {"SOME_TOKEN"}


# -- running the command -----------------------------------------------------------------------------------------

def base_env(tmp_path, **extra) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in (standin.TEMPLATE_ENV, "HERMES_HOME", "SOME_TOKEN")}
    env["PYTHONPATH"] = os.pathsep.join([str(TREE), str(tmp_path)])
    env.update({k: str(v) for k, v in extra.items()})
    return env


def reporter(tmp_path) -> None:
    (tmp_path / "standin_report.py").write_text(REPORT, encoding="utf-8")


def step(tmp_path, command, *, how=None, by_path=False, timeout=60, **extra):
    """Run the start-up step in a process of its own, the way the sandbox's start command names it."""
    reporter(tmp_path)
    if how:  # a way of running the command other than this system's own
        head = [sys.executable, "-c", f"import sys; from {MODULE} import main; sys.exit(main(sys.argv[1:], mode={how!r}))"]
    elif by_path:
        head = [sys.executable, standin.__file__]
    else:
        head = [sys.executable, "-m", MODULE]
    return subprocess.run([*head, "--", *command], env=base_env(tmp_path, **extra), capture_output=True, text=True,
                          timeout=timeout)


def with_template(tmp_path, home) -> dict:
    template, environ = template_for()
    (tmp_path / "template.json").write_text(json.dumps(template), encoding="utf-8")
    return {standin.TEMPLATE_ENV: tmp_path / "template.json", "HERMES_HOME": home, **environ}


def test_without_a_template_the_command_runs_unchanged(tmp_path, home):
    done = step(tmp_path, [sys.executable, "-m", "standin_report", "7", "--flag", "-- x"], HERMES_HOME=home)
    said = json.loads(done.stdout)
    assert done.returncode == 7 and done.stderr == ""
    assert said["argv"][1:] == ["7", "--flag", "-- x"] and said["name"] == "__main__"
    assert (said["store"], said["token"], said["template"]) == (None, None, None)
    assert list(home.iterdir()) == []


@pytest.mark.parametrize("by_path", [False, True])
def test_the_store_is_in_place_before_the_command_starts(tmp_path, home, by_path):
    extra = with_template(tmp_path, home)
    done = step(tmp_path, [sys.executable, "-m", "standin_report", "3"], by_path=by_path, **extra)
    assert done.returncode == 3, done.stderr
    said = json.loads(done.stdout)
    token = json.loads(said["store"])["providers"]["nous"]["access_token"]
    assert token.split(".")[2] == "OPENSHELL-RESOLVE-ENV-" + extra["CRED_NOUS"].split("env:")[1]
    assert said["token"].split(".")[2] == "OPENSHELL-RESOLVE-ENV-" + extra["SOME_TOKEN"].split("env:")[1]
    assert said["template"] == str(tmp_path / "template.json")
    # The command starts in an interpreter that holds nothing of this step, of Hermes or of the launcher.
    assert said["modules"] == [] and said["name"] == "__main__"
    assert os.path.abspath(said["path0"] or os.getcwd()) != os.path.dirname(os.path.abspath(standin.__file__))


def test_a_start_that_cannot_prepare_the_store_names_the_provider_and_runs_nothing(tmp_path, home):
    extra = with_template(tmp_path, home)
    extra["CRED_NOUS"] = "sk-not-a-placeholder"
    done = step(tmp_path, [sys.executable, "-m", "standin_report"], **extra)
    assert done.returncode == standin.EXIT_START_ERROR == 78 and done.stdout == ""
    assert "the sign-in store could not be prepared: sign-in for nous (nous:access_token)" in done.stderr
    assert "sk-not-a-placeholder" not in done.stderr and "Traceback" not in done.stderr
    assert list(home.iterdir()) == []


def test_a_command_is_needed_and_must_exist(tmp_path, home):
    assert step(tmp_path, []).returncode == 2
    done = step(tmp_path, [str(tmp_path / "no-such-program")], how="exec" if POSIX else "child")
    assert done.returncode == 127 and "could not run" in done.stderr


def test_which_way_a_command_runs_on_which_system():
    hermes = [sys.executable, "-m", "hermes_cli.main", "serve", "--isolated"]
    assert standin._mode_for(hermes, "posix") == "exec" and standin._mode_for(["sh", "-c", "true"], "posix") == "exec"
    assert standin._mode_for(hermes, "nt") == "inline"
    assert standin._mode_for([sys.executable, "script.py"], "nt") == "child"
    assert standin._mode_for(["another-python", "-m", "hermes_cli.main"], "nt") == "child"
    assert standin._mode_for(hermes) == ("exec" if POSIX else "inline")


@pytest.mark.skipif(not POSIX, reason="a process cannot replace itself on Windows")
def test_the_step_becomes_the_command(tmp_path, home):
    """The process the sandbox started is the command: the same process id, and a signal reaches it directly."""
    reporter(tmp_path)
    extra = with_template(tmp_path, home)
    running = subprocess.Popen([sys.executable, "-m", MODULE, "--", sys.executable, "-m", "standin_report", "4"],
                               env=base_env(tmp_path, **extra), stdout=subprocess.PIPE, text=True)
    out, _ = running.communicate(timeout=60)
    said = json.loads(out)
    assert (said["pid"], said["ppid"], running.returncode) == (running.pid, os.getpid(), 4)
    waiting = subprocess.Popen([sys.executable, "-m", MODULE, "--", sys.executable, "-c",
                                "import sys, time; print('up', flush=True); time.sleep(60)"],
                               env=base_env(tmp_path, **extra), stdout=subprocess.PIPE, text=True)
    assert waiting.stdout.readline().strip() == "up"
    waiting.send_signal(signal.SIGTERM)
    assert waiting.wait(timeout=30) == -signal.SIGTERM


def test_a_command_of_this_interpreter_runs_in_the_same_process(tmp_path, home):
    """What Windows gets, where no process can replace itself: ``python -m module`` runs in the step's process
    the way ``python -m`` runs it."""
    extra = with_template(tmp_path, home)
    reporter(tmp_path)
    running = subprocess.Popen(
        [sys.executable, "-c", f"import sys; from {MODULE} import main; sys.exit(main(sys.argv[1:], mode='inline'))",
         "--", sys.executable, "-m", "standin_report", "5", "serve"],
        env=base_env(tmp_path, **extra), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = running.communicate(timeout=60)
    said = json.loads(out)
    assert running.returncode == 5, err
    assert said["name"] == "__main__" and said["argv"][1:] == ["5", "serve"]
    assert said["argv"][0] == str(tmp_path / "standin_report.py")  # as ``python -m`` sets it
    assert said["modules"] == []  # nothing of the step is left in the interpreter
    assert json.loads(said["store"])["providers"]["nous"]["refresh_token"] == "held-on-the-host"
    if POSIX:  # a Windows venv starts its interpreter as a child of the venv's own python.exe
        assert said["pid"] == running.pid


def test_a_command_that_ends_without_an_exit_code_ends_the_step_with_zero(tmp_path):
    (tmp_path / "standin_quiet.py").write_text("print('done')\n", encoding="utf-8")
    done = step(tmp_path, [sys.executable, "-m", "standin_quiet"], how="inline")
    assert (done.returncode, done.stdout.strip()) == (0, "done")
    (tmp_path / "standin_fails.py").write_text("raise RuntimeError('the command failed')\n", encoding="utf-8")
    done = step(tmp_path, [sys.executable, "-m", "standin_fails"], how="inline")
    assert done.returncode == 1 and "RuntimeError: the command failed" in done.stderr


def test_a_child_command_passes_its_exit_code_on(tmp_path, home):
    extra = with_template(tmp_path, home)
    done = step(tmp_path, [sys.executable, "-m", "standin_report", "9"], how="child", **extra)
    said = json.loads(done.stdout)
    assert done.returncode == 9 and said["token"] and said["store"] and said["modules"] == []


@pytest.mark.skipif(not POSIX, reason="signals")
def test_a_signal_to_the_step_reaches_a_child_command_and_ends_both_the_same_way(tmp_path):
    reporter(tmp_path)
    running = subprocess.Popen(
        [sys.executable, "-c", f"import sys; from {MODULE} import main; sys.exit(main(sys.argv[1:], mode='child'))",
         "--", sys.executable, "-c", "import os, time; print(os.getpid(), flush=True); time.sleep(60)"],
        env=base_env(tmp_path), stdout=subprocess.PIPE, text=True)
    child = int(running.stdout.readline())
    running.send_signal(signal.SIGTERM)
    assert running.wait(timeout=30) == -signal.SIGTERM
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("the command outlived the step")
