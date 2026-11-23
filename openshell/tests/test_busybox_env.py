"""Behaviour tests for the busybox-w32 terminal backend.

Pure path/command helpers run anywhere; the rest drive a real busybox-w32 on a Windows host
(``OPENSHELL_BUSYBOX`` or a build on PATH) through the same seams Hermes uses: ``execute()`` and the
file tools' ``ShellFileOperations``. HERMES_HOME is a temp dir (conftest.py).

Run: PYTHONPATH="<hermes checkout>;<this repo>" <hermes checkout>/.venv/Scripts/python -m pytest openshell/tests -q
"""
import sys
import time
from pathlib import Path


import pytest  # noqa: E402

from openshell import busybox_env as bb  # noqa: E402

WINDOWS = sys.platform == "win32"
BUSYBOX = bb.find_busybox() if WINDOWS else None
needs_busybox = pytest.mark.skipif(not BUSYBOX, reason="needs Windows and busybox-w32 (OPENSHELL_BUSYBOX or PATH)")


# --- pure helpers ------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw, want", [
    ("C:\\work\\x y\\f.txt", "C:/work/x y/f.txt"),
    ("/c/work/x", "C:/work/x"),
    ("/cygdrive/d/data", "D:/data"),
    ("/mnt/c/x", "C:/x"),
    ("/c", "C:/"),
    ("rel\\dir", "rel/dir"),
    ("~/x", "~/x"),
    ("/root", "/root"),
])
def test_shell_path(raw, want):
    assert bb.shell_path(raw) == want


def test_native_path():
    assert bb.native_path("C:/work/x y/sub\n") == "C:\\work\\x y\\sub"
    assert bb.native_path("/c/work") == "C:\\work"
    assert bb.native_path("relative/x") == "relative/x"


@pytest.mark.parametrize("command, want", [
    ("cat '/c/work/me/f.txt'", "cat 'C:/work/me/f.txt'"),
    ("cd /c/work && ls \"/d/data\"", "cd C:/work && ls \"D:/data\""),
    ("tool --out=/c/x/y", "tool --out=C:/x/y"),
    ("ls /mnt/c/x", "ls C:/x"),
    ("cmd /c echo hi", "cmd /c echo hi"),
    ("sed 's/c/d/' f", "sed 's/c/d/' f"),
    ("curl http://c/x", "curl http://c/x"),
    ("ls $X/c/y", "ls $X/c/y"),
    ("awk '/c/ {print}' f", "awk '/c/ {print}' f"),
    ("ls /q/x", "ls /q/x"),  # no Q: drive
    ("ls /c/", "ls /c/"),
])
def test_translate_msys_drive_paths(command, want):
    assert bb.translate_msys_drive_paths(command, {"C", "D"}) == want


def test_compose_path_drops_msys_dirs_and_puts_tools_first(tmp_path):
    msys, native, tool = tmp_path / "usr-bin", tmp_path / "native", tmp_path / "tool"
    for d in (msys, native, tool):
        d.mkdir()
    (msys / "msys-2.0.dll").write_bytes(b"")
    composed = bb.compose_path(f"{native};{msys};{native}", [str(tool)])
    assert composed.split(";") == [str(tool), str(native)]


# --- a real busybox ------------------------------------------------------------------------------------

@pytest.fixture
def env(tmp_path):
    e = bb.BusyboxEnvironment(cwd=str(tmp_path), timeout=60, busybox=BUSYBOX)
    yield e
    e.cleanup()


@needs_busybox
def test_snapshot_cwd_and_exports_persist(env, tmp_path):
    assert env._snapshot_ready
    r = env.execute("mkdir -p 'sub dir' && cd 'sub dir' && export BB_PERSIST=yes && echo ok")
    assert r["returncode"] == 0 and r["output"].strip() == "ok"
    assert env.cwd == str(tmp_path / "sub dir")
    r = env.execute('pwd; echo "v=$BB_PERSIST"')
    lines = r["output"].splitlines()
    assert r["returncode"] == 0 and lines[1] == "v=yes", r
    assert Path(lines[0]) == tmp_path / "sub dir"


@needs_busybox
def test_snapshot_never_keeps_per_session_variables(tmp_path):
    e = bb.BusyboxEnvironment(cwd=str(tmp_path), timeout=60, busybox=BUSYBOX,
                              env={"HERMES_SESSION_KEY": "first-session", "HERMES_UI_SESSION_ID": "ui-1", "KEEP_ME": "kept"})
    try:
        snap = Path(e._snapshot_path).read_text(encoding="utf-8")
        assert "KEEP_ME" in snap and "first-session" not in snap and "ui-1" not in snap
        assert e.execute("export HERMES_SESSION_LEAK=x KEEP_TOO=y")["returncode"] == 0
        snap = Path(e._snapshot_path).read_text(encoding="utf-8")
        assert "KEEP_TOO" in snap and "HERMES_SESSION_LEAK" not in snap
    finally:
        e.cleanup()


@needs_busybox
def test_exit_status_and_msys_drive_path(env, tmp_path):
    (tmp_path / "m.txt").write_text("msys-ok\n")
    msys = "/" + str(tmp_path)[0].lower() + bb.shell_path(str(tmp_path))[2:]
    assert env.execute(f'cat "{msys}/m.txt"')["output"].strip() == "msys-ok"
    assert env.execute("exit 3")["returncode"] == 3
    assert env.execute("cmd /c echo cmd-ok")["output"].strip() == "cmd-ok"


@needs_busybox
def test_unicode_and_exact_stdin(env, tmp_path):
    r = env.execute("printf '%s\\n' 'héllo 日本' && printf x > 'été-日.txt' && ls")
    assert "héllo 日本" in r["output"] and "été-日.txt" in r["output"], r
    payload = "a\nb\r\n€\n"
    assert env.execute("cat > in.txt", stdin_data=payload)["returncode"] == 0
    assert (tmp_path / "in.txt").read_bytes() == payload.encode("utf-8")


@needs_busybox
def test_timeout_kills_the_tree(env, tmp_path):
    import psutil
    t0 = time.monotonic()
    r = env.execute("ping -n 30 127.0.0.1 >/dev/null & echo $! > bg.pid; wait", timeout=2)
    assert r["returncode"] == 124 and time.monotonic() - t0 < 15, r
    fork_pid = int((tmp_path / "bg.pid").read_text().strip())
    time.sleep(1)
    survivors = [p.info for p in psutil.process_iter(["pid", "ppid", "name"])
                 if p.info["pid"] == fork_pid or p.info["ppid"] == fork_pid]
    assert not survivors, survivors


@needs_busybox
def test_command_longer_than_a_command_line(env):
    blob = "x" * 40_000
    r = env.execute(f"v='{blob}'; echo ${{#v}}")
    assert r["returncode"] == 0 and r["output"].strip() == "40000", r["output"][:200]
    assert not list(Path(env.get_temp_dir()).glob(f"hermes-bb-{env._session_id}-*.sh"))


@needs_busybox
def test_shims(env):
    r = env.execute("type nohup; nohup echo via-nohup")
    assert "via-nohup" in r["output"], r


@needs_busybox
def test_mkdir_shim_keeps_mkdir_semantics(env, tmp_path):
    t = bb.shell_path(str(tmp_path))
    script = "; ".join([
        f"mkdir -p '{t}/a/b c/d'", f"mkdir -p '{tmp_path}\\x\\y'", f"mkdir -pv -m 700 '{t}/m1/m2' >/dev/null",
        f"mkdir -p '{t}/a'", "mkdir plain", "mkdir --parents rel1/rel2", "mkdir -p -- -dash", "mkdir -p a1/b1 a2/b2",
        "echo ok"])
    r = env.execute(script)
    assert r["returncode"] == 0 and r["output"].strip() == "ok", r
    for made in ("a/b c/d", "x/y", "m1/m2", "plain", "rel1/rel2", "-dash", "a1/b1", "a2/b2"):
        assert (tmp_path / made).is_dir(), made
    assert env.execute("mkdir plain")["returncode"] == 1
    assert env.execute("mkdir nope/deeper")["returncode"] == 1


@needs_busybox
def test_file_tools_roundtrip(env, tmp_path):
    from tools.file_operations import ShellFileOperations
    ops = ShellFileOperations(env)
    target = str(tmp_path / "deep" / "notes.txt")
    w = ops.write_file(target, "alpha\nhéllo wörld\n")
    assert not w.error, w
    assert (tmp_path / "deep" / "notes.txt").read_bytes() == "alpha\nhéllo wörld\n".encode()
    r = ops.read_file(target)
    assert not r.error and "héllo wörld" in r.content, r
    p = ops.patch_replace(target, "alpha", "beta")
    assert not p.error, p
    assert (tmp_path / "deep" / "notes.txt").read_text(encoding="utf-8").startswith("beta\n")
    found = ops.search(r"h\w+o", path=str(tmp_path), target="content")
    assert not found.error and found.matches and found.matches[0].line_number == 2, found
    files = ops.search("*.txt", path=str(tmp_path), target="files")
    assert not files.error and any(f.endswith("notes.txt") for f in files.files), files
    missing = ops.read_file(str(tmp_path / "nope.txt"))
    assert missing.error


@needs_busybox
def test_background_process_via_env(env):
    from tools.process_registry import process_registry
    session = process_registry.spawn_via_env(env, "echo bg-start; pwd; sleep 1; echo bg-done", cwd=env.cwd)
    assert session.pid, session.output_buffer
    deadline = time.monotonic() + 30
    while not session.exited and time.monotonic() < deadline:
        time.sleep(0.5)
    assert session.exited and "bg-done" in session.output_buffer, session.output_buffer
    assert bb.shell_path(env.cwd) in session.output_buffer, session.output_buffer


@needs_busybox
def test_background_kill_takes_the_tree(env):
    import psutil
    from tools.process_registry import process_registry
    session = process_registry.spawn_via_env(env, "ping -n 60 127.0.0.1", cwd=env.cwd)
    assert session.pid, session.output_buffer
    time.sleep(2)
    tree = [session.pid, *(c.pid for c in psutil.Process(session.pid).children(recursive=True))]
    assert len(tree) > 1, tree
    process_registry.kill_process(session.id)
    time.sleep(1)
    assert not [pid for pid in tree if psutil.pid_exists(pid)], tree


@needs_busybox
def test_provider_falls_back_from_a_cwd_busybox_cannot_use(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    provider = bb.BusyboxProvider()
    assert provider.is_available() and provider.probe()[0] == "ready"
    e = provider.create_environment(cwd="/root", timeout=30)
    try:
        assert Path(e.cwd) == tmp_path
        assert e.execute("pwd")["returncode"] == 0
    finally:
        e.cleanup()
