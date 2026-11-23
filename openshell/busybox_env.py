"""busybox-w32 terminal backend: Hermes's terminal and file tools inside a Windows sandbox.

Git for Windows' bash cannot start in an AppContainer (its MSYS runtime fails DLL init with
0xC0000142), so a ``hermes serve`` running inside an MXC process container has no shell for the
terminal and file tools. busybox-w32 is a native Win32 busybox whose ``sh`` (ash) starts there,
runs child processes and takes native ``C:/`` paths.

The shell runs where Hermes runs: inside the sandbox, beside the backend, over the same filesystem
view. That makes this a local backend (``is_remote`` and ``is_container`` false, so host paths and
the file tools' host-path handling stay right), and :class:`BusyboxEnvironment` reuses
``LocalEnvironment`` for the environment scrub, cwd recovery and temp dir. What differs from Git Bash
(each point was hit inside an MXC process container):

* ash has no ``declare``, ``shopt`` or ``${!PREFIX*}``, so the session snapshot and the per-command
  wrapper are plain POSIX sh.
* busybox reads ``/c/work`` as ``C:/c/work``. Paths are handed to it as ``C:/work``, and MSYS
  drive paths in a command are rewritten to drive form first: Hermes's file tools still quote paths
  in MSYS form on Windows, and the Windows system prompt tells the model they work.
* The wrapper defines shell functions for what busybox or the sandbox gets wrong: ``mkdir -p`` (fails
  at the drive root, whose attributes a sandbox denies), ``nohup`` (missing; Hermes's background
  wrapper needs it), ``kill PID`` (leaves the PID's children running on Windows) and ``python3``.
* ``taskkill /T``, Hermes's Windows tree kill, is refused in an AppContainer; timeouts and
  interrupts kill the command's tree with psutil instead.
* MSYS programs (Git's ``usr/bin``) die at startup in an AppContainer, so their directories are
  dropped from PATH and Hermes-managed native tools (git, ripgrep, node, uv) are put on it.
"""

from __future__ import annotations

import contextlib
import functools
import glob
import logging
import ntpath
import os
import re
import shlex
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Iterable, Optional

from agent.terminal_env_provider import TerminalEnvironmentProvider
from tools.environments.base import BaseEnvironment
from tools.environments.base_output import _pipe_stdin
from tools.environments.base_session_env import _SNAP_TMP, _cwd_marker_printf, _passthrough_save_restore
from tools.environments.local import LocalEnvironment, _make_run_env

logger = logging.getLogger(__name__)

BACKEND_NAME = "busybox"
# Set by the sandbox launcher to the busybox-w32 binary it granted the sandbox read access to.
BUSYBOX_ENV = "OPENSHELL_BUSYBOX"
_PLUGIN_BIN = Path(__file__).resolve().parent / "bin"
# Unicode builds first: the ANSI ones pass any character outside the code page as '?', so a
# non-ASCII path or argument breaks. busybox64a is the native ARM64 (Unicode) build.
_BUSYBOX_NAMES = {
    "arm64": ("busybox64a.exe", "busybox64u.exe", "busybox64.exe", "busybox.exe"),
    "amd64": ("busybox64u.exe", "busybox64.exe", "busybox.exe"),
}
# Hermes-managed tools whose native binaries belong on the sandboxed shell's PATH.
_MANAGED_TOOLS = ("git", "ripgrep", "node", "uv")
# CreateProcess caps a command line at 32,767 characters; longer scripts go through a file.
_MAX_COMMAND_LINE = 32_000

# For HERMES_ENVIRONMENT_HINT in the sandboxed backend: it is appended after the Windows host
# block, whose Git Bash note this corrects.
SANDBOX_ENVIRONMENT_HINT = (
    "Sandbox: this Hermes backend runs inside a Windows sandbox. The `terminal` tool runs busybox-w32 "
    "`sh` (ash), not Git Bash: POSIX sh plus `[[ ]]`, `local` and `source`, but no arrays, `declare`, "
    "`shopt` or process substitution. Use native drive paths with forward slashes (`C:/Users/x`); a "
    "`/c/...` path in a command is rewritten to `C:/...`. Only folders granted to the sandbox can be read "
    "or written and network access is limited: treat 'Permission denied' or 'Access is denied' outside "
    "those folders as the sandbox's answer, and ask the user instead of working around it."
)

_SNAPSHOT_EXCLUDED_PREFIXES = (
    "HERMES_SESSION_", "HERMES_CRON_AUTO_DELIVER_", "HERMES_BROWSER_CONTROL_", "HERMES_RPC_")
_SNAPSHOT_EXCLUDED_NAMES = (
    "AI_AGENT", "HERMES_AGENT", "HERMES_DELEGATED_CHILD_CONTEXT", "HERMES_CRON_SESSION",
    "HERMES_KERNEL_DIR", "HERMES_UI_SESSION_ID")
_SHIMS = (
    # Hermes's background-process wrapper runs `nohup bash -lc CMD`. busybox has no nohup, and its
    # login shell changes to $HOME, so the command would run outside the session's directory.
    'command -v nohup >/dev/null 2>&1 || nohup() { case "$1 $2" in "bash -lc") shift 2; set -- sh -c "$@";; esac; "$@"; }',
    'command -v python3 >/dev/null 2>&1 || ! command -v python >/dev/null 2>&1 || python3() { python "$@"; }',
    # Windows does not take a process's children down with it, and Hermes stops a background command
    # with `kill PID` on the subshell that runs it, which left the command itself running. A bare
    # `kill PID` therefore kills the PID's whole tree (busybox-w32's negative-PID form).
    'kill() { case $#:$1 in 1:|1:*[!0-9]*) command kill "$@";; 1:*) command kill -- "-$1";; *) command kill "$@";; esac; }',
    # busybox's `mkdir -p` creates every ancestor of an absolute path in turn, starting at the drive
    # root; a sandbox denies the root's attributes, so it fails even for a directory that exists.
    # Create below the deepest existing ancestor instead. ${2//\\//} turns backslashes into slashes.
    r'''__hermes_mkdir_p() {
  [ -d "$2" ] && return 0
  __hm_b=${2//\\//} __hm_r=
  while :; do
    case $__hm_b in ?:/|/) break;; */) __hm_b=${__hm_b%/}; continue;; esac
    [ -d "$__hm_b" ] && break
    case $__hm_b in */*) __hm_n=${__hm_b%/*};; *) __hm_n=.;; esac
    case $__hm_n in '') __hm_n=/;; ?:) __hm_n=$__hm_n/;; esac
    __hm_r=${__hm_b##*/}${__hm_r:+/$__hm_r}
    __hm_b=$__hm_n
  done
  [ -d "$__hm_b" ] || { eval "command mkdir $1 -- \"\$2\""; return; }
  (cd -- "$__hm_b" && eval "command mkdir $1 -- \"\$__hm_r\"")
}
mkdir() {
  __hm_p= __hm_opts= __hm_end= __hm_arg=
  for __hm_a do
    if [ -n "$__hm_arg" ]; then __hm_opts="$__hm_opts '$__hm_a'"; __hm_arg=; continue; fi
    [ -n "$__hm_end" ] && continue
    case $__hm_a in
      --) __hm_end=1;;
      --parents) __hm_p=1; __hm_opts="$__hm_opts --parents";;
      -m|-[!-]*m) case $__hm_a in *p*) __hm_p=1;; esac; __hm_opts="$__hm_opts $__hm_a"; __hm_arg=1;;
      --*) __hm_opts="$__hm_opts '$__hm_a'";;
      -?*) case $__hm_a in *p*) __hm_p=1;; esac; __hm_opts="$__hm_opts $__hm_a";;
    esac
  done
  [ -n "$__hm_p" ] || { command mkdir "$@"; return; }
  __hm_rc=0 __hm_end= __hm_arg=
  for __hm_a do
    if [ -n "$__hm_arg" ]; then __hm_arg=; continue; fi
    if [ -z "$__hm_end" ]; then
      case $__hm_a in --) __hm_end=1; continue;; -m|-[!-]*m) __hm_arg=1; continue;; -?*) continue;; esac
    fi
    __hermes_mkdir_p "$__hm_opts" "$__hm_a" || __hm_rc=1
  done
  return $__hm_rc
}''',
)


# --- paths -----------------------------------------------------------------------------------------

_MSYS_PATH = re.compile(r"^/(?:(?:cygdrive|mnt)/)?([A-Za-z])(?:/(.*))?$", re.S)
_DRIVE_PATH = re.compile(r"^[A-Za-z]:/")
# An MSYS drive prefix at the start of a word: after whitespace, a quote, ``=``, ``(``, a backtick
# or a shell operator, never inside one (``s/c/d/``, ``http://c/``, ``$X/c/``). A path character must
# follow, so ``cmd /c`` and an ``awk '/c/ ...'`` pattern stay untouched; only letters of drives that
# exist are rewritten (see translate_msys_drive_paths).
_MSYS_PREFIX_IN_COMMAND = re.compile(
    r"(?<![^\s'\"=(`;|&<>,])/(?:(?:cygdrive|mnt)/)?([A-Za-z])(?=/[^\s'\"`;|&<>(){}])")


def shell_path(path: str) -> str:
    """The form busybox takes: a drive path with forward slashes (``C:/Users/x``).

    MSYS forms (``/c/work/x``, ``/cygdrive/c/x``, ``/mnt/c/x``) become drive paths; any other path
    only has its backslashes turned (a relative path stays relative, ``~`` stays for the shell)."""
    text = (path or "").replace("\\", "/")
    match = _MSYS_PATH.match(text)
    if match:
        return f"{match.group(1).upper()}:/{match.group(2) or ''}"
    return text


def native_path(path: str) -> str:
    """``C:/Users/x`` (what busybox's ``pwd -P`` prints) as ``C:\\Users\\x`` for the rest of Hermes;
    a path that is not a drive or UNC path is returned stripped and otherwise unchanged."""
    text = shell_path((path or "").strip())
    if _DRIVE_PATH.match(text) or text.startswith("//"):
        return ntpath.normpath(text)
    return (path or "").strip()


@functools.lru_cache(maxsize=1)
def windows_drives() -> frozenset:
    """Drive letters present on this machine (upper case)."""
    try:
        listdrives = getattr(os, "listdrives", None)
        if listdrives is not None:
            return frozenset(drive[0].upper() for drive in listdrives())
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        return frozenset(chr(ord("A") + i) for i in range(26) if mask >> i & 1)
    except (OSError, AttributeError, ValueError):
        return frozenset({(os.environ.get("SYSTEMDRIVE") or "C:")[0].upper()})


def translate_msys_drive_paths(command: str, drives: Iterable[str]) -> str:
    """Rewrite MSYS drive paths in *command* (``/c/work``, ``'/c/x'``, ``--out=/d/y``) to drive form.

    Only letters of drives that exist are rewritten. Text inside a heredoc body or an ``awk``/``sed``
    script is not told apart from arguments, so ``sed '/c/d'`` on a machine with a C: drive is
    rewritten too; Hermes's own file tools feed file contents through stdin, which is never touched."""
    present = {d.upper() for d in drives}

    def _sub(match: re.Match) -> str:
        letter = match.group(1).upper()
        return f"{letter}:" if letter in present else match.group(0)

    return _MSYS_PREFIX_IN_COMMAND.sub(_sub, command)


def _is_msys_dir(directory: str) -> bool:
    """A PATH directory of MSYS-runtime programs, which cannot start inside an AppContainer."""
    try:
        return os.path.isfile(os.path.join(directory, "msys-2.0.dll"))
    except (OSError, ValueError):
        return False


def compose_path(path: str, front: Iterable[str]) -> str:
    """PATH with *front* first and every MSYS directory dropped (Windows ``;`` separator)."""
    entries = [*front, *(e for e in path.split(";") if e)]
    seen: set[str] = set()
    out: list[str] = []
    for entry in entries:
        key = ntpath.normcase(ntpath.normpath(entry))
        if key in seen or _is_msys_dir(entry):
            continue
        seen.add(key)
        out.append(entry)
    return ";".join(out)


def _managed_tool_dirs() -> list[str]:
    """PATH entries of the Hermes-managed native tools that are installed (never installs any)."""
    try:
        import pm
        env = pm.env_for(*_MANAGED_TOOLS, base_env={"PATH": ""})
    except Exception:
        logger.debug("busybox: managed tool lookup failed", exc_info=True)
        return []
    return [d for d in env.get("PATH", "").split(os.pathsep) if d and os.path.isdir(d)]


# --- busybox lookup ----------------------------------------------------------------------------------

def _candidate_names() -> tuple[str, ...]:
    try:
        from hermes_platform.host.facts import native_arch
        arch = native_arch()
    except Exception:
        # An older core without host facts: the plugin's own reading of the machine (kernel, then registry).
        try:
            from .launcher.hostarch import windows_native_arch
            arch = {"aarch64": "arm64"}.get(windows_native_arch(), "amd64")
        except Exception:
            arch = "amd64"
    return _BUSYBOX_NAMES.get(arch, _BUSYBOX_NAMES["amd64"])


def find_busybox() -> Optional[str]:
    """The busybox-w32 binary: ``$OPENSHELL_BUSYBOX`` when the launcher set it (and nothing else
    then), else the first build on PATH or in this plugin's ``bin/``. Reads file metadata only."""
    from hermes_platform.resolver.core import locate_command
    explicit = os.environ.get(BUSYBOX_ENV, "").strip()
    if explicit:
        found = locate_command(explicit)
        return found.command[0] if found.found else None
    for name in _candidate_names():
        found = locate_command(name, known_dirs=(str(_PLUGIN_BIN),))
        if found.found:
            return found.command[0]
    return None


# --- POSIX sh session scripts -----------------------------------------------------------------------

def posix_export_dump(tmp_path: str, excluded_names: Iterable[str] = ()) -> str:
    """``export -p`` into *tmp_path* minus Hermes's per-session variables, in POSIX sh.

    Same exclusions as the bash snapshot (``base_session_env``), unset in a subshell before the dump.
    Without ``${!PREFIX*}`` the prefixed names are read off ``export -p`` itself; a forged
    continuation line in a multi-line value can only add a name to unset."""
    safe = {n for n in (*_SNAPSHOT_EXCLUDED_NAMES, *excluded_names) if isinstance(n, str) and n}
    fixed = " ".join(shlex.quote(n) for n in sorted(safe))
    prefixes = "|".join(f"{p}*" for p in _SNAPSHOT_EXCLUDED_PREFIXES)
    names = r"$(export -p | sed -n 's/^export \([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p')"
    return (
        f'{{ ( for __hermes_n in {names}; do case "$__hermes_n" in {prefixes}) unset "$__hermes_n";; esac; done; '
        f"unset {fixed} 2>/dev/null; export -p; ) || true; }} > {tmp_path}")


def posix_bootstrap_script(*, quoted_cwd: str, quoted_snap: str, snap_tmp_template: str,
                           excluded_names: Iterable[str], cwd_marker: str) -> str:
    """Session bootstrap: capture ``export -p`` into the snapshot (``mktemp`` then ``mv`` so a
    concurrent reader never sources half a file), enter the cwd, print the cwd marker. Functions and
    aliases are not captured: the sandboxed shell starts from Hermes's environment, not a profile."""
    return "\n".join((
        "umask 077",
        f"__hermes_snap_tmp=$(mktemp {snap_tmp_template}) || exit 1",
        posix_export_dump(_SNAP_TMP, excluded_names),
        f"echo 'set +e' >> {_SNAP_TMP}",
        f"echo 'set +u' >> {_SNAP_TMP}",
        f"mv -f {_SNAP_TMP} {quoted_snap} || rm -f {_SNAP_TMP}",
        f"cd -- {quoted_cwd} 2>/dev/null || true",
        _cwd_marker_printf(cwd_marker), ""))


def posix_wrap_command_script(command: str, *, quoted_cwd: str, quoted_snap: str, snap_tmp_template: str,
                              passthrough_names: Iterable[str], snapshot_ready: bool, cwd_marker: str) -> str:
    """Per-command script: source the snapshot, cd, define the shims, run, re-dump the environment,
    print the cwd marker, exit with the command's status (``base_session_env`` semantics in POSIX sh)."""
    names = tuple(passthrough_names)
    escaped = command.replace("'", "'\\''")
    save, restore = _passthrough_save_restore(names)
    parts = list(save)
    if snapshot_ready:
        parts.append(f". {quoted_snap} >/dev/null 2>&1 || true")
    parts += restore
    parts += [
        'export AI_AGENT="${AI_AGENT:-hermes-agent}" HERMES_AGENT="${HERMES_AGENT:-true}"',
        'export GIT_PAGER="${GIT_PAGER:-cat}" PAGER="${PAGER:-cat}"',
        *_SHIMS,
        f"cd -- {quoted_cwd} || exit 126",
        f"eval '{escaped}'",
        "__hermes_ec=$?",
        "umask 077",
    ]
    if snapshot_ready:
        parts.append(
            f"__hermes_snap_tmp=$(mktemp {snap_tmp_template}) && "
            f"{{ {posix_export_dump(_SNAP_TMP, names)} && mv -f {_SNAP_TMP} {quoted_snap}; }} "
            f"2>/dev/null || rm -f {_SNAP_TMP} 2>/dev/null || true")
    parts += [_cwd_marker_printf(cwd_marker), "exit $__hermes_ec"]
    return "\n".join(parts)


# --- environment ------------------------------------------------------------------------------------

class BusyboxEnvironment(LocalEnvironment):
    """``LocalEnvironment`` with busybox-w32 ``sh`` as the shell (see the module docstring).

    The class name must not contain a built-in backend name (``local``, ``ssh``, ``docker``...):
    file-tool path resolution infers the backend from it before reading the plugin's stamp."""

    # Not Git Bash's argv transport: regex arguments must reach native tools with their
    # backslashes as written, so the file tools' Git Bash backslash doubling has to stay off.
    is_local = False
    # busybox has no sudo; skip the `sudo -n true` probe a command naming sudo would trigger.
    _passwordless_sudo_probe_supported = False
    # The shell runs inside the same sandbox as this backend, so the backend's own view of the files is
    # the shell's view: the file tools may keep reading and writing them directly.
    uses_host_filesystem = True

    def __init__(self, cwd: str = "", timeout: int = 60, env: Optional[dict] = None, *, busybox: str):
        self._busybox = busybox
        self._tool_dirs = [str(Path(busybox).parent), *_managed_tool_dirs()]
        super().__init__(cwd=native_path(cwd) if cwd else cwd, timeout=timeout, env=env)

    @staticmethod
    def _quote_cwd_for_cd(cwd: str) -> str:
        return BaseEnvironment._quote_cwd_for_cd(shell_path(cwd))

    def _quote_shell_path(self, path: str) -> str:
        return shlex.quote(shell_path(path))

    def init_session(self):
        """Snapshot ``export -p`` once; on failure every command runs without it (no login fallback:
        busybox has no profile worth sourcing in a sandbox)."""
        self._prefer_nonlogin = True
        bootstrap = posix_bootstrap_script(
            excluded_names=self._snapshot_excluded_passthrough_names(), **self._snapshot_script_kwargs(self.cwd))
        try:
            proc = self._run_bash(bootstrap, timeout=self._snapshot_timeout)
            result = self._wait_for_process(proc, timeout=self._snapshot_timeout)
            if int(result.get("returncode") or 0) != 0:
                raise RuntimeError(f"exit {result.get('returncode')}: {(result.get('output') or '').strip()[:300]}")
            self._snapshot_ready = True
            self._update_cwd(result)
        except Exception as exc:
            self._snapshot_ready = False
            logger.warning("busybox session snapshot failed (session=%s): %s", self._session_id, exc)

    def _wrap_command(self, command: str, cwd: str, *, cwd_fallback: bool = False) -> str:
        """*cwd_fallback* (Hermes passes it for the terminal tool's own commands) needs nothing here: Hermes has
        already swapped a directory that is gone for one that exists before it builds the wrapper
        (``_usable_cwd``), and the shell sees the same files as this backend."""
        return posix_wrap_command_script(
            translate_msys_drive_paths(command, windows_drives()),
            passthrough_names=self._snapshot_excluded_passthrough_names(),
            snapshot_ready=self._snapshot_ready, **self._snapshot_script_kwargs(cwd))

    def _run_env(self) -> dict:
        env = _make_run_env(self.env)
        path_key = next((k for k in env if k.upper() == "PATH"), "PATH")
        env[path_key] = compose_path(env.get(path_key, ""), self._tool_dirs)
        # busybox-w32 expands wildcards in its own argv unless told not to; the script is one argument.
        env["BB_GLOBBING"] = "0"
        return env

    def _run_bash(self, cmd_string: str, *, login: bool = False, timeout: int = 120,
                  stdin_data: Optional[str] = None) -> subprocess.Popen:
        argv = [self._busybox, "sh", "-c", cmd_string]
        script = None
        if len(subprocess.list2cmdline(argv)) > _MAX_COMMAND_LINE:
            script = f"{self.get_temp_dir()}/hermes-bb-{self._session_id}-{uuid.uuid4().hex[:8]}.sh"
            with open(script, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(cmd_string)
            argv = [self._busybox, "sh", script]
        proc = subprocess.Popen(
            argv, text=True, env=self._run_env(), encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            cwd=self._start_dir(), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        proc._hermes_busybox_script = script
        if stdin_data is not None:
            _pipe_stdin(proc, stdin_data)
        return proc

    def _start_dir(self) -> str:
        """A directory the shell can be started in when the session's own is gone (a command removed it): a
        process cannot start in a missing directory. Hermes names one without moving the session
        (``_spawn_cwd``: only a command's own cwd marker moves it); an earlier Hermes moved the session there
        itself (``_recover_cwd``)."""
        spawn_cwd = getattr(self, "_spawn_cwd", None)
        if spawn_cwd is not None:
            return spawn_cwd()
        getattr(self, "_recover_cwd")()
        return self.cwd

    def _wait_for_process(self, proc, timeout: int = 120, **kwargs) -> dict:
        try:
            return super()._wait_for_process(proc, timeout, **kwargs)
        finally:
            script = getattr(proc, "_hermes_busybox_script", None)
            if script and proc.poll() is not None:
                with contextlib.suppress(OSError):
                    os.unlink(script)

    def _kill_process(self, proc):
        """Kill the shell and every descendant.

        ``LocalEnvironment`` kills the tree with ``taskkill /T``, which an AppContainer refuses ("The
        user name or password is incorrect"); it then kills only the shell, and a timed-out command's
        children keep running. psutil enumerates and terminates them there. Our Popen holds the
        shell's handle, so its PID cannot be recycled, and psutil drops children older than it."""
        try:
            import psutil
            root = psutil.Process(proc.pid)
            tree = [*root.children(recursive=True), root]
        except Exception:
            return super()._kill_process(proc)
        for member in tree:
            with contextlib.suppress(Exception):
                member.kill()
        with contextlib.suppress(Exception):
            proc.wait(timeout=2)

    def _parse_cwd_marker(self, result: dict):
        """Base marker parsing, then ``C:/x`` -> ``C:\\x`` in what the command reported; a cwd that is not a
        directory here is not an observation. Never writes ``self.cwd``: Hermes moves the session afterwards,
        and only for a command that may move it (``_update_cwd``)."""
        BaseEnvironment._parse_cwd_marker(self, result)
        if not result.get("cwd_observed"):
            return
        native = native_path(result.get("cwd") or "")
        if native and os.path.isdir(native):
            result["cwd"] = native
        else:
            result.pop("cwd_observed", None)
            result.pop("cwd", None)

    def _extract_cwd_from_output(self, result: dict):
        """The same rule for a Hermes whose marker parsing also moves the session (it runs this step, not
        ``_parse_cwd_marker``): a cwd that is not a directory here rolls back to the previous one, which this
        command did not observe."""
        prev_cwd = self.cwd
        BaseEnvironment._extract_cwd_from_output(self, result)
        if self.cwd == prev_cwd:
            return
        native = native_path(self.cwd)
        if native and os.path.isdir(native):
            self.cwd = result["cwd"] = native
        else:
            self.cwd = prev_cwd
            result.pop("cwd_observed", None)
            result.pop("cwd", None)

    def cleanup(self):
        super().cleanup()
        with contextlib.suppress(Exception):
            for leftover in glob.glob(f"{self.get_temp_dir()}/hermes-bb-{self._session_id}-*.sh"):
                with contextlib.suppress(OSError):
                    os.unlink(leftover)


def _initial_cwd(cwd: str) -> str:
    """*cwd* when it is a directory here, else the backend's own working directory.

    Hermes hands plugin backends ``/root`` when ``terminal.cwd`` is unset, which busybox would
    read as ``C:/root``."""
    candidate = native_path(os.path.expanduser(cwd)) if cwd else ""
    if candidate and os.path.isdir(candidate):
        return candidate
    fallback = os.getcwd()
    if cwd:
        logger.info("busybox: terminal cwd %r is not a directory here; using %s", cwd, fallback)
    return fallback


# --- provider ---------------------------------------------------------------------------------------

_MISSING = (f"busybox-w32 was not found: set {BUSYBOX_ENV} to busybox64u.exe (or busybox64a.exe on ARM64), "
            "or put it on PATH. Builds: https://frippery.org/busybox/")


class BusyboxProvider(TerminalEnvironmentProvider):
    """``terminal.backend: busybox`` for a Hermes backend running inside a Windows sandbox."""

    name = BACKEND_NAME
    display_name = "busybox-w32 (Windows sandbox)"
    # The shell runs beside the backend, over the same files: host paths are the right paths.
    is_remote = False
    is_container = False

    @property
    def description(self) -> str:
        return ("Run terminal and file tools through busybox-w32 sh, for a Hermes backend inside a "
                "Windows sandbox where Git Bash cannot start.")

    @property
    def env_description(self) -> str:
        return "busybox-w32 sh on Windows"

    def is_available(self) -> bool:
        return sys.platform == "win32" and find_busybox() is not None

    def check_requirements(self, config) -> bool:
        if sys.platform != "win32":
            logger.error("The busybox terminal backend runs only on Windows.")
            return False
        if find_busybox() is None:
            logger.error(_MISSING)
            return False
        return True

    def probe(self):
        if sys.platform != "win32":
            return "unavailable", "Windows only."
        busybox = find_busybox()
        return ("ready", busybox) if busybox else ("needs_setup", _MISSING)

    def setup_instructions(self):
        return [f"Point {BUSYBOX_ENV} at busybox64u.exe (https://frippery.org/busybox/) or put it on PATH.",
                "This backend is meant for a Hermes backend running inside a Windows sandbox; "
                "`hermes sandbox serve` selects it there."]

    def create_environment(self, *, cwd: str, timeout: int, task_id: str = "default", image=None,
                           container_config=None, **kwargs):
        busybox = find_busybox()
        if busybox is None:
            raise RuntimeError(_MISSING)
        return BusyboxEnvironment(cwd=_initial_cwd(cwd), timeout=timeout, busybox=busybox)
