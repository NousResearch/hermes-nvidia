"""Hand-back: what the sandbox changed among the files this computer trusts, and how to take it back.

While a profile's sandbox is on, the sandbox writes most of the profile's home. Once it is off, Hermes on this
computer reads that home as its own: a cron job's script, an MCP server's command, a shell hook, a secret
source's command, a model's endpoint and key. This module keeps a host-only record of those inputs as they were
when the sandbox was switched on, and compares the home with it before the profile is handed back:

* ``take_baseline``  at switch-on (never at a restart): config.yaml parsed whole, a manifest (size, sha256, mode,
  link target) of every watched file and folder, each cron job's payload, and byte copies of the small files that
  run (``handback/base/``). Watched: ``scripts``, ``hooks``, the folders this computer runs programs from
  (``PROGRAM_TREES``) and every file a setting or a cron job names, also one that is not there until later.
  Text the agent reads (skills, memories, SOUL.md) is hashed only; env files and credential stores are hashed,
  never copied.
* ``diff``           one row per changed file that runs here and per changed setting (Tier 1); counts and a list
  for the text the agent reads (Tier 2); a count for the other settings (``OTHER_SETTINGS``, ``OTHER_TEXTS``).
* ``revert``         puts the baseline's value or file back for the rows named and moves the sandbox's version
  to ``handback/held/<time>/``. In config.yaml only the row's key changes (Hermes's round-trip YAML writer:
  comments, order and quoting stay; see ``_edit_config``). ``keep`` records an answer; ``close`` ends the baseline.
* ``revert_from_copies``  a revert without the look at the whole home, for when that look cannot be made: every
  saved copy that differs from the home's file comes back, and new files leave the folders that run.
  ``revert_within`` bounds either revert in time and tells a step that is late to change nothing more.
* ``update_baseline_for_host_write``  after the launcher itself wrote a file or a config key for the user.
* ``remember_kept`` / ``kept``  what the user kept at a hand-back, for as long as it is still in the home.
* ``stamp``          a cheap token of the watched files, for a status that is polled: it changes when the list may.

Only what the sandbox can write is compared. The folders every launch grants it read-only (``layout.
sandbox_readonly_dirs``: the plugin folders) are left out: a change there while the sandbox is on was made on this
computer (a plugin update, the bytecode Python writes beside a plugin's sources when the launcher and ``hermes``
commands import it), never by the sandbox. Bytecode in a folder the sandbox can write (``scripts/__pycache__``) is
a file like any other there, and a row.

Everything lives in ``<state_dir>/handback/`` (the launcher's state folder: outside every profile home, never
granted to a sandbox), owner-only. Nothing here follows a link: a link is recorded by its target, a link that
leads out of the home is a row of its own, and nothing is read, hashed or restored through one. No network.

What the sandbox wrote decides no more than its own rows. A settings file or a jobs file that cannot be walked (a
value of the wrong type, a file that refers to itself or is nested too deep) is one row for the whole file, restored
from its copy on a revert; the other comparisons keep their rows.

Limits, on purpose: the listing is bounded (``MAX_ENTRIES`` for each watched folder; a folder cut short is named in
``incomplete`` and is a row of its own), files over ``COPY_MAX_FILE`` are hashed but not copied, files over
``HASH_MAX_FILE`` are compared by size and time, links outside the watched folders are looked for
``LINK_WALK_DEPTH`` folders deep, and a config.yaml that is itself a link is not read (named in ``incomplete``).
"""
from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import shlex
import shutil
import stat
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import Any, Iterable, Optional

from . import held as held_files

STATE_DIRNAME = "handback"
VERSION = 1

# -- what is watched --------------------------------------------------------------------------------
# config.yaml: every setting that differs from the baseline is a row, and a revert puts it back. A top-level key
# that is a mapping gives one row per child (an MCP server, a provider, ``browser.executable_path``), any other
# key one row. The exception is OTHER_SETTINGS below. PER_ENTRY and WHOLE name the rows that have a label of their
# own; the keys of WHOLE are one row even when their value is a mapping.
PER_ENTRY = {"secrets": "Secret source", "mcp_servers": "MCP server", "hooks": "Shell hook",
             "quick_commands": "Quick command", "approvals": "Approvals", "plugins": "Plugins",
             "security": "Security setting", "terminal": "Terminal setting", "network": "Network setting",
             "providers": "Provider", "auxiliary": "Auxiliary model"}
WHOLE = {"hooks_auto_accept": "Shell hooks", "command_allowlist": "Approved commands", "model": "Model",
         "fallback_model": "Fallback model", "fallback_providers": "Fallback providers",
         "custom_providers": "Custom providers", "telemetry.shared_metrics": "Usage data"}
TIER1_KEYS = (*PER_ENTRY, *WHOLE)
# The other settings, which differ after a session without a row: a top-level key with everything below it, or one
# dotted path. A key is here only when its numbers and switches cannot change what this computer runs or where a
# credential is sent: how Hermes looks, its limits and its housekeeping. The first line holds what Hermes writes
# by itself, without the user asking. Every other key, a key Hermes adds later included, is a row.
OTHER_SETTINGS = frozenset({
    "_config_version", "onboarding", "monitoring.install_id",
    "display", "sessions", "session", "streaming", "compression", "logging", "human_delay", "tool_output",
    "paste_collapse_threshold", "paste_collapse_threshold_fallback", "paste_collapse_char_threshold",
    "file_read_max_chars", "context_file_max_chars", "context_file_read_timeout", "goals", "loops", "checkpoints",
    "worktrees", "database", "runtime", "max_concurrent_sessions", "max_live_sessions", "doctor", "bot_mode",
    "prompt_caching", "vision"})
# Under the other settings a number, a switch or an empty value differs without a row. A text does so only at a
# path named here: a text that Hermes checks against its own choices, or that it only shows (a theme, a mode, a
# label). A text at any other path under those keys is a row, because nothing here knows what reads it: it can be
# a command, a module, a host or a file. So is a text that Hermes looks up as a name in a module or hands to a
# formatter, such as ``logging.level`` and ``display.timestamp_format``: no check stands between such a word and
# code that can raise. A text at a named path is a row too when it is no plain word (``_plain_text``). A list is
# judged by its items, a mapping by its values (``_counted_texts``).
OTHER_TEXTS = frozenset({
    "monitoring.install_id", "onboarding.profile_build", "database.journal_mode", "compression.tail_mode",
    "compression.codex_app_server_auto", "display.resume_display", "display.busy_input_mode", "display.interface",
    "display.cli_layout", "display.memory_notifications", "display.background_process_notifications",
    "display.final_response_markdown", "display.inline_images", "display.focus_saved_tool_progress", "display.skin",
    "display.language", "display.tui_status_indicator", "display.tool_progress_grouping", "display.reasoning_style",
    "display.runtime_footer.fields", "display.pet.render_mode", "human_delay.mode", "streaming.transport",
    "streaming.cursor", "sessions.fts_optimize_notice"})
_TEXT_MAX = 64                  # characters a text at a path of OTHER_TEXTS has at most to pass as a plain word
_TEXT_DEPTH = 16                # how deep the texts under one of the other settings are looked for one by one
# Model entries are compared whole, like every entry. These names only word the row (endpoint, key, provider).
MODEL_KEYS = frozenset({"model", "fallback_model", "fallback_providers", "custom_providers", "providers", "auxiliary"})
_ENDPOINT_FIELDS = ("base_url", "url", "api")
_KEY_FIELDS = ("key_env", "api_key_env", "api_key", "key_cmd")
# A saved answer or kept record names the state of a model entry in one of two forms: by the whole entry, or by
# these fields of it alone (``_route_state``). Either form holds for the entry it names.
_MODEL_ROUTE_FIELDS = ("provider", "base_url", "key_env", "api_key_env", "api_key")
# A cron job's payload: what it runs, with what, when, and where its output goes. Run state is not payload.
JOB_FIELDS = ("prompt", "script", "skills", "no_agent", "schedule", "workdir", "enabled_toolsets", "model",
              "provider", "base_url", "monitor_script", "monitor_url", "interpreter", "context_from", "deliver",
              "failure_deliver", "enabled")
CONFIG, JOBS, ALLOWLIST = "config.yaml", "cron/jobs.json", "shell-hooks-allowlist.json"
TIER1_TREES = {"scripts": "Script", "hooks": "Hook file", "plugins": "Plugin file", "desktop-plugins": "Plugin file",
               "bin": "Program file", "lsp/bin": "Program file", "node/bin": "Program file",
               "mcp-installs": "MCP install"}
# The folders this computer runs programs from by name or by a setting. The sandbox writes them (its own installs
# go there), so they are watched like ``scripts``: a new file is a row and a revert moves it out.
PROGRAM_TREES = ("bin", "lsp/bin", "node/bin", "mcp-installs")
COPIED_TREES = ("scripts", "hooks", "bin", "lsp/bin", "node/bin")  # read, hashed, and copied while the limits allow
# Whole installs with their dependencies live here, one folder each. The record has one entry for an install: the
# number of its files and a digest of their names, sizes and times (``_install_summary``). Its files are never
# read and never copied, so an install that differs is one row, and a revert moves it out whole.
LISTED_TREES = ("mcp-installs",)
# A record names the folders it covers (``trees``). A record without that list covers these.
_DEFAULT_TREES = ("scripts", "hooks", "plugins", "desktop-plugins")
TIER2_TREES = {"memories": "Memory", "skills": "Skill"}
TIER2_FILES = {"SOUL.md": "Context file"}
ENV_FILES = (".env", ".op.env")
_FALLBACK_STORES = (*ENV_FILES, "auth.json", ".anthropic_oauth.json")

MAX_ENTRIES = 50_000            # folder entries one take or diff walks in each watched folder
STOP_GRACE = 10.0               # seconds a revert that was told to stop is waited for (its one write in flight)
COPY_MAX_FILE = 8 * 1024 * 1024
# Beta decision: what a revert does with a file the profile had at switch-on, that the sandbox changed, and of which
# no copy was kept (it is over COPY_MAX_FILE, or the copies had reached COPY_MAX_TOTAL: scripts, hook files, a
# program an entry names, or config.yaml / cron/jobs.json when one of them is that large).
#   "leave"  the file stays in the profile as the sandbox changed it, and the revert's answer names it
#            (``unreverted``): the user never ends up with less than they had. The changed file still runs here.
#   "hold"   the sandbox's version is moved to the held folder and nothing takes its place (how it was before):
#            nothing the sandbox changed stays, and the profile no longer has that file.
# Credential stores are not part of this: one that changed is always taken out (the ``fixed`` rows).
NO_COPY_REVERT = "leave"
COPY_MAX_TOTAL = 128 * 1024 * 1024
HASH_MAX_FILE = 64 * 1024 * 1024
LINK_WALK_DEPTH = 3
_READERS = 8 if os.name == "nt" else 1  # files read at a time after a listing (see _Scan._read_later)
_MAX_REFERENCED = 200
_SWAP_RETRIES = 3               # looks at a file that was replaced (by rename) between the look and the read
_REREADS, _REREAD_PAUSE = 2, 0.05  # a settings file that does not parse is read again: a writer may be mid-way
_STAMP_ENTRIES = 512            # folder entries one ``stamp`` looks at
KEPT_FILE = "kept.json"
_SYMLINK_TAG, _JUNCTION_TAG = 0xA000000C, 0xA0000003
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_ABSENT = {"type": "absent"}
# The two files the sandbox and this computer share, as a row for the whole file: id prefix, kind, label.
_WHOLE_FILE = {CONFIG: ("cfgfile:", "config_file", "Settings file"), JOBS: ("cronfile:", "cron_file", "Cron jobs file")}
UNCOMPARED = "could not be compared"
NOT_REACHED = "not reached in time"  # why a revert that was told to stop skipped a row


def host_written_trees() -> tuple:
    """The watched folders the sandbox cannot write (it is granted them read-only): not compared, see the module
    docstring. To list plugin files again, return ``()`` here; every host-side write there (a plugin update,
    bytecode) is then a row at the next switch-off."""
    try:
        from .layout import sandbox_readonly_dirs

        return tuple(sandbox_readonly_dirs())
    except Exception:  # no grant list to read: everything is compared
        return ()


class _Swapped(Exception):
    """Another file is at the path than the one that was looked at (a writer replaced it by rename)."""


class _Stopped(Exception):
    """The caller of a revert stopped waiting for it: nothing more is changed in the home."""


def _pause(seconds: float) -> None:
    time.sleep(seconds)


# -- paths ------------------------------------------------------------------------------------------

def _clean(raw) -> str:
    text = os.fspath(raw)
    if os.name == "nt":  # an extended-length prefix names the same folder; paths are compared without it
        if text.startswith("\\\\?\\UNC\\"):
            text = "\\\\" + text[8:]
        elif text.startswith("\\\\?\\"):
            text = text[4:]
    return os.path.abspath(text)


def _store(state_dir) -> Path:
    return Path(_clean(state_dir)) / STATE_DIRNAME


def _inside(home: str, path: str) -> bool:
    a, b = os.path.normcase(home), os.path.normcase(path)
    return b == a or b.startswith(a.rstrip("\\/") + os.sep)


def _resolve(path: str) -> str:
    """Where *path* leads with every link followed; for a target that does not exist, its nearest existing folder
    resolved and the rest appended (Windows leaves such a path as it was written, short names included)."""
    real = os.path.realpath(path)
    head, tail = real, []
    while not os.path.lexists(head):
        parent = os.path.dirname(head)
        if parent == head:
            break
        tail.append(os.path.basename(head))
        head = parent
    return os.path.join(os.path.realpath(head), *reversed(tail)) if tail else real


def _kind(st: os.stat_result) -> str:
    if stat.S_ISLNK(st.st_mode):
        return "link"
    if getattr(st, "st_file_attributes", 0) & _REPARSE:  # Windows: a junction is a folder that leads elsewhere
        return "link" if getattr(st, "st_reparse_tag", 0) in (_SYMLINK_TAG, _JUNCTION_TAG) else "other"
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    return "file" if stat.S_ISREG(st.st_mode) else "other"


def _lstat(path) -> Optional[os.stat_result]:
    try:
        return os.lstat(path)
    except (OSError, ValueError):
        return None


def _kind_at(path) -> str:
    st = _lstat(path)
    return "absent" if st is None else _kind(st)


def _names(folder) -> list[str]:
    return [name for name, _ in _listing(folder)]


def _listing(folder) -> list[tuple[str, Optional[os.stat_result]]]:
    """``(name, lstat)`` of every entry of a folder, sorted by name; the stat is the one the listing itself gives
    (on Windows it costs no further call, and carries no file id)."""
    out = []
    try:
        with os.scandir(folder) as it:
            for entry in it:
                try:
                    out.append((entry.name, entry.stat(follow_symlinks=False)))
                except OSError:  # gone since it was listed
                    continue
    except OSError:  # gone, not a folder, or not readable
        return []
    return sorted(out, key=lambda item: item[0])


def _install_summary(path: str) -> dict:
    """What is known of one install folder without reading a file: the number of its files, and a digest of the
    name, size and time of each (of a link: where it points; a link is never followed). ``MAX_ENTRIES`` entries
    are looked at; ``cut`` says that the folder holds more than that."""
    digest, files, left, cut, stack = hashlib.sha256(), 0, MAX_ENTRIES, False, [(path, "")]
    while stack and not cut:
        folder, rel = stack.pop()
        below = []
        for name, st in _listing(folder):
            if left <= 0:
                cut = True
                break
            left -= 1
            child, kind = f"{rel}/{name}" if rel else name, _kind(st)
            if kind == "dir":
                below.append((os.path.join(folder, name), child))
                line = f"{child}\0dir"
            elif kind == "link":
                try:
                    line = f"{child}\0link\0{os.readlink(os.path.join(folder, name))}"
                except OSError:
                    line = f"{child}\0link"
            else:
                files += 1
                line = f"{child}\0{kind}\0{st.st_size}\0{st.st_mtime_ns}"
            digest.update(line.encode("utf-8", "surrogatepass") + b"\n")
        stack.extend(reversed(below))
    return {"files": files, "digest": digest.hexdigest(), **({"cut": True} if cut else {})}


def _install_state(entry: dict) -> list:
    """What of an entry at the top of a folder of installs is compared: a folder by its summary, a file by size and
    time, a link by where it points."""
    if entry["type"] == "dir":
        return ["dir", entry.get("install")]
    return [entry["type"], entry.get("link"), entry.get("size"), entry.get("mtime_ns")]


def _other_volume(exc: OSError) -> bool:
    """Whether a rename failed because the two places are on different volumes."""
    return exc.errno == errno.EXDEV or getattr(exc, "winerror", None) == 17


class _Home:
    """A profile home: names as Hermes writes them -> what is on disk (without case where the file system
    ignores it), and the look at one entry."""

    def __init__(self, home, case_insensitive: Optional[bool]):
        self.path = os.path.realpath(_clean(home))
        self.ci = (os.name == "nt" or sys.platform == "darwin") if case_insensitive is None else bool(case_insensitive)

    def fold(self, rel: str) -> str:
        return rel.casefold() if self.ci else rel

    def actual(self, rel: str) -> str:
        """The path on disk for *rel*; parts that do not exist keep the spelling given. A name at the top of the
        home that is the launcher's own link to a file it keeps from a running sandbox (``held.py``) gives that
        file: the list compares what the profile holds, not where the launcher put it meanwhile."""
        path = self.path
        for part in rel.split("/"):
            name = part
            if self.ci and _lstat(os.path.join(path, part)) is None:
                name = next((n for n in _names(path) if n.casefold() == part.casefold()), part)
            path = os.path.join(path, name)
        return str(held_files.source(path)) if "/" not in rel else path

    def plain_parents(self, rel: str) -> bool:
        """Whether every folder between the home and *rel* is a real folder or absent (never a link)."""
        parts = rel.split("/")[:-1]
        return all(_kind_at(self.actual("/".join(parts[:n]))) in ("dir", "absent") for n in range(1, len(parts) + 1))

    def entry(self, path: str, *, want_bytes: int = 0, known: Optional[dict] = None,
              st: Optional[os.stat_result] = None, read: bool = True) -> tuple[Optional[dict], Optional[bytes]]:
        """``(entry, bytes)`` for what is at *path*, never through a link; ``(None, None)`` when nothing is there.
        The bytes come back for a file up to *want_bytes*. *st*: the lstat, when a listing gave it. With *read*
        False a file is only looked at; ``fill`` reads it later."""
        st = st or _lstat(path)
        if st is None:
            return None, None
        kind = _kind(st)
        entry = {"type": kind, "size": st.st_size if kind == "file" else 0, "sha256": None,
                 "mode": stat.S_IMODE(st.st_mode), "mtime_ns": st.st_mtime_ns, "link": None}
        if kind == "link":
            try:
                target = os.readlink(path)
            except OSError:
                target = ""
            entry["link"] = target[4:] if target.startswith("\\\\?\\") else target
            try:
                entry["outside"] = not _inside(self.path, _resolve(path))
            except (OSError, ValueError):
                entry["outside"] = True
        if kind != "file" or not read:
            return entry, None
        gone, data = self.fill(entry, path, st, want_bytes, known)
        return (None, None) if gone else (entry, data)

    @staticmethod
    def fill(entry: dict, path: str, st: os.stat_result, want_bytes: int = 0, known: Optional[dict] = None) -> tuple:
        """Read the file *entry* describes: its sha256 into the entry, and ``(gone, bytes)`` back (the bytes for a
        file up to *want_bytes*). *known* (an earlier entry of the same file) is trusted when size and time still
        match, so the file is not read again. A file over ``HASH_MAX_FILE`` is not read: size and time stand in."""
        if (known and not want_bytes and known.get("type") == "file" and known.get("size") == entry["size"]
                and known.get("mtime_ns") == entry["mtime_ns"]):
            entry["sha256"] = known.get("sha256")
            return False, None
        if entry["size"] > max(HASH_MAX_FILE, want_bytes):
            return False, None
        data = None
        for _ in range(_SWAP_RETRIES):
            try:
                entry["sha256"], data = _read(path, st, want_bytes)
                break
            except _Swapped:
                # A writer that replaces by rename (Hermes's own config writer does) put another file there
                # between the look and the read: look again and read that one.
                st = _lstat(path)
                if st is None:
                    return True, None
                if _kind(st) != "file":
                    break  # something else now: left unread, the entry says so
                entry.update(size=st.st_size, mode=stat.S_IMODE(st.st_mode), mtime_ns=st.st_mtime_ns)
            except FileNotFoundError:  # gone between the look and the read
                return True, None
            except OSError:
                break
        if entry["sha256"] is None:
            entry["unreadable"] = True
        return False, data


def _read(path: str, st: os.stat_result, want_bytes: int) -> tuple[Optional[str], Optional[bytes]]:
    """sha256 of a regular file (and its bytes when no larger than *want_bytes*), opened without following a
    link and checked to be the file that was looked at."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        now = os.fstat(fd)
        if not stat.S_ISREG(now.st_mode):
            return None, None  # swapped for something else in between
        if st.st_ino and now.st_ino and st.st_ino != now.st_ino:
            raise _Swapped(path)
        digest, chunks, keep, left = hashlib.sha256(), [], now.st_size <= want_bytes, now.st_size
        while left > 0:  # the size the open file has: no further read to find its end
            chunk = os.read(fd, min(left, 1 << 20))
            if not chunk:
                break
            left -= len(chunk)
            digest.update(chunk)
            if keep:
                chunks.append(chunk)
        return digest.hexdigest(), b"".join(chunks) if keep else None
    finally:
        os.close(fd)


# -- owner-only state, atomic writes ----------------------------------------------------------------

def _private_dir(root, rel: str = "") -> Path:
    """*root*/*rel*, each folder from *root* down created owner-only."""
    path = Path(root)
    path.mkdir(parents=True, exist_ok=True)
    for part in ("", *[p for p in rel.replace("\\", "/").split("/") if p]):
        if part:
            path = path / part
            path.mkdir(exist_ok=True)
        if os.name != "nt":
            with suppress(OSError):
                os.chmod(path, 0o700)
    return path


def _tighten(path) -> None:
    """Owner-only for a file or a folder moved into the state folder, and everything below it; links are left."""
    todo = [os.fspath(path)] if os.name != "nt" else []
    while todo:
        item = todo.pop()
        kind = _kind_at(item)
        if kind in ("file", "dir"):
            with suppress(OSError):
                os.chmod(item, 0o700 if kind == "dir" else 0o600)
        if kind == "dir":
            todo += [os.path.join(item, name) for name in _names(item)]


def _replace(src, dst) -> None:
    for attempt in range(6):
        try:
            os.replace(src, dst)
            return
        except PermissionError:  # Windows: a scanner or an indexer holds the target for a moment
            if os.name != "nt" or attempt == 5:
                raise
            time.sleep(0.05 * (attempt + 1))


def _write(path, data: bytes, mode: int = 0o600, *, sync: bool = True) -> None:
    """Write through a temp file beside *path* and a rename: the target is whole or untouched, and a link at
    *path* is replaced, never written through. *sync* False skips the flush to disk (a baseline copy: it is
    checked against its hash before it is ever used)."""
    path = os.fspath(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".handback-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            if sync:
                os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(tmp, mode)
        _replace(tmp, path)
    except BaseException:
        with suppress(OSError):
            os.unlink(tmp)
        raise


def _write_json(path: Path, data) -> None:
    _write(path, json.dumps(data, indent=1, sort_keys=True).encode("utf-8"))


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def _stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _remove(path: Path) -> None:
    """Delete a file or a folder of this module's own state (never a home's)."""
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
    else:
        with suppress(OSError):
            os.unlink(path)


# -- config.yaml ------------------------------------------------------------------------------------

def _plain(value: Any) -> Any:
    """A parsed YAML value as JSON holds it (keys as text, dates as text), the same on both sides of a compare."""
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_plain(v) for v in value]
        return sorted(items, key=repr) if isinstance(value, (set, frozenset)) else items
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return "sha256:" + hashlib.sha256(value).hexdigest()
    return value.isoformat() if hasattr(value, "isoformat") else repr(value)


def _parse_config(data: Optional[bytes]) -> Optional[dict]:
    """The settings in *data*, or None when it is not a YAML mapping (an empty file is no settings)."""
    import hermes_yaml

    if data is None:
        return None
    try:
        doc = hermes_yaml.safe_load(data.decode("utf-8-sig"))
        if doc is None:
            return {}
        return _plain(doc) if isinstance(doc, dict) else None
    except Exception:  # a YAML error, bytes that are not text, or a value that holds itself or is nested too deep
        return None


def _dig(doc: Any, path: Iterable[str]) -> Any:
    for part in path:
        doc = doc.get(part) if isinstance(doc, dict) else None
    return doc


def _route_state(path: tuple, value: Any) -> str:
    """The state of the setting at *path* in the form that names a model entry by ``_MODEL_ROUTE_FIELDS`` alone.
    An answer in ``answers.json`` or an item of ``kept.json`` in that form holds for the entry it names."""
    def project(item: Any) -> Any:
        if isinstance(item, dict):
            return {f: item[f] for f in _MODEL_ROUTE_FIELDS if item.get(f) not in (None, "")}
        return [p for p in (project(v) for v in item) if p] if isinstance(item, list) else {}

    return _digest((project(value) or None) if path and path[0] in MODEL_KEYS else value)


def _plain_text(text: str) -> bool:
    """Whether *text* is a plain word: short, and without a slash, a backslash or a colon (no path, no address)."""
    return len(text) <= _TEXT_MAX and not any(mark in text for mark in "/\\:")


def _other_key(path: tuple) -> bool:
    """Whether *path* lies under one of the other settings (``OTHER_SETTINGS``)."""
    return path[0] in OTHER_SETTINGS or ".".join(path[:2]) in OTHER_SETTINGS


def _counted_texts(path: tuple, value: Any) -> Optional[list]:
    """What of a value under one of the other settings is compared: ``[dotted path, text]`` for every text in it
    that is at no path of ``OTHER_TEXTS`` or is no plain word there, sorted by path; None when it holds none.
    Numbers, switches and empty values are left out, so they differ without a row. A key of a mapping that is no
    plain word counts as a text of that mapping. ``_TEXT_DEPTH`` levels down a list or a mapping counts whole.
    The value is walked with a list of what is left to look at, so the cost is its size, whatever it holds."""
    found, stack = [], [(path, value, 0)]
    while stack:
        parts, item, depth = stack.pop()
        name = ".".join(parts)
        if isinstance(item, str):
            if name not in OTHER_TEXTS or not _plain_text(item):
                found.append([name, item])
        elif isinstance(item, (dict, list)) and depth >= _TEXT_DEPTH:
            found.append([name, item])
        elif isinstance(item, dict):
            for key, below in item.items():
                if not _plain_text(str(key)):
                    found.append([name, str(key)])
                stack.append(((*parts, str(key)), below, depth + 1))
        elif isinstance(item, list):
            stack.extend((parts, below, depth + 1) for below in item)
    found.sort(key=lambda pair: pair[0])
    return found or None


def _tier1(doc: dict) -> dict:
    """``path -> value`` for every setting of a parsed config that is a row when it differs. Entries are compared
    whole, so every field of a provider or a server counts. Of a value under the other settings only the texts
    that count are compared (``_counted_texts``)."""
    out = {}
    for key, value in doc.items():
        if isinstance(value, dict) and key not in WHOLE:
            for name, entry in value.items():
                path = (key, str(name))
                entry = _counted_texts(path, entry) if _other_key(path) else entry
                if entry is not None:
                    out[path] = entry
        else:
            value = _counted_texts((key,), value) if _other_key((key,)) else value
            if value is not None:
                out[(key,)] = value
    return out


def _other_settings(base: dict, now: dict, rows: set) -> list[str]:
    """Paths of the settings that differ and are no row: numbers, switches and named texts under
    ``OTHER_SETTINGS``."""
    paths = []
    for key in sorted(set(base) | set(now)):
        b, n = base.get(key), now.get(key)
        if b == n or (key,) in rows:
            continue
        if key not in WHOLE and all(v is None or isinstance(v, dict) for v in (b, n)):
            b, n = b or {}, n or {}
            paths += [f"{key}.{child}" for child in sorted(set(b) | set(n))
                      if b.get(child) != n.get(child) and (key, child) not in rows]
        else:
            paths.append(key)
    return paths


def _short(text: Any, limit: int = 96) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _host(url: Any) -> str:
    if not isinstance(url, str) or "://" not in url:
        return ""
    try:
        return urllib.parse.urlsplit(url).netloc.rpartition("@")[2]
    except ValueError:
        return ""


def _runs(value: Any) -> str:
    """What an entry starts or talks to, for the row: its command and arguments, or its server. Never a value of
    its environment or headers."""
    for item in value if isinstance(value, list) else [value]:
        if not isinstance(item, dict):
            continue
        command = item.get("command") or item.get("binary_path")
        if isinstance(command, str) and command.strip():
            args = item.get("args")
            tail = " ".join(str(a) for a in args) if isinstance(args, list) else ""
            return "runs " + _short(f"{command} {tail}")
        for key in ("url", "server_url"):
            if _host(item.get(key)):
                return "connects to " + _host(item[key])
    return ""


def _fields(projected: Any, names: tuple) -> list:
    entries = projected if isinstance(projected, list) else [projected] if isinstance(projected, dict) else []
    return sorted((f, json.dumps(v, sort_keys=True)) for entry in entries for f, v in entry.items() if f in names)


def _config_detail(path: tuple, kind: str, base: Any, now: Any) -> str:
    if kind == "config_removed":
        return "removed"
    word = "new" if kind == "config_added" else "changed"
    if path[0] in MODEL_KEYS:
        if kind == "config_added":
            return word
        if _fields(base, _ENDPOINT_FIELDS) != _fields(now, _ENDPOINT_FIELDS):
            return "endpoint changed"
        if _fields(base, _KEY_FIELDS) != _fields(now, _KEY_FIELDS):
            return "key changed"
        return "provider changed" if _fields(base, ("provider",)) != _fields(now, ("provider",)) else word
    if isinstance(now, bool):
        return "turned on" if now else "turned off"
    before = base if isinstance(base, list) else []
    if isinstance(now, list) and all(isinstance(v, (str, int, float)) for v in (*now, *before)):
        had, has = set(before), set(now)  # sets: the cost stays in step with the length of a long list
        added = ", ".join(str(v) for v in now if v not in had)
        gone = ", ".join(str(v) for v in before if v not in has)
        parts = [p for p in (f"added {_short(added)}" if added else "", f"removed {_short(gone)}" if gone else "") if p]
        return "; ".join(parts) or word
    runs = _runs(now)
    return f"{word}, {runs}" if runs else word


def _config_name(path: tuple, value: Any) -> str:
    if len(path) == 1 and path[0] in MODEL_KEYS:  # a model entry is named by where it sends requests
        entries = [e for e in (value if isinstance(value, list) else [value]) if isinstance(e, dict)]
        names = [_host(e.get("base_url")) for e in entries] + [e.get("provider") for e in entries]
        return str(next((name for name in names if name), path[0]))
    return str(path[-1]) if path[0] in PER_ENTRY and len(path) > 1 else ".".join(map(str, path))


def _edit_config(current: bytes, base: bytes, paths: list[tuple], base_doc: Optional[dict] = None) -> bytes:
    """*current* (a config.yaml) with each of *paths* set to what *base* (another config.yaml) has there, or
    removed when *base* has nothing there. Everything else in *current* stays.

    Written with the round-trip YAML editor Hermes's own config writer uses (``hermes_yaml.roundtrip_yaml``):
    comments, key order, quoting and flow style of the untouched keys survive, and a restored value arrives
    with the comments and quoting it had in *base*. What else changes (measured, and pinned by a test):
    indentation is written two-space (list items four), as every Hermes config write does, and an end-of-line
    comment keeps its column; the comment lines and blank lines that directly follow a mapping or a list that is
    replaced come from *base* with it, and those that follow a removed key go with it (the editor keeps them
    with the entry before them); a comment after a replaced plain value stays. CRLF line endings are kept."""
    import hermes_yaml
    from ruamel.yaml.comments import CommentedMap

    def load(data: bytes):
        return hermes_yaml.roundtrip_yaml().load(data.decode("utf-8-sig").replace("\r\n", "\n")) if data.strip() else None

    names: dict = {}  # id of a mapping -> (the mapping, its keys by their text): a lookup costs the same in a long file

    def find(node, name):
        if not isinstance(node, dict):
            return None
        if id(node) not in names:
            known: dict = {}
            for key in node:
                known.setdefault(str(key), key)
            names[id(node)] = (node, known)
        return names[id(node)][1].get(str(name))

    def put(node, key, value) -> None:
        node[key] = value
        if id(node) in names:
            names[id(node)][1].setdefault(str(key), key)

    def drop(node, key) -> None:
        del node[key]
        if id(node) in names:
            names[id(node)][1].pop(str(key), None)

    doc, source = load(current), load(base)
    if not isinstance(doc, CommentedMap):
        doc = CommentedMap(doc or {})
    for path in paths:
        theirs = source
        for part in path:
            key = find(theirs, part)
            theirs = theirs[key] if key is not None else None
            if theirs is None:
                break
        node, parents = doc, []
        for part in path[:-1]:
            key = find(node, part)
            if key is None or not isinstance(node[key], dict):
                if theirs is None:
                    node = None  # nothing to remove below a section that is not there
                    break
                key = part if key is None else key
                put(node, key, CommentedMap())
            parents.append((node, key))
            node = node[key]
        if node is None:
            continue
        key = find(node, path[-1])
        if theirs is not None:
            put(node, path[-1] if key is None else key, theirs)
            continue
        if key is not None:
            drop(node, key)
        for parent, name in reversed(parents):  # a section this emptied that the other file does not have
            if len(parent[name]) or _dig(base_doc or {}, [str(path[0])]) is not None:
                break
            drop(parent, name)
    out = io.StringIO()
    hermes_yaml.roundtrip_yaml().dump(doc, out)
    text = out.getvalue()
    return (text.replace("\n", "\r\n") if b"\r\n" in current else text).encode("utf-8")


# -- cron/jobs.json ---------------------------------------------------------------------------------

def _parse_jobs(data: Optional[bytes]) -> Optional[tuple[Any, list]]:
    """``(document, jobs)`` of a jobs file as Hermes reads it, or None when it is not one."""
    if data is None:
        return None
    try:
        text = data.decode("utf-8-sig")
        try:
            doc = json.loads(text)
        except ValueError:
            doc = json.loads(text, strict=False)
    except (ValueError, UnicodeDecodeError, RecursionError):  # not JSON, not text, or nested too deep to read
        return None
    jobs = doc.get("jobs") if isinstance(doc, dict) else doc
    if not isinstance(jobs, list) or not all(isinstance(job, dict) for job in jobs):
        return None
    return doc, jobs


def _job_id(job: dict, index: int) -> str:
    return str(job.get("id") or f"#{index}")


def _runnable(job: dict) -> bool:
    return bool(job.get("enabled", True)) and not (str(job.get("state") or "") == "paused" or bool(job.get("paused_at")))


def _payload(job: dict) -> dict:
    out = {f: _plain(job[f]) for f in JOB_FIELDS if f not in ("skills", "enabled") and job.get(f)}
    skills = job.get("skills")
    # Hermes writes a list of names. Any other value is compared as it is, so the record differs and is a row.
    names = [job.get("skill")] if skills is None else list(skills) if isinstance(skills, (list, dict)) else [skills]
    names = list(dict.fromkeys(str(name) for name in names if name))
    if names:
        out["skills"] = names
    out["enabled"] = _runnable(job)
    return out


def _job_runs(payload: dict) -> str:
    parts = []
    script = str(payload.get("script") or "").replace("\\", "/")
    if script:
        parts.append(script if script.startswith(("/", "~")) or ":" in script[:3] else f"scripts/{script}")
    if payload.get("prompt") and not payload.get("no_agent"):
        parts.append("a prompt")
    if payload.get("skills") and not payload.get("no_agent"):
        parts.append("skill " + ", ".join(payload["skills"]))
    return "runs " + _short(" and ".join(parts)) if parts else "runs nothing"


# -- the scan ---------------------------------------------------------------------------------------

def _credential_rels(home: _Home) -> list[str]:
    """Env files and credential stores of a home, present or not, as the launcher hides them from a sandbox."""
    try:
        from .layout import credential_paths

        found = [os.path.relpath(str(p), home.path).replace("\\", "/") for p in credential_paths(Path(home.path))]
        rels = [rel for rel in found if not rel.startswith("..")]
    except Exception:  # a core without the list: the env files and the token store at least
        rels = list(_FALLBACK_STORES)
    return sorted(set(rels) | set(ENV_FILES))


def _tree_of(rel: str) -> Optional[str]:
    """The watched folder *rel* lies in (``lsp/bin`` for ``lsp/bin/server``), or None."""
    parts = rel.split("/")
    return next((root for root in ("/".join(parts[:2]), parts[0]) if root in TIER1_TREES or root in TIER2_TREES), None)


def _referenced(home: _Home, doc: Optional[dict], jobs: Optional[list], absent: bool = False) -> list[str]:
    """Files in the home that a setting which is a row or a cron job names (a hook's script, an MCP server's
    program, a secret helper, the browser): they run when the entry does, wherever in the home they sit. With
    *absent*, also the paths such an entry names where nothing is: a program that appears there during the
    session is the sandbox's. ``_MAX_REFERENCED`` names at most."""
    texts: list[str] = []

    def collect(value):
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, (dict, list)):
            for item in value.values() if isinstance(value, dict) else value:
                collect(item)

    doc = doc or {}
    collect([value for key, value in doc.items() if key not in OTHER_SETTINGS])
    collect([job.get(f) for job in jobs or [] for f in ("script", "monitor_script", "interpreter")])
    found: list[str] = []
    seen: set = set()
    for text in texts:
        if len(found) >= _MAX_REFERENCED:
            break
        if len(text) > 2048 or "\n" in text:
            continue
        try:
            tokens = shlex.split(text, posix=os.name != "nt")
        except ValueError:
            tokens = text.split()
        for token in dict.fromkeys([text, *tokens]):
            token = token.strip("'\"")
            for name in ("${HERMES_HOME}", "$HERMES_HOME", "%HERMES_HOME%"):
                token = token.replace(name, home.path)
            if not token or "://" in token:  # nothing, or an address: never a file of the home
                continue
            path = os.path.normpath(os.path.join(home.path, os.path.expanduser(token)))
            if not _inside(home.path, path) or os.path.normcase(path) == os.path.normcase(home.path):
                continue
            rel = os.path.relpath(path, home.path).replace("\\", "/")
            if rel in seen:
                continue
            seen.add(rel)
            kind = _kind_at(path)
            # A bare word is a name only while a file of that name is in the home; a path is one either way.
            if kind == "file" or (absent and kind == "absent" and ("/" in token or "\\" in token)):
                found.append(rel)
    return found[:_MAX_REFERENCED]


class _Scan:
    """One look at a home: the manifest of everything watched, where each entry is on disk, the bytes of the
    files that are parsed or copied, and which folders the listing did not finish. With *copies*, the bytes of the
    small files that run are kept (up to ``COPY_MAX_TOTAL``), the two shared files first."""

    def __init__(self, home: _Home, *, copies: bool = False, known: Optional[dict] = None, quick: bool = False,
                 referenced: Optional[list] = None, stores: Iterable[str] = (), leave: Iterable[str] = ()):
        """*leave*: watched folders that are not walked (the record this look is compared with has none of them)."""
        self.home, self.manifest, self.paths, self.data, self.incomplete = home, {}, {}, {}, []
        self._folded: dict[str, str] = {}
        self._known = {home.fold(rel): entry for rel, entry in (known or {}).items()} if quick else {}
        self._copy_left = COPY_MAX_TOTAL
        self._later: list[tuple] = []
        self.host_written = frozenset(home.fold(root) for root in host_written_trees())
        want = COPY_MAX_FILE if copies else 0
        self._add(CONFIG, want=COPY_MAX_FILE)
        self._add(JOBS, want=COPY_MAX_FILE)
        self._add(ALLOWLIST, want=want)
        # The sandbox cannot write the host-written folders: not compared. The program folders come last, after
        # the files that entries name, so a large install never takes the copies of what the settings run.
        self.trees = [root for root in TIER1_TREES if home.fold(root) not in self.host_written and root not in leave]
        for root in self.trees:
            if root not in PROGRAM_TREES:
                self._tree(root, tier=1, want=want if root in COPIED_TREES else 0)
        store_rels = sorted(set(_credential_rels(home)) | set(stores))
        for rel in store_rels:
            self._add(rel, store=True)
        self.config = self._parsed(CONFIG, _parse_config)
        parsed = self._parsed(JOBS, _parse_jobs)
        self.jobs = parsed[1] if parsed else None
        hidden = (*(home.fold(rel) for rel in store_rels), *self.host_written)
        for rel in _referenced(home, self.config, self.jobs) if referenced is None else referenced:
            key = home.fold(rel)
            if not any(key == store or key.startswith(store + "/") for store in hidden):
                self._add(rel, want=want, ref=True)
        for root in self.trees:
            if root in LISTED_TREES:
                self._installs(root)
            elif root in PROGRAM_TREES:
                self._tree(root, tier=1, want=want if root in COPIED_TREES else 0)
        for rel in TIER2_FILES:
            self._add(rel, tier=2)
        for root in TIER2_TREES:
            self._tree(root, tier=2, want=0)
        self._links()
        self._read_later()
        if self.manifest.get(CONFIG, _ABSENT)["type"] not in ("file", "absent"):
            self.incomplete.append(CONFIG)  # a link: not read, so its settings are not compared

    def _add(self, rel: str, path: Optional[str] = None, *, tier: int = 1, want: int = 0, store: bool = False,
             ref: bool = False, st: Optional[os.stat_result] = None, read: bool = True) -> Optional[dict]:
        """Record what is at *rel*. *path* and *st* are given by a listing, whose folders are real ones, and its
        files are read after the listing, several at a time (not at all with *read* False: an entry at the top
        of a folder of installs); a name looked up by itself is read at once, and only when no link stands between
        it and the home."""
        key = self.home.fold(rel)
        if key in self._folded:
            return self.manifest[self._folded[key]]
        walked = path is not None
        if not walked:
            if not self.home.plain_parents(rel):
                return None  # below a link: the link is the entry, nothing behind it is the profile's
            path = self.home.actual(rel)
        st = st or _lstat(path)
        if st is None:
            return None
        data = None
        if store and _kind(st) == "dir":  # a credential folder: never opened; known by being the same folder
            entry = {"type": "dir", "size": 0, "sha256": None, "mode": stat.S_IMODE(st.st_mode), "mtime_ns": 0,
                     "link": None, "ino": st.st_ino}
        else:
            want = want if st.st_size <= min(want, self._copy_left) else 0
            known = self._known.get(key) if tier == 2 else None
            entry, data = self.home.entry(path, want_bytes=want, known=known, st=st, read=not walked)
            if entry is None:
                return None
            if walked and entry["type"] == "file" and read:
                self._later.append((rel, path, st, want, known))
                self._copy_left -= st.st_size if want else 0
        entry["tier"] = tier
        entry.update({flag: True for flag, on in (("store", store), ("ref", ref)) if on})
        self._folded[key], self.manifest[rel], self.paths[rel] = rel, entry, path
        if data is not None:
            self.data[rel] = data
            self._copy_left -= len(data)
        return entry

    def _parsed(self, rel: str, parse):
        """What *parse* makes of the file at *rel* (one of the two files the sandbox and this computer share).
        A file that does not parse, or is empty, is read again a moment later, ``_REREADS`` times at most: a
        writer that truncates and rewrites in place leaves it empty or half-written for an instant, and that
        instant must not be listed as a broken settings file."""
        value, tries = parse(self.data.get(rel)), _REREADS
        while (value is None or not self.data.get(rel)) and tries:
            entry = self.manifest.get(rel)
            if entry is None or entry["type"] != "file" or entry["size"] > COPY_MAX_FILE:
                break  # absent, a link, or too large to be read at all: nothing a second look changes
            tries -= 1
            _pause(_REREAD_PAUSE)
            del self._folded[self.home.fold(rel)], self.manifest[rel], self.paths[rel]
            self._copy_left += len(self.data.pop(rel, b""))
            self._add(rel, want=COPY_MAX_FILE)
            value = parse(self.data.get(rel))
        return value

    def _read_later(self) -> None:
        """Hash (and, for a copy, read) the files the listings found. On Windows several at a time: the first open
        of a file waits on the virus scanner there, and those waits do not add up across threads (measured:
        5,000 new files in 3 to 6 s instead of 13 to 20 s, three runs). Elsewhere one at a time is the faster way."""
        def read(items):
            return [self.home.fill(self.manifest[rel], path, st, want, known) for rel, path, st, want, known in items]

        chunks = [self._later[n:n + 32] for n in range(0, len(self._later), 32)]
        if _READERS < 2 or len(chunks) < 2:
            results = [read(chunk) for chunk in chunks]
        else:
            with ThreadPoolExecutor(max_workers=_READERS) as pool:
                results = list(pool.map(read, chunks))
        for (rel, *_), (gone, data) in zip(self._later, (result for chunk in results for result in chunk)):
            if gone:  # removed while the listing went on: as if it had never been listed
                del self._folded[self.home.fold(rel)], self.manifest[rel], self.paths[rel]
            elif data is not None:
                self.data[rel] = data

    def _installs(self, root: str) -> None:
        """A folder of installs (``LISTED_TREES``): one entry for each thing at its top, ``MAX_ENTRIES`` at most. A
        folder there is an install and is recorded by its summary; nothing below it is an entry of its own, so
        the record stays small however many files an install has, and each install has a limit of its own."""
        top = self._add(root, tier=1)
        if top is None or top["type"] != "dir":
            return
        left = MAX_ENTRIES
        for name, st in _listing(self.paths[root]):
            if left <= 0:
                self.incomplete.append(root)
                return
            left -= 1
            child, path = f"{root}/{name}", os.path.join(self.paths[root], name)
            entry = self._add(child, path, tier=1, st=st, read=False)
            if entry is not None and entry["type"] == "dir" and "install" not in entry:
                entry["install"] = _install_summary(path)
                if entry["install"].get("cut"):
                    self.incomplete.append(child)

    def _tree(self, root: str, *, tier: int, want: int) -> None:
        top = self._add(root, tier=tier)
        if top is None or top["type"] != "dir":
            return
        stack, left = [(self.paths[root], root)], MAX_ENTRIES  # each watched folder has a limit of its own
        while stack:
            folder, rel = stack.pop()
            below = []
            for name, st in _listing(folder):
                if left <= 0:
                    self.incomplete.append(root)
                    return
                left -= 1
                child, path = f"{rel}/{name}", os.path.join(folder, name)
                entry = self._add(child, path, tier=tier, want=want, st=st)
                if entry is not None and entry["type"] == "dir":
                    below.append((path, child))
            stack.extend(reversed(below))

    def _links(self) -> None:
        """Links outside the watched folders, where a host process would write through them (a log file, a cache
        folder): the top of the home and a few folders down, never into a link or a credential store."""
        skip = {self.home.fold(rel) for rel in (*TIER1_TREES, *TIER2_TREES)}  # walked above, or not the sandbox's
        skip |= {self.home.fold(rel) for rel, entry in self.manifest.items() if entry.get("store")}
        level, left = [(self.home.path, "")], MAX_ENTRIES
        for depth in range(1, LINK_WALK_DEPTH + 1):
            below = []
            for folder, rel in level:
                for name, st in _listing(folder):
                    left -= 1
                    if left < 0:
                        self.incomplete.append("links")
                        return
                    child, path = f"{rel}/{name}" if rel else name, os.path.join(folder, name)
                    if self.home.fold(child) in skip or self.home.fold(child) in self._folded:
                        continue
                    kind = _kind(st)
                    if kind == "link":
                        self._add(child, path, tier=0, st=st)
                    elif kind == "dir" and depth < LINK_WALK_DEPTH:
                        below.append((path, child))
            level = below


def _same(base: dict, now: dict) -> bool:
    if base["type"] != now["type"]:
        return False
    if now["type"] == "link":
        return base.get("link") == now.get("link")
    if now["type"] != "file":
        return base.get("ino") == now.get("ino") if base.get("store") else True
    if base.get("sha256") and now.get("sha256"):
        return base["sha256"] == now["sha256"]
    return (base["size"], base["mtime_ns"], base.get("unreadable")) == (now["size"], now["mtime_ns"], now.get("unreadable"))


def _file_state(scan: _Scan, rel: str, parsed: Any) -> str:
    kind = scan.manifest.get(rel, _ABSENT)["type"]
    if kind != "file":
        return "absent" if kind == "absent" else "link"
    return "ok" if parsed is not None else "invalid"


# -- baseline ---------------------------------------------------------------------------------------

def is_open(state_dir) -> bool:
    """Whether a baseline is open for the profile whose launcher state folder is *state_dir*."""
    return (_store(state_dir) / "baseline.json").is_file()


def take_baseline(home, state_dir, *, replace: bool = False, case_insensitive: Optional[bool] = None) -> dict:
    """Record *home* as it is now. Call at switch-on, before the launcher starts, never at a restart: an open
    baseline is kept as it is (``taken`` False) unless *replace*, so a home the sandbox has already had is
    never taken for the user's. ``baseline.json`` is written last: a take that fails leaves no baseline."""
    started = time.monotonic()
    store = _store(state_dir)
    if is_open(state_dir) and not replace:
        base = _read_json(store / "baseline.json") or {}
        return {"taken": False, "open": True, "taken_at": base.get("taken_at"), "incomplete": base.get("incomplete", [])}
    _private_dir(store)
    for leftover in ("baseline.json", "base", "answers.json"):
        _remove(store / leftover)
    where = _Home(home, case_insensitive)
    scan = _Scan(where, copies=True)
    made = set()
    for rel, data in scan.data.items():
        if os.path.dirname(rel) not in made:
            _private_dir(store / "base", os.path.dirname(rel))
            made.add(os.path.dirname(rel))
        _write(store / "base" / rel, data, sync=False)
        scan.manifest[rel]["copy"] = True
    jobs: dict = {}
    for index, job in enumerate(scan.jobs or []):
        jobs.setdefault(_job_id(job, index), _payload(job))
    base = {"version": VERSION, "taken_at": _stamp(), "home": where.path, "case_insensitive": where.ci,
            "config": {"state": _file_state(scan, CONFIG, scan.config), "doc": scan.config},
            "cron": {"state": _file_state(scan, JOBS, scan.jobs), "jobs": jobs},
            "manifest": scan.manifest, "incomplete": scan.incomplete, "trees": scan.trees,
            "limits": {"entries": MAX_ENTRIES, "copy_file": COPY_MAX_FILE, "copy_total": COPY_MAX_TOTAL,
                       "hash_file": HASH_MAX_FILE, "link_depth": LINK_WALK_DEPTH}}
    _write_json(store / "baseline.json", base)
    files = [entry["tier"] for entry in scan.manifest.values() if entry["type"] == "file"]
    return {"taken": True, "open": True, "taken_at": base["taken_at"], "tier1": files.count(1), "tier2": files.count(2),
            "copied": len(scan.data), "incomplete": scan.incomplete, "seconds": round(time.monotonic() - started, 3)}


def close(state_dir) -> dict:
    """End the baseline: the next switch-on takes a new one. What was held stays."""
    store = _store(state_dir)
    if not is_open(state_dir):
        return {"closed": False}
    os.unlink(store / "baseline.json")  # first: from here on nothing is open
    for leftover in ("base", "answers.json"):
        _remove(store / leftover)
    return {"closed": True}


def held(state_dir) -> list[dict]:
    """What earlier reverts moved out of the home, oldest first: ``[{"dir", "at", "rows"}]``."""
    root = _store(state_dir) / "held"
    indexes = [(name, _read_json(root / name / "held.json")) for name in _names(root)]
    return [{"dir": name, **index} for name, index in indexes if isinstance(index, dict)]


# -- diff -------------------------------------------------------------------------------------------

def _digest(state: Any) -> str:
    """Names a row's subject as it is now: an answer, and a kept record, hold for that state only."""
    return hashlib.sha256(json.dumps(state, sort_keys=True, default=repr).encode("utf-8")).hexdigest()[:20]


def _file_row_state(now: dict) -> list:
    return [now["type"], now.get("sha256"), now.get("link"), now.get("size"), now.get("ino")]


def _row(row_id: str, kind: str, label: str, name: str, detail: str, *, tier: int = 1, can_restore: bool = True,
         fixed: bool = False, state: Any = None, **private) -> dict:
    return {"id": row_id, "kind": kind, "tier": tier, "label": label, "name": name, "detail": detail, "answer": None,
            "can_restore": can_restore, "fixed": fixed, "state": _digest(state),
            **{f"_{k}": v for k, v in private.items()}}


def _public(row: dict) -> dict:
    return {k: v for k, v in row.items() if not k.startswith("_")}


class _Diff:
    """The baseline and the home side by side: Tier 1 rows, Tier 2 items, the other settings that differ."""

    def __init__(self, home, state_dir, quick: bool = False, listed: bool = True):
        """*listed* False: no look at the whole home is made. The rows are the saved copies the home's files
        differ from and the new files of the folders that run (``_from_copies``), for a revert without a list."""
        self.store = _store(state_dir)
        self.base = _read_json(self.store / "baseline.json")
        self.open = isinstance(self.base, dict) and isinstance(self.base.get("manifest"), dict)
        if not self.open:
            return
        self.home = _Home(home, self.base.get("case_insensitive"))
        before = self.base["manifest"]
        self.before = {self.home.fold(rel): (rel, entry) for rel, entry in before.items()}
        self.rows, self.items, self.other, self.base_doc = [], [], [], {}
        self.installs: set = set()  # the installs that are a row: a file inside one is no second row
        # A record has no entry of a folder it does not cover, so every file there would read as new. Such a
        # folder is not compared against that record, and ``incomplete`` names it.
        walked = self.base.get("trees")
        self.unrecorded = sorted(set(TIER1_TREES) - set(walked if isinstance(walked, list) else _DEFAULT_TREES))
        if not listed:
            self.now, self.incomplete = {}, sorted(set(self.base.get("incomplete") or []))
            self._from_copies()
            self.rows.sort(key=lambda row: row["id"])
            return
        self.scan = _Scan(self.home, known=before, quick=quick, referenced=self._named(),
                          stores=[rel for rel, e in before.items() if e.get("store")], leave=self.unrecorded)
        self.now = {self.home.fold(rel): (rel, entry) for rel, entry in self.scan.manifest.items()}
        self.incomplete = sorted(set(self.base.get("incomplete") or []) | set(self.scan.incomplete))
        self._part(self._config, CONFIG)
        self._part(self._cron, JOBS)
        self._files()
        unrecorded = [root for root in self.unrecorded if self.home.fold(root) not in self.scan.host_written]
        self.incomplete = sorted(set(self.incomplete) | set(unrecorded))
        answers = _read_json(self.store / "answers.json") or {}
        for row in self.rows:
            saved = answers.get(row["id"])
            if (isinstance(saved, dict) and saved.get("state") in (row["state"], row.get("_route"))
                    and not row["fixed"]):
                row["answer"] = saved.get("answer")
        self.rows.sort(key=lambda row: row["id"])
        self.items.sort(key=lambda row: row["id"])

    def pair(self, rel: str) -> tuple[dict, dict]:
        key = self.home.fold(rel)
        return self.before.get(key, (rel, _ABSENT))[1], self.now.get(key, (rel, _ABSENT))[1]

    def _named(self) -> list[str]:
        """The files the settings and cron jobs of the record name: the ones it holds an entry of, and the paths
        they name where nothing was at switch-on (a program that appears there is a row)."""
        named = [rel for rel, entry in self.base["manifest"].items() if entry.get("ref")]
        doc, jobs = self.base["config"].get("doc"), self.base["cron"].get("jobs")
        try:
            named += _referenced(self.home, doc if isinstance(doc, dict) else {},
                                 list(jobs.values()) if isinstance(jobs, dict) else [], absent=True)
        except Exception:  # the record's own settings cannot be walked: the entries it holds are compared
            pass
        return list(dict.fromkeys(named))

    def _whole(self, rel: str, detail: str) -> None:
        """One row for the whole of a shared file: a revert puts its copy back."""
        was, now = self.pair(rel)
        prefix, kind, label = _WHOLE_FILE[rel]
        self.rows.append(_row(prefix + rel, kind, label, rel, detail, rel=rel,
                              state=[now["type"], now.get("sha256"), now.get("link")],
                              can_restore=bool(was.get("copy")) or was["type"] == "absent"))

    def _part(self, compare, rel: str) -> None:
        """Run the comparison of one shared file. The sandbox writes that file, so a value in it that the comparison
        cannot walk must cost no more than the file's own rows: they give way to one row for the whole file, and
        the other comparisons keep theirs. A file that is byte for byte as it was at switch-on is no row."""
        mark = len(self.rows)
        try:
            compare()
        except Exception:
            del self.rows[mark:]
            if rel == CONFIG:
                self.other = []
            was, now = self.pair(rel)
            if "absent" in (was["type"], now["type"]) or not _same(was, now):
                self._whole(rel, UNCOMPARED)

    def _from_copies(self) -> None:
        """The rows of a revert without a list: each file a copy was kept of that is gone or differs from that copy,
        each file in the folders that run (``COPIED_TREES``) that the record does not have, each install that is
        new or differs (``LISTED_TREES``), and each program a setting names that was not there at switch-on. A
        folder whose listing was cut short at switch-on, or that the record does not cover, is left out: its new
        files cannot be told from the profile's own. A
        folder with more entries than ``MAX_ENTRIES`` is one row for the folder (``folder_cut``) in place of a row
        for each new file, so the sandbox cannot make the list longer than that."""
        for key, (rel, was) in sorted(self.before.items()):
            if not was.get("copy"):
                continue
            now = (self.home.entry(self.home.actual(rel))[0] if self.home.plain_parents(rel) else None) or _ABSENT
            if now is not _ABSENT and _same(was, now):
                continue
            if rel in _WHOLE_FILE:
                self.now[key] = (rel, now)
                self._whole(rel, "removed" if now is _ABSENT else "changed")
                continue
            what = "removed" if now is _ABSENT else "changed"
            label = "Program file" if was.get("ref") else TIER1_TREES.get(rel.split("/")[0], "File")
            self.rows.append(_row(f"file:{rel}", f"file_{what}", label, rel, what, state=_file_row_state(now), rel=rel))
        for rel in self._named():
            if self.home.fold(rel) not in self.before and self.home.plain_parents(rel):
                now = self.home.entry(self.home.actual(rel), read=False)[0]
                if now is not None and now["type"] == "file" and _tree_of(rel) is None:
                    self.rows.append(_row(f"file:{rel}", "file_new", "Program file", rel, "new",
                                          state=_file_row_state(now), rel=rel))
        for root in LISTED_TREES:
            if root in self.incomplete or root in self.unrecorded or _kind_at(self.home.actual(root)) != "dir":
                continue
            for name, st in _listing(self.home.actual(root))[:MAX_ENTRIES]:
                child, path = f"{root}/{name}", os.path.join(self.home.actual(root), name)
                now = self.home.entry(path, st=st, read=False)[0] or _ABSENT
                if now["type"] == "dir":
                    now = {**now, "install": _install_summary(path)}
                self._install(child, self.before.get(self.home.fold(child), (child, _ABSENT))[1], now, set())
        for root in COPIED_TREES:
            if root in self.incomplete or root in self.unrecorded or _kind_at(self.home.actual(root)) != "dir":
                continue
            stack, mark, left = [(self.home.actual(root), root)], len(self.rows), MAX_ENTRIES
            while stack:
                folder, rel = stack.pop()
                for name, st in _listing(folder):
                    left -= 1
                    child, path = f"{rel}/{name}", os.path.join(folder, name)
                    if _kind(st) == "dir":
                        stack.append((path, child))
                    elif self.home.fold(child) not in self.before:
                        now = self.home.entry(path, st=st, read=False)[0] or _ABSENT
                        self.rows.append(_row(f"file:{child}", "file_new", TIER1_TREES[root], child, "new",
                                              state=_file_row_state(now), rel=child))
                if left < 0:
                    del self.rows[mark:]
                    self.rows.append(_row(f"folder:{root}", "folder_cut", "Folder", root, "too many files to compare",
                                          state=[root, "cut"], rel=root))
                    break

    def _config(self) -> None:
        was, now = self.pair(CONFIG)
        state, doc = self.base["config"]["state"], self.base["config"].get("doc")
        if now["type"] == "file" and self.scan.config is not None and state in ("ok", "absent"):
            self.base_doc = doc if state == "ok" and isinstance(doc, dict) else {}
            old, new = _tier1(self.base_doc), _tier1(self.scan.config)
            changed = {path for path in set(old) | set(new) if old.get(path) != new.get(path)}
            for path in changed:
                b, n = old.get(path), new.get(path)
                # By the setting itself: under the other settings *b* and *n* hold only the texts that count.
                was_set, is_set = _dig(self.base_doc, path) is not None, _dig(self.scan.config, path) is not None
                kind = "config_added" if not was_set else "config_removed" if not is_set else "config_changed"
                label = PER_ENTRY.get(path[0]) or WHOLE.get(".".join(path)) or "Setting"
                shown = _dig(self.scan.config if n is not None else self.base_doc, path)
                self.rows.append(_row("cfg:" + ".".join(map(str, path)), kind, label, _config_name(path, shown),
                                      _config_detail(path, kind, b, n), state=n, path=path,
                                      route=_route_state(path, n),
                                      can_restore=bool(was.get("copy")) or state == "absent"))
            self.other = _other_settings(self.base_doc, self.scan.config, changed)
            return
        if was["type"] == now["type"] == "absent" or ("absent" not in (was["type"], now["type"]) and _same(was, now)):
            return  # as it was at switch-on, readable or not
        self._whole(CONFIG, "removed" if now["type"] == "absent" else "replaced by a link" if now["type"] != "file"
                    else "not valid YAML" if self.scan.config is None else "changed")

    def _cron(self) -> None:
        was, now = self.pair(JOBS)
        if now["type"] == "absent":
            return  # no jobs file runs nothing
        readable = now["type"] == "file" and self.scan.jobs is not None
        if not readable or self.base["cron"]["state"] not in ("ok", "absent"):
            if was["type"] == "absent" or not _same(was, now):
                self._whole(JOBS, "changed" if readable else "not valid JSON" if now["type"] == "file"
                            else "replaced by a link")
            return
        before = self.base["cron"].get("jobs") or {}
        for index, job in enumerate(self.scan.jobs):
            job_id = _job_id(job, index)
            old = before.get(job_id)
            try:
                payload = _payload(job)
                if old == payload:
                    continue
                if old is None:
                    detail = f"new, {_job_runs(payload)}"
                else:
                    fields = ", ".join(f for f in JOB_FIELDS if old.get(f) != payload.get(f))
                    detail = f"changed ({fields}), {_job_runs(payload)}"
                name, state = _short(job.get("name") or job_id, 60), payload
            except Exception:  # a value of this record cannot be walked: the record is a row all the same
                name, state, detail = _short(job_id, 60), [job_id, now.get("sha256")], UNCOMPARED
            self.rows.append(_row(f"cron:{job_id}", "cron_new" if old is None else "cron_changed", "Cron job", name,
                                  detail, state=state, job=job_id, can_restore=old is None or bool(was.get("copy"))))

    def _files(self) -> None:
        cut = set(self.incomplete)
        for key in sorted(set(self.before) | set(self.now)):
            try:
                self._file(key, cut)
            except Exception:  # what was recorded of this one file cannot be compared: a row, and the others go on
                rel, was = self.before.get(key) or self.now[key]
                self.rows.append(_row(f"file:{rel}", "file_changed", "File", rel, UNCOMPARED, state=[rel], rel=rel,
                                      can_restore=bool(was.get("copy"))))
        for root in TIER1_TREES:
            if root in cut and self.home.fold(root) not in self.scan.host_written:
                # More files than one listing takes: the files both looks saw are compared above, the rest is
                # this row. A revert moves out every file of the folder that the record does not have.
                self.rows.append(_row(f"folder:{root}", "folder_cut", "Folder", root, "too many files to compare",
                                      state=[root, "cut"], rel=root))

    def _file(self, key: str, cut: set) -> None:
        rel, was = self.before.get(key, (None, _ABSENT))
        now_rel, now = self.now.get(key, (None, _ABSENT))
        rel, known = rel or now_rel, was if was is not _ABSENT else now
        same_link = was["type"] == "link" and was.get("link") == now.get("link")
        if now["type"] == "link" and now.get("outside") and not same_link:
            self.rows.append(_row(f"link:{rel}", "link_outside", "Link", rel, "points outside the profile",
                                  state=now.get("link"), rel=rel, target=now.get("link")))
            return
        store = bool(was.get("store") or now.get("store"))
        if rel in (CONFIG, JOBS) or not known.get("tier"):
            return  # the two shared files have their own rows; elsewhere only a link leading out counts
        if key.split("/")[0] in self.scan.host_written:
            return  # the sandbox cannot write there, whether or not the record names them
        tree = _tree_of(rel)
        if tree in LISTED_TREES and rel.count("/") == tree.count("/") + 1:
            return self._install(rel, was, now, cut)
        if tree in LISTED_TREES and self.home.fold("/".join(rel.split("/")[:tree.count("/") + 2])) in self.installs:
            return  # a program a setting names inside an install that is a row: that row covers it
        if not store and "dir" in (was["type"], now["type"]) and (was["type"] == now["type"] or _ABSENT in (was, now)):
            return  # a folder that is there, came or went: its files are the rows
        if was is not _ABSENT and now is not _ABSENT and _same(was, now):
            return
        what = "new" if was is _ABSENT else "removed" if now is _ABSENT else "changed"
        if (_tree_of(rel) or rel.split("/")[0]) in cut and what != "changed":
            return  # the listing did not finish there: only what both looks saw is compared
        state = _file_row_state(now)
        if store:
            # Beta decision: every credential store that changed is a row that is always reverted (``fixed``),
            # the sign-in store (auth.json) included, although only the env files have a pinned copy to come
            # back from: a replaced store is moved to the held folder and the user signs in again; a removed
            # one cannot be brought back. Where the sandbox cannot write these files at all (Linux masks
            # them) such a change came from a host process. To treat them otherwise, change this branch (or
            # pin the store beside the env files).
            folder = "dir" in (was["type"], now["type"])
            label = "Env file" if rel in ENV_FILES else "Credential folder" if folder else "Credential file"
            word = {"new": "created", "changed": "replaced", "removed": "removed"}[what]
            self.rows.append(_row(f"env:{rel}", f"env_{word}", label, rel, word, fixed=True, state=state, rel=rel,
                                  can_restore=what == "new"))
        elif known["tier"] == 1:
            label = ("Program file" if known.get("ref") else "Hook approvals" if rel == ALLOWLIST
                     else TIER1_TREES.get(_tree_of(rel) or "", "File"))
            self.rows.append(_row(f"file:{rel}", f"file_{what}", label, rel, what, state=state, rel=rel,
                                  can_restore=what == "new" or bool(was.get("copy"))))
        else:
            label = TIER2_FILES.get(rel) or TIER2_TREES.get(rel.split("/")[0], "File")
            self.items.append(_row(f"t2:{rel}", f"file_{what}", label, rel, what, tier=2, state=state, rel=rel,
                                   can_restore=what == "new"))

    def _install(self, rel: str, was: dict, now: dict, cut: set) -> None:
        """One row for an entry at the top of a folder of installs that is new, differs or is gone. Its detail
        says how the number of files differs: what changed in which file is not known, by name, size and time."""
        if was is not _ABSENT and now is not _ABSENT and _install_state(was) == _install_state(now):
            return
        what = "new" if was is _ABSENT else "removed" if now is _ABSENT else "changed"
        if _tree_of(rel) in cut and what != "changed":
            return  # the listing of the folder of installs did not finish: only what both looks saw is compared

        def files(count: int) -> str:
            return f"{count:,} file" if count == 1 else f"{count:,} files"

        detail = what
        if what == "new" and now["type"] == "dir":
            detail = f"new, {files((now.get('install') or {}).get('files') or 0)}"
        elif what == "changed" and was["type"] == now["type"] == "dir":
            had, has = ((entry.get("install") or {}).get("files") or 0 for entry in (was, now))
            detail = ("changed: files differ in name, size or time" if had == has
                      else f"changed: {files(abs(has - had))} {'more' if has > had else 'fewer'}")
        self.installs.add(self.home.fold(rel))
        self.rows.append(_row(f"install:{rel}", f"install_{what}", TIER1_TREES[_tree_of(rel)], rel, detail,
                              state=_install_state(now) if now is not _ABSENT else ["absent"], rel=rel,
                              can_restore=what != "removed"))

    def tier2(self) -> dict:
        known, skills = set(self.before) | set(self.now), set()
        for item in self.items:
            parts = item["_rel"].split("/")
            if parts[0] != "skills":
                continue
            folder = parts[:-1]  # a skill is the nearest folder that holds a SKILL.md
            while len(folder) > 1 and self.home.fold("/".join([*folder, "SKILL.md"])) not in known:
                folder = folder[:-1]
            skills.add("/".join(folder if len(folder) > 1 else parts[:-1]))
        counts = {"skills": len(skills),
                  "memories": sum(1 for item in self.items if item["_rel"].split("/")[0] == "memories"),
                  "context": sum(1 for item in self.items if item["_rel"] in TIER2_FILES)}
        return {"counts": counts, "files": len(self.items), "items": [_public(item) for item in self.items]}

    def select(self, row_ids) -> tuple[list[dict], list[dict]]:
        """``(rows, skipped)`` for ids, ``"all"`` (every Tier 1 row), ``"unanswered"`` or ``"fixed"`` (the rows
        that are always reverted)."""
        if row_ids == "all":
            return list(self.rows), []
        if row_ids in ("unanswered", "fixed"):
            return [row for row in self.rows if (row["fixed"] if row_ids == "fixed" else row["answer"] is None)], []
        known = {row["id"]: row for row in (*self.rows, *self.items)}
        wanted = list(dict.fromkeys([row_ids] if isinstance(row_ids, str) else row_ids))
        return ([known[i] for i in sorted(wanted) if i in known],
                [{"id": i, "reason": "not changed"} for i in wanted if i not in known])


def diff(home, state_dir, *, quick: bool = False) -> dict:
    """What changed in *home* since the baseline. ``rows``: Tier 1, each ``{"id", "kind", "tier", "label", "name",
    "detail", "answer", "can_restore", "fixed", "state"}``, sorted by id and printable as they are (``state`` names
    the row as it is now; an answer is given for that state); ``tier2``: counts and the same shape per file;
    ``other_settings``: a count and the paths; ``incomplete``: what the listing did not finish. *quick* trusts size
    and time for the text the agent reads (a preview); Tier 1 is always read."""
    started = time.monotonic()
    found = _Diff(home, state_dir, quick)
    if not found.open:
        return {"open": False, "rows": [], "unanswered": 0}
    return {"open": True, "taken_at": found.base.get("taken_at"), "rows": [_public(row) for row in found.rows],
            "no_copy": NO_COPY_REVERT,  # what a revert does with a "no copy kept" row: the page's tip says it
            "unanswered": sum(1 for row in found.rows if row["answer"] is None and not row["fixed"]),
            "other_settings": {"count": len(found.other), "paths": found.other}, "tier2": found.tier2(),
            "incomplete": found.incomplete, "seconds": round(time.monotonic() - started, 3)}


def keep(home, state_dir, row_ids="all", *, seen: Optional[dict] = None) -> dict:
    """Record ``keep`` for the rows named (ids, ``"all"`` or ``"unanswered"``). The answer holds for the row as
    it is now: a later change to the same thing asks again. With *seen* (``{id: state}`` of the rows the user was
    shown) a row that is no longer what was shown is not kept. A row that is always reverted takes no answer."""
    found = _Diff(home, state_dir)
    if not found.open:
        return {"open": False, "kept": [], "skipped": []}
    rows, skipped = found.select(row_ids)
    answers = _read_json(found.store / "answers.json") or {}
    kept = []
    for row in rows:
        if row["fixed"] or row["tier"] != 1:
            skipped.append({"id": row["id"], "reason": "always reverted" if row["fixed"] else "kept unless reverted"})
            continue
        if seen is not None and seen.get(row["id"]) != row["state"]:
            skipped.append({"id": row["id"], "reason": "changed since it was shown"})
            continue
        answers[row["id"]] = {"answer": "keep", "state": row["state"], "at": _stamp()}
        kept.append(row["id"])
    if kept:
        _write_json(found.store / "answers.json", answers)
    return {"open": True, "kept": kept, "skipped": skipped}


# -- revert -----------------------------------------------------------------------------------------

class _Revert:
    def __init__(self, found: _Diff, skipped: list[dict], stop: Optional[threading.Event] = None):
        self.found, self.home, self.store, self.skipped = found, found.home, found.store, skipped
        self.stop = stop
        self.dir: Optional[Path] = None
        self.index: list[dict] = []
        self.results: dict[str, dict] = {}
        self.left: list[str] = []
        self.unreverted: list[str] = []  # the profile's own files left as the sandbox changed them: no copy
        self.reinstall: list[str] = []   # installs the profile had at switch-on that were moved out

    def _held(self) -> Path:
        if self.dir is None:
            root = _private_dir(self.store, "held")
            name, n = time.strftime("%Y%m%d-%H%M%S"), 1
            while (root / (name if n == 1 else f"{name}-{n}")).exists():
                n += 1
            self.dir = _private_dir(root, name if n == 1 else f"{name}-{n}")
        return self.dir

    def _go(self) -> None:
        """Called before each change to the home: once the caller stopped waiting, nothing more is changed."""
        if self.stop is not None and self.stop.is_set():
            raise _Stopped()

    def _hold(self, rel: str) -> Optional[str]:
        """Move what is at *rel* out of the home into the held folder; a link is removed, never moved or read.
        Returns where it went, relative to the held folder."""
        path = self.home.actual(rel)
        kind = _kind_at(path)
        if kind == "absent":
            return None
        self._go()
        if kind == "link":
            try:
                os.unlink(path)
            except OSError:
                os.rmdir(path)  # Windows: a link to a folder
            return None
        _private_dir(self._held(), os.path.dirname(f"files/{rel}"))
        target = self._held() / "files" / rel
        try:
            _replace(path, target)
        except OSError as exc:  # another volume: a file is copied over, a folder file by file (a link as a link)
            if kind == "file":
                _write(target, self.home.entry(path, want_bytes=os.lstat(path).st_size)[1] or b"")
                os.unlink(path)
            elif _other_volume(exc):
                shutil.move(path, os.fspath(target))
            else:
                raise
        _tighten(target)
        return f"files/{rel}"

    def _prune(self, rel: str) -> None:
        """Remove the folders a held file came in, when they are empty and were not there at switch-on."""
        parts = rel.split("/")[:-1]
        while parts and self.home.fold("/".join(parts)) not in self.found.before:
            try:
                os.rmdir(self.home.actual("/".join(parts)))
            except OSError:
                return
            parts.pop()

    def _restore(self, rel: str) -> bool:
        """Put the baseline's copy of *rel* back, byte for byte, with its mode. False when no copy was kept, or
        the copy is not what was recorded."""
        base_rel, entry = self.found.before.get(self.home.fold(rel), (rel, _ABSENT))
        data = _read_bytes(self.store / "base" / base_rel) if entry.get("copy") else b""
        if not entry.get("copy") or hashlib.sha256(data).hexdigest() != entry.get("sha256"):
            return False
        self._go()
        parts = base_rel.split("/")[:-1]
        for n in range(1, len(parts) + 1):
            folder = self.home.actual("/".join(parts[:n]))
            if _kind_at(folder) == "absent":
                os.mkdir(folder)
        if _kind_at(self.home.actual(base_rel)) == "dir":
            self._hold(base_rel)
        _write(self.home.actual(base_rel), data, entry.get("mode") or 0o600)
        return True

    def _done(self, row: dict, action: str, restored: bool, **extra) -> None:
        self.results[row["id"]] = {"id": row["id"], "action": action, "restored": restored}
        self.index.append({**_public(row), "action": action, "restored": restored,
                           **{k: v for k, v in extra.items() if v is not None}})

    def _skip(self, rows, reason: str, left: bool = True) -> None:
        """Not reverted. *left*: the sandbox's version is still in the home (False when there is nothing of the
        sandbox's there, only a baseline file that cannot be brought back)."""
        rows = rows if isinstance(rows, list) else [rows]
        self.skipped += [{"id": row["id"], "reason": reason} for row in rows]
        self.left += [row["id"] for row in rows if left and row["tier"] == 1]

    def link(self, row: dict) -> None:
        rel = row["_rel"]
        if not self.home.plain_parents(rel):
            return self._skip(row, "a link is in the way")
        if _kind_at(self.home.actual(rel)) == "link":
            self._hold(rel)
        prefix = self.home.fold(rel)
        for key, (base_rel, entry) in sorted(self.found.before.items()):
            if entry.get("copy") and (key == prefix or key.startswith(prefix + "/")):
                self._restore(base_rel)  # what the link stood in for comes back with it
        self._done(row, "removed", True, link=row["_target"])

    def file(self, row: dict) -> None:
        """A whole file: a script, a hook, a program an entry names, config.yaml or the jobs file when it cannot
        be read, an env file, or (when named) a new file among the text the agent reads."""
        rel = row["_rel"]
        if not self.home.plain_parents(rel):
            return self._skip(row, "a link is in the way")
        was = self.found.before.get(self.home.fold(rel), (rel, _ABSENT))[1]
        env = row["kind"].startswith("env_")
        if not env and was is not _ABSENT and not was.get("copy") and (row["tier"] == 2 or row["kind"] == "file_removed"):
            return self._skip(row, "no copy to restore", left=row["kind"] != "file_removed")
        if not env and was is not _ABSENT and not was.get("copy") and NO_COPY_REVERT == "leave":
            # The profile's own file, changed, and no copy to put back: taking the sandbox's version out would
            # leave the profile without the file. It stays, and the answer says so (never counted as reverted,
            # never as a row that keeps the profile from being handed back).
            self.unreverted.append(row["id"])
            return self._skip(row, "no copy to restore: left as the sandbox changed it", left=False)
        current = self.home.entry(self.home.actual(rel))[0]
        differs = current is not None and not (was is not _ABSENT and _same(was, current))
        link = current.get("link") if differs and current["type"] == "link" else None
        held = self._hold(rel) if differs else None
        # An env file is never put back from here: whoever pinned it at switch-on does that.
        put_back = False if env or was is _ABSENT else self._restore(rel)
        if was is _ABSENT:
            self._prune(rel)
        if not (held or link or put_back):
            # Nothing of the sandbox's was there to take out and nothing could be put back: nothing was done.
            return self._skip(row, "not changed" if was is _ABSENT else "no copy to restore", left=False)
        self._done(row, "restored" if put_back else "held", put_back or was is _ABSENT, held=held, link=link)

    def install(self, row: dict) -> None:
        """An entry at the top of a folder of installs that is new or differs: moved out whole to the held folder
        (one rename where both folders are on one volume), whichever of the two it is. An install that differs is
        never left for this computer to run, and nothing can be put back in its place: no copy of an install is
        kept. ``reinstall`` names the ones the profile had at switch-on."""
        rel = row["_rel"]
        if not self.home.plain_parents(rel):
            return self._skip(row, "a link is in the way")
        if row["kind"] == "install_removed":
            return self._skip(row, "no copy to restore", left=False)
        link = _kind_at(self.home.actual(rel)) == "link"
        held = self._hold(rel)
        if not (held or link):
            return self._skip(row, "not changed", left=False)
        self._prune(rel)
        if row["kind"] == "install_changed":
            self.reinstall.append(rel)
        self._done(row, "held", row["kind"] == "install_new", held=held)

    def folder(self, row: dict) -> None:
        """A folder with more files than one listing takes. Every file and folder in it that the record does not
        have is moved out (a look by name: it needs no limit), and every file a copy was kept of that is gone or
        changed comes back. When the listing was already cut short at switch-on, new files cannot be told from the
        profile's own: only the copies come back, and the answer names the folder as left."""
        root = row["_rel"]
        if not self.home.plain_parents(root) or _kind_at(self.home.actual(root)) == "link":
            return self._skip(row, "a link is in the way")
        whole = root not in (self.found.base.get("incomplete") or [])
        stack, moved = [(self.home.actual(root), root)] if whole else [], False
        while stack:
            folder, rel = stack.pop()
            for name, st in _listing(folder):
                child = f"{rel}/{name}"
                if self.home.fold(child) not in self.found.before:
                    self._hold(child)
                    moved = True
                elif _kind(st) == "dir" and root not in LISTED_TREES:  # an install is one entry: not looked into
                    stack.append((os.path.join(folder, name), child))
        prefix = self.home.fold(root) + "/"
        for key, (base_rel, entry) in sorted(self.found.before.items()):
            if key.startswith(prefix) and entry.get("copy"):
                current = self.home.entry(self.home.actual(base_rel))[0]
                if current is None or not _same(entry, current):
                    self._hold(base_rel)
                    self._restore(base_rel)
        if not whole:
            self.unreverted.append(row["id"])
            return self._skip(row, "more files at switch-on than one listing takes: new files are not told apart",
                              left=False)
        self._done(row, "restored", True, held=f"files/{root}" if moved else None)

    def config_keys(self, rows: list[dict]) -> None:
        path = self.home.actual(CONFIG)
        if not rows:
            return
        if not self.home.plain_parents(CONFIG) or _kind_at(path) != "file":
            return self._skip(rows, "a link is in the way")
        current = self.home.entry(path, want_bytes=COPY_MAX_FILE)[1]
        base = _read_bytes(self.store / "base" / CONFIG)
        try:
            text = _edit_config(current or b"", base, [row["_path"] for row in rows], self.found.base_doc)
        except Exception:  # the editor could not load or write it: nothing was changed
            return self._skip(rows, "config.yaml cannot be edited")
        was = self.found.before.get(self.home.fold(CONFIG), (CONFIG, _ABSENT))[1]
        if (was.get("copy") and hashlib.sha256(base).hexdigest() == was.get("sha256")
                and _parse_config(text) == _parse_config(base) != None):  # noqa: E711
            # With these rows put back no setting differs from the saved copy any more: the file is written as
            # that copy, byte for byte (the editor alone would keep an empty line or a comment the sandbox's
            # block came with).
            text = base
        self._go()
        _private_dir(self._held(), "files")
        _write(self._held() / "files" / CONFIG, current or b"")  # the sandbox's whole file, as it was
        _write(path, text, stat.S_IMODE(os.lstat(path).st_mode))
        for row in rows:
            self._done(row, "restored", True, held=f"files/{CONFIG}")

    def cron_jobs(self, rows: list[dict]) -> None:
        path = self.home.actual(JOBS)
        if not rows:
            return
        parsed = _parse_jobs(self.home.entry(path, want_bytes=COPY_MAX_FILE)[1]) if self.home.plain_parents(JOBS) else None
        if parsed is None:
            return self._skip(rows, "cron/jobs.json cannot be edited")
        doc, jobs = parsed
        base = _parse_jobs(_read_bytes(self.store / "base" / JOBS))
        before = {_job_id(job, n): job for n, job in enumerate(base[1])} if base else {}
        wanted, kept, done = {row["_job"]: row for row in rows}, [], []
        for index, job in enumerate(jobs):
            row, old = wanted.get(_job_id(job, index)), before.get(_job_id(job, index))
            if row is None:
                kept.append(job)
            elif row["kind"] == "cron_new":
                done.append((row, "removed", job))
            elif old is None:
                kept.append(job)
                self._skip(row, "no copy to restore")
            else:
                theirs = dict(job)
                fields = [f for f in JOB_FIELDS if f != "enabled"] + ["skill"]
                if _runnable(job) != _runnable(old):
                    fields += ["enabled", "state", "paused_at", "paused_reason"]
                for field in fields:  # the payload comes back; the run state stays as the sandbox left it
                    if field in old:
                        job[field] = old[field]
                    else:
                        job.pop(field, None)
                kept.append(job)
                done.append((row, "restored", theirs))
        if isinstance(doc, dict):
            doc["jobs"] = kept
        self._go()
        if not kept and self.home.fold(JOBS) not in self.found.before:
            os.unlink(path)  # there was no jobs file at switch-on and no job is left: no file again
        else:
            whole = doc if isinstance(doc, dict) else kept
            try:
                data = json.dumps(whole, indent=2, ensure_ascii=False).encode("utf-8")
            except UnicodeEncodeError:  # half of a surrogate pair in some value: written escaped, as it was read
                data = json.dumps(whole, indent=2).encode("ascii")
            _write(path, data, stat.S_IMODE(os.lstat(path).st_mode))
        for row, action, theirs in done:  # reported once the file is written
            self._done(row, action, True, job=theirs)

    def _try(self, call, rows) -> None:
        """Run one step; one that fails (a file held open or read-only, a value that cannot be written back) or
        that the caller stopped waiting for skips its rows and leaves the other steps to go on."""
        try:
            call(rows)
        except Exception as exc:
            rest = [row for row in (rows if isinstance(rows, list) else [rows]) if row["id"] not in self.results]
            self._skip(rest, NOT_REACHED if isinstance(exc, _Stopped)
                       else f"could not be changed ({exc.__class__.__name__})")

    def run(self, rows: list[dict]) -> dict:
        def of(*prefixes):
            return [row for row in rows if row["kind"].startswith(prefixes)]

        for row in of("link_"):  # links first: nothing below is restored through one
            self._try(self.link, row)
        for row in of("install_"):
            self._try(self.install, row)
        for row in of("config_file", "cron_file", "file_", "env_"):
            self._try(self.file, row)
        self._try(self.config_keys, of("config_added", "config_changed", "config_removed"))
        self._try(self.cron_jobs, of("cron_new", "cron_changed"))
        for row in of("folder_"):
            self._try(self.folder, row)
        order = [row["id"] for row in rows]
        reverted = [i for i in order if i in self.results]
        if reverted:
            place = {row_id: n for n, row_id in enumerate(order)}
            self.index.sort(key=lambda item: place[item["id"]])
            _write_json(self._held() / "held.json", {"at": _stamp(), "rows": self.index})
        return {"open": True, "reverted": reverted, "skipped": self.skipped, "left": sorted(self.left),
                **({"unreverted": sorted(self.unreverted)} if self.unreverted else {}),
                **({"reinstall": sorted(self.reinstall)} if self.reinstall else {}),
                "held": str(self.dir) if self.dir is not None else None, "results": [self.results[i] for i in reverted]}


def revert(home, state_dir, row_ids="all", *, stop: Optional[threading.Event] = None) -> dict:
    """Put the baseline back for the rows named: ids, ``"all"`` (every Tier 1 row), ``"unanswered"`` (those
    without a ``keep``) or ``"fixed"`` (those that are never offered: env files and credential stores). The
    sandbox's version of each goes to ``handback/held/<time>/`` with an index (``held.json``). A row that no
    longer differs is skipped, so a second revert does nothing; so is a row where nothing of the sandbox's is in
    the home and no copy was kept (a credential file it removed): nothing can be done for it here. A row whose
    file cannot be moved or written is skipped with the reason and the others go on. Text the agent reads is
    touched only when named, and only a new file can be held: no copy of the others was kept. ``left`` names the
    Tier 1 rows asked for whose sandbox version is still in the home afterwards: with any, the profile is not
    ready to be handed back. ``unreverted`` (only when there are any) names the rows that were left on purpose:
    the profile's own file, changed, with no copy to put back (``NO_COPY_REVERT``); they hold nothing up.
    ``reinstall`` (only when there are any) names the installs the profile had at switch-on that differed and
    were moved out: they are not put back, and the servers have to be installed again.
    Once *stop* is set nothing more is changed in the home: the rows not reached are skipped and in ``left``."""
    found = _Diff(home, state_dir)
    if not found.open:
        return {"open": False, "reverted": [], "skipped": [], "left": [], "held": None, "results": []}
    rows, skipped = found.select(row_ids)
    return _Revert(found, skipped, stop).run(rows)


def revert_from_copies(home, state_dir, *, stop: Optional[threading.Event] = None) -> dict:
    """A revert when the list cannot be made (the look at the whole home fails or does not come back). It needs
    no such look: every file a copy was kept of at switch-on (config.yaml and cron/jobs.json whole, the hook
    approvals, scripts, hook files, the programs entries name) that is gone or differs from that copy is put back,
    every file in the folders that run that the record does not have is moved out, and so is every install that
    is new or differs. The answer has the shape of ``revert``'s, one row per file or install. What only the full
    look finds stays as it is: a link that leads out of the home, a changed file no copy was kept of, the text
    the agent reads; the baseline is left open for a later review."""
    found = _Diff(home, state_dir, listed=False)
    if not found.open:
        return {"open": False, "reverted": [], "skipped": [], "left": [], "held": None, "results": []}
    return _Revert(found, [], stop).run(list(found.rows))


def revert_within(seconds: float, home, state_dir, row_ids="all", *, from_copies: bool = False) -> dict:
    """``revert`` (``revert_from_copies`` with *from_copies*), waited for *seconds* at most. A step that is late is
    told to stop: it changes nothing more in the home and names the rows it did not reach in ``left``, and its
    answer is waited for ``STOP_GRACE`` seconds longer (the one write that was under way). ``TimeoutError`` when
    it still does not come back; it writes nothing after that either."""
    stop, box = threading.Event(), {}

    def run() -> None:
        try:
            box["value"] = (revert_from_copies(home, state_dir, stop=stop) if from_copies
                            else revert(home, state_dir, row_ids, stop=stop))
        except BaseException as exc:  # handed to the caller below
            box["error"] = exc

    worker = threading.Thread(target=run, name="openshell-handback-revert", daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        stop.set()
        worker.join(STOP_GRACE)
    if worker.is_alive():
        raise TimeoutError(f"took longer than {seconds:g} seconds")
    if "error" in box:
        raise box["error"]
    return box["value"]


# -- what the user kept ------------------------------------------------------------------------------

def _state_now(where: _Home, item: dict, doc: Optional[dict], jobs: Optional[list]) -> Optional[str]:
    """The state digest of what a kept *item* names, as the home has it now (None when it cannot be told). A
    kept setting whose state is in the form that names a model entry by a few fields (``_route_state``) answers
    with that item's own state while the entry has that state in that form."""
    kind = str(item.get("kind") or "")
    if kind.startswith("config_") and kind != "config_file":
        if doc is None:
            return None
        path = tuple(item.get("path") or ())
        value = _tier1(doc).get(path)
        return item["state"] if item.get("state") == _route_state(path, value) else _digest(value)
    if kind.startswith("cron_") and kind != "cron_file":
        found = next((job for n, job in enumerate(jobs or []) if _job_id(job, n) == item.get("job")), None)
        return _digest(_payload(found)) if found is not None else ""
    rel = item.get("rel")
    if not isinstance(rel, str) or not where.plain_parents(rel):
        return ""
    if kind.startswith("install_"):
        now = where.entry(where.actual(rel), read=False)[0]
        if now is not None and now["type"] == "dir":
            now["install"] = _install_summary(where.actual(rel))
        return _digest(_install_state(now) if now is not None else ["absent"])
    now = where.entry(where.actual(rel))[0] or _ABSENT
    if kind == "link_outside":
        return _digest(now.get("link"))
    if kind in ("config_file", "cron_file"):
        return _digest([now["type"], now.get("sha256"), now.get("link")])
    return _digest(_file_row_state(now))


def _kept_in_home(home, items: list) -> list[dict]:
    """The *items* that are still in the home as they were kept. An item the user has since changed or removed
    is no longer the sandbox's; a config.yaml that cannot be read just now drops none of its items."""
    if not items:
        return []
    where = _Home(home, None)
    config = where.entry(where.actual(CONFIG), want_bytes=COPY_MAX_FILE)[1] if where.plain_parents(CONFIG) else None
    doc = _parse_config(config) if config is not None else ({} if _kind_at(where.actual(CONFIG)) == "absent" else None)
    parsed = _parse_jobs(where.entry(where.actual(JOBS), want_bytes=COPY_MAX_FILE)[1]) if where.plain_parents(JOBS) else None
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            now = _state_now(where, item, doc, parsed[1] if parsed else None)
        except Exception:  # its state cannot be read: the item stays
            now = None
        if now is None or now == item.get("state"):
            out.append(item)
    return out


def remember_kept(home, state_dir, row_ids: Iterable[str]) -> list[dict]:
    """Call when a hand-back ends with *row_ids* kept (Tier 1 rows the user chose to keep), before the baseline
    is closed: they join the profile's record of what was kept from a sandbox (``handback/kept.json``, host
    only), each with its label, name, detail and its state as kept. Earlier items that are no longer in the home
    as they were kept leave the record. The record is what ``kept`` reads; nothing else uses it, and deleting
    the file forgets it. Returns the record."""
    store = _store(state_dir)
    wanted = set(row_ids)
    found = _Diff(home, state_dir) if wanted else None
    rows = [row for row in (found.rows if found is not None and found.open else []) if row["id"] in wanted]
    old = _read_json(store / KEPT_FILE)
    items = {item["id"]: item for item in (old.get("items") if isinstance(old, dict) else None) or []
             if isinstance(item, dict) and isinstance(item.get("id"), str)}
    for row in rows:
        items[row["id"]] = {**{key: row[key] for key in ("id", "kind", "label", "name", "detail", "state")},
                            "kept_at": _stamp(), "path": list(row["_path"]) if "_path" in row else None,
                            "job": row.get("_job"), "rel": row.get("_rel")}
    record = _kept_in_home(home, sorted(items.values(), key=lambda item: item["id"]))
    if record:
        _private_dir(store)
        _write_json(store / KEPT_FILE, {"version": VERSION, "items": record})
    else:
        _remove(store / KEPT_FILE)
    return record


def kept(home, state_dir) -> list[dict]:
    """What the user kept from a sandbox and is still in the home as it was kept: ``[{"id", "kind", "label",
    "name", "detail", "kept_at"}]``, printable as they are. These run on this computer like the user's own (a
    kept secret source is run at every start, a kept one is pinned at the next switch-on); the status and the
    page name them with one line. Cheap when nothing was kept (one read of a file that is not there)."""
    record = _read_json(_store(state_dir) / KEPT_FILE)
    items = record.get("items") if isinstance(record, dict) else None
    if not isinstance(items, list) or not items:
        return []
    shown = ("id", "kind", "label", "name", "detail", "kept_at")
    return [{key: item.get(key) for key in shown} for item in _kept_in_home(home, items)]


# -- a token for a polled status ---------------------------------------------------------------------

def stamp(home, state_dir) -> str:
    """A short token that changes when the list ``diff`` gives may have changed: size and time of the two shared
    files, of the hook approvals, of the env files and the sign-in store, of the entries of the folders that run
    (``scripts``, ``hooks``; ``_STAMP_ENTRIES`` at most) and of the text folders' tops, and of the baseline, the
    answers and the kept record. A few ``stat`` calls and no file is read, so a status that is polled can carry
    it; whoever shows the list reads it again when the token differs. Never raises."""
    parts: list = []
    try:
        where, store = _Home(home, None), _store(state_dir)
        top = [CONFIG, JOBS, ALLOWLIST, *ENV_FILES, "auth.json", ".anthropic_oauth.json", *TIER2_FILES, *TIER2_TREES]
        for path in [*(where.actual(rel) for rel in top),
                     *(os.path.join(str(store), name) for name in ("baseline.json", "answers.json", KEPT_FILE))]:
            st = _lstat(path)
            parts.append(None if st is None else (_kind(st), st.st_size, st.st_mtime_ns))
        left = _STAMP_ENTRIES
        stack = [where.actual(root) for root in COPIED_TREES]
        while stack and left > 0:
            folder = stack.pop()
            for name, st in _listing(folder):
                left -= 1
                kind = _kind(st)
                parts.append((name, kind, st.st_size if kind == "file" else 0, st.st_mtime_ns))
                if kind == "dir":
                    stack.append(os.path.join(folder, name))
                if left <= 0:
                    break
    except Exception:
        parts.append("unreadable")
    return _digest(parts)


_KEPT_COUNTS: dict = {}  # state folder -> (stamp, how many kept items were in the home at that stamp)


def status_view(home, state_dir) -> dict:
    """What a polled status carries of the hand-back: ``open`` (a baseline is open), ``stamp`` (above) and
    ``kept`` (how many kept items are still in the home; counted again only when the stamp differs). Never
    raises."""
    try:
        token, key = stamp(home, state_dir), os.fspath(state_dir)
        if _KEPT_COUNTS.get(key, ("", 0))[0] != token:
            _KEPT_COUNTS[key] = (token, len(kept(home, state_dir)))
        return {"open": is_open(state_dir), "stamp": token, "kept": _KEPT_COUNTS[key][1]}
    except Exception:
        return {"open": False, "stamp": "", "kept": 0}


# -- writes the launcher makes for the user ---------------------------------------------------------

def tier1_paths(home) -> dict:
    """``{path: state}`` for every Tier 1 entry of the home's config.yaml as it is now (empty when it cannot be
    read). A host route takes it before and after its own write: the paths whose state differs are the ones it
    wrote, which is what ``update_baseline_for_host_write`` wants as *config_keys*."""
    where = _Home(home, None)
    data = where.entry(where.actual(CONFIG), want_bytes=COPY_MAX_FILE)[1] if where.plain_parents(CONFIG) else None
    entries = _tier1(_parse_config(data) or {})
    return {path: _row("", "", "", "", "", state=value)["state"] for path, value in entries.items()}


def update_baseline_for_host_write(home, state_dir, *, files: Iterable[str] = (), config_keys: Iterable[str] = ()) -> dict:
    """Call right after a launcher host route wrote *files* (paths relative to the home, such as ``.env``) or the
    config.yaml keys *config_keys* (``custom_providers``, ``mcp_servers.name``, or a path as ``tier1_paths``
    gives it) for the user: their current state becomes the baseline's, so the edit is not later listed as the
    sandbox's. Only what is named is taken: config.yaml and cron/jobs.json are shared with the sandbox and are
    never taken whole (ValueError)."""
    files = [str(f).replace("\\", "/").rstrip("/") for f in files]
    paths = [tuple(map(str, key)) if isinstance(key, (tuple, list)) else tuple(str(key).split(".")) for key in config_keys]
    config_keys = [".".join(path) for path in paths]
    store = _store(state_dir)
    base = _read_json(store / "baseline.json")
    if not isinstance(base, dict) or not isinstance(base.get("manifest"), dict):
        return {"updated": False, "files": [], "config_keys": []}
    where = _Home(home, base.get("case_insensitive"))
    for rel in files:
        if where.fold(rel) in (where.fold(CONFIG), where.fold(JOBS)):
            raise ValueError(f"{rel} is shared with the sandbox and is never taken whole")
        if not rel or rel.startswith("/") or ":" in rel or ".." in rel.split("/"):
            raise ValueError(f"not a path inside the profile: {rel!r}")
    manifest = base["manifest"]
    folded = {where.fold(rel): rel for rel in manifest}
    stores = {where.fold(rel) for rel in _credential_rels(where)}
    for rel in files:
        old_rel = folded.get(where.fold(rel), rel)
        old = manifest.pop(old_rel, {})
        _remove(store / "base" / old_rel)
        is_store = where.fold(rel) in stores or bool(old.get("store"))
        entry, data = (where.entry(where.actual(rel), want_bytes=0 if is_store else COPY_MAX_FILE)
                       if where.plain_parents(rel) else (None, None))
        if entry is None:
            continue
        entry["tier"] = old.get("tier", 1)
        entry.update({flag: True for flag, on in (("store", is_store), ("ref", old.get("ref"))) if on})
        if data is not None:
            _private_dir(store / "base", os.path.dirname(rel))
            _write(store / "base" / rel, data)
            entry["copy"] = True
        manifest[rel] = entry
    current = where.entry(where.actual(CONFIG), want_bytes=COPY_MAX_FILE)[1] if where.plain_parents(CONFIG) else None
    doc = _parse_config(current)
    if not config_keys or doc is None or base["config"]["state"] not in ("ok", "absent"):
        _write_json(store / "baseline.json", base)  # a config that cannot be read keeps its rows
        return {"updated": True, "files": files, "config_keys": []}
    base_doc = base["config"].get("doc") if isinstance(base["config"].get("doc"), dict) else {}
    copy = _edit_config(_read_bytes(store / "base" / CONFIG), current, paths, doc)
    for path in paths:
        value, node = _dig(doc, path), base_doc
        for part in path[:-1]:
            node = node.setdefault(part, {}) if value is not None else node.get(part)
            if not isinstance(node, dict):
                break
        if isinstance(node, dict) and value is None:
            node.pop(path[-1], None)
        elif isinstance(node, dict):
            node[path[-1]] = value
    _private_dir(store / "base")
    _write(store / "base" / CONFIG, copy)
    name = folded.get(where.fold(CONFIG), CONFIG)
    manifest[name] = {"mode": 0o600, "mtime_ns": 0, "link": None, "tier": 1, **manifest.get(name, {}), "type": "file",
                      "size": len(copy), "sha256": hashlib.sha256(copy).hexdigest(), "copy": True}
    base["config"] = {"state": "ok", "doc": base_doc}
    _write_json(store / "baseline.json", base)
    return {"updated": True, "files": files, "config_keys": config_keys}
