"""What the sandbox may touch, and where the launcher keeps its host-only state.

The launcher's state lives at ``<hermes root>/openshell/<profile>/``: outside every profile home, so
a sandbox can never rewrite its own spec, read its own outer token, or reach another profile's. For
the default profile (whose home IS the hermes root) that directory, ``profiles/`` and the install
infrastructure are carved out of the home grant explicitly; MXC applies the most specific grant.
"""
from __future__ import annotations

import logging
import ntpath
import os
import re
import shutil
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

STATE_DIRNAME = "openshell"

# Default-profile root entries that are install infrastructure, not profile data
# (hermes_cli.profiles.DEFAULT_EXPORT_EXCLUDE_ROOT's infrastructure block + PM's tool store and uv
# cache). A sandbox that could write them could rewrite the code, interpreter or wheels the host runs
# next. The rest of cache/ is the profile's own (terminal state, scratch) and stays writable.
_ROOT_INFRA_READONLY = (
    "hermes-agent", ".worktrees", "worktrees", "bin", "node_modules", ".hermes-runtime", "node", "tools",
    "cache/uv",
)
# Install state (locks, leases, facts) is denied outright, not read-only: see current_runtime.
_ROOT_INFRA_DENIED = ("installs", "profiles", STATE_DIRNAME)
# Plugin code the desktop hot-loads into its renderer from the profile home: never sandbox-writable.
_PLUGIN_DIRS = ("plugins", "desktop-plugins")
_FALLBACK_HOME_CREDENTIAL_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gh",
                                  ".config/gcloud")
# Windows credential stores under the user profile (Credential Manager blobs, DPAPI master keys).
_WINDOWS_CREDENTIAL_DIRS = ("AppData/Roaming/Microsoft/Credentials", "AppData/Local/Microsoft/Credentials",
                            "AppData/Roaming/Microsoft/Protect")

# Credential stores that sit below a folder of the home, not at its top. MXC hides a path, not a file: a sandbox
# that may rename a writable folder between the hidden path and its grant (``ren cache cache2``) reads the store at
# its new path (MXC 1.0.1; NVIDIA/OpenShell#5033). So the launcher hides each such store
# by its top-level folder where Hermes inside the sandbox never uses that folder, which puts the deny directly
# under the home grant (rename-safe):
#   .config    .config/gh, .config/gcloud: OS credential dirs in a profile home; Hermes keeps nothing else there
#   auth       auth/google_oauth.json, the only file Hermes keeps there
#   matrix, whatsapp   legacy layouts of platforms/matrix/store and platforms/whatsapp/session
#   platforms  messaging state (pairing ledgers, Matrix/WhatsApp sessions, the WhatsApp bridge port, WhatsApp Cloud
#              media): read and written by the platform adapters, which run in the host gateway only, and the
#              gateway skips a sandboxed profile (core's run-elsewhere marker)
#   weixin     weixin/accounts, the only folder Hermes keeps there
HIDDEN_WHOLE_DIRS = (".config", "auth", "matrix", "platforms", "weixin", "whatsapp")
# Folders Hermes inside the sandbox writes (cache: web, terminal, media and catalog caches; runtime: the
# active-session registry and live delivery; workspace: the google_meet plugin's meetings, Linux and macOS only)
# that hold credential stores below them. Those stores stay listed one by one: the Linux driver masks them with
# bind mounts (rename-safe there), while the Windows driver cannot hide them rename-safely and refuses to start
# while one exists (openshell_windows.rename_exposure).
WRITABLE_STORE_DIRS = ("cache", "runtime", "workspace")
# Stores under those folders that an older core's PROFILE_CREDENTIAL_PATHS does not list. A core with
# home_data_layout.LEGACY_SECRET_CACHE_PATHS lists each of them itself, and the launcher removes them before a
# launch (remove_legacy_secret_copies).
_EXTRA_NESTED_STORES = ("cache/op_cache.json",)  # 1Password secret values (agent/secret_sources/onepassword.py)

log = logging.getLogger("openshell.layout")

# A full path as Windows names a folder on one of this computer's drives: the drive letter, a colon, a separator.
_DRIVE_PATH = re.compile(r"[A-Za-z]:[\\/]")
# How every other full Windows path starts: a share, an extended-length or device path, a volume named by its id.
_TWO_SEPARATORS = re.compile(r"[\\/]{2}")
# The longest path that is taken for a path of this computer. A refusal the sandbox relays can name any text;
# what looks at a path does one step for each folder in it, so a longer text is never looked at.
PATH_CHARS = 4096
# How many links one path is followed through before it counts as leading nowhere (``on_this_computer``).
LINKS_FOLLOWED = 8
# The bit of a Windows reparse tag that says the entry stands for another name: a symbolic link, a junction.
_NAME_SURROGATE = 0x20000000
# Where the OpenShell CLI keeps the gateways a user registered, each with the client key that signs in to it
# (``<config home>/openshell/gateways/<name>/mtls``), below the user's home: ``~/.config`` is the config home
# the launcher hands the CLI for a gateway the settings name (openshell_driver.py ``config_from_spec``), and the
# roaming application data folder is the one the CLI takes on Windows when nothing names another.
_OPENSHELL_CONFIG_HOMES = (".config", "AppData/Roaming")

# The files at the top of a profile folder that hold keys or sign-ins by themselves, and the names a copy of one
# gets from a writer, an editor or a person: the name with something after a dot, underscore, tilde, hyphen, hash,
# bracket or space (``.env.save``, ``.env_k3j2.tmp``, ``.env~``, ``.env (copy)``, ``auth.json.bak``), or wrapped
# the way an editor names its own file (``..env.swp``, ``#.env#``, ``.#.env``, ``~.env``). Matched case-folded.
# ``.envoy`` and ``.environment`` are other files. ``.env`` stands last in the pattern: Hermes's install scan takes
# ``env`` right before a bar for a command that prints the environment.
_KEY_FILE = r"(?:auth\.json|gateway-connections?(?:-tokens)?\.json|(?:\.op)?\.env)"
_KEY_FILE_COPY = re.compile(rf"{_KEY_FILE}[._~\-#( ].*|\.{_KEY_FILE}\.sw.|#{_KEY_FILE}#|\.#{_KEY_FILE}|~{_KEY_FILE}"
                            r"|\.keys-.*\.tmp")
# The file a writer fills before it renames it over the keys file (Hermes: ``.env_<random>.tmp``; the move of keys
# out of config.yaml: ``.keys-<random>.tmp``). One younger than TEMP_GRACE seconds belongs to a write under way.
_WRITERS_TEMP = re.compile(r"\.env_.*\.tmp|\.keys-.*\.tmp")
TEMP_GRACE = 5.0


def sandbox_readonly_dirs() -> tuple[str, ...]:
    """The folders at the top of a profile home that every launch grants the sandbox read-only
    (``profile_grants``; the Linux driver mounts them read-only, the Windows driver lists them read-only and
    refuses to start where a rename could carry them away). The sandbox cannot create, change or remove anything
    below them, so whatever changes there while a sandbox is on was written on this computer. The hand-back
    (handback.py) reads this list for what it does not compare."""
    return _PLUGIN_DIRS


class LayoutError(RuntimeError):
    """The current profile or a requested folder cannot be sandboxed."""


@dataclass(frozen=True)
class Runtime:
    """The interpreter and source tree this launcher runs from; the sandbox runs the same ones."""

    python: Path
    code_dir: Path
    env_dir: Path
    base_python: Path
    store: Path | None
    install_state: Path | None = None  # PM's per-install state: denied, see current_runtime

    def readonly_paths(self) -> list[Path]:
        return [p for p in (self.code_dir, self.env_dir, self.base_python, self.store) if p is not None]


def current_runtime() -> Runtime:
    """The interpreter the sandbox runs: PM's selected dependency environment for this source tree
    (what the installed launcher activates), started directly as a venv interpreter. The install
    state around it (``installs/<key>``: locks, leases, facts) is denied, with the environment
    granted read-only inside it: a backend that can see that state takes its write locks at boot,
    which read-only access turns into a fatal error, while a venv interpreter that sees no install
    state boots on its own packages. The launcher's own boot lease pins the generation meanwhile."""
    import hermes_cli

    code_dir = Path(hermes_cli.__file__).resolve().parent.parent
    venv = _selected_venv(code_dir)
    if venv is None:
        python, env_dir, base = Path(sys.executable).resolve(), Path(sys.base_prefix).resolve(), Path(sys.base_prefix).resolve()
    else:
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        # A PM generation (environments/<id>/venv) keeps its editable-install snapshot beside it.
        env_dir = venv.parent if venv.parent.parent.name == "environments" else venv
        base = _venv_home(venv) or Path(sys.base_prefix).resolve()
    return Runtime(python=python, code_dir=code_dir, env_dir=env_dir, base_python=base, store=_store_root(code_dir),
                   install_state=_install_state(code_dir))


def _install_state(code_dir: Path) -> Path | None:
    try:
        from pm.environments import install_state_dir
    except ImportError:
        return None
    state = install_state_dir(code_dir)
    return state.resolve() if state.parent.is_dir() else None


def _selected_venv(code_dir: Path) -> Path | None:
    try:
        from pm.environments import selected_venv
        venv = selected_venv(code_dir)
    except (ImportError, RuntimeError, OSError):
        venv = None
    if venv is None or not (venv / "pyvenv.cfg").is_file():
        venv = Path(sys.prefix) if sys.prefix != sys.base_prefix else None  # a dev or test venv
    return venv.resolve() if venv is not None else None


def _venv_home(venv: Path) -> Path | None:
    for line in (venv / "pyvenv.cfg").read_text(encoding="utf-8-sig").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "home":
            return Path(value.strip()).resolve()
    return None


def _store_root(code_dir: Path) -> Path | None:
    try:
        from pm.environments import store_root
    except ImportError:
        raw = os.environ.get("HERMES_RUNTIME_DIR")
        return Path(raw).resolve() if raw else None
    store = store_root(code_dir)
    return store if store.is_dir() else None


@dataclass(frozen=True)
class ProfileLayout:
    name: str
    home: Path
    root: Path

    @property
    def state_dir(self) -> Path:
        return self.root / STATE_DIRNAME / self.name

    @property
    def box(self) -> Path:
        """The sandbox's private scratch (TEMP, LOCALAPPDATA, APPDATA, USERPROFILE)."""
        return self.state_dir / "box"

    @property
    def spec_path(self) -> Path:
        return self.state_dir / "spec.yaml"

    @property
    def token_path(self) -> Path:
        return self.state_dir / "token"

    @property
    def state_path(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def log_path(self) -> Path:
        return self.state_dir / "serve.log"

    @property
    def is_root_home(self) -> bool:
        return self.home == self.root


def current_profile() -> ProfileLayout:
    from hermes_cli.profiles import get_active_profile_name
    from hermes_constants import get_default_hermes_root, get_hermes_home

    name = get_active_profile_name()
    if name == "custom":
        raise LayoutError("HERMES_HOME is not the default profile or a named profile; "
                          "a sandbox needs one (use `hermes -p <name> sandbox ...`).")
    return ProfileLayout(name=name, home=get_hermes_home().resolve(), root=get_default_hermes_root().resolve())


@dataclass
class Grants:
    readonly: list[Path] = field(default_factory=list)
    readwrite: list[Path] = field(default_factory=list)
    denied: list[Path] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {k: [str(p) for p in v] for k, v in (("readonly", self.readonly), ("readwrite", self.readwrite),
                                                     ("denied", self.denied))}


def box_dirs(layout: ProfileLayout) -> dict[str, Path]:
    """The sandbox's own read & write scratch. ``requests`` is where the in-sandbox card hook relays the
    refusals it sees (sandbox_hook.py); the launcher reads them as untrusted input."""
    return {name: layout.box / name for name in ("tmp", "localappdata", "appdata", "userprofile", "requests")}


def shared_sign_in_dir(layout: ProfileLayout) -> Path:
    """The sandbox's own shared sign-in folder, in its scratch. Hermes keeps the Nous Portal sign-in that every
    profile of this computer shares in one folder below the Hermes root (``<root>/shared``) and takes a lock file
    there whenever a profile's own sign-in has no token; a sandbox can neither open nor make that folder. Named
    to Hermes inside as ``HERMES_SHARED_AUTH_DIR``, this folder stands in for it and holds no sign-in."""
    return layout.box / "shared"


def fresh_shared_sign_in_dir(layout: ProfileLayout) -> Path:
    """Make ``shared_sign_in_dir`` and empty it, for a sandbox that starts: Hermes inside then finds no shared
    sign-in and reads as it does on a computer that is not signed in. The sandbox writes this folder (the lock
    file, and a copy of its stand-in sign-in when it has one), so what is in it is never followed: a link is
    taken off as a link. Raises ``OSError`` when something in it cannot be removed."""
    return _emptied(shared_sign_in_dir(layout))


def install_state_dir(layout: ProfileLayout) -> Path:
    """The sandbox's own install-state folder, in its scratch. Hermes keeps an install's dependency state (the
    record of the selected environment, locks, leases) in ``<root>/installs/<key>``. Where the host's own
    interpreter runs inside, that folder is an ancestor of the environment the sandbox reads: Hermes inside sees
    it, can neither read nor lock it, and ends at start. Named to Hermes inside as ``HERMES_INSTALL_STATE_DIR``,
    this folder stands in for it, and Hermes inside runs on the interpreter it was started with."""
    return layout.box / "install-state"


def fresh_install_state_dir(layout: ProfileLayout) -> Path:
    """Make ``install_state_dir`` and empty it, for a sandbox that starts. The sandbox writes this folder (its
    lock), so what is in it is never followed. Raises ``OSError`` when something in it cannot be removed."""
    return _emptied(install_state_dir(layout))


def _emptied(folder: Path) -> Path:
    """*folder*, made if need be and with nothing in it. A link in it is taken off as a link."""
    if folder.is_symlink() or (folder.exists() and not folder.is_dir()):
        folder.unlink()
    folder.mkdir(parents=True, exist_ok=True)
    with os.scandir(folder) as entries:
        found = list(entries)
    for entry in found:
        if entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
            try:
                shutil.rmtree(entry.path)
            except OSError:
                os.rmdir(entry.path)  # a folder that is a link of another kind: the link itself
        else:
            os.unlink(entry.path)
    return folder


def credential_paths(home: Path) -> list[Path]:
    """Every credential store Hermes knows for a profile home, present or not, plus root copies of them.

    A store at the top of the home is denied by its own path; one below a folder Hermes in the sandbox never uses
    (HIDDEN_WHOLE_DIRS) by that folder, so every such deny sits directly under the home grant, where the sandbox
    cannot rename a folder between them. Stores below a folder the sandbox writes (WRITABLE_STORE_DIRS) stay
    listed by their own paths; the Windows driver refuses to start while one of them exists.
    Absent paths are listed too: the sandbox cannot create one by opening it (a rename onto the path still
    works on MXC 1.0.1, see NVIDIA/OpenShell#5033), and every deny's parent is the home itself or a folder MXC sees."""
    from hermes_cli.profiles import PROFILE_CREDENTIAL_PATHS

    paths = {_hidden_path(home, rel) for rel in (*PROFILE_CREDENTIAL_PATHS, *_EXTRA_NESTED_STORES)}
    if home.is_dir():
        paths.update(entry for entry in home.iterdir() if is_private_name(entry.name))
    return sorted(paths)


def is_private_name(name: str) -> bool:
    """Whether an entry called *name* at the top of a profile folder is a credential store or a copy of one:
    by Hermes's own rule, or by the names a copy of a key file gets (``_KEY_FILE_COPY``), without regard to
    case. A lock file holds no key. A copy of ``config.yaml`` that Hermes did not make is not private: the
    sandbox reads it like ``config.yaml``, and the switch looks through it for keys (config_keys.py)."""
    from hermes_cli.profiles import profile_path_is_private

    if profile_path_is_private((name,)):
        return True
    folded = name.casefold()
    return bool(_KEY_FILE_COPY.fullmatch(folded)) and not folded.endswith(".lock")


def listed_names(home: Path, paths) -> frozenset:
    """The names at the top of *home* among *paths* (what a start listed to hide, present or absent), each as
    this system compares file names: exactly where two names that differ in case are two files, case-folded on
    Windows, where they are one."""
    return frozenset(os.path.normcase(Path(p).name) for p in paths if Path(p).parent == home)


def new_private_entries(home: Path, listed) -> list[str]:
    """The entries at the top of *home* that Hermes calls a credential store or a copy of one now and that are not
    in *listed* (``listed_names`` of the running sandbox's start), by their names on disk, sorted.

    ``credential_paths`` is taken when a sandbox starts, and what it finds by looking (a copy such as
    ``.env.bak-<stamp>``, ``.env.save`` or ``auth.json.old``) can only be what was there then. A copy made while
    the sandbox is on is found here; the stores Hermes knows by name are on every start's list, present or not.
    A name is looked up in *listed* as the file system compares names, so ``.ENV`` beside a listed ``.env`` is
    found where the two are two files. A writer's temp file is found once it has stayed for ``TEMP_GRACE``
    seconds: one of a write under way is gone before a restart could hide it. One listing of the folder,
    nothing opened. [] when the folder cannot be listed."""
    try:
        with os.scandir(home) as entries:
            names = [entry.name for entry in entries]
    except OSError:
        return []
    new = sorted(name for name in names if os.path.normcase(name) not in listed and is_private_name(name))
    return [name for name in new if not _write_under_way(Path(home) / name)]


def _write_under_way(path: Path) -> bool:
    """Whether *path* is a writer's temp file (``_WRITERS_TEMP``) that is younger than ``TEMP_GRACE`` seconds, or
    gone again."""
    if not _WRITERS_TEMP.fullmatch(path.name.casefold()):
        return False
    try:
        return time.time() - os.stat(path).st_mtime < TEMP_GRACE
    except OSError:
        return True


def hide_note(names, since: float) -> dict:
    """Why the sandbox restarts when it does so to hide *names* (``new_private_entries``): the supervisor's
    restart note, which the status carries as ``restarting`` and the page shows as its line."""
    return {"why": "hide", "reason": None, "folder": None, "hide": list(names),
            "label": "Restarting the sandbox to hide " + ", ".join(names), "since": since}


def _hidden_path(home: Path, rel: str) -> Path:
    """The path that hides store *rel*: the store itself at the top of the home or below a folder the sandbox
    writes; otherwise the store's top-level folder (also for a folder no list names: hidden whole, fail closed)."""
    parts = rel.split("/")
    if len(parts) == 1 or parts[0].casefold() in WRITABLE_STORE_DIRS:
        return home.joinpath(*parts)
    return home / parts[0]


def legacy_secret_cache_paths() -> tuple[str, ...] | None:
    """Where earlier Hermes releases kept the secret-manager caches and the Photon sidecar record, in folders the
    sandbox writes (core's ``home_data_layout.LEGACY_SECRET_CACHE_PATHS``, POSIX paths relative to a home). Hermes
    now keeps those stores at the top of the home and deletes these copies unread. None when the installed core
    predates that: it still reads and writes the copies there, so the launcher leaves them alone."""
    try:
        from hermes_cli.home_data_layout import LEGACY_SECRET_CACHE_PATHS
        return tuple(str(rel) for rel in LEGACY_SECRET_CACHE_PATHS)
    except Exception:
        return None


def remove_legacy_secret_copies(home: Path) -> list[Path]:
    """Delete the old copies of the secret stores below a folder the sandbox writes before a launch, as core does on
    first use, so a profile that still has one can start (the Windows driver refuses while one is present: it can't
    be hidden rename-safely there). Unlinks only: a link is removed itself, never followed; nothing is removed through
    a linked or junctioned folder; a folder is left alone. Never raises. Returns the paths removed, none with a core
    that still uses those copies (``legacy_secret_cache_paths`` is None)."""
    removed = []
    try:
        home = Path(home)
        for rel in legacy_secret_cache_paths() or ():
            parts = [p for p in rel.replace("\\", "/").split("/") if p]
            if len(parts) < 2 or any(p in (".", "..") or ":" in p for p in parts):
                continue
            path = home.joinpath(*parts)
            try:
                if not _plain_folders(home, parts[:-1]):
                    continue
                os.unlink(path)  # a file, or a symlink / junction itself; a real folder raises
            except OSError:  # absent, a folder, in use or read-only: left as it is
                continue
            removed.append(path)
            log.warning("removed an old copy of a secret store Hermes no longer uses there: %s", path)
    except Exception:  # never stop a launch over cleanup; the rename check still refuses a store that stays
        log.warning("could not remove old secret store copies under %s", home, exc_info=True)
    return removed


def _plain_folders(home: Path, parts: list[str]) -> bool:
    """Whether each folder from *home* down along *parts* is a real directory, not a symlink or junction."""
    folder = home
    for part in parts:
        folder = folder / part
        st = os.lstat(folder)
        if not stat.S_ISDIR(st.st_mode) or getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            return False
    return True


def profile_grants(layout: ProfileLayout, runtime: Runtime, folders: list[dict]) -> Grants:
    """Grants for one launch. Creates the plugin dirs so their read-only grant exists (an absent one
    would let the sandbox create it with its own code) and the box dirs the sandbox writes, and removes the old
    secret store copies core no longer uses (remove_legacy_secret_copies)."""
    remove_legacy_secret_copies(layout.home)
    for name in sandbox_readonly_dirs():
        (layout.home / name).mkdir(parents=True, exist_ok=True)
    box = box_dirs(layout)
    for d in box.values():
        d.mkdir(parents=True, exist_ok=True)
    grants = Grants(readonly=[*runtime.readonly_paths(), *(layout.home / n for n in sandbox_readonly_dirs())],
                    readwrite=[layout.home, *box.values()], denied=credential_paths(layout.home))
    if runtime.install_state is not None:
        grants.denied.append(runtime.install_state)
    if layout.is_root_home:
        grants.readonly += [layout.root.joinpath(*n.split("/")) for n in _ROOT_INFRA_READONLY
                            if layout.root.joinpath(*n.split("/")).exists()]
        grants.denied += [layout.root / n for n in _ROOT_INFRA_DENIED]
    for folder in folders:
        (grants.readwrite if folder.get("access") == "rw" else grants.readonly).append(Path(folder["path"]))
    grants.readonly = _dedupe(p for p in grants.readonly if p not in grants.readwrite)
    grants.readwrite, grants.denied = _dedupe(grants.readwrite), _dedupe(grants.denied)
    return grants


def _dedupe(paths) -> list[Path]:
    seen, out = set(), []
    for p in paths:
        key = os.path.normcase(str(p))
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def names_local_path(raw, *, windows: Optional[bool] = None) -> bool:
    """Whether *raw* is written as a full path of this computer: from a drive letter on Windows (``C:\\...``),
    from the root elsewhere. A Windows path that starts with two separators names its target another way: a
    share of this or of another computer, an extended-length or device path, a volume by its id. Such a name
    reaches the same folders as a drive path does, no comparison of paths reads it as one of them, and opening
    it can connect to another computer. A text longer than ``PATH_CHARS`` is no path of this computer either.
    Nothing is opened here."""
    text = str(raw or "")
    if len(text) > PATH_CHARS:
        return False
    if os.name == "nt" if windows is None else windows:
        return bool(_DRIVE_PATH.match(text))
    return text.startswith("/")


def on_this_computer(path, plain: Optional[set] = None) -> bool:
    """Whether *path* is written as a full path of this computer (``names_local_path``) and no link on the way
    to it leads anywhere else. This is asked before a path the sandbox named is opened, resolved or compared by
    what it points to: Windows follows a link from a local folder to a share, so opening a path below such a
    link connects to the computer the link names, with the user's sign-in.

    The path is walked from its drive, one folder at a time. Each entry is looked at with ``os.lstat``, which
    does not follow the entry it is asked about, and a link's target is read with ``os.readlink``, which opens
    the link and not what it points to. A target on a drive of this computer continues the walk from there, at
    most ``LINKS_FOLLOWED`` times. A target of any other kind (a share, a device, a volume named by its id), a
    target that cannot be read and an entry that cannot be looked at end the walk with no. An entry that is not
    there ends it with yes: nothing below it is a link. An entry that Windows marks as stored elsewhere without
    standing for another name (the placeholder of a cloud file) is the folder or file it is.

    Elsewhere a link names a path of the same computer, and a path from the root needs no walk.
    *plain*: a set the caller keeps over a row of questions. The folders found to be no links are noted in it
    and are not looked at twice."""
    if not names_local_path(path):
        return False
    if os.name != "nt":
        return True
    known = set() if plain is None else plain
    text = ntpath.normpath(str(path))
    for _ in range(LINKS_FOLLOWED + 1):
        text = _to_first_link(text, known)
        if not isinstance(text, str):
            return text
    return False


def _to_first_link(text: str, known: set):
    """One pass of ``on_this_computer`` over the drive path *text*: True when no entry on the way is a link,
    False when one leads off this computer or cannot be read, else the path the first link makes of *text*."""
    parts = [part for part in text[3:].split("\\") if part]
    prefix = text[:3]
    for index, part in enumerate(parts):
        prefix = prefix + part if index == 0 else prefix + "\\" + part
        key = prefix.casefold()
        if key in known:
            continue
        try:
            found = os.lstat(prefix)
        except (FileNotFoundError, NotADirectoryError):
            return True
        except (OSError, ValueError):
            return False
        if not getattr(found, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            if stat.S_ISDIR(found.st_mode):
                known.add(key)
            continue
        if not (stat.S_ISLNK(found.st_mode) or getattr(found, "st_reparse_tag", 0) & _NAME_SURROGATE):
            continue
        try:
            target = _drive_target(prefix, os.readlink(prefix))
        except (OSError, ValueError):
            return False
        if target is None:
            return False
        text = ntpath.normpath("\\".join([target, *parts[index + 1:]]))
        return text if len(text) <= PATH_CHARS and _DRIVE_PATH.match(text) else False
    return True


def _drive_target(link: str, target: str) -> Optional[str]:
    """Where the link at *link* leads when its target reads *target*, as a drive path; None when it leads
    anywhere else. Windows stores a junction's target as an extended-length path: one of a drive is that drive
    path, and one of a share, a volume id or a device is not. A relative target is taken from the link's folder."""
    for extended in ("\\\\?\\", "\\??\\"):
        if target.startswith(extended):
            target = target[len(extended):]
            return ntpath.normpath(target) if _DRIVE_PATH.match(target) else None
    if _TWO_SEPARATORS.match(target):
        return None
    if not _DRIVE_PATH.match(target):
        target = ntpath.join(ntpath.dirname(link), target)
    target = ntpath.normpath(target)
    return target if _DRIVE_PATH.match(target) else None


def _identity(path) -> Optional[tuple]:
    """What *path* points to, as the file system knows it: its device and its file id. None when it cannot be
    read or the file system gives no id, so two such paths never count as one. It follows links: ask
    ``on_this_computer`` first for a path the sandbox named or was able to put a link in."""
    try:
        found = os.stat(path)
    except (OSError, ValueError):
        return None
    return (found.st_dev, found.st_ino) if found.st_ino else None


def identities(path, plain: Optional[set] = None) -> frozenset:
    """``_identity`` of *path* and of every folder above it, taken along its real path (a link in it is followed
    first, so the folders above are the ones that hold it). A path that does not exist gives the folders above
    it that do. Empty for a path that is not written as a full path of this computer or that a link leads off
    it (``on_this_computer``; *plain* is its): nothing is opened for such a path."""
    if not on_this_computer(path, plain):
        return frozenset()
    try:
        real = Path(os.path.realpath(path))
    except (OSError, ValueError):
        return frozenset()
    return frozenset(found for found in (_identity(folder) for folder in (real, *real.parents)) if found is not None)


def inside(child, parent, *, above: Optional[frozenset] = None, plain: Optional[set] = None) -> bool:
    """Whether *child* is *parent* or lies in it. The two are compared as paths, the way this system compares
    names, and by what they point to: *parent* is then one of the folders above *child* (*above*:
    ``identities(child)``, for a caller that asks about many parents; *plain*: ``on_this_computer``'s). So a
    child named through a link, a short name or a second mount of a folder lies in that folder."""
    try:
        a, b = os.path.normcase(os.path.abspath(child)), os.path.normcase(os.path.abspath(parent))
    except (OSError, ValueError):
        return False
    if a == b or a.startswith(b.rstrip("\\/") + os.sep):
        return True
    if not on_this_computer(parent, plain):
        return False
    theirs = _identity(parent)
    return theirs is not None and theirs in (identities(child, plain) if above is None else above)


def gateway_client_dirs(layout: ProfileLayout, user_home: Path) -> list[Path]:
    """The folders that hold the client keys of the OpenShell gateways a user registered: ``openshell`` in every
    config home the OpenShell CLI or the launcher reads for one. Those are the two below the user's home
    (``_OPENSHELL_CONFIG_HOMES``), the folder ``XDG_CONFIG_HOME`` names, and the one the profile's saved
    settings name as ``openshell.config_home``. The launcher's own gateway keeps its registration below the
    Hermes root."""
    homes = [user_home.joinpath(*rel.split("/")) for rel in _OPENSHELL_CONFIG_HOMES]
    named = [os.environ.get("XDG_CONFIG_HOME"), _saved_config_home(layout)]
    homes += [Path(home).expanduser() for home in named if home and Path(home).expanduser().is_absolute()]
    return _dedupe(home / "openshell" for home in homes)


def _saved_config_home(layout: ProfileLayout) -> Optional[str]:
    """``openshell.config_home`` of the profile's saved settings; None when they name none or cannot be read.
    The file is parsed only when it holds the word."""
    try:
        text = layout.spec_path.read_text(encoding="utf-8")
        if "config_home" not in text:
            return None
        import hermes_yaml

        named = (hermes_yaml.safe_load(text).get("openshell") or {}).get("config_home")
    except Exception:
        return None
    return named if isinstance(named, str) and named.strip() else None


def _protected(layout: ProfileLayout, user_home: Path, plain: Optional[set] = None) -> list[tuple[Path, str]]:
    """The folders no folder grant can be, lie in or contain, each with the refusal that names it: the Hermes
    root, the launcher's folder for the profile, every profile folder (one that is a link out of the root is
    taken where it points), the credential folders of the user's home, and the folders that hold the client
    keys of the user's OpenShell gateways (``gateway_client_dirs``)."""
    data = f"Overlaps the Hermes data folder ({layout.root})."
    out = [(layout.root, data), (layout.state_dir, data)]
    homes = [layout.home]
    try:
        homes += sorted((layout.root / "profiles").iterdir())
    except OSError:
        pass
    for home in homes:
        if not on_this_computer(home, plain) or not home.is_dir():
            continue
        real = Path(os.path.realpath(home))
        if not _overlaps(real, layout.root):  # one inside the root is refused with the root
            out.append((real, f"Overlaps the Hermes data folder ({real})."))
    try:
        from agent.file_safety import HOME_CREDENTIAL_DIRS
    except ImportError:
        HOME_CREDENTIAL_DIRS = _FALLBACK_HOME_CREDENTIAL_DIRS
    creds = [user_home.joinpath(*rel.split("/")) for rel in (*HOME_CREDENTIAL_DIRS, *_WINDOWS_CREDENTIAL_DIRS)]
    for cred in (*creds, *gateway_client_dirs(layout, user_home)):
        out.append((cred, f"Overlaps a credential folder ({cred})."))
    return out


def validate_folder(raw: str, layout: ProfileLayout) -> Path:
    """Resolve a folder grant to the one path the launcher hands on, and refuse roots that would over-grant:
    drive roots, the user's home and its ancestors, the Hermes root (profile data is granted per profile), the
    launcher's folder, the profile folders and credential folders (``_protected``).

    Every route that takes a folder comes through here: the settings page, a card, ``--folder`` and the saved
    spec at each start. On Windows the folder is named from a drive letter, no link on the way to it leads off
    this computer (``on_this_computer``, asked before anything is opened), and its final path is on a drive
    (``names_local_path``). It is compared with each protected folder as a path and by what both point to
    (``identities``), so another name of a protected folder is refused like the folder itself: a link to it, a
    second mount of it, a name in another case on a file system that folds case."""
    if not raw or not raw.strip():
        raise LayoutError("Enter a folder path.")
    text = raw.strip()
    if len(text) > PATH_CHARS:
        raise LayoutError("The path is too long.")
    windows = os.name == "nt"
    path = Path(text).expanduser()
    if windows and _TWO_SEPARATORS.match(str(path)):
        raise LayoutError(f"Use a path on a drive of this computer (C:\\...): {text}")
    if not path.is_absolute():
        raise LayoutError(f"Use a full path: {text}")
    if len(str(path)) > PATH_CHARS:
        raise LayoutError("The path is too long.")
    plain: set = set()
    if windows and not on_this_computer(path, plain):
        raise LayoutError(f"This folder is not on a drive of this computer: {text}")
    if not windows:
        path = Path("/" + str(path).lstrip("/"))  # POSIX reads two leading slashes as one; Path keeps them apart
    try:
        path = path.resolve()
        found = path.is_dir()
    except (OSError, RuntimeError, ValueError):
        found = False
    if not found:
        raise LayoutError(f"Not a folder: {path}")
    if windows and not names_local_path(path):
        raise LayoutError(f"This folder is not on a drive of this computer: {text}")
    user_home = Path.home().resolve()
    own, above = _identity(path), identities(path, plain)
    if path == Path(path.anchor) or path == user_home or path in user_home.parents \
            or (own is not None and own in identities(user_home, plain)):
        raise LayoutError(f"A drive root or home folder can't be shared: {path}")
    for folder, refusal in _protected(layout, user_home, plain):
        theirs = _identity(folder) if on_this_computer(folder, plain) else None
        if _overlaps(path, folder) or (theirs is not None and theirs in above) \
                or (own is not None and own in identities(folder, plain)):
            raise LayoutError(refusal)
    return path


def _overlaps(a: Path, b: Path) -> bool:
    a, b = Path(os.path.normcase(a)), Path(os.path.normcase(b))
    return a == b or a in b.parents or b in a.parents
