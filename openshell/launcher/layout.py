"""What the sandbox may touch, and where the launcher keeps its host-only state.

The launcher's state lives at ``<hermes root>/openshell/<profile>/``: outside every profile home, so
a sandbox can never rewrite its own spec, read its own outer token, or reach another profile's. For
the default profile (whose home IS the hermes root) that directory, ``profiles/`` and the install
infrastructure are carved out of the home grant explicitly; MXC applies the most specific grant.
"""
from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

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
    from hermes_cli.profiles import PROFILE_CREDENTIAL_PATHS, profile_path_is_private

    paths = {_hidden_path(home, rel) for rel in (*PROFILE_CREDENTIAL_PATHS, *_EXTRA_NESTED_STORES)}
    if home.is_dir():
        paths.update(entry for entry in home.iterdir() if profile_path_is_private((entry.name,)))
    return sorted(paths)


def listed_names(home: Path, paths) -> frozenset:
    """The names at the top of *home* among *paths* (what a start listed to hide, present or absent), case-folded
    as Hermes judges them."""
    return frozenset(Path(p).name.casefold() for p in paths if Path(p).parent == home)


def new_private_entries(home: Path, listed) -> list[str]:
    """The entries at the top of *home* that Hermes calls a credential store or a copy of one now and that are not
    in *listed* (``listed_names`` of the running sandbox's start), by their names on disk, sorted.

    ``credential_paths`` is taken when a sandbox starts, and what it finds by looking (a copy such as
    ``.env.bak-<stamp>`` or ``auth.json.old``) can only be what was there then. A copy made while the sandbox
    is on is found here; the stores Hermes knows by name are on every start's list, present or not. One listing
    of the folder, nothing opened. [] when the folder cannot be listed."""
    from hermes_cli.profiles import profile_path_is_private

    try:
        with os.scandir(home) as entries:
            names = [entry.name for entry in entries]
    except OSError:
        return []
    return sorted(name for name in names if name.casefold() not in listed and profile_path_is_private((name,)))


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


def validate_folder(raw: str, layout: ProfileLayout) -> Path:
    """Resolve a folder grant and refuse roots that would over-grant: drive roots, the user's home and
    its ancestors, the hermes root (profile data is granted per profile), and credential folders."""
    if not raw or not raw.strip():
        raise LayoutError("Enter a folder path.")
    path = Path(raw.strip()).expanduser()
    if not path.is_absolute():
        raise LayoutError(f"Use a full path: {raw.strip()}")
    path = path.resolve()
    if not path.is_dir():
        raise LayoutError(f"Not a folder: {path}")
    user_home = Path.home().resolve()
    if path == Path(path.anchor) or path == user_home or path in user_home.parents:
        raise LayoutError(f"A drive root or home folder can't be shared: {path}")
    if _overlaps(path, layout.root):
        raise LayoutError(f"Overlaps the Hermes data folder ({layout.root}).")
    try:
        from agent.file_safety import HOME_CREDENTIAL_DIRS
    except ImportError:
        HOME_CREDENTIAL_DIRS = _FALLBACK_HOME_CREDENTIAL_DIRS
    for rel in (*HOME_CREDENTIAL_DIRS, *_WINDOWS_CREDENTIAL_DIRS):
        cred = user_home.joinpath(*rel.split("/"))
        if _overlaps(path, cred):
            raise LayoutError(f"Overlaps a credential folder ({cred}).")
    return path


def _overlaps(a: Path, b: Path) -> bool:
    a, b = Path(os.path.normcase(a)), Path(os.path.normcase(b))
    return a == b or a in b.parents or b in a.parents
