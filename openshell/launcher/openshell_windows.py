"""OpenShell on Windows: the profile's backend as one OpenShell sandbox on the gateway's MXC driver.

Targets the OpenShell ``windows`` branch's RFC 0012 architecture: the gateway's MXC compute driver
starts a host ``openshell-supervisor`` per sandbox (policy, the authenticated per-sandbox proxy that
swaps provider placeholders for keys, the policy advisor) and ``openshell-windows-sandbox.exe``
inside an MXC process container, which runs the workload. ``OpenShellDriver.from_spec`` hands out
this driver on Windows. What differs from the Linux driver:

* Every gateway call goes through the ``openshell`` CLI: Hermes's Windows environments carry no gRPC
  stack, and a CLI built from the same branch as the gateway always speaks its protocol. Nothing
  secret rides in an argv: model keys reach ``provider create`` through its environment
  (``--credential NAME``) and the inner token reaches ``sandbox create`` through ``--env-from``.
* No image and no mounts: the sandbox runs the host's own Hermes runtime (source tree, PM env, store
  Python) under read-only grants, and the profile home and folders under grants at their real paths.
  Credential stores are hidden, present or absent, through the MXC driver's own config
  (``driver_config.mxc.denied_paths``, RFC 0006 driver config passthrough; MXC ``deniedPaths``), never
  in the OpenShell policy, which has no deny field. The driver refuses a denied path that equals or
  contains a grant, so a denied directory that holds a grant (install state around the selected env,
  the launcher's state dir around the box) is carved into its other children, and made read-only
  where it sits inside a read & write grant so the sandbox cannot create entries in it. Only a build
  with the runtime feature ``mxc-driver-config-denied-paths`` takes the field (an older one rejects
  it as unknown); the driver refuses to start on any other.
* The workload command, cwd and deny list go in ``driver_config.mxc``; ``serve`` listens on its own loopback
  port and ``openshell forward service`` holds the launcher's inner port in front of it. The policy
  sets ``ui.allow_graphical_ui: true`` (MXC's Win32k lockdown otherwise kills Python at DLL init).
* Policy binaries are native backslash paths: the branch matches the kernel's path verbatim and keeps
  a policy's paths in the form it was given. Network rules
  name the leaf interpreter (the store ``python.exe``), not the venv launcher, which never connects.
* ``OPENSHELL_*`` names are reserved for ``--env``: busybox goes on PATH instead of ``OPENSHELL_BUSYBOX``.
* MXC's ``wxc-exec`` and the shell are the plugin's own pinned installs (``windows_programs.py``) unless the
  person named a copy of their own; the switch-on installs both before the MXC gate asks ``wxc-exec`` anything.
* A model server on host loopback is reachable only at ``host.openshell.internal:<port>``, through the
  provider of its key or, when it takes no key, through the launcher's own rule
  (``openshell_driver.model_rules``); the sandbox's managed scope points the profile's model there.
* MXC lets a sandbox reach every port on host-owned addresses (``host_loopback: open``), so the
  launcher uses the gateway only over mTLS and its own host routes authenticate every request.
"""
from __future__ import annotations

import calendar
import collections
import json
import logging
import os
import re
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path, PureWindowsPath
from typing import Optional

from . import usage_data, windows_programs
from ..loopback_env import DIRECT, LOOPBACK_ENV
from .driver import DriverUnavailable, LaunchRequest, NotSupported, ProposalChanged, SandboxDriver
from .gateway_service import TELEMETRY_OFF, gateway_log
from .gateway_watch import GatewayWatch, registered as gateway_registered
from .layout import legacy_secret_cache_paths
from .openshell_driver import (HOST_GATEWAY, CredentialSinkMixin, OpenShellConfig, config_from_spec, ensure_managed,
                               gateway_endpoint, leftover_names, model_rules, network_from_policy, network_rules,
                               other_profiles, parse_event, passthrough, profile_labels, sandbox_name)
from .refusals import denied_in_events

log = logging.getLogger("openshell.driver.windows")

# A runtime feature (runtime/pins.json "features"): the MXC driver takes ``driver_config.mxc.denied_paths``
# (absolute local paths -> MXC ``deniedPaths``; NVIDIA/OpenShell#5033).
# Without it credential files inside the profile home cannot be hidden, so the driver refuses to start. A gateway
# the spec names says so with ``openshell.mxc_denied_paths: true``.
DENY_FEATURE = "mxc-driver-config-denied-paths"
SANDBOX_EXE = "openshell-windows-sandbox.exe"  # beside the CLI in a managed runtime's bin/ (gateway_service)
# A runtime feature (runtime/pins.json "features"): a live policy update keeps unchanged connections open
# (the model's streaming reply survives a card's network answer).
RELOAD_FEATURE = "policy-reload-keeps-streams"
# A runtime feature: the sandbox's CA bundle (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO,
# which replace a client's own trust) holds the Windows roots as well as the sandbox CA. Only then can a granted
# site be a plain TLS tunnel (``tls: skip``, the site's own certificate): with a bundle of the sandbox CA alone,
# requests, git and OpenSSL clients reject every certificate the proxy did not issue, so without the feature
# grants stay terminated by the proxy (and Schannel clients such as curl.exe, which ignore the bundle, fail).
TUNNEL_FEATURE = "ca-bundle-system-roots"
# curl's config file for the sandbox (``_curl_home``): in this folder of the launcher's state dir, beside managed/
# and verdicts/. One option; the certificate chain and host name checks stay as curl has them.
CURL_DIRNAME = "curl"
CURL_CONFIG = (
    "# Written by the Hermes sandbox launcher on every start.\n"
    "# Windows cannot reach certificate revocation servers from inside the sandbox. curl still validates the\n"
    "# certificate chain and refuses a certificate known to be revoked; it goes on only when the revocation\n"
    "# server cannot be reached.\n"
    "ssl-revoke-best-effort\n")
# How long a policy update waits for its revision to report loaded. The supervisor polls the gateway and
# loads a revision a few seconds after it is submitted; past this the update reports ``loaded: False``
# (submitted, not confirmed) instead of failing.
LOAD_TIMEOUT = 20.0
_SUBMITTED_RE = re.compile(r"Policy version (\d+) submitted")
_UNCHANGED_RE = re.compile(r"Policy unchanged \(version (\d+)")
UI_POLICY = {"allow_graphical_ui": True, "clipboard": "none", "allow_input_injection": False}
TOKEN_ENV = "HERMES_DASHBOARD_SESSION_TOKEN"
MARKER_NAME = "profiles_run_elsewhere"  # core's host-only "this profile runs elsewhere" registry
# The launcher's own files in its state dir (layout.ProfileLayout), denied by name even before they exist.
_HOST_ONLY_FILES = ("token", "spec.yaml", "spec.tmp", "state.json", "state.tmp", "cards.jsonl", "pins", "handback")
_LIVE_PHASES = ("PROVISIONING", "STARTING", "READY", "UNKNOWN", "UNSPECIFIED", "PENDING")
_STATE_CHECK_INTERVAL = 2.0
_START_GRACE = 15.0  # seconds after READY in which a missing/ERROR read is rechecked, not reported
_FORWARD_RETRY = 5.0
# The follower of the gateway's log file (``RefusalFollower``). How long after a refused connection its record can
# still be on its way into the verdict file: what the hook of a program call that named a host waits before it
# returns the call as it came (sandbox_hook.py reads it from ``HERMES_SANDBOX_REFUSALS``). Measured on Windows over
# 160 refused connections (curl over https and http, Python), with and without a second program refused ten times a
# second: the line was in the file within 0.02 s of the refusal and readable at most 0.08 s after the refused
# program returned with a look every 0.05 s; none was missing or out of order.
REFUSALS_SETTLE = 0.25
_FOLLOW_POLL = 0.025    # a look is the file's size: microseconds
_MAX_POLICY_PATHS = 256  # OpenShell's cap on a policy's filesystem paths
_MAX_DENIED_PATHS = 256  # the launcher's own cap on driver_config.mxc.denied_paths (kept at the policy's)
_LOG_RE = re.compile(r"^\[(?P<t>[\d.]+)\]\s+\[(?P<src>[^\]]*)\]\s+\[(?P<lvl>[^\]]*)\]\s+\[(?P<tgt>[^\]]*)\]\s?(?P<msg>.*)$")
_ENDPOINT_RE = re.compile(r"([^\s,\[\]]+):(\d+)(?:\s*\[([^\]]*)\])?")
_HITS_RE = re.compile(r"(\d+)(?:\s*\(first seen ([^,]+), last seen ([^)]+)\))?")


def native(path) -> str:
    """A Windows path in native (backslash) form; anything else unchanged."""
    text = str(path)
    return str(PureWindowsPath(text)) if re.match(r"^[A-Za-z]:[\\/]", text) else text


def leaf_python(python: Path) -> Path:
    """The interpreter that really runs (and connects): a venv's ``python.exe`` is a launcher that
    starts the store Python named by ``home`` in ``pyvenv.cfg``."""
    cfg = Path(python).parent.parent / "pyvenv.cfg"
    if cfg.is_file():
        for line in cfg.read_text(encoding="utf-8-sig").splitlines():
            key, _, value = line.partition("=")
            if key.strip().lower() == "home" and value.strip():
                candidate = Path(value.strip()) / "python.exe"
                if candidate.is_file():
                    return candidate.resolve()
    return Path(python).resolve()


# -- filesystem policy: grants, deny list, carve-outs ------------------------------------------------

def _key(path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def _inside(child, parent) -> bool:
    c, p = _key(child), _key(parent)
    return c == p or c.startswith(p.rstrip("\\/") + os.sep)


def carve_denials(denied, readonly, readwrite, keep=()) -> tuple[list[Path], list[Path], list[str]]:
    """The MXC driver refuses a denied path that contains (or equals) a grant. Each such denied directory
    becomes a deny of its other children instead, recursively around the grants; where it sits in a
    read & write grant it also becomes read-only, so the sandbox cannot create entries in it.
    *keep*: paths the driver grants on its own and checks the same way (the sandbox executable), carved
    around like grants but never part of the policy.
    Returns ``(deny, extra read-only, notes)``."""
    grants = [Path(p) for p in (*readonly, *readwrite, *keep)]
    deny, extra_ro, notes = [], [], []

    def carve(directory: Path, inner: list[Path]) -> None:
        if any(_inside(directory, rw) and _key(directory) != _key(rw) for rw in readwrite):
            extra_ro.append(directory)
        try:
            children = sorted(directory.iterdir())
        except OSError as exc:
            notes.append(f"cannot list {directory}: {exc}")
            return
        for child in children:
            mine = [g for g in inner if _inside(g, child)]
            if any(_key(g) == _key(child) for g in mine):
                continue
            if mine:
                carve(child, mine)
            else:
                deny.append(child)

    for path in (Path(p) for p in denied):
        inner = [g for g in grants if _inside(g, path)]
        if not inner:
            deny.append(path)
        elif any(_key(g) == _key(path) for g in inner):
            notes.append(f"{path} is both granted and denied; the grant stands")
        elif not any(_inside(path, g) for g in grants):
            notes.append(f"{path} lies outside every grant (unreachable); only its granted parts are mapped")
        else:
            carve(path, inner)
    return _dedupe(deny), _dedupe(extra_ro), notes


def _dedupe(paths) -> list[Path]:
    seen, out = set(), []
    for p in paths:
        if _key(p) not in seen:
            seen.add(_key(p))
            out.append(Path(p))
    return out


# -- rename safety -------------------------------------------------------------------------------------
# MXC (1.0.0 and 1.0.1) hides and protects paths, not files. A workload may rename a folder when the folder itself
# and its parent are both read & write for it; the folder's contents then sit at new paths that no deny and no
# read-only grant names (NVIDIA/OpenShell#5033). On MXC 1.0.1 it renames a plain folder inside a read & write
# grant and a read & write grant root nested in another read & write grant, and reads or writes what was hidden
# or read-only below it; it cannot rename a denied path, a read-only folder, or a grant root whose parent it
# cannot write. OpenShell's MXC driver (NVIDIA/OpenShell#5033) rejects a deny with a writable folder
# between it and a read & write grant containing it; this check counts the same folders (a nested read & write
# grant root too) and also guards read-only grants, so the launcher never sends a deny OpenShell rejects, nor one
# the sandbox can undo.

def _access(path, readonly, readwrite, deny) -> Optional[str]:
    """What MXC gives the sandbox at *path*: the most specific grant or deny containing it wins (a deny equal to
    a grant removes it; read & write equal to read-only wins, as the policy lists it). None: not granted."""
    best, out = -1, None
    for kind, items in (("ro", readonly), ("rw", readwrite), ("deny", deny)):  # later kinds win ties
        for g in items:
            if _inside(path, g) and len(_key(g)) >= best:
                best, out = len(_key(g)), kind
    return out


def rename_exposure(path, readonly, readwrite, deny) -> Optional[Path]:
    """The folder above *path* the sandbox could rename, carrying *path* away from its deny or read-only grant;
    None when every folder above it is out of reach (denied, read-only, ungranted, or a grant root whose parent
    the sandbox cannot write)."""
    for folder in Path(path).parents:
        if folder.parent == folder:
            break
        if _access(folder, readonly, readwrite, deny) == "rw" and \
                _access(folder.parent, readonly, readwrite, deny) == "rw":
            return folder
    return None


def _drop_nested(deny: list[Path]) -> list[Path]:
    """A deny inside another deny hides nothing more (``installs/<key>`` under ``installs``)."""
    return [d for d in deny if not any(_key(o) != _key(d) and _inside(d, o) for o in deny)]


def check_rename_safe(deny, readonly, readwrite) -> tuple[list[Path], list[str]]:
    """The deny list the sandbox cannot undo by renaming a folder above an entry. A present path that cannot be
    hidden or kept read-only that way refuses the launch (DriverUnavailable, naming the path and the folder);
    an absent one is left out with a note (nothing to read; the sandbox may create it at that path, as it may
    create any absent store by renaming a file onto it). Returns ``(deny, notes)``."""
    deny = _dedupe(deny)
    kept, notes, refused = [], [], []
    for path in deny:
        folder = rename_exposure(path, readonly, readwrite, deny)
        if folder is None:
            kept.append(path)
        elif os.path.lexists(path):
            refused.append(f"{path} (the sandbox can rename {folder})")
        else:
            notes.append(f"not hidden (absent; a deny below {folder} is not rename-safe): {path}")
    for path in readonly:
        folder = rename_exposure(path, readonly, readwrite, deny)
        if folder is not None:
            refused.append(f"read-only {path} (the sandbox can rename {folder} and write it)")
    if refused:
        raise DriverUnavailable(
            "the sandbox can't keep these paths hidden or read-only: it may write the folder that holds them, "
            "and on Windows a sandbox that can rename a folder reaches what was hidden below it at the new path: "
            + "; ".join(refused) + ". " + _remedy())
    return kept, notes


# What the user can do about a store below a folder the sandbox writes (layout.WRITABLE_STORE_DIRS). A core with
# layout.legacy_secret_cache_paths() keeps its secret-manager caches and the Photon sidecar record at the top of the
# profile folder, and the launcher removes the old copies before each launch, so only other files stay to name.
_REMEDY = "Remove those files while the profile is not sandboxed, or keep this profile unsandboxed."
# An older core still keeps those stores in cache and runtime.
_REMEDY_OLD_CORE = ("Remove those files while the profile is not sandboxed (bws_cache*.json and op_cache.json in cache "
                    "are secret-manager caches Hermes fetches again; runtime\\photon-sidecar.json belongs to a running "
                    "Photon sidecar), or keep this profile unsandboxed until Hermes stores them at the top of the "
                    "profile folder.")


def _remedy() -> str:
    return _REMEDY if legacy_secret_cache_paths() is not None else _REMEDY_OLD_CORE


def native_rules(rules: dict) -> dict:
    """Network rules with every Windows binary path in native form (the branch matches verbatim)."""
    out = {}
    for name, rule in (rules or {}).items():
        rule = json.loads(json.dumps(rule))
        rule["binaries"] = [{**b, "path": native(b.get("path", ""))} for b in rule.get("binaries") or []]
        out[name] = rule
    return out


def build_windows_policy(grants, network: dict, binaries, *, extra_readonly=(), extra_deny=(),
                         stored_deny=(), reserved=(), keep=(), home=None, models=()
                         ) -> tuple[dict, list[str], list[str]]:
    """The create-time OpenShell policy for one launch and its deny list: grants -> filesystem_policy
    (read-only and read & write), the page's network view -> network_policies bound to *binaries*, plus the
    launcher's built-in destination while the profile at *home* shares its usage data (usage_data.py) and its
    rules for *models* (``openshell_driver.local_models``: model servers on this computer that take no key), plain
    host grants as TLS tunnels to the site (``passthrough``; *reserved*: provider endpoints); the denied
    paths, carved around nested grants and *keep* (see ``carve_denials``), -> native paths for
    ``driver_config.mxc.denied_paths``. The deny list never goes in the policy (OpenShell's policy has no deny field).
    Returns ``(policy, denied_paths, notes)``."""
    readonly = [Path(p) for p in (*grants.readonly, *extra_readonly)]
    readwrite = [Path(p) for p in grants.readwrite]
    deny, carved_ro, notes = carve_denials([*grants.denied, *extra_deny, *stored_deny], readonly, readwrite, keep)
    readonly = _dedupe([*readonly, *carved_ro])
    readonly = [p for p in readonly if not any(_key(p) == _key(rw) for rw in readwrite)]
    deny, rename_notes = check_rename_safe(_drop_nested(deny), readonly, readwrite)
    notes = [*notes, *rename_notes]
    count = len(readonly) + len(readwrite)
    if count > _MAX_POLICY_PATHS:
        raise DriverUnavailable(f"the sandbox policy would list {count} paths; OpenShell allows {_MAX_POLICY_PATHS}")
    if len(deny) > _MAX_DENIED_PATHS:
        raise DriverUnavailable(f"the sandbox would hide {len(deny)} paths; the launcher allows {_MAX_DENIED_PATHS}")
    fs = {"include_workdir": False, "read_only": [native(p) for p in readonly],
          "read_write": [native(p) for p in readwrite]}
    policy = {"version": 1, "filesystem_policy": fs, "ui": dict(UI_POLICY)}
    natives = [native(b) for b in binaries]
    rules = model_rules(usage_data.rules(network_rules(network, natives), home, natives), models, natives)
    rules = passthrough(native_rules(rules), reserved)
    if rules:
        policy["network_policies"] = rules
    return policy, [native(p) for p in deny], notes


# -- the gateway through the CLI ----------------------------------------------------------------------

class CliError(RuntimeError):
    pass


# Console children of a windowless process each get a new console window unless told not to.
_NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


class CliGateway:
    """The gateway as the Windows driver uses it, one CLI call per method. Tests substitute ``run``."""

    def __init__(self, cfg: OpenShellConfig, run=subprocess.run):
        self.cfg = cfg
        self._run = run

    def env(self, extra: Optional[dict] = None) -> dict:
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("OPENSHELL_", "HERMES_"))}
        env.update({"XDG_CONFIG_HOME": str(self.cfg.config_home), "OPENSHELL_GATEWAY": self.cfg.gateway,
                    "OPENSHELL_WORKSPACE": self.cfg.workspace, "NO_COLOR": "1"})
        if extra:
            env.update(extra)
        env.update(TELEMETRY_OFF)  # last: a provider key named like the switch cannot turn it on
        return env

    def run(self, *args: str, extra_env: Optional[dict] = None, timeout: float = 120.0, check: bool = True) -> str:
        # The launcher runs as a windowless logon task, so every console child it starts without
        # CREATE_NO_WINDOW opens a new terminal window on the user's desktop.
        done = self._run([str(self.cfg.cli), *args], env=self.env(extra_env), capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=timeout, stdin=subprocess.DEVNULL,
                         **_NO_WINDOW)
        out = ((done.stdout or "") + ("\n" + done.stderr if done.stderr else "")).strip()
        if check and done.returncode != 0:
            raise CliError(f"openshell {' '.join(args[:3])} failed ({done.returncode}): {out[-600:]}")
        return out if check else f"{done.returncode}\n{out}"

    def _json(self, *args: str, timeout: float = 60.0) -> dict:
        out = self.run(*args, timeout=timeout)
        try:
            return _first_json(out) or {}
        except ValueError as exc:
            raise CliError(f"openshell {' '.join(args[:3])}: not JSON: {out[:300]}") from exc

    # lifecycle
    def version(self) -> str:
        return self.run("--version", timeout=30)

    def status(self) -> str:
        return self.run("status", timeout=30)

    def info(self) -> str:
        return self.run("gateway", "info", "-g", self.cfg.gateway, timeout=30)

    def sandbox(self, name: str) -> Optional[dict]:
        raw = self.run("sandbox", "get", name, "-o", "json", timeout=30, check=False)
        code, _, out = raw.partition("\n")
        if code != "0":
            if "not found" in out.lower() or "notfound" in out.lower().replace(" ", ""):
                return None
            raise CliError(f"openshell sandbox get {name}: {out[-300:]}")
        return _first_json(out)

    def create(self, name: str, policy_path: Path, driver_config: dict, env: dict, env_from: dict,
               providers=(), labels: Optional[dict] = None) -> str:
        # --no-credential-warnings: the CLI otherwise stops at the inner token ("looks like a credential
        # passed as a plain environment variable"); the sandbox holds that token by design.
        args = ["sandbox", "create", "--name", name, "--policy", str(policy_path), "--driver-config-json",
                json.dumps(driver_config), "--no-tty", "--detach", "--no-auto-providers", "--no-credential-warnings"]
        for provider in providers:
            args += ["--provider", provider]
        for key, value in (labels or {}).items():
            args += ["--label", f"{key}={value}"]
        for key, value in env.items():
            args += ["--env", f"{key}={value}"]
        for key in env_from:
            args += ["--env-from", key]
        return self.run(*args, extra_env=dict(env_from), timeout=180)

    def delete(self, name: str, timeout: float = 120.0) -> None:
        self.run("sandbox", "delete", name, timeout=60, check=False)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.sandbox(name) is None:
                return
            time.sleep(1.0)
        raise CliError(f"sandbox {name} still exists {timeout:.0f}s after delete")

    # providers
    def upsert_profile(self, path: Path, profile_id: str) -> str:
        raw = self.run("provider", "profile", "import", "--file", str(path), check=False)
        if raw.startswith("0\n"):
            return "imported"
        if "stable_placeholder" in raw:  # the gateway cannot keep a placeholder stable: no update would help
            raise CliError(f"openshell provider profile import failed: {raw[-600:]}")
        try:
            current = self._json("provider", "profile", "export", profile_id, "-o", "json")
        except CliError as exc:  # no such profile: the import failed for a reason of its own
            raise CliError(f"openshell provider profile import failed: {raw.partition(chr(10))[2][-600:]}") from exc
        version = int(current.get("resource_version") or 0)
        profile = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps({**profile, "resource_version": version}, indent=1), encoding="utf-8")
        self.run("provider", "profile", "update", "--file", str(path), profile_id)
        return "updated"

    def upsert_provider(self, name: str, profile_id: str, values: dict) -> str:
        """The values travel in the CLI's environment (``--credential NAME`` is an env lookup), never in
        its arguments."""
        names = [arg for env_name in values for arg in ("--credential", env_name)]
        raw = self.run("provider", "create", "--name", name, "--type", profile_id, *names,
                       extra_env=dict(values), check=False)
        if raw.startswith("0\n"):
            return "created"
        try:
            self.run("provider", "update", name, *names, extra_env=dict(values))
        except CliError as exc:  # it does not exist either: what the create said is the reason
            raise CliError(f"{exc}; provider create said: {raw.partition(chr(10))[2][-300:]}") from exc
        return "updated"

    def update_provider(self, name: str, values: dict, expires: Optional[dict] = None, clear=()) -> None:
        """A value-only update: the new values (from the CLI's environment), the expiry of each (*expires*:
        variable -> epoch seconds; the CLI takes milliseconds) and the expiries to take off (a zero)."""
        args = [arg for env_name in values for arg in ("--credential", env_name)]
        for env_name, when in (expires or {}).items():
            args += ["--credential-expires-at", f"{env_name}={int(float(when) * 1000)}"]
        for env_name in clear:
            args += ["--credential-expires-at", f"{env_name}=0"]
        self.run("provider", "update", name, *args, extra_env=dict(values))

    def delete_provider(self, name: str) -> None:
        """Delete provider *name* and the profile of the same name; neither has to exist."""
        self.run("provider", "delete", name, check=False)
        self.run("provider", "profile", "delete", name, check=False)

    def provider_state(self, sandbox: str, provider: str) -> tuple:
        """(state, reason) of what *sandbox* did with *provider*, from ``sandbox provider status``; (None, None)
        when the answer does not say. A call the CLI refuses raises."""
        return parse_provider_status(self._json("sandbox", "provider", "status", sandbox, provider, "-o", "json"),
                                     sandbox, provider)

    # policy
    def policy(self, name: str, rev: int = 0) -> dict:
        args = ["policy", "get", name, "--base", "-o", "json"]
        if rev:
            args[3:3] = ["--rev", str(int(rev))]
        return self._json(*args)

    def revisions(self, name: str) -> list[dict]:
        return list(self._json("policy", "list", name, "--page-size", "100", "-o", "json").get("revisions") or [])

    def set_policy(self, name: str, path: Path, timeout: float = LOAD_TIMEOUT) -> dict:
        """Submit a policy and let the CLI wait (``--wait``) until its revision loads, at most *timeout*.
        ``{"code", "version", "unchanged", "out"}``: code 0 loaded (or superseded, or unchanged), 124 still
        loading when the wait ended (submitted all the same), 1 the sandbox rejected it. Anything else
        (no gateway, a bad file) raises."""
        raw = self.run("policy", "set", name, "--policy", str(path), "--wait", "--timeout", str(max(1, int(timeout))),
                       timeout=timeout + 30, check=False)
        code_text, _, out = raw.partition("\n")
        code = int(code_text) if code_text.lstrip("-").isdigit() else -1
        submitted, unchanged = _SUBMITTED_RE.search(out), _UNCHANGED_RE.search(out)
        version = int((submitted or unchanged).group(1)) if (submitted or unchanged) else None
        if code not in (0, 124) and not (code == 1 and submitted):
            raise CliError(f"openshell policy set failed ({code}): {out[-600:]}")
        return {"code": code, "version": version, "unchanged": bool(unchanged) and not submitted, "out": out}

    def rules(self, name: str, status: str = "") -> list[dict]:
        args = ["rule", "get", name] + (["--status", status] if status else [])
        return parse_rules(self.run(*args, timeout=60))

    def approve(self, name: str, chunk_id: str) -> str:
        return self.run("rule", "approve", "--chunk-id", chunk_id, name, timeout=90)

    def reject(self, name: str, chunk_id: str, reason: str) -> str:
        return self.run("rule", "reject", "--chunk-id", chunk_id, "--reason", reason, name, timeout=60)

    def set_setting(self, name: str, key: str, value: str) -> str:
        return self.run("settings", "set", name, "--key", key, "--value", value, timeout=30)

    def logs(self, name: str, lines: int, since: Optional[float] = None, source: str = "sandbox") -> list[dict]:
        args = ["logs", name, "-n", str(int(lines)), "--source", source]
        if since:
            args += ["--since", f"{max(1, int(time.time() - since) + 1)}s"]
        return parse_log_lines(self.run(*args, timeout=60))


def _first_json(out: str):
    """The first JSON object in a command's output, None when it has none. What follows it (a line the CLI
    writes beside its answer) is left alone. Raises ValueError for an object that does not parse."""
    start = out.find("{")
    return json.JSONDecoder().raw_decode(out, start)[0] if start >= 0 else None


def parse_provider_status(doc, sandbox: str, provider: str) -> tuple:
    """``sandbox provider status -o json`` -> (state, reason) in upper case; (None, None) when *doc* does not say.

    The CLI prints ``{"mutation_id", "targets": [{"receipt": {"provider", "desired": {"sandbox"}}, "state",
    "reason", "observed", "wait_outcome"}]}``: one target for this command, none or several for the commands
    that print the same form. Of several targets only those whose receipt names this sandbox and provider
    count, and among them one that is not ready before one that is. ``unknown`` is the CLI's word for a
    number it has no name for: no answer. A state at the top level, or under ``status``, is read as well."""
    def word(value, prefix: str):
        text = str(value or "").strip().upper().replace(prefix, "")
        return None if text in ("", "UNKNOWN") else text

    def pair(node: dict) -> tuple:
        return word(node.get("state"), "PROVIDER_READINESS_STATE_"), word(node.get("reason"), "PROVIDER_READINESS_REASON_")

    def names(target: dict) -> tuple:
        receipt = target.get("receipt") if isinstance(target.get("receipt"), dict) else {}
        desired = receipt.get("desired") if isinstance(receipt.get("desired"), dict) else {}
        return desired.get("sandbox"), receipt.get("provider")

    if not isinstance(doc, dict):
        return None, None
    targets = doc.get("targets")
    if isinstance(targets, list):
        found = [target for target in targets if isinstance(target, dict)]
        mine = [target for target in found if names(target) == (sandbox, provider)]
        if not mine and len(found) == 1 and names(found[0]) == (None, None):
            mine = found  # the one answer to this question, without a receipt to tell by
        pairs = [pair(target) for target in mine]
        for wanted in (lambda p: p[0] not in (None, "READY"), lambda p: p[0] is None, lambda p: True):
            match = next((p for p in pairs if wanted(p)), None)
            if match is not None:
                return match if match[0] is not None else (None, None)
        return None, None
    inner = doc.get("status") if isinstance(doc.get("status"), dict) else doc
    state, reason = pair(inner)
    return (state, reason) if state is not None else (None, None)


def parse_rules(text: str) -> list[dict]:
    """``openshell rule get`` (text) -> chunks: id, status, rule_name, binary, endpoints, binaries,
    rationale, prover findings, confidence, hits."""
    chunks, current = [], None
    for raw in text.splitlines():
        line = raw.strip()
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "chunk":
            current = {"id": value, "endpoints": [], "binaries": []}
            chunks.append(current)
        elif current is None:
            continue
        elif key == "status":
            current["status"] = value.lower()
        elif key == "rule":
            current["rule_name"] = value
        elif key == "binary":
            current["binary"] = value
        elif key == "confidence":
            current["confidence"] = value
        elif key == "rationale":
            current["rationale"] = value
        elif key == "prover":
            current["security_notes"] = value
        elif key == "security":
            current["flags"] = value
        elif key == "candidate":
            current["candidate"] = value
        elif key == "endpoints":
            for host, port, detail in _ENDPOINT_RE.findall(value):
                ep = {"host": host, "port": int(port)}
                if detail:
                    ep["detail"] = detail
                    # "L7 rest, allow GET /repos/**": the HTTP requests the chunk allows (the in-chat card)
                    current.setdefault("requests", []).extend(
                        {"method": m.upper(), "path": p} for m, p in re.findall(r"allow\s+(\S+)\s+(\S+)", detail))
                current["endpoints"].append(ep)
        elif key == "binaries":
            current["binaries"] = [b.strip() for b in value.split(",") if b.strip()]
        elif key == "hits":
            m = _HITS_RE.match(value)
            if m:
                current["hit_count"] = int(m.group(1))
                if m.group(2):
                    current["first_seen"], current["last_seen"] = m.group(2).strip(), m.group(3).strip()
        elif key in ("reason", "rejection reason"):
            current["rejection_reason"] = value
    return chunks


def parse_log_lines(text: str) -> list[dict]:
    """``openshell logs`` lines (``[ts] [source] [LEVEL] [target] message``) -> the dicts ``parse_event`` reads."""
    out = []
    for raw in text.splitlines():
        m = _LOG_RE.match(raw.strip())
        if not m:
            continue
        out.append({"time": float(m.group("t")), "source": m.group("src").strip(), "level": m.group("lvl").strip(),
                    "target": m.group("tgt").strip(), "message": m.group("msg"), "fields": {}})
    return out


# -- the sandbox's refusals as they happen ------------------------------------------------------------------

_PROGRAM_RE = re.compile(r"^\s*\S.*\(\d+\)\s*->")
_ANSI_RE = re.compile(rb"\x1b\[[0-9;]*m")
# One line of the gateway's own log that relays a line of a sandbox's supervisor (the MXC driver hands on what the
# supervisor writes), colour escapes removed: ``<gateway time> WARN <target>: <supervisor time, UTC>Z OCSF
# <shorthand> sandbox=<name> component="supervisor"``.
_RELAYED_RE = re.compile(r'(?P<t>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?P<frac>\.\d+)?Z OCSF (?P<msg>.*) sandbox=(?P<name>\S+) '
                         r'component="supervisor"\s*$')


def refusal_of(line: dict) -> Optional[dict]:
    """The refused connection one line of the sandbox's log reports (a ``parse_log_lines`` dict), as ``{"time",
    "host", "port"}`` (epoch seconds; the name the program asked for), or None: any other line, an allowed
    connection, a destination that never gets a card (an address, this computer's alias), and a DENIED line that
    names no program (a tunnel OpenShell closed because the policy changed, which is no refusal of its host)."""
    event = parse_event(line)
    t = event.get("time")
    if not event.get("ocsf") or isinstance(t, bool) or not isinstance(t, (int, float)) or t <= 0:
        return None
    if not _PROGRAM_RE.match(str(event.get("detail") or "")):
        return None
    for host, ports in denied_in_events([event]).items():
        return {"time": t / 1000.0 if t > 1e11 else float(t), "host": host, "port": next(iter(ports), None)}
    return None


def relayed_refusal(raw: bytes, sandbox: str) -> Optional[dict]:
    """``refusal_of`` for one raw line of the gateway's log file: the supervisor's shorthand record of a refused
    connection of *sandbox* (the file holds every sandbox's lines, coloured although it is a file). The time is
    the supervisor's own, when it refused. The full JSON copy of the same record (``OCSF-JSON``), which follows
    once that export is on, is not read a second time."""
    if b" OCSF " not in raw or b" DENIED " not in raw:
        return None
    m = _RELAYED_RE.search(_ANSI_RE.sub(b"", raw).decode("utf-8", "replace").rstrip("\r\n"))
    if m is None or m.group("name") != sandbox:
        return None
    try:
        t = calendar.timegm(time.strptime(m.group("t"), "%Y-%m-%dT%H:%M:%S")) + float(m.group("frac") or 0)
    except ValueError:
        return None
    return refusal_of({"time": t, "source": "sandbox", "level": "OCSF", "target": "ocsf", "message": m.group("msg")})


class RefusalFollower:
    """Follows the gateway's own log file (``<gateway dir>/logs/gateway.log``: the gateway's output, where a refusal
    of a sandbox's supervisor is a line within about 20 ms) from a thread of the launcher and keeps the refused
    connections of one sandbox in memory (``recent``, at most ``RECENT``), so the launcher hears of a refusal as it
    happens: no process is started and the gateway is not asked. Each look is the file's size; only when it grew is
    the file opened, read from the last position to its last whole line, and closed again (a reader that held it
    open would keep the gateway from removing or renaming it). A file that is gone or shorter than before is a new
    file, read from its start; lines older than the follower are not kept. Started with the sandbox, ended by
    ``stop`` before the sandbox is deleted; a thread ends with the launcher by itself."""

    RECENT = 256

    def __init__(self, path, sandbox: str, *, poll: float = _FOLLOW_POLL, clock=time.time):
        self.path, self.sandbox, self._poll = Path(path), str(sandbox), poll
        self._since = clock() - 1.0  # records from before this follower are another run's
        self._pos = self._size()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.recent: collections.deque = collections.deque(maxlen=self.RECENT)
        self.looks = 0
        self.read = 0

    def _size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0  # no file (yet, or any more): no records yet

    def start(self) -> None:
        self._thread = threading.Thread(target=self._follow, name="openshell-refusals", daemon=True)
        self._thread.start()

    def _follow(self) -> None:
        while not self._stop.wait(self._poll):
            try:
                self.look()
            except Exception:  # never let a look end the follower
                log.debug("a look at the gateway's log failed", exc_info=True)

    def look(self) -> int:
        """One look at the file; returns how many refusals it added."""
        self.looks += 1
        size = self._size()
        if size < self._pos:
            self._pos = 0  # a new file: the gateway started again
        if size <= self._pos:
            return 0
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self._pos)
                data = fh.read(size - self._pos)
        except OSError:
            return 0
        end = data.rfind(b"\n")
        if end < 0:
            return 0  # no whole line yet
        self._pos += end + 1
        self.read += end + 1
        added = 0
        for raw in data[:end].split(b"\n"):
            row = relayed_refusal(raw, self.sandbox)
            if row is not None and row["time"] >= self._since:
                self.recent.append(row)
                added += 1
        return added

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    def status(self) -> dict:
        thread = self._thread
        return {"running": bool(thread is not None and thread.is_alive()), "file": str(self.path), "looks": self.looks,
                "bytes_read": self.read, "refusals": len(self.recent)}


# -- the driver -----------------------------------------------------------------------------------------

class OpenShellWindowsDriver(CredentialSinkMixin, SandboxDriver):
    name = "openshell"
    uses_host_shell = True  # the host's interpreter and busybox run inside; the supervisor pins busybox
    asks_gateway = True  # ``exit_code`` runs the CLI against the gateway
    capabilities_info = {"label": "OpenShell sandbox (Windows)", "requests_supported": True,
                         "credentials": "placeholders",
                         # MXC: every port on every host-owned address is reachable from inside, whatever
                         # the policy says; loopback rules would show a limit nothing enforces.
                         "host_loopback": "open", "network_rules": ["host", "cidr"], "network_live": True,
                         "egress_allow_all": False, "policy_revisions": True, "audit_events": True,
                         "model_endpoints": "provider", "network_live_interrupts": True}

    def __init__(self, cfg: OpenShellConfig, *, wxc_exec: Optional[Path] = None,
                 gateway: Optional[CliGateway] = None, run=subprocess.run, popen=subprocess.Popen,
                 reload_keeps_streams: bool = False, tls_tunnels: bool = False, denied_paths: bool = False,
                 programs_root: Optional[Path] = None, own_shell: Optional[Path] = None):
        self.cfg = cfg
        self.wxc_exec = Path(wxc_exec) if wxc_exec else None
        # *wxc_exec* is a copy the person named (the spec, OPENSHELL_WXC_EXEC_PATH). Without one, the plugin's
        # own pinned wxc-exec is installed under this Hermes root and checked before every use
        # (``_pinned_wxc_exec``). No root: only a wxc-exec that was handed in is used.
        self._own_wxc_exec = self.wxc_exec is not None
        self._programs_root = Path(programs_root) if programs_root else None
        # A shell the person named (the spec, OPENSHELL_BUSYBOX): the switch-on then installs none (``_pinned_shell``).
        self._own_shell = Path(own_shell) if own_shell else None
        # Whether the MXC driver takes ``driver_config.mxc.denied_paths``: the managed runtime's pinned features say
        # so (DENY_FEATURE); a gateway the spec names says so with ``openshell.mxc_denied_paths``. Without it the
        # driver refuses to start (credential files would be readable inside).
        self.denied_paths_supported = bool(denied_paths)
        self._runtime_id: Optional[str] = None  # the managed runtime adopted last (for messages)
        # The managed runtime's openshell-windows-sandbox.exe: the MXC driver grants it to every sandbox and refuses
        # a denied path that contains it. For the default profile it sits inside the denied launcher state.
        self._sandbox_exe: Optional[Path] = None
        # Whether a live policy update keeps unchanged connections (the model's streaming reply) open: the
        # managed runtime's pinned features say so (RELOAD_FEATURE); a gateway the spec names says so with
        # ``openshell.reload_keeps_streams``. Without it card answers for the network apply between turns.
        self.reload_keeps_streams = bool(reload_keeps_streams)
        # Whether granted sites are plain TLS tunnels (TUNNEL_FEATURE; ``openshell.tls_tunnels`` for a named gateway).
        self.tls_tunnels = bool(tls_tunnels)
        # capabilities() on this instance reports it; the class-level answer stays the conservative one
        self.capabilities = self._instance_capabilities
        self.gw = gateway or CliGateway(cfg, run=run)
        self._popen = popen
        self._name: Optional[str] = None
        self._request: Optional[LaunchRequest] = None
        self._forward: Optional[subprocess.Popen] = None
        self._forward_started = 0.0
        self._follower: Optional[RefusalFollower] = None
        self._serve_port = 0
        self._log = None
        self._launch_policy: dict = {}
        self._denied_paths: list[str] = []  # what driver_config.mxc.denied_paths carried at create
        self._policy_path: Optional[Path] = None
        self._binaries: list[str] = []
        self._providers: list[dict] = []
        self._provider_notes: list[str] = []
        self._withheld: list[str] = []
        self._changed: list[dict] = []
        self._sink_state()
        self._notes: list[str] = []
        self._model_overrides: dict = {}
        self._final_code: Optional[int] = -1
        self._cached: Optional[int] = None
        self._checked = 0.0
        self._ready_at = 0.0
        self._starting = False
        self._gone = True  # False after a stop whose delete failed: the sandbox is not known to be gone
        self._gateway = GatewayWatch(cfg)  # whether the gateway is still there (gateway_watch.py)

    @classmethod
    def from_spec(cls, spec: dict) -> "OpenShellWindowsDriver":
        from hermes_constants import get_default_hermes_root

        raw = dict(spec.get("openshell") or {})
        wxc = windows_programs.own("wxc-exec", spec)["file"]
        if wxc is None and not windows_programs.supported("wxc-exec"):
            wxc = windows_programs.on_path("wxc-exec")  # No pinned build for this PC: one on PATH, as before
        return cls(config_from_spec(spec), wxc_exec=wxc, programs_root=get_default_hermes_root().resolve(),
                   own_shell=windows_programs.own("busybox", spec)["file"],
                   reload_keeps_streams=bool(raw.get("reload_keeps_streams", False)),
                   tls_tunnels=bool(raw.get("tls_tunnels", False)),
                   denied_paths=bool(raw.get("mxc_denied_paths", False)))

    def _instance_capabilities(self) -> dict:
        return {**type(self).capabilities(), "network_live_interrupts": not self.reload_keeps_streams}

    def _adopt_runtime(self, managed: Optional[dict]) -> None:
        if managed is not None:
            features = managed.get("features") or []
            self._runtime_id = str(managed.get("runtime_id") or managed.get("id") or "") or None
            if managed.get("cli"):
                self._sandbox_exe = Path(managed["cli"]).with_name(SANDBOX_EXE)
            self.reload_keeps_streams = RELOAD_FEATURE in features
            self.tls_tunnels = TUNNEL_FEATURE in features
            self.denied_paths_supported = DENY_FEATURE in features

    def _check_deny_support(self) -> None:
        """Refuse a build whose MXC driver cannot take the deny list: credential files would be readable inside."""
        if self.denied_paths_supported:
            return
        if self.cfg.managed_root is not None or self._runtime_id:
            which = f"the OpenShell runtime {self._runtime_id}" if self._runtime_id else "the managed OpenShell runtime"
            raise DriverUnavailable(
                f"{which} cannot hide credential files: it lacks the feature {DENY_FEATURE} "
                f"(driver_config.mxc.denied_paths). Install an OpenShell build that has it; no sandbox was started.")
        raise DriverUnavailable(
            f"gateway '{self.cfg.gateway}' is not known to hide credential files: its MXC driver must take "
            f"driver_config.mxc.denied_paths ({DENY_FEATURE}); set openshell.mxc_denied_paths: true in the spec only "
            f"for such a build. No sandbox was started.")

    # -- plumbing ------------------------------------------------------------------------------
    def _note(self, message: str) -> None:
        log.info("%s", message)
        if self._log is not None:
            self._log.write(f"[openshell-windows {time.strftime('%H:%M:%S')}] {message}\n".encode())
            self._log.flush()

    def _require(self) -> str:
        if self._name is None or self._request is None:
            raise NotSupported("the sandbox is not running")
        return self._name

    # -- lifecycle -----------------------------------------------------------------------------
    def _pinned_wxc_exec(self) -> None:
        """Without a wxc-exec of the person's own: the plugin's pinned one, installed when it is missing and
        compared with its pinned sha256 again, before anything asks it a question or starts a sandbox with it
        (``windows_programs.ensure``; an install that fails or is refused raises ``DriverUnavailable``)."""
        if self._own_wxc_exec or self._programs_root is None or not windows_programs.supported("wxc-exec"):
            return
        self.wxc_exec = windows_programs.ensure(self._programs_root, "wxc-exec")

    def _pinned_shell(self) -> None:
        """The shell is the supervisor's to hand in at every sandbox start (``Supervisor._busybox``). The
        switch-on installs the plugin's pinned one here already: a download that cannot be made then stops the
        switch with its reason, before OpenShell is installed and a gateway started."""
        if self._own_shell is None and self._programs_root is not None and windows_programs.supported("busybox"):
            windows_programs.ensure(self._programs_root, "busybox")

    def preflight(self) -> dict:
        if os.name != "nt":
            raise DriverUnavailable("the Windows OpenShell driver runs on Windows only.")
        self._pinned_wxc_exec()
        self._pinned_shell()
        if self.wxc_exec is None:
            raise DriverUnavailable("wxc-exec not found: the launcher probes MXC before using OpenShell's MXC driver; "
                                    "set wxc_exec in the spec, OPENSHELL_WXC_EXEC_PATH, or put it on PATH.")
        from . import mxc as mxc_gate

        # MXC 1.0+, base-container tier, no DACL augmentation. OpenShell's MXC driver sends
        # fallback.allowDaclMutation=false only with denied paths (every launch here has them: the credential files);
        # this gate refuses a host that would need DACL changes in any case.
        mxc = mxc_gate.preflight(self.wxc_exec)
        # The plugin-managed gateway (spec names none): installed from the pinned build, started as a
        # login service and health-checked, only after the MXC gate above passed.
        managed = ensure_managed(self.cfg, kind="mxc", wxc_exec=self.wxc_exec)
        self._adopt_runtime(managed)
        endpoint, _ = gateway_endpoint(self.cfg)  # refuses anything but https + client certificates
        try:
            version = self.gw.version()
            status = self.gw.status()
        except (CliError, OSError, subprocess.SubprocessError) as exc:
            raise DriverUnavailable(f"gateway '{self.cfg.gateway}' at {endpoint} did not answer: {exc}") from exc
        if "connected" not in status.lower() or "mtls" not in status.lower():
            raise DriverUnavailable(f"gateway '{self.cfg.gateway}' is not connected over mTLS: {status[-300:]}")
        info = ""
        try:
            info = self.gw.info()
        except CliError as exc:
            info = str(exc)
        if "mxc" not in info.lower():
            raise DriverUnavailable(f"gateway '{self.cfg.gateway}' has no MXC compute driver")
        self._check_deny_support()
        out = {"driver": self.name, "cli": version.strip(), "gateway": self.cfg.gateway, "endpoint": endpoint,
               "mxc": mxc, "deny_list": self.denied_paths_supported,
               "deny_via": "driver_config.mxc.denied_paths" if self.denied_paths_supported else None}
        if managed is not None:
            out["managed_gateway"] = {k: str(v) if isinstance(v, Path) else v for k, v in managed.items()}
        return out

    def drop_leftover(self, profile: str) -> bool:
        """Also the switch-off without a launcher: returns once the sandbox is gone from the gateway, and
        raises when it cannot be deleted or the gateway cannot say. A gateway that has no registration with the
        CLI is not asked (the CLI finds its gateway through the registration): it has no sandbox. A
        registration that is there and cannot be read says nothing of the gateway: that raises."""
        if not self._registered():
            return False
        try:
            names = leftover_names(profile, self.gw.sandbox, other_profiles(profile))
        except (CliError, OSError, subprocess.SubprocessError):
            if not self._ended_with_gateway():
                raise
            self._note(f"the gateway is not listening: the sandbox of profile {profile} ended with it")
            return False
        for name in names:
            self._note(f"deleting leftover sandbox {name} before the profile's folder is reviewed")
            self.gw.delete(name)
        return bool(names)

    def _registered(self) -> bool:
        """Whether the gateway has a registration with the CLI. Raises when a registration file is there and
        cannot be read: nothing is known of the gateway then."""
        known = gateway_registered(self.cfg)
        if known is None:
            raise DriverUnavailable(f"the registration of gateway {self.cfg.gateway} cannot be read")
        return known

    def _ended_with_gateway(self) -> bool:
        """After a question the gateway did not answer: True when nothing listens at its address and its own
        login service is not running. The gateway's process has ended then, and OpenShell ends every sandbox
        process with it (the gateway holds each in a job). Nothing is known of the sandboxes of a gateway that
        listens and does not answer, of one whose service runs or cannot be asked, and of one the profile's spec
        names (it has no service of the plugin's to ask)."""
        return self._gateway.down() == "stopped"

    def start(self, request: LaunchRequest) -> None:
        if self._name is not None and self.exit_code() is None:
            raise RuntimeError("sandbox already running")
        # While the sandbox is being (re)created under its old name, the gateway has no record or a
        # stale one: the supervisor's exit watch must not read that as the new sandbox having exited.
        self._starting = True
        self._gateway.reset()  # the start brings the gateway back, or fails
        try:
            self._start(request)
        finally:
            self._starting = False
            self._ready_at = time.monotonic()

    def _start(self, request: LaunchRequest) -> None:
        if request.home is None or not request.inner_port or not request.inner_token:
            raise RuntimeError("the OpenShell driver needs the profile home, inner port and inner token")
        self._pinned_wxc_exec()  # Every start: the file the gateway starts sandboxes with still is the pinned one
        if self.cfg.managed_root is not None:  # the shared gateway is healthy before a sandbox is created
            self._adopt_runtime(ensure_managed(self.cfg, kind="mxc", wxc_exec=self.wxc_exec))
        self._check_deny_support()  # before anything is created: the runtime may have changed since preflight
        self._request, self._final_code, self._cached, self._checked = request, None, None, 0.0
        self._log = open(request.log_path, "ab")
        profile = request.profile or request.sandbox_id
        name = sandbox_name(profile)
        # A sandbox of this profile is a leftover from a launcher that died: replace it. Another profile's
        # sandbox is never deleted, whatever its name (``leftover_names``).
        for leftover in leftover_names(profile, self.gw.sandbox, other_profiles(profile)):
            self._note(f"deleting leftover sandbox {leftover}")
            self.gw.delete(leftover)
        self._name = name
        config_dir = Path(request.config_dir)
        config_dir.mkdir(parents=True, exist_ok=True)
        self._binaries = [native(leaf_python(Path(request.argv[0])))]
        providers = self._register_providers(request)
        if request.network.get("egress") == "allow":
            raise DriverUnavailable("OpenShell has no rule for all internet access; list the websites instead.")
        env, extra_ro = self._sandbox_env(request)
        # The stored policy's own deny paths (spec.yaml filesystem_policy.deny) join the launcher's: every one goes
        # in driver_config.mxc.denied_paths, none in the policy.
        self._launch_policy, self._denied_paths, self._notes = build_windows_policy(
            request.grants, request.network, self._binaries, extra_readonly=extra_ro,
            extra_deny=self._root_denials(request), stored_deny=_stored_deny(config_dir),
            reserved=self._provider_endpoints(), keep=[self._sandbox_exe] if self._sandbox_exe else [],
            home=request.home, models=self._local_models())
        self.usage_data_open = usage_data.RULE_NAME in (self._launch_policy.get("network_policies") or {})
        self._policy_path = config_dir / "openshell-launch-policy.yaml"
        self._write_policy(self._policy_path, self._launch_policy)
        self._serve_port = _free_port(exclude=request.inner_port)
        argv = _with_port(request.argv, self._serve_port)
        mxc = {"command": [str(a) for a in argv], "cwd": native(request.cwd)}
        if self._denied_paths:
            mxc["denied_paths"] = list(self._denied_paths)
        driver_config = {"mxc": mxc}
        self._note(f"creating sandbox {name}: {len(self._denied_paths)} denied paths (driver_config.mxc.denied_paths), "
                   f"providers {[p['name'] for p in providers]}, keys withheld {self._withheld}, serve port "
                   f"{self._serve_port} -> inner {request.inner_port}" + (f"; notes {self._notes}" if self._notes else ""))
        self._start_follower()
        try:
            self.gw.create(name, self._policy_path, driver_config, env, {TOKEN_ENV: request.inner_token},
                           providers=[p["name"] for p in providers],
                           labels=profile_labels(request.profile or "default"))
        except CliError as exc:
            self._stop_follower()
            text = str(exc).lower()
            if "denied_paths" in text and "unknown field" in text:
                # A build without the feature (MxcSandboxConfig refuses unknown fields): nothing was created.
                raise DriverUnavailable(
                    f"this OpenShell build's MXC driver does not take driver_config.mxc.denied_paths ({DENY_FEATURE}), "
                    f"so it cannot hide credential files; the gateway refused the sandbox. {str(exc)[-300:]}") from exc
            raise
        self._wait_ready(name, timeout=300)
        self._check_readiness()
        self._ready_at = time.monotonic()
        try:
            self.gw.set_setting(name, "ocsf_json_enabled", "true")
        except CliError as exc:  # best effort: the shorthand OCSF stream remains
            self._note(f"could not enable OCSF JSON export: {exc}")
        self._start_forward()

    def _gateway_log(self) -> Optional[Path]:
        """The log of the gateway this driver manages (``gateway_service.gateway_log``: the file its login service
        writes, not the CLI's entry for the gateway). None for a gateway the spec names: the launcher does not
        know where a gateway it did not start writes."""
        root = self.cfg.managed_root
        return gateway_log(Path(root)) if root is not None else None

    def _start_follower(self) -> None:
        """The sandbox's refusals as they happen (``recent_refusals``), for as long as it runs. Called before the
        sandbox is created: what its first seconds are refused is in the file from this position on."""
        self._stop_follower()
        log = self._gateway_log()
        if log is None:
            return
        self._follower = RefusalFollower(log, self._name)
        self._follower.start()

    def _stop_follower(self) -> None:
        follower, self._follower = self._follower, None
        if follower is not None:
            follower.stop()

    def recent_refusals(self, since: float) -> list[dict]:
        """Connections the sandbox was refused at or after *since*, from its log stream as it arrives
        (``RefusalFollower.recent``): ``[{"time", "host", "port"}]``, oldest first. In memory, no call to the gateway
        and no process started: cheap enough to ask many times a second while a tool call runs."""
        follower = self._follower
        if follower is None:
            return []
        for _ in range(3):
            try:
                return [dict(row) for row in list(follower.recent) if row["time"] >= since]
            except RuntimeError:  # the follower thread appended while the tail was copied
                continue
        return []

    def _sandbox_env(self, request: LaunchRequest) -> tuple[dict, list[Path]]:
        """The launcher's environment for the sandbox minus what ``--env`` refuses or must not carry:
        the inner token goes by ``--env-from``; ``OPENSHELL_*`` names are reserved, so busybox goes on PATH."""
        env = {k: str(v) for k, v in request.env.items() if k != TOKEN_ENV}
        if env.get("HERMES_SANDBOX_VERDICTS") and self._gateway_log() is not None:
            # This driver follows the gateway's log file (``_start_follower``), so the launcher hears of a refusal
            # as it happens and copies it into the verdict file: the hook looks there when a program call that
            # named a host did not fail (sandbox_hook.py, ``REFUSALS_ENV``), for as long as a record can trail here.
            env["HERMES_SANDBOX_REFUSALS"] = str(REFUSALS_SETTLE)
        extra_ro: list[Path] = []
        busybox = env.pop("OPENSHELL_BUSYBOX", None)
        for key in [k for k in env if k.upper().startswith("OPENSHELL_")]:
            env.pop(key)
        if busybox:
            bb_dir = Path(busybox).parent
            env["PATH"] = os.pathsep.join([str(bb_dir), *[p for p in env.get("PATH", "").split(os.pathsep) if p]])
            extra_ro.append(bb_dir)
        # Node's fetch/http ignore HTTP(S)_PROXY unless told to; inside the sandbox the proxy is the only way out
        # (a direct connection fails with EACCES), so Node uses the proxy OpenShell sets, like curl and Python do.
        env.setdefault("NODE_USE_ENV_PROXY", "1")
        # MXC leaves every port on this computer's own addresses reachable from inside, and OpenShell's proxy refuses
        # loopback addresses: the plugin inside keeps the loopback names away from the proxy (loopback_env.py). They
        # cannot travel as NO_PROXY from here, because OpenShell replaces that variable with an empty one.
        env[LOOPBACK_ENV] = DIRECT
        # git's default Schannel backend checks revocation strictly when nothing configures it, and the sandbox has
        # no route to CRL/OCSP servers ("schannel: the revocation status is unknown"). OpenSSL verifies against
        # GIT_SSL_CAINFO, the sandbox's bundle (the Windows roots and the sandbox CA), as curl and Python do.
        _git_config(env, "http.sslBackend", "openssl")
        curl_home = self._curl_home(request, env)
        if curl_home is not None:
            extra_ro.append(curl_home)
        managed = self._managed_overrides(request, env)
        if managed is not None:
            extra_ro.append(managed)
        return env, extra_ro

    def _curl_home(self, request: LaunchRequest, env: dict) -> Optional[Path]:
        """Windows' own curl.exe has one TLS backend, Schannel, which asks Windows whether the site's certificate
        was revoked. Windows has no route to the CA's OCSP/CRL servers from inside the sandbox, so curl stops on an
        allowed site that does not staple the answer (exit 35, CRYPT_E_REVOCATION_OFFLINE). curl takes this setting
        from its config file only, reads the first file it finds, and looks in ``CURL_HOME`` first. The file is
        written again on every start into the launcher's state dir, which the sandbox reads and cannot write;
        nothing goes into the sandbox's own profile folders. A ``CURL_HOME`` the environment already carries is
        left as it is. Returns the folder to grant read-only, or None."""
        if any(key.upper() == "CURL_HOME" for key in env):
            return None
        folder = Path(request.config_dir) / CURL_DIRNAME
        try:
            folder.mkdir(parents=True, exist_ok=True)
            (folder / ".curlrc").write_bytes(CURL_CONFIG.encode("ascii"))
        except OSError as exc:  # curl then checks revocation strictly, as it does without the file
            self._note(f"could not write curl's config file in {folder}: {exc}")
            return None
        env["CURL_HOME"] = str(folder)
        return folder

    def _managed_overrides(self, request: LaunchRequest, env: dict) -> Optional[Path]:
        """Inside, a model on host loopback is ``host.openshell.internal``: the profile keeps its own URL
        (the switch turned off changes nothing) and the sandbox's managed scope overrides it."""
        self._model_overrides = {}
        from .settings_view import _model_entries
        from .openshell_driver import _read_yaml

        config = _read_yaml(Path(request.home) / "config.yaml")
        model = next((entry for label, entry in _model_entries(config) if label == "Model"), None)
        url = str((model or {}).get("base_url") or "").strip()
        parts = urllib.parse.urlsplit(url)
        if not url or (parts.hostname or "").lower() not in ("127.0.0.1", "localhost", "::1"):
            return None
        netloc = HOST_GATEWAY + (f":{parts.port}" if parts.port else "")
        self._model_overrides = {"model": {"base_url": urllib.parse.urlunsplit(parts._replace(netloc=netloc))}}
        import hermes_yaml

        from .managed import _merge, write_managed_scope

        target = Path(env["HERMES_MANAGED_DIR"]) if env.get("HERMES_MANAGED_DIR") else None
        if target is None:
            target = write_managed_scope(Path(request.config_dir) / "managed", {})
            env["HERMES_MANAGED_DIR"] = str(target)
        current = hermes_yaml.safe_load((target / "config.yaml").read_text(encoding="utf-8")) or {} \
            if (target / "config.yaml").is_file() else {}
        (target / "config.yaml").write_text(hermes_yaml.safe_dump(_merge(current, self._model_overrides),
                                                                  sort_keys=False), encoding="utf-8")
        return target

    def _root_denials(self, request: LaunchRequest) -> list[Path]:
        """Host-only state beside the launcher's that the layout does not list: core's "runs elsewhere"
        registry, the launcher's state root and its secrets by name, present or not yet written
        (denied when the root itself is granted, as for the default profile)."""
        state_dir = Path(request.config_dir)
        state_root = state_dir.parent
        root = state_root.parent
        if not any(_inside(root, rw) for rw in request.grants.readwrite):
            return []
        return [state_root, root / MARKER_NAME, *(state_dir / n for n in _HOST_ONLY_FILES)]

    # -- the gateway calls of CredentialSinkMixin -------------------------------------------------
    def _gw_stable_supported(self) -> bool:
        return True  # the CLI asks the gateway itself before it imports such a profile (``_gw_profile``)

    def _gw_profile(self, profile: dict, index: int) -> str:
        path = Path(self._request.config_dir) / f"provider-profile-{index}.json"
        path.write_text(json.dumps(profile, indent=1), encoding="utf-8")
        try:
            return self.gw.upsert_profile(path, profile["id"])
        except CliError as exc:
            if "stable_placeholder" in str(exc):
                raise DriverUnavailable(
                    "this OpenShell gateway does not support stable placeholders, which a credential that is "
                    f"replaced while the sandbox runs needs. Update OpenShell. {str(exc)[-300:]}") from exc
            raise

    def _gw_provider(self, name: str, values: dict, expires: dict) -> str:
        action = self.gw.upsert_provider(name, name, values)
        if expires:
            self.gw.update_provider(name, values, expires)
        return action

    def _gw_update(self, name: str, values: dict, expires: dict, clear: list) -> None:
        self.gw.update_provider(name, values, expires, clear)

    def _gw_forget(self, name: str) -> None:
        self.gw.delete_provider(name)

    def _gw_provider_state(self, sandbox: str, provider: str) -> tuple:
        return self.gw.provider_state(sandbox, provider)

    def _write_policy(self, path: Path, policy: dict) -> None:
        import hermes_yaml

        from .spec import YAML_WIDTH

        path.write_text(hermes_yaml.safe_dump(policy, sort_keys=False, width=YAML_WIDTH), encoding="utf-8")

    def _wait_ready(self, name: str, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = self.gw.sandbox(name)
            phase = str((last or {}).get("phase") or "").upper()
            if phase == "READY":
                return
            if last is None or phase in ("ERROR", "FAILED", "DELETING"):
                raise RuntimeError(f"sandbox {name} did not start (phase {phase or 'missing'}): "
                                   f"{json.dumps((last or {}).get('conditions'))[:600]}")
            time.sleep(1.0)
        raise RuntimeError(f"sandbox {name} not ready after {timeout:.0f}s (phase {(last or {}).get('phase')})")

    def _start_forward(self) -> None:
        cmd = [str(self.cfg.cli), "forward", "service", "--target-port", str(self._serve_port), "--local",
               f"127.0.0.1:{self._request.inner_port}", self._name]
        self._forward = self._popen(cmd, env=self.gw.env(), stdout=self._log or subprocess.DEVNULL,
                                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    **_NO_WINDOW)
        self._forward_started = time.monotonic()

    def _keep_forward(self) -> None:
        if self._forward is not None and self._forward.poll() is not None \
                and time.monotonic() - self._forward_started >= _FORWARD_RETRY:
            self._note(f"forward exited with {self._forward.returncode}; restarting it")
            self._start_forward()

    def exit_code(self) -> Optional[int]:
        if self._starting:
            return None
        if self._name is None or self._request is None:
            return self._final_code
        now = time.monotonic()
        if now - self._checked < _STATE_CHECK_INTERVAL or self._gateway.asking:
            return self._cached
        self._checked = now
        try:
            with self._gateway.ask():
                state = self.gw.sandbox(self._name)
        except Exception:
            # A gateway hiccup is not an exit, and neither is a gateway that is gone (``gateway_lost``). The
            # wait for the next look counts from the end of this one: a look that waits out a refused
            # connection is not followed by the next at once.
            self._checked = time.monotonic()
            return self._cached
        phase = str((state or {}).get("phase") or "").upper()
        if state is None or phase in ("ERROR", "FAILED"):
            code = 1
        elif phase in _LIVE_PHASES:
            code = None
            self._keep_forward()
        else:
            raw = state.get("exit_code")
            code = 1 if raw is None else int(raw)
        if code is not None and now - self._ready_at < _START_GRACE:
            # Recreating a sandbox under the same name (a restart for new folder grants) can show a
            # stale ERROR or missing record for a moment while the gateway reconciles the old one.
            self._note(f"sandbox {self._name} reads {phase or 'missing'} {now - self._ready_at:.1f}s after start; "
                       f"rechecking")
            return None
        if code is not None and self._cached is None:
            self._note(f"sandbox {self._name} ended: phase {phase or 'missing'}, exit {code}")
        self._cached = code
        return code

    def stop(self, timeout: float = 20.0) -> None:
        forward, self._forward = self._forward, None
        self._stop_follower()
        try:
            if forward is not None and forward.poll() is None:
                forward.terminate()
                try:
                    forward.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    forward.kill()
            # Also a stop that follows one whose delete failed: the gateway is asked again.
            if self._name is not None and (self._request is not None or not self._gone):
                if self._gateway_away():
                    self._gone = self._ended_with_gateway()
                else:
                    try:
                        self.gw.delete(self._name, timeout=max(timeout, 60.0))
                        self._gone = True
                    except Exception as exc:
                        self._gone = self._ended_with_gateway()
                        self._note(f"delete {self._name} failed: {exc}")
        finally:
            self._final_code = self._cached if self._cached is not None else 0
            self._request = None
            if self._log is not None:
                self._log.close()
                self._log = None

    def sandbox_gone(self) -> bool:
        return self._gone

    def last_exit_code(self) -> Optional[int]:
        """``exit_code`` as of the last look: nothing is asked of the gateway."""
        if self._starting:
            return None
        return self._final_code if self._name is None or self._request is None else self._cached

    def gateway_lost(self) -> bool:
        """The gateway is gone, or it came back a moment ago and the sandbox it had has ended."""
        return self._request is not None and (
            self._gateway.lost or (self._cached is not None and self._gateway.back()))

    def _gateway_away(self) -> bool:
        """At a stop: True when the last look at the sandbox got no answer and nothing listens at the gateway's
        address. The gateway is then not asked to delete the sandbox: each call would wait out a refused
        connection, and the sandbox's processes ended with the gateway (it holds each in a job). The record it
        keeps is deleted by the next start."""
        if not self._gateway.silent or self._gateway.down() is None:
            return False
        self._note(f"the gateway is not listening: it was not asked to delete sandbox {self._name}")
        return True

    def endpoint_changed(self) -> list[dict]:
        return [dict(c) for c in self._changed]

    def policy(self) -> dict:
        # ``denied_paths``: what the sandbox hides (driver_config.mxc.denied_paths at create; fixed for its life). The
        # gateway's policy read back below carries no deny list, so this is the one place it shows.
        view = {"sandbox": self._name, "gateway": self.cfg.gateway, "workspace": self.cfg.workspace,
                "engine": "mxc", "providers": self._providers, "keys_withheld": self._withheld,
                "endpoint_changed": self._changed, "provider_notes": self._provider_notes,
                "binaries": self._binaries, "model_overrides": self._model_overrides, "notes": self._notes,
                "serve_port": self._serve_port, "launch_policy": self._launch_policy,
                "denied_paths": list(self._denied_paths)}
        if self._name is not None and self._request is not None:
            try:
                view["active"] = self.gw.policy(self._name)
            except Exception as exc:
                view["active_error"] = str(exc)
        return view

    # -- live network, requests, revisions, audit --------------------------------------------------
    def _latest(self) -> dict:
        revs = self.gw.revisions(self._require())
        return max(revs, key=lambda r: int(r.get("version") or 0)) if revs else {}

    def _wait_version(self, after: int, timeout: float = 30.0) -> dict:
        deadline = time.monotonic() + timeout
        latest = {}
        while time.monotonic() < deadline:
            latest = self._latest()
            if int(latest.get("version") or 0) > after and latest.get("status") in ("loaded", "failed", "superseded"):
                return latest
            time.sleep(0.5)
        return {**latest, "timed_out": True}

    def loaded(self, version: int) -> Optional[bool]:
        """Whether revision *version* (or a later one, which the launcher builds from the same state) is the
        one the sandbox enforces: True loaded, False failed, None not yet."""
        revs = self.gw.revisions(self._require())
        mine = next((r for r in revs if int(r.get("version") or 0) == int(version)), None)
        if mine is not None and mine.get("status") == "loaded":
            return True
        if mine is not None and mine.get("status") == "failed":
            return False
        if any(int(r.get("version") or 0) > int(version) and r.get("status") == "loaded" for r in revs):
            return True  # superseded by a later revision that loaded
        return None

    def _wait_loaded(self, version: int, timeout: float) -> dict:
        """Poll the gateway's revision list (as ``policy set --wait`` does) until *version* reports loaded or
        failed, at most *timeout* (at least one look)."""
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            state = self.loaded(version)
            if state is not None or time.monotonic() >= deadline:
                return {"loaded": state is True, "failed": state is False, "timed_out": state is None}
            time.sleep(0.5)

    def _apply(self, policy: dict, label: str, *, load_timeout: float = LOAD_TIMEOUT) -> dict:
        """Submit *policy* and wait (bounded) until its revision is the one the sandbox enforces. ``loaded``
        False with ``timed_out`` means submitted but not confirmed yet: the rule may still land, and the
        caller says so instead of telling the agent it is in place."""
        name = self._require()
        started = time.monotonic()
        before = int(self._latest().get("version") or 0)
        path = Path(self._request.config_dir) / f"openshell-{label}-policy.yaml"
        self._write_policy(path, policy)
        sent = self.gw.set_policy(name, path, timeout=load_timeout)
        version = sent["version"] or (before if sent["unchanged"] else before + 1)
        remaining = load_timeout - (time.monotonic() - started)
        state = self._wait_loaded(version, remaining if sent["code"] == 0 else min(remaining, 1.0))
        if state["failed"] or (sent["code"] == 1 and not state["loaded"]):
            detail = next((r.get("load_error") for r in self.gw.revisions(name)
                           if int(r.get("version") or 0) == version), None) or sent["out"][-300:]
            raise RuntimeError(f"the sandbox rejected policy revision {version}: {detail}")
        waited = round(time.monotonic() - started, 2)
        if not state["loaded"]:
            self._note(f"policy revision {version} ({label}) not loaded after {waited:.1f}s")
        return {"policy_version": version, "status": "loaded" if state["loaded"] else "pending",
                "loaded": state["loaded"], "timed_out": not state["loaded"], "waited": waited}

    def apply_network(self, network: dict) -> dict:
        if network.get("egress") == "allow":
            raise DriverUnavailable("OpenShell has no rule for all internet access; list the websites instead.")
        policy = json.loads(json.dumps(self._launch_policy))
        rules = passthrough(native_rules(self._with_builtin(network_rules(network, self._binaries))),
                            self._provider_endpoints())
        policy.pop("network_policies", None)
        if rules:
            policy["network_policies"] = rules
        result = self._apply(policy, "network")
        self._launch_policy = policy
        return result

    def _with_builtin(self, rules: dict) -> dict:
        """*rules* with the launcher's built-in destination as the profile's config says right now
        (usage_data.py) and its rules for the pinned model servers on this computer that take no key
        (``model_rules``): decided at every start, network update and restored revision."""
        home = self._request.home if self._request is not None else None
        out = usage_data.rules(rules, home, self._binaries)
        self.usage_data_open = usage_data.RULE_NAME in out
        return model_rules(out, self._local_models(), self._binaries)

    def current_network(self) -> Optional[dict]:
        policy = self.gw.policy(self._require()).get("policy") or {}
        policy = {**policy, "network_policies": native_rules(policy.get("network_policies") or {})}
        return network_from_policy(policy, self._binaries)

    def _provider_endpoints(self) -> Optional[list[tuple[str, int]]]:
        """``(host, port)`` of every provider endpoint this sandbox has (they keep TLS termination: the proxy
        substitutes their credential placeholders), so no plain host grant on them becomes a raw tunnel. None
        when this runtime cannot have tunnels at all (no TUNNEL_FEATURE): every grant stays terminated."""
        if not self.tls_tunnels:
            return None
        out = []
        for p in self._providers or []:
            for endpoint in p.get("endpoints") or [p.get("endpoint")]:
                host, _, port = str(endpoint or "").rpartition(":")
                if host and port.isdigit():
                    out.append((host, int(port)))
        return out

    def proposals(self, status: str = "pending") -> list[dict]:
        status = "" if status in ("", "all") else status
        return [_proposal_view(c) for c in self.gw.rules(self._require(), status)]

    def _chunk(self, proposal_id: str) -> dict:
        for chunk in self.gw.rules(self._require()):
            if chunk.get("id") == proposal_id:
                return chunk
        raise KeyError(proposal_id)

    def approve(self, proposal_id: str) -> dict:
        chunk = self._chunk(proposal_id)
        if chunk.get("status") != "pending":
            raise ProposalChanged(f"request {proposal_id} is already {chunk.get('status')}", _proposal_view(chunk))
        before = int(self._latest().get("version") or 0)
        try:
            self.gw.approve(self._name, proposal_id)
        except CliError as exc:
            raise ProposalChanged(str(exc), _proposal_view(self._chunk(proposal_id))) from exc
        latest = self._wait_version(before)
        return {"approved": proposal_id, "policy_version": int(latest.get("version") or 0),
                "status": latest.get("status"), "rule": _proposal_view(chunk)}

    def reject(self, proposal_id: str, reason: str) -> dict:
        chunk = self._chunk(proposal_id)
        if chunk.get("status") != "pending":
            raise ProposalChanged(f"request {proposal_id} is already {chunk.get('status')}", _proposal_view(chunk))
        self.gw.reject(self._name, proposal_id, reason)
        return {"rejected": proposal_id, "reason": reason}

    def revisions(self) -> dict:
        revs = sorted(self.gw.revisions(self._require()), key=lambda r: -int(r.get("version") or 0))
        loaded = [r for r in revs if r.get("status") == "loaded"]
        return {"active_version": int(loaded[0]["version"]) if loaded else None, "revisions": revs}

    def revision(self, version: int) -> dict:
        data = self.gw.policy(self._require(), int(version))
        if int(data.get("version") or 0) != int(version):
            raise KeyError(version)
        return {"version": int(version), "status": data.get("status"), "hash": data.get("hash"),
                "policy": data.get("policy")}

    def rollback(self, version: int) -> dict:
        old = self.revision(version)
        if not old.get("policy"):
            raise RuntimeError(f"revision {version} has no stored policy")
        # Only the live part comes back: folders and UI are fixed at sandbox start.
        policy = json.loads(json.dumps(self._launch_policy))
        policy.pop("network_policies", None)
        # The built-in destination follows the profile's config today, not what that revision held.
        kept = {k: v for k, v in (old["policy"].get("network_policies") or {}).items() if not k.startswith("_provider_")}
        rules = passthrough(native_rules(self._with_builtin(kept)), self._provider_endpoints())
        if rules:
            policy["network_policies"] = rules
        result = self._apply(policy, "rollback")
        self._launch_policy = policy
        return {**result, "restored": int(version)}

    def events(self, *, since: float | None = None, until: float | None = None, limit: int = 200,
               classes: tuple[str, ...] = ()) -> list[dict]:
        out = []
        for line in self.gw.logs(self._require(), lines=min(max(limit * 4, 200), 2000), since=since):
            event = parse_event(line)
            if not event.get("ocsf"):
                continue
            if until is not None and (event.get("time") or 0) > until:
                continue
            if classes and event.get("class") not in classes:
                continue
            out.append(event)
        return out[-limit:]


def _proposal_view(chunk: dict) -> dict:
    keys = ("rule_name", "binary", "endpoints", "binaries", "rationale", "security_notes", "confidence",
            "hit_count", "first_seen", "last_seen", "rejection_reason", "flags", "requests")
    view = {k: chunk[k] for k in keys if chunk.get(k) not in (None, "", [])}
    return {"id": chunk.get("id"), "status": chunk.get("status"), **view}


def _git_config(env: dict, key: str, value: str) -> None:
    """Add ``key = value`` to git's command-line config through ``GIT_CONFIG_COUNT``/``_KEY_n``/``_VALUE_n``,
    after any the environment already carries; a key already given there is left as the user set it."""
    try:
        count = int(env.get("GIT_CONFIG_COUNT") or 0)
    except ValueError:
        return
    if any(str(env.get(f"GIT_CONFIG_KEY_{i}", "")).lower() == key.lower() for i in range(count)):
        return
    env[f"GIT_CONFIG_KEY_{count}"] = key
    env[f"GIT_CONFIG_VALUE_{count}"] = value
    env["GIT_CONFIG_COUNT"] = str(count + 1)


def _stored_deny(config_dir: Path) -> list[Path]:
    """Deny paths the stored policy names itself (``filesystem_policy.deny`` in spec.yaml): extra paths to hide,
    sent in ``driver_config.mxc.denied_paths`` with the launcher's own (never in the OpenShell policy)."""
    spec_path = config_dir / "spec.yaml"
    if not spec_path.is_file():
        return []
    try:
        import hermes_yaml

        data = hermes_yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return []
    fs = ((data.get("policy") or {}).get("filesystem_policy") or {}) if isinstance(data, dict) else {}
    return [Path(p) for p in fs.get("deny") or [] if isinstance(p, str) and Path(p).is_absolute()
            and Path(p).parent.is_dir()]


def _with_port(argv: list, port: int) -> list[str]:
    out = [str(a) for a in argv]
    if "--port" in out:
        out[out.index("--port") + 1] = str(port)
    else:
        out += ["--port", str(port)]
    return out


def _free_port(exclude: int = 0) -> int:
    import socket

    while True:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        if port != exclude:
            return port
