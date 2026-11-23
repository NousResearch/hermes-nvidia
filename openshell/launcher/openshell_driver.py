"""OpenShell gateway driver: the profile's backend as one OpenShell sandbox (Linux; Docker driver).

Requires OpenShell v0.1.5 or newer (CLI and gateway; preflight refuses older ones). The launcher talks
to a private, mTLS-only OpenShell gateway with the OpenShell Python SDK: sandbox create/wait/delete
through ``SandboxClient``, and the SDK's generated gRPC stub (same mTLS channel) for what the SDK has
no method for: providers, policy revisions, drafts, settings and logs. The CLI does two things the
SDK cannot: import provider profiles (YAML) and ``forward service``, which holds the inner port open
on host loopback for the proxy. Nothing secret travels in an argv: the inner token rides in the
create request's environment and model keys in provider credentials, both over the mTLS channel.

What the sandbox gets:

* A small base image (glibc, a shell, curl, a non-root user mapped to the launcher's uid) and the
  host's own Hermes runtime, bind-mounted read-only at its host paths: the source tree, the selected
  dependency environment and the store Python it points at. The sandbox always runs the installed
  Hermes; nothing Hermes-specific is baked into an image.
* The profile home and granted folders, bind-mounted at their host paths so session paths stay
  valid when the sandbox is turned off. Every credential folder that exists is masked by an empty
  read-only folder. Credential files at the top of the home are not masked one by one (a mount on a
  file's name is gone as soon as a host process replaces the file by rename, as Hermes's writers do):
  they are kept in one folder of the home that is masked as a whole, with a link under each name
  (held.py). A store that does not exist yet cannot be masked without creating it on the host, so
  the launcher quarantines any the sandbox creates (checked when the sandbox stops).
* No secret values. Each key with an address the user set up, or with its own provider's registered
  address, becomes an OpenShell provider bound to that address (``discover_routes``): inside, the env
  var holds a placeholder, and OpenShell's proxy swaps the real value in only on requests to that host
  and port from Hermes's interpreter, and only in the place the key travels in there (a bearer token,
  ``x-api-key``, ``x-goog-api-key``). Every other key stays on the host (``keys_withheld`` in the
  policy view). The launcher hands further credentials over the same way (``CredentialSinkMixin``).
* The spec's network rules (websites by hostname, addresses by CIDR), applied live; blocked
  connections become proposals the host routes list, approve and reject.
* Audit: with ``ocsf_json_enabled`` the sandbox's supervisor writes full OCSF JSON records to its
  stderr (v0.1.5). The driver follows that stream through the container CLI and appends each record
  to host-only JSONL files under the launcher's state dir, so the audit trail outlives the sandbox
  (the supervisor's own files sit on a tmpfs that dies with it, and the gateway's log API is a
  2000-line in-memory tail).
"""
from __future__ import annotations

import collections
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import held, usage_data
from . import categories
from .credential_sink import PLACEMENTS, PROTOCOLS, CredentialDecl, Endpoint
from .driver import DriverUnavailable, LaunchRequest, NotSupported, ProposalChanged, SandboxDriver
from .gateway_watch import GatewayWatch

log = logging.getLogger("openshell.driver")

RULE_PREFIX = "hermes_"
DEFAULT_IMAGE = "hermes-sandbox-base:latest"
# Empty: website rules and model providers name the host runtime's interpreter, resolved at launch.
DEFAULT_BINARIES: tuple = ()
SERVE_PORT = 9119
HOST_GATEWAY = "host.openshell.internal"
# The oldest OpenShell release the Linux driver works with (supervisor OCSF JSON on stderr, .jsonl files, host-alias
# pin, push config). Linux only: a Windows package is built from OpenShell's windows branch and carries a release
# number whose changes it may not hold, so the Windows driver never reads the number. What a Windows build can do is
# listed in runtime/pins.json "features".
MIN_OPENSHELL = (0, 1, 5)
# Landlock paths the base image needs; the host runtime and grants are added per launch.
PROFILE_SNIPPET = "/etc/profile.d/zz-hermes-runtime.sh"  # login shells: the mounted runtime first on PATH
STANDIN_ENV = "HERMES_OPENSHELL_STANDIN"  # names the stand-in sign-in store's template (inside/standin.py)
_BASE_READ_ONLY = ("/usr", "/lib", "/etc", "/proc", "/dev/urandom", "/var/log")
_BASE_READ_WRITE = ("/tmp", "/dev/null")
# Never bind-mounted from the host: the image's own system tree and OpenShell's reserved paths. A
# runtime that lives there (a venv on the system Python) is refused instead of shadowing the image.
_SYSTEM_PATHS = tuple(Path(p) for p in ("/", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/var",
                                        "/proc", "/sys", "/dev", "/run", "/tmp", "/sandbox", "/home", "/root",
                                        "/opt/openshell", "/etc/openshell", "/run/openshell", "/usr/local"))
_OCSF_CLASSES = {4001: "NET", 4002: "HTTP", 4007: "SSH", 1007: "PROC", 2004: "FINDING", 5019: "CONFIG",
                 6002: "LIFECYCLE", 0: "EVENT", 1001: "FILE", 3002: "AUTH"}
_LIVE_PHASES = ("PROVISIONING", "STARTING", "READY", "UNKNOWN", "UNSPECIFIED")
_STATE_CHECK_INTERVAL = 2.0
_FORWARD_RETRY = 5.0
# How long a policy update waits for its revision to report loaded (the supervisor polls the gateway; loads
# take a few seconds). Past it the update reports ``loaded: False`` instead of claiming the rule is in place.
LOAD_TIMEOUT = 20.0
_OCSF_RE = re.compile(r"^(?P<cls>[A-Z]+)(?::(?P<act>[A-Z_]+))?\s+\[(?P<sev>[A-Z]+)\]\s*(?P<rest>.*)$")
_PAIR_RE = re.compile(r"([a-z_]+):(\S+(?:\s(?![a-z_]+:)\S+)*)")
_FREE_TEXT_KEYS = ("reason", "message", "error")  # their values contain spaces and colons


# -- configuration ------------------------------------------------------------------------------

@dataclass
class OpenShellConfig:
    gateway: str
    config_home: Path  # XDG_CONFIG_HOME holding openshell/gateways/<gateway>/{metadata.json,mtls/}
    cli: Path
    image: str = DEFAULT_IMAGE
    workspace: str = "default"
    binaries: tuple = DEFAULT_BINARIES  # what may use website rules and model providers inside (empty:
    # the host runtime's interpreter)
    serve_port: int = SERVE_PORT
    ocsf_json: bool = True
    # The container engine CLI the gateway's driver runs on (docker or podman): reads the supervisor's
    # stderr for the OCSF JSON archive. None: no archive (the gateway's log tail still works).
    container_cli: Optional[str] = field(default_factory=lambda: shutil.which("docker") or shutil.which("podman"))
    run_as: tuple = field(default_factory=lambda: (str(os.getuid()), str(os.getgid())) if hasattr(os, "getuid")
                          else ("10000", "10000"))
    # The plugin-managed gateway of this Hermes root (gateway_service.py), used when the spec names no
    # gateway: the driver installs, starts and health-checks it before it creates a sandbox.
    managed_root: Optional[Path] = None
    managed_image: bool = False  # the locally built base image (base_image.py) instead of a spec image
    sdk_path: Optional[Path] = None  # the managed OpenShell SDK (Linux), appended to sys.path

    @property
    def gateway_dir(self) -> Path:
        return self.config_home / "openshell" / "gateways" / self.gateway


def config_from_spec(spec: dict) -> OpenShellConfig:
    """``spec["openshell"]`` keys, each with an environment or default fallback. With no gateway named
    (spec or ``OPENSHELL_GATEWAY``), the plugin-managed private gateway of this Hermes root."""
    raw = dict(spec.get("openshell") or {})
    gateway = raw.get("gateway") or os.environ.get("OPENSHELL_GATEWAY")
    if not gateway:
        return _managed_config(raw)
    config_home = Path(raw.get("config_home") or os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config").expanduser()
    cli = raw.get("cli") or os.environ.get("OPENSHELL_CLI") or shutil.which("openshell")
    if not cli or not Path(cli).is_file():
        raise DriverUnavailable("openshell CLI not found: set openshell.cli in the spec, OPENSHELL_CLI, or put it on PATH.")
    cfg = OpenShellConfig(gateway=str(gateway), config_home=config_home, cli=Path(cli).resolve(),
                          image=str(raw.get("image") or DEFAULT_IMAGE), workspace=str(raw.get("workspace") or "default"))
    if raw.get("binaries"):
        cfg.binaries = tuple(str(b) for b in raw["binaries"])
    if raw.get("ocsf_json") is not None:
        cfg.ocsf_json = bool(raw["ocsf_json"])
    if "container_cli" in raw:
        cfg.container_cli = str(raw["container_cli"]) if raw["container_cli"] else None
    return cfg


def _managed_config(raw: dict) -> OpenShellConfig:
    """The managed gateway's paths (no side effects; ``ensure_managed`` installs and starts it)."""
    from hermes_constants import get_default_hermes_root

    from .gateway_service import managed_defaults

    d = managed_defaults(get_default_hermes_root().resolve())
    cfg = OpenShellConfig(gateway=d["gateway"], config_home=d["config_home"], cli=d["cli"],
                          image=str(raw.get("image") or DEFAULT_IMAGE), workspace=str(raw.get("workspace") or "default"),
                          managed_root=d["root"], managed_image=not raw.get("image"), sdk_path=d["sdk_path"])
    if raw.get("binaries"):
        cfg.binaries = tuple(str(b) for b in raw["binaries"])
    if raw.get("ocsf_json") is not None:
        cfg.ocsf_json = bool(raw["ocsf_json"])
    if "container_cli" in raw:
        cfg.container_cli = str(raw["container_cli"]) if raw["container_cli"] else None
    return cfg


def ensure_managed(cfg: OpenShellConfig, **kwargs) -> Optional[dict]:
    """Install, start and health-check the managed gateway (and, on Linux, the base image), then
    point *cfg* at what runs. No-op for a gateway the spec names. Returns the gateway's facts."""
    if cfg.managed_root is None:
        return None
    from .gateway_service import ensure_gateway

    info = ensure_gateway(cfg.managed_root, container_cli=cfg.container_cli, base_image=cfg.managed_image, **kwargs)
    cfg.gateway, cfg.config_home, cfg.cli, cfg.sdk_path = info["gateway"], Path(info["config_home"]), \
        Path(info["cli"]), info.get("sdk_path")
    if cfg.managed_image and info.get("image"):
        cfg.image = info["image"]
    return info


def sandbox_name(profile: str) -> str:
    """One sandbox per profile, under a stable name: a crashed launcher's sandbox is found and
    replaced on the next start, and logs and proposals stay keyed to the profile."""
    slug = re.sub(r"[^a-z0-9-]+", "-", profile.lower()).strip("-") or "default"
    return f"hermes-{slug}"[:63].rstrip("-")


def parse_version(text: str) -> Optional[tuple]:
    """``openshell 0.1.5`` / ``0.1.6-pre.2`` -> (0, 1, 5) / (0, 1, 6); None when there is no version."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


# -- the host's Hermes runtime, mounted read-only ------------------------------------------------------

@dataclass
class HostRuntime:
    """The Hermes the launcher runs, which the sandbox runs too: same interpreter, code and packages,
    mounted read-only at their host paths (the venv's interpreter links and ``pyvenv.cfg`` name
    absolute host paths, so the paths must not move)."""

    python: Path  # the interpreter the sandbox starts (the venv's, as the launcher runs it)
    real_python: Path  # what it resolves to: the executable OpenShell sees opening connections
    code_dir: Path
    env_dir: Path  # the selected dependency environment (a PM generation dir, or the venv itself)
    prefix: Path  # the base Python installation (stdlib) the venv points at
    store: Optional[Path] = None  # Hermes's tool store (HERMES_RUNTIME_DIR)

    def mount_paths(self) -> list[Path]:
        """The smallest set of directories that holds every runtime path (nested ones dropped)."""
        paths = sorted({p for p in (self.code_dir, self.env_dir, self.prefix, self.store) if p is not None},
                       key=lambda p: (len(p.parts), str(p)))
        out: list[Path] = []
        for p in paths:
            if not any(p == q or q in p.parents for q in out):
                out.append(p)
        return out


def host_runtime(request: LaunchRequest) -> HostRuntime:
    """The runtime the launcher hands the sandbox, read from the launch request (``argv[0]`` is the
    selected environment's interpreter, ``PYTHONPATH`` the source tree, ``HERMES_RUNTIME_DIR`` the
    store). Refuses runtimes the sandbox cannot mount: a system interpreter, or paths that would
    shadow the base image's own system tree."""
    if not request.argv:
        raise DriverUnavailable("the launch request names no Hermes interpreter")
    python = Path(request.argv[0])
    code = (request.env.get("PYTHONPATH") or "").split(os.pathsep)[0]
    if not python.is_absolute() or not code:
        raise DriverUnavailable(f"cannot tell which Hermes runtime to mount (interpreter {python}, source {code!r})")
    venv = python.parent.parent
    cfg_file = venv / "pyvenv.cfg"
    if not cfg_file.is_file():
        raise DriverUnavailable(f"{python} is not a virtual environment's interpreter; the sandbox mounts "
                                f"Hermes's own environment and store Python, not a system interpreter")
    home = None
    for line in cfg_file.read_text(encoding="utf-8-sig").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "home":
            home = Path(value.strip())
    if home is None:
        raise DriverUnavailable(f"{cfg_file} names no base interpreter (home =)")
    home = home.resolve()
    prefix = home.parent if home.name == "bin" else home  # stdlib sits beside bin/, not in it
    env_dir = venv.parent if venv.parent.parent.name == "environments" else venv  # PM generation snapshot
    store = request.env.get("HERMES_RUNTIME_DIR")
    rt = HostRuntime(python=python, real_python=python.resolve(), code_dir=Path(code).resolve(),
                     env_dir=env_dir.resolve(), prefix=prefix, store=Path(store).resolve() if store else None)
    for path in rt.mount_paths():
        _check_runtime_path(path)
    roots = rt.mount_paths()
    for hop in [*_link_chain(rt.python), rt.real_python]:  # every link hop must exist inside too
        if not any(hop == p or p in hop.parents for p in roots):
            raise DriverUnavailable(f"Hermes's interpreter {rt.python} reaches {hop}, outside its runtime "
                                    f"({', '.join(map(str, roots))}); the sandbox cannot run it")
    return rt


def _link_chain(path: Path, limit: int = 16) -> list[Path]:
    """``path`` and each symlink hop after it, as written (lexically normalized, not resolved)."""
    out, p = [path], path
    for _ in range(limit):
        if not p.is_symlink():
            break
        target = Path(os.readlink(p))
        p = Path(os.path.normpath(target if target.is_absolute() else p.parent / target))
        out.append(p)
    return out


def _check_runtime_path(path: Path) -> None:
    trees = [p for p in _SYSTEM_PATHS if p.parts[1:2] and p.parts[1] in ("usr", "bin", "sbin", "lib", "lib64", "etc", "proc",
                                                                          "sys", "dev", "run", "sandbox")]
    trees += [Path("/opt/openshell"), Path("/etc/openshell"), Path("/run/openshell")]
    if path in _SYSTEM_PATHS or any(path in p.parents for p in _SYSTEM_PATHS) or \
            any(t in path.parents for t in trees) or path == Path.home():
        raise DriverUnavailable(f"Hermes runtime path {path} is part of the system tree; the sandbox mounts only a "
                                f"Hermes install with its own store Python (for example ~/.hermes)")
    if not path.is_absolute() or not path.is_dir():
        raise DriverUnavailable(f"Hermes runtime path {path} is not a directory")


# -- what the sandbox mounts -----------------------------------------------------------------------

@dataclass
class MountPlan:
    mounts: list = field(default_factory=list)  # docker driver_config mounts
    read_write: list = field(default_factory=list)  # container paths (== host paths)
    read_only: list = field(default_factory=list)
    masked: list = field(default_factory=list)  # credential stores hidden behind empty mounts
    held: list = field(default_factory=list)  # top-level credential files kept in the held folder (held.py)
    unmasked_absent: list = field(default_factory=list)  # stores that did not exist: watched instead
    runtime: list = field(default_factory=list)  # the host Hermes runtime, mounted read-only
    shadowed: list = field(default_factory=list)  # denied folders holding a runtime mount: empty, writable stand-ins


def _under(path: Path, roots) -> bool:
    return any(path == r or r in path.parents for r in roots)


def ensure_masks(state_dir: Path) -> dict:
    """Empty, read-only mask sources, kept in the launcher's host-only state dir."""
    masks = state_dir / "masks"
    (masks / "emptydir").mkdir(parents=True, exist_ok=True)
    out = {"dir": masks / "emptydir", "file": masks / "empty", "json": masks / "empty.json"}
    for key, content in (("file", ""), ("json", "{}\n")):
        if not out[key].is_file() or out[key].read_text(encoding="utf-8") != content:
            out[key].write_text(content, encoding="utf-8")
        out[key].chmod(0o444)
    out["dir"].chmod(0o555)
    return out


def held_stand_ins(state_dir: Path, home: Path) -> Path:
    """The folder mounted over a home's held folder (``held.py``): one empty, read-only stand-in per held file,
    under the file's name, so inside the sandbox each credential file reads as it did behind its own mask (empty,
    ``{}`` for a JSON store) and a held name with nothing behind it reads as absent. Rebuilt at every start, in
    the launcher's host-only state dir."""
    stand = state_dir / "masks" / "held"
    if stand.exists():
        for path in stand.iterdir():
            path.chmod(0o600)
        stand.chmod(0o700)
        shutil.rmtree(stand)
    stand.mkdir(parents=True)
    for name in held._held_names(home):
        (stand / name).write_text("{}\n" if name.endswith(".json") else "", encoding="utf-8")
        (stand / name).chmod(0o444)
    stand.chmod(0o555)
    return stand


def plan_mounts(request: LaunchRequest, masks: dict, runtime: Optional[HostRuntime] = None) -> MountPlan:
    """Grants (host paths) -> same-path bind mounts plus Landlock paths.

    The host's Hermes runtime (source tree, dependency environment, store Python) is mounted
    read-only at its host paths; the launcher's box dirs (Windows TEMP and friends) are not mounted.
    Read-only grants and denials matter where they sit inside a read-write mount (plugin dirs, the
    default profile's install tree, credential stores), plus read-only folders the user granted.
    """
    plan = MountPlan()
    skip = Path(request.config_dir)
    rw_roots = [p for p in request.grants.readwrite if not _under(Path(p), [skip])]
    ro_folders = [Path(f["path"]) for f in request.folders if f.get("access") == "ro"]
    targets = set()

    def add(source: Path, target: Path, read_only: bool) -> None:
        key = str(target)
        if key in targets:
            return
        targets.add(key)
        plan.mounts.append({"type": "bind", "source": str(source), "target": key, "read_only": read_only})

    for path in rw_roots:
        add(path, path, False)
        plan.read_write.append(str(path))
    # The card hook's channel (sandbox_hook.py): its verdict folder read-only, its requests folder read &
    # write; both live in the launcher's state dir, which is otherwise never mounted. So does the sandbox's own
    # shared sign-in folder (layout.py ``shared_sign_in_dir``), which Hermes inside writes its lock file in.
    for env_name, read_only in (("HERMES_SANDBOX_VERDICTS", True), ("HERMES_SANDBOX_REQUESTS", False),
                                ("HERMES_SHARED_AUTH_DIR", False),
                                ("HERMES_MANAGED_DIR", True)):  # the supervisor's managed scope (pins, model URL)
        raw = (request.env or {}).get(env_name)
        if raw and Path(raw).is_dir():
            add(Path(raw), Path(raw), read_only)
            (plan.read_only if read_only else plan.read_write).append(str(raw))
    # The stand-in sign-in store's template and the start-up step that fills it (standins.py): one folder of
    # the launcher's state, read-only inside. Neither file holds a secret.
    raw = (request.env or {}).get(STANDIN_ENV)
    if raw and Path(raw).parent.is_dir() and _under(Path(raw).parent, [skip]):
        add(Path(raw).parent, Path(raw).parent, True)
        plan.read_only.append(str(Path(raw).parent))
    runtime_paths = runtime.mount_paths() if runtime else []
    # A runtime mount nested under a denied folder (PM's install state installs/<key> holds the selected
    # environment) makes Docker create that folder in the container as an empty, root-owned mount point.
    # Hermes then finds an install state it cannot write and refuses to boot ("install state is not writable
    # by this user"). Shadow such a folder with a fresh, empty, writable folder from the launcher's state, the
    # nested mount points made beforehand (Docker creates nothing on the host): the sandbox sees an install
    # state with nothing committed and boots on the mounted environment's own packages, as on Windows, where
    # the folder is denied outright. Mounted before the runtime, which sits inside it.
    for path in request.grants.denied:
        path = Path(path)
        nested = [r for r in runtime_paths if path in r.parents]
        if not nested or _under(path, rw_roots):
            continue
        shadow = skip / "shadow" / hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:16]
        if shadow.exists():
            shutil.rmtree(shadow)
        for inner in nested:
            (shadow / inner.relative_to(path)).mkdir(parents=True, exist_ok=True)
        add(shadow, path, False)
        plan.read_write.append(str(path))
        plan.shadowed.append(str(path))
    for path in runtime_paths:
        add(path, path, True)
        plan.read_only.append(str(path))
        plan.runtime.append(str(path))
    if runtime is not None:
        # Login shells (the agent terminal's environment snapshot, `openshell sandbox exec`) start from the image's
        # /etc/profile, which resets PATH and drops the runtime put first on the backend's PATH: python and hermes
        # were "command not found" in the agent's terminal. A profile.d snippet puts it back in front.
        snippet = skip / "profile.d" / "hermes-runtime.sh"
        snippet.parent.mkdir(parents=True, exist_ok=True)
        snippet.write_text(f'PATH={shlex.quote(str(runtime.python.parent))}:"$PATH"\nexport PATH\n', encoding="utf-8")
        add(snippet, Path(PROFILE_SNIPPET), True)
    for path in request.grants.readonly:
        path = Path(path)
        if path in ro_folders or (_under(path, rw_roots) and path not in rw_roots):
            if path.exists():
                add(path, path, True)
                if path in ro_folders:
                    plan.read_only.append(str(path))
    home = Path(request.home) if request.home is not None else None
    for path in request.grants.denied:
        path = Path(path)
        if not _under(path, rw_roots):
            continue
        if home is not None and path.parent == home and held.is_link(path):
            # The file is in the held folder, mounted over as a whole below: no mount on this name, which a
            # rename on the host would take away (and a mount on a link would land on the link's target).
            plan.held.append(str(path))
            continue
        if path.is_dir() and not path.is_symlink():
            add(masks["dir"], path, True)
        elif path.exists() or path.is_symlink():
            add(masks["json"] if path.suffix == ".json" else masks["file"], path, True)
        else:
            plan.unmasked_absent.append(str(path))
            continue
        plan.masked.append(str(path))
    if home is not None and held.active(home) and _under(home, rw_roots):
        add(held_stand_ins(skip, home), held.folder(home), True)
        plan.masked.append(str(held.folder(home)))
    return plan


# -- credentials -> providers ------------------------------------------------------------------------

def loopback_model_override(request: LaunchRequest) -> dict:
    """Inside the sandbox a model server on host loopback is ``host.openshell.internal`` (the provider's endpoint);
    the profile keeps its own URL, so the switch turned off changes nothing, and the sandbox's managed scope
    (``HERMES_MANAGED_DIR``, written by the supervisor) overrides it. Without this the sandboxed backend dials its
    own loopback and every model call fails with a connection error. Returns the override written ({} if none)."""
    from .settings_view import _model_entries

    config = _read_yaml(Path(request.home) / "config.yaml") if request.home else {}
    model = next((entry for label, entry in _model_entries(config) if label == "Model"), None)
    url = str((model or {}).get("base_url") or "").strip()
    parts = urllib.parse.urlsplit(url)
    managed = (request.env or {}).get("HERMES_MANAGED_DIR")
    if not url or not managed or (parts.hostname or "").lower() not in ("127.0.0.1", "localhost", "::1"):
        return {}
    import hermes_yaml

    from .managed import _merge

    netloc = HOST_GATEWAY + (f":{parts.port}" if parts.port else "")
    override = {"model": {"base_url": urllib.parse.urlunsplit(parts._replace(netloc=netloc))}}
    target = Path(managed) / "config.yaml"
    current = (hermes_yaml.safe_load(target.read_text(encoding="utf-8")) or {}) if target.is_file() else {}
    target.write_text(hermes_yaml.safe_dump(_merge(current, override), sort_keys=False), encoding="utf-8")
    return override


# OpenShell's policy DNS answers every name inside a Docker sandbox with a synthetic address from the benchmarking
# block 198.18.0.0/15 (the supervisor maps it back and enforces the policy), so Hermes's SSRF gate would refuse every
# web fetch ("URL targets a private or internal network address"), allowed sites included. Core exempts a local
# proxy's fake-IP block by name (security.fake_ip_ranges). The SSRF protection the block stood for stays with
# OpenShell: its proxy refuses names that resolve private.
POLICY_DNS_RANGE = "198.18.0.0/15"
# The CA variables OpenShell sets in the sandbox (its bundle holds the system roots too). Core's execute_code scrubs
# every variable it does not know, so Python run there distrusts the proxy's certificate on every allowed site and
# the agent learns to switch verification off; terminal.env_passthrough lets them through.
SANDBOX_CA_ENV = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO")


def _as_list(value) -> list:
    return [value] if isinstance(value, str) else [v for v in (value or []) if isinstance(v, str)]


def sandbox_network_settings(request: LaunchRequest) -> dict:
    """Managed-scope settings Hermes needs to use what the sandbox allows (``POLICY_DNS_RANGE``, ``SANDBOX_CA_ENV``),
    merged with the profile's own and the host administrator's values (a managed list replaces the profile's).
    A Hermes core that reads both keys from config.yaml only ignores them: nothing fails, but its web tools then
    refuse every site and execute_code distrusts allowed ones (README, "What the sandbox can reach").
    Returns the override written ({} without a managed scope)."""
    managed = (request.env or {}).get("HERMES_MANAGED_DIR")
    if not managed:
        return {}
    import hermes_yaml

    from .managed import _merge

    config = _read_yaml(Path(request.home) / "config.yaml") if request.home else {}
    target = Path(managed) / "config.yaml"
    current = (hermes_yaml.safe_load(target.read_text(encoding="utf-8")) or {}) if target.is_file() else {}

    def merged(section: str, key: str, extra) -> list:
        values = []
        for doc in (config, current):
            block = doc.get(section) if isinstance(doc, dict) else None
            values += _as_list(block.get(key)) if isinstance(block, dict) else []
        return list(dict.fromkeys([*values, *extra]))

    override = {"security": {"fake_ip_ranges": merged("security", "fake_ip_ranges", [POLICY_DNS_RANGE])},
                "terminal": {"env_passthrough": merged("terminal", "env_passthrough", SANDBOX_CA_ENV)}}
    target.write_text(hermes_yaml.safe_dump(_merge(current, override), sort_keys=False), encoding="utf-8")
    return override


_LOOPBACK_NAMES = ("127.0.0.1", "localhost", "::1")


def route_host(host: str) -> str:
    """The name a model host has from inside the sandbox: host loopback is ``host.openshell.internal``."""
    host = str(host or "").lower()
    return HOST_GATEWAY if host in _LOOPBACK_NAMES else host


def _endpoint(url: str) -> Optional[tuple[str, int, str]]:
    """(host as the sandbox reaches it, port, host as the URL names it) of a model URL; None without a port."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    return route_host(host), port, host


# A sandbox takes at most this many providers (OpenShell's limit on the list in a sandbox's spec).
MAX_SANDBOX_PROVIDERS = 32
# Web search and extract services whose key placement Hermes's own code states: variable -> (label, host, port,
# placement, header name). A service that hands its key to its vendor's client library is not listed here, so
# its key stays on the host. Such a key is a tool's, not a model's: it is bound once the user approved a tool
# category that uses it (categories.KEY_CATEGORIES), never at switch-on by itself.
WEB_BACKENDS = {
    "TAVILY_API_KEY": ("Tavily", "api.tavily.com", 443, "bearer", None),
    "KEENABLE_API_KEY": ("Keenable", "api.keenable.ai", 443, "bearer", None),
    "PERPLEXITY_API_KEY": ("Perplexity", "api.perplexity.ai", 443, "bearer", None),
    "BRAVE_SEARCH_API_KEY": ("Brave Search", "api.search.brave.com", 443, "header", "x-subscription-token"),
}
# The variables OpenShell's request signer reads from an endpoint's provider (AWS Signature Version 4).
SIGV4_ENV = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
# The provider names under which Hermes speaks Google AI Studio's own API.
_GEMINI_NAMES = ("gemini", "google", "google-gemini", "google-ai-studio")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_AWS_HOST_RE = re.compile(r"\.([a-z]{2}(?:-[a-z]+)+-\d)\.amazonaws\.com(?:\.cn)?$")
# How long a credential may take to become ready in a sandbox that has started. The wait ends as soon as every
# one is ready; only a start that is about to fail waits this long.
_READINESS_WAIT = 20.0
# What the gateway says while a credential is on its way into the sandbox, and when it will not get there.
_READINESS_WAITING = ("PERSISTED", "PENDING", "SUPERSEDED")
_READINESS_REFUSED = ("WITHHELD", "FAILED", "REVOKED")


@dataclass
class Discovery:
    """What ``discover_routes`` found. ``routes``: one row per (key, address) the sandbox may use; ``changed``:
    pairs a model entry of the home names that the user did not set up (``{label, host, port, env}``);
    ``withheld``: keys that stay on the host; ``notes``: what was left out, and why; ``on_approval``: keys of web
    services that are bound once a tool category that uses them is approved (``{label, env, host, port,
    categories}``)."""
    routes: list = field(default_factory=list)
    changed: list = field(default_factory=list)
    withheld: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    on_approval: list = field(default_factory=list)


def discover_routes(home: Optional[Path], secrets: dict, pin: Optional[dict] = None) -> Discovery:
    """Which host keys the sandbox gets, the address each may be used at, and where it travels on the wire.

    Read from the launcher's host-only copy: *secrets* (the pinned ``.env`` and secret sources) and *pin*
    (``pins.route_pin``: the model entries as they were when the sandbox was switched on, and the pairs the user
    allowed since). The sandbox can rewrite its profile's model entries, so the home's own ``config.yaml`` never
    adds a pair by itself. A (key, address) pair is bound only when

    (a) it is in the pin: the model, the fallback models, the auxiliary models and the saved endpoints the user
        had set up at switch-on; or
    (b) the key is one of its own provider's keys and the address that provider's registered one. This holds for
        every such key in *secrets*, whether a model uses it or not, so another model of a provider the user has
        a key for works when it is chosen inside; or
    (c) the user allowed the pair (``pin["allowed"]``, written by the launcher's host route) and a model entry
        of the home names it; or
    (d) the key belongs to a web search or extract service (``WEB_BACKENDS``) at that service's own address, and
        the user approved a tool category that uses it (``pin["tools"]``: the ids of the approved categories).

    Any other pair a model entry of the home names has its key withheld there and is reported. Without a pin
    only (b) binds. A model entry's ``key_env``/``api_key_env`` names its key; otherwise its provider's
    registered variables do (the first one set). Host loopback (a model server on this computer) is reached
    from inside as ``host.openshell.internal``, and only when a model entry names it."""
    from .settings_view import _model_entries, _provider_default_url

    pin = pin or {}
    found = Discovery()
    bound: dict = {}
    placements: dict = {}

    def add(label: str, env: Optional[str], url: str, entry: dict, source: str, where: Optional[tuple] = None) -> None:
        target = _endpoint(url) if url else None
        if not env or not secrets.get(env) or target is None or not target[0]:
            return
        host, port, named = target
        if (env, host, port) in bound:
            return
        where = where or wire_placement(entry, url, secrets[env])
        first = placements.setdefault(env, where[:2])
        if first != where[:2]:
            # One credential has one place on the wire: the same key cannot be a bearer token at one address
            # and travel in another header at the next.
            found.notes.append(f"{env} is not handed in for {named}:{port}: it would travel as "
                               f"{placement_text(*where[:2])} there and travels as {placement_text(*first)} at "
                               f"the first address it is bound to")
            return
        bound[(env, host, port)] = {"label": label, "env": env, "host": host, "port": port, "url": url,
                                    "loopback_rewrite": host != named, "placement": where[0], "name": where[1],
                                    "source": source, "token": bool(where[2])}

    def named_by(entry: dict) -> tuple:
        url = str(entry.get("base_url") or "").strip() or _provider_default_url(str(entry.get("provider") or ""))
        return url, _key_env(entry, secrets)

    for entry in pin.get("models") or []:  # (a)
        if isinstance(entry, dict):
            add(str(entry.get("label") or "Model"), _key_env(entry, secrets),
                str(entry.get("url") or entry.get("base_url") or "").strip(), entry, "configured")
    allowed = set()
    for item in pin.get("allowed") or []:
        try:
            allowed.add((str(item["env"]), str(item["host"]).lower(), int(item["port"])))
        except (KeyError, TypeError, ValueError):
            continue
    current = list(_model_entries(_read_yaml(home / "config.yaml") if home else {}))
    for label, entry in current:  # (b) as a model entry names it, and (c)
        url, env = named_by(entry)
        target = _endpoint(url) if url else None
        if env and target and ((env, target[0], target[1]) in allowed or _own_provider(entry, env, target[0], target[1])):
            add(label, env, url, entry, "configured")
    approved = {str(cid) for cid in pin.get("tools") or ()}
    for env, (label, host, port, placement, name) in WEB_BACKENDS.items():  # (d)
        uses = categories.key_categories(env)
        if approved.intersection(uses):
            add(label, env, f"https://{host}:{port}", {}, "web", (placement, name, False))
        elif secrets.get(env):
            found.on_approval.append({"label": label, "env": env, "host": host, "port": port,
                                      "categories": list(uses)})
    for label, env, url, entry in registered_keys(secrets):  # (b) for every other key
        target = _endpoint(url)
        if target is not None and target[0] == target[2]:  # not this computer's own loopback (see above)
            add(label, env, url, entry, "provider")
    for label, entry in current:
        url, env = named_by(entry)
        target = _endpoint(url) if url else None
        if not env or not secrets.get(env) or target is None or not target[0]:
            continue
        host, port, named = target
        if (env, host, port) not in bound and \
                not any(c["env"] == env and c["host"] == named and c["port"] == port for c in found.changed):
            found.changed.append({"label": label, "host": named, "port": port, "env": env})
    found.routes = list(bound.values())
    used = {r["env"] for r in found.routes}
    found.withheld = sorted(k for k in secrets if k not in used)
    return found


def route_decisions(home: Optional[Path], secrets: dict, pin: Optional[dict] = None
                    ) -> tuple[list[dict], list[dict], list[str]]:
    """``discover_routes`` as (routes, pairs withheld as ``{label, host, port, env}``, keys withheld from the
    sandbox)."""
    found = discover_routes(home, secrets, pin)
    return found.routes, found.changed, found.withheld


def credential_routes(home: Optional[Path], secrets: dict, pin: Optional[dict] = None) -> tuple[list[dict], list[str]]:
    """``route_decisions`` without the withheld pairs: (routes, keys withheld from the sandbox)."""
    routes, _changed, withheld = route_decisions(home, secrets, pin)
    return routes, withheld


def registered_keys(secrets: dict) -> list[tuple[str, str, str, dict]]:
    """(label, variable, address, model entry) for every key in *secrets* that one of Hermes's built-in
    providers registers together with an address. Read as registered, never as a provider plugin in a profile's
    home overrides it."""
    out: list = []
    try:
        from hermes_cli import auth
    except ImportError:
        auth = None
    registry = getattr(auth, "PROVIDER_REGISTRY", None)
    builtin = getattr(auth, "BUILTIN_PROVIDER_IDS", None)
    if isinstance(registry, dict):
        for provider in [p for p in dict.keys(registry) if builtin is None or p in builtin]:
            row = dict.get(registry, provider)
            url = str(getattr(row, "inference_base_url", "") or "")
            if getattr(row, "auth_type", "") != "api_key" or not url:
                continue
            for env in getattr(row, "api_key_env_vars", ()) or ():
                if secrets.get(env):
                    out.append((str(getattr(row, "name", "") or provider), env, url, {"provider": provider}))
    if secrets.get("OPENROUTER_API_KEY"):
        try:
            from hermes_constants import OPENROUTER_BASE_URL
        except ImportError:
            return out
        out.append(("OpenRouter", "OPENROUTER_API_KEY", OPENROUTER_BASE_URL, {"provider": "openrouter"}))
    return out


def _own_provider(entry: dict, env: str, host: str, port: int) -> bool:
    """Whether *env* is one of the entry's provider's own keys and (host, port) that provider's registered
    address. Only Hermes's built-in providers count, read as registered: a provider plugin in the profile's
    home overrides rows for that home, and the home is not what decides this."""
    provider = str(entry.get("provider") or "")
    envs, url = (), ""
    try:
        from hermes_cli import auth
    except ImportError:
        auth = None
    registry = getattr(auth, "PROVIDER_REGISTRY", None)
    builtin = getattr(auth, "BUILTIN_PROVIDER_IDS", None)
    if provider and isinstance(registry, dict) and (builtin is None or provider in builtin):
        row = dict.get(registry, provider)
        envs = tuple(getattr(row, "api_key_env_vars", ()) or ())
        url = str(getattr(row, "inference_base_url", "") or "")
    if not url and provider == "openrouter":
        try:
            from hermes_constants import OPENROUTER_BASE_URL
        except ImportError:
            return False
        envs, url = ("OPENROUTER_API_KEY",), OPENROUTER_BASE_URL
    target = _endpoint(url) if url else None
    return target is not None and env in envs and (host, port) == target[:2]


def _key_env(entry: dict, secrets: dict) -> Optional[str]:
    for hint in ("key_env", "api_key_env"):
        if entry.get(hint):
            return str(entry[hint])
    provider = str(entry.get("provider") or "")
    try:
        from hermes_cli.auth import PROVIDER_REGISTRY
    except ImportError:
        return None
    config = PROVIDER_REGISTRY.get(provider)
    for env in getattr(config, "api_key_env_vars", ()) or ():
        if secrets.get(env):
            return env
    return None


# -- where a key travels on the wire -----------------------------------------------------------------

def wire_placement(entry: dict, url: str, value: str) -> tuple[str, Optional[str], bool]:
    """Where Hermes puts this key on a request to *url*: ``(placement, header name, token)``.

    Decided the way Hermes decides it, with Hermes's own functions where this Hermes has them: the Gemini
    provider on Google AI Studio's own API sends the key in ``x-goog-api-key`` (the same address under another
    provider's name gets a bearer token: Hermes speaks OpenAI's protocol there); a route that speaks Anthropic
    Messages takes an API key in ``x-api-key`` and a sign-in token, or any key at the hosts that ask for it, as
    a bearer token; every other route sends a bearer token. ``token`` is True for an Anthropic sign-in token:
    Hermes tells it from an API key by its shape, so inside the sandbox it must be handed over in a form that
    keeps that shape."""
    provider = str(entry.get("provider") or "").strip().lower()
    if provider in _GEMINI_NAMES and _gemini_native(url):
        return "header", "x-goog-api-key", False
    if _api_mode(entry, provider, url) == "anthropic_messages":
        style = _anthropic_style(str(value or ""), url)
        if style in ("bearer", "oauth"):
            return "bearer", None, style == "oauth"
        return "header", "x-api-key", False
    return "bearer", None, False


def placement_text(placement: str, name: Optional[str] = None) -> str:
    """A placement in words, for the launcher's notes and the Sandbox page."""
    if placement == "bearer":
        return "a bearer token"
    if placement == "sigv4":
        return "a request signature"
    if placement == "basic":
        return "a Basic password"
    return f"the {placement} {name}" if name else placement


def _gemini_native(url: str) -> bool:
    try:
        from agent.gemini_native_adapter import is_native_gemini_base_url
    except ImportError:
        text = str(url or "").strip().rstrip("/").lower()
        return "generativelanguage.googleapis.com" in text and not text.endswith("/openai")
    try:
        return bool(is_native_gemini_base_url(url))
    except Exception:
        return False


def _api_mode(entry: dict, provider: str, url: str) -> str:
    """The request shape of a model entry: its own ``api_mode`` when it names one, else what Hermes works out
    from the provider, the address and the model, read from what this computer already has. The discovery runs
    on the Sandbox page's poll and before every sandbox start: it makes no request."""
    model = str(entry.get("model") or entry.get("default") or "")
    try:
        from hermes_cli import providers, runtime_provider

        named = runtime_provider._parse_api_mode(entry.get("api_mode") or entry.get("transport"))
        return str(named or _worked_out_api_mode(providers, runtime_provider, provider, url, model) or "")
    except Exception:  # a Hermes without these helpers: the address alone decides
        parts = urllib.parse.urlsplit(str(url or "").strip().lower())
        path = parts.path.rstrip("/")
        if (parts.hostname or "") == "api.anthropic.com" or path.endswith(("/anthropic", "/anthropic/v1")):
            return "anthropic_messages"
        return "chat_completions"


def _worked_out_api_mode(providers, runtime_provider, provider: str, url: str, model: str) -> str:
    """What Hermes's ``runtime_provider._fallback_api_mode`` answers, step for step and with Hermes's own
    functions, with one difference: the provider's definition is read without the network
    (``get_provider(..., allow_network=False)``). Hermes's function downloads its public model catalog when the
    process has none; the transport a provider declares does not come from that catalog. The steps: the
    address, the Nous rule, the transport the provider declares, and a declared Anthropic transport only on the
    provider's own endpoint."""
    if providers.is_actual_route(provider, url):
        return "chat_completions"
    detected = runtime_provider._detect_api_mode_for_url(url) or providers.host_mandated_api_mode(url)
    if detected:
        return detected
    if (provider or "").strip().lower() in ("nous", "nous-portal", "nousresearch"):
        return providers.nous_api_mode(model)
    known = providers.get_provider(provider, allow_network=False)
    if known is None:
        return "bedrock_converse" if provider == "bedrock" else "chat_completions"
    declared = providers.TRANSPORT_TO_API_MODE.get(known.transport)
    if declared is None:
        from agent.transports import registered_api_modes

        declared = known.transport if known.transport in registered_api_modes() else "chat_completions"
    if declared == "anthropic_messages" and not runtime_provider._on_declared_anthropic_endpoint(provider, url):
        return "chat_completions"
    return declared


def _anthropic_style(value: str, url: str) -> str:
    """Hermes's own answer for an Anthropic Messages route: ``api_key`` or ``kimi`` (``x-api-key``), ``bearer``
    or ``oauth`` (a bearer token)."""
    try:
        from agent.anthropic_adapter import _auth_style

        return str(_auth_style(value, url, url))
    except Exception:
        host = (urllib.parse.urlsplit(str(url or "")).hostname or "").lower()
        if host in ("api.minimax.io", "api.minimaxi.com") or host.endswith(".azure.com"):
            return "bearer"
        token = value.startswith(("sk-ant-", "eyJ", "cc-")) and \
            not value.startswith(("sk-ant-api", "sk-ant-usr", "sk-ant-svc", "sk-ant-admin"))
        return "oauth" if host == "api.anthropic.com" and token else "api_key"


# -- credentials as OpenShell providers ----------------------------------------------------------------

def key_declarations(routes: list) -> list[tuple[CredentialDecl, str]]:
    """The discovered routes as credentials: one per key, valid at every address the key is bound to (an
    OpenShell sandbox takes a variable from one provider only). Each comes with its variable's name."""
    by_env: dict = {}
    for route in routes:
        by_env.setdefault(route["env"], []).append(route)
    out = []
    for env, rows in by_env.items():
        first = rows[0]
        out.append((CredentialDecl(id=f"env:{env}", label=f"{first['label']} ({env})",
                                   endpoints=tuple(Endpoint(r["host"], int(r["port"])) for r in rows),
                                   placement=first["placement"], name=first["name"]), env))
    return out


def credential_env(decl: CredentialDecl) -> str:
    """The variable that holds a credential's placeholder inside the sandbox: the variable itself for a key
    Hermes reads from one (``env:<NAME>``), else a name made from the credential's id."""
    if decl.id.startswith("env:") and _ENV_NAME_RE.match(decl.id[4:]):
        return decl.id[4:]
    return "HERMES_CRED_" + re.sub(r"[^A-Z0-9]+", "_", decl.id.upper()).strip("_")


def check_declaration(decl: CredentialDecl) -> None:
    """Refuse a credential OpenShell could not be told about, with the reason."""
    if decl.placement not in PLACEMENTS:
        raise ValueError(f"credential {decl.id}: unknown placement {decl.placement!r}")
    if not decl.endpoints:
        raise ValueError(f"credential {decl.id}: no address to use it at")
    for ep in decl.endpoints:
        if ep.protocol not in PROTOCOLS or not ep.host or not 0 < int(ep.port) < 65536:
            raise ValueError(f"credential {decl.id}: not an address: {ep!r}")
    if decl.placement in ("header", "query") and not decl.name:
        raise ValueError(f"credential {decl.id}: a {decl.placement} placement needs the {decl.placement}'s name")
    if decl.placement == "path" and (decl.name or "").count("{credential}") != 1:
        raise ValueError(f"credential {decl.id}: a path placement needs a template with one {{credential}}")
    if decl.placement == "sigv4" and credential_env(decl) not in SIGV4_ENV:
        raise ValueError(f"credential {decl.id}: a signing credential is one of {', '.join(SIGV4_ENV)} "
                         f"(declared as env:<NAME>)")


def _endpoint_key(ep: Endpoint) -> tuple:
    return (ep.host.lower(), int(ep.port), ep.path_prefix or "", ep.protocol)


def _digest(value) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def provider_groups(decls: list) -> list[list]:
    """Credentials grouped as OpenShell takes them: one provider each, except that the two or three values
    one request signature is made from share a provider (the signer reads them from the endpoint's
    provider). *decls*: ``(CredentialDecl, variable)`` pairs."""
    groups: list = []
    signing: dict = {}
    for decl, env in decls:
        if decl.placement != "sigv4":
            groups.append([(decl, env)])
            continue
        key = (decl.name or "", tuple(sorted(_endpoint_key(ep) for ep in decl.endpoints)))
        if key not in signing:
            signing[key] = []
            groups.append(signing[key])
        signing[key].append((decl, env))
    return groups


def provider_id(prefix: str, group: list, stable: bool) -> str:
    """A provider's name, which is also its profile's id: the sandbox's name, the variable, and a digest of
    everything the profile says (the credential, where it travels, every address). Two credentials, or one
    credential bound to two sets of addresses, never share an id."""
    said = [[decl.id, env, decl.placement, decl.name or "", bool(stable),
             sorted(_endpoint_key(ep) for ep in decl.endpoints)] for decl, env in group]
    digest = hashlib.sha256(json.dumps(sorted(said), sort_keys=True).encode()).hexdigest()[:8]
    slug = re.sub(r"[^a-z0-9]+", "-", "-".join(env for _decl, env in group).lower()).strip("-")
    return f"{prefix}-{slug}"[:54].rstrip("-") + "-" + digest


def _signing(decl: CredentialDecl, host: str) -> tuple[str, str]:
    """(service, region) a request to *host* is signed for: ``name`` is ``<service>`` or
    ``<service>/<region>``; without a region the host's own (``...<region>.amazonaws.com``)."""
    service, _, region = (decl.name or "").partition("/")
    if not region:
        match = _AWS_HOST_RE.search(host.lower())
        region = match.group(1) if match else ""
    return service or "bedrock", region


def credential_profile(profile_id: str, group: list, binaries, stable: bool = False) -> dict:
    """An OpenShell provider profile for one credential (or the values of one request signature): every
    address it may be used at, the one place it travels in, and Hermes's interpreter as the only program that
    may use it."""
    first = group[0][0]
    credentials = []
    for decl, env in group:
        entry = {"name": re.sub(r"[^a-z0-9]+", "_", env.lower()).strip("_") if len(group) > 1 else "api_key",
                 "description": f"{decl.label} (managed by the Hermes launcher)", "env_vars": [env],
                 "required": env != "AWS_SESSION_TOKEN"}
        if decl.placement == "bearer":
            entry.update({"auth_style": "bearer", "header_name": (decl.name or "authorization").lower()})
        elif decl.placement == "header":
            entry.update({"auth_style": "header", "header_name": str(decl.name).lower()})
        elif decl.placement == "query":
            entry.update({"auth_style": "query", "query_param": str(decl.name)})
        elif decl.placement == "path":
            entry.update({"auth_style": "path", "path_template": str(decl.name)})
        elif decl.placement == "basic":
            entry["auth_style"] = "basic"
        if stable:
            entry["stable_placeholder"] = True
        credentials.append(entry)
    endpoints = []
    for ep in first.endpoints:
        row = {"host": ep.host, "port": int(ep.port), "protocol": ep.protocol,
               "access": "full" if ep.protocol == "websocket" else "read-write", "enforcement": "enforce"}
        if ep.path_prefix:
            row["path"] = ep.path_prefix
        if first.placement == "sigv4":
            service, region = _signing(first, ep.host)
            row.update({"credential_signing": "sigv4", "signing_service": service})
            if region:
                row["signing_region"] = region
        endpoints.append(row)
    where = ", ".join(f"{ep.host}:{ep.port}" for ep in first.endpoints)
    return {
        "id": profile_id, "display_name": f"Hermes {first.label}"[:120],
        "description": f"Hermes credential for {where} (managed by the Hermes launcher)"[:400],
        "category": "inference", "inference_capable": True, "credentials": credentials,
        "discovery": {"credentials": [c["name"] for c in credentials]},
        "endpoints": endpoints, "binaries": list(binaries),
    }


def provider_profile(profile_id: str, route: dict, binaries) -> dict:
    """An OpenShell provider profile binding one key to one model endpoint and Hermes's interpreter."""
    decl = CredentialDecl(id=f"env:{route['env']}", label=f"{route['label'].lower()} ({route['env']})",
                          endpoints=(Endpoint(route["host"], int(route["port"])),),
                          placement=route.get("placement") or "bearer", name=route.get("name"))
    return credential_profile(profile_id, [(decl, route["env"])], binaries)


class CredentialSinkMixin:
    """``CredentialSink`` (credential_sink.py) for a driver whose sandbox runs behind an OpenShell gateway.

    ``declare`` records a credential; the next sandbox start registers one OpenShell provider for it, with the
    declared placement, and attaches it. The driver's own key discovery goes through ``declare`` too. A
    credential whose value may be replaced while the sandbox runs (``expires``, and every key the Keys page can
    save) is declared with a stable placeholder, so ``update`` changes the value and the running backend keeps
    the placeholder it started with. The driver supplies the gateway calls (``_gw_*``)."""

    # Set by the launcher (launcher_cli): a callable that is True while no chat turn runs.
    turns_idle = None

    def _sink_state(self) -> None:
        self._decls: dict = {}  # credential id -> {"decl", "env", "value", "expires_at", "own"}
        # credential id -> {"provider", "env", "stable", "live", "expires", "value": digest} as the running sandbox
        # has it
        self._bound: dict = {}
        # A value update comes from another thread than a sandbox start (the sign-in schedule has its own):
        # one of them at a time, so no update falls between a start reading the values and binding them.
        self._sink_lock = threading.RLock()

    # -- CredentialSink ------------------------------------------------------------------------
    def declare(self, decl: CredentialDecl, value: str, expires_at: Optional[float] = None, *, own: bool = False) -> str:
        """Record *decl* for the next sandbox start. Returns the variable that holds its placeholder inside.
        A credential declared while a sandbox runs reaches it at its next start."""
        check_declaration(decl)
        env = credential_env(decl)
        taken = next((cid for cid, held in self._decls.items() if held["env"] == env and cid != decl.id), None)
        if taken is not None:
            raise ValueError(f"credential {decl.id}: the variable {env} already holds {taken}")
        self._decls[decl.id] = {"decl": decl, "env": env, "value": str(value), "expires_at": expires_at, "own": own}
        return env

    def update(self, cred_id: str, value: str, expires_at: Optional[float] = None) -> None:
        """Replace a declared credential's value. While the sandbox runs this is a value-only provider update:
        the placeholder inside stays, and the next request carries the new value (the next signature is made
        with it, for the values of a request signature). OpenShell closes the sandbox's open connections on
        every provider change, so call it while ``quiet()``."""
        with self._sink_lock:
            self._update_locked(cred_id, value, expires_at)

    def _update_locked(self, cred_id: str, value: str, expires_at: Optional[float]) -> None:
        held = self._decls.get(cred_id)
        if held is None:
            raise NotSupported(f"no credential {cred_id!r} was declared")
        held["value"], held["expires_at"] = str(value), expires_at
        row = self._bound.get(cred_id)
        if row is None or not self._sandbox_runs():
            return  # the next start registers the new value
        if not row["live"]:
            raise NotSupported(f"the placeholder of {cred_id} is not a stable one; restart the sandbox to use "
                               f"the new value")
        expires = {row["env"]: float(expires_at)} if expires_at is not None else {}
        clear = [row["env"]] if expires_at is None and row.get("expires") else []
        self._gw_update(row["provider"], {row["env"]: str(value)}, expires, clear)
        row["expires"], row["value"] = expires_at is not None, _digest(value)
        self._note(f"credential {cred_id}: value replaced in provider {row['provider']}, placeholder unchanged"
                   + (f", expires at {int(expires_at)}" if expires_at is not None else ""))

    def withdraw(self, cred_id: str) -> None:
        """Take a declared credential out of the sandbox starts that follow: no provider is registered for it,
        so the gateway is asked nothing about it and no address is bound to it. Declared again, it is back.
        The sandbox that runs keeps what it started with."""
        with self._sink_lock:
            self._decls.pop(cred_id, None)

    def quiet(self) -> bool:
        """True while no reply is streaming in this sandbox, as far as the launcher can tell: no sandbox runs,
        or no chat turn runs in a chat the launcher relays. A turn counts from its first event to its end, tool
        calls included. Requests the backend makes outside a relayed turn (a title or a summary written after
        the reply, a scheduled job) are not seen. False when the launcher gave this driver no such signal."""
        if not self._sandbox_runs():
            return True
        idle = self.turns_idle
        return bool(idle()) if callable(idle) else False

    def registered_providers(self) -> list[dict]:
        """The providers the running sandbox was started with, as ``policy`` lists them. No gateway call."""
        return [dict(row) for row in getattr(self, "_providers", None) or []]

    # -- the Keys page ------------------------------------------------------------------------
    def keys_saved(self, secrets: dict, pin: Optional[dict] = None) -> bool:
        """A key was saved on this computer while the sandbox runs. True when the running sandbox now uses what
        was saved, without a restart: the keys and their addresses are the ones it started with and every
        changed value went in as a value-only update. False when a restart is still needed: a key or an address
        was added or removed, a placeholder is not a stable one, or a reply is running (an update would cut
        it)."""
        if not self._sandbox_runs():
            return False
        wanted = {decl.id: (decl, secrets[env]) for decl, env in
                  key_declarations(discover_routes(self._request.home, secrets, pin).routes)}
        own = {cid: held for cid, held in self._decls.items() if held["own"] and cid in self._bound}
        if set(wanted) != set(own) or any(wanted[cid][0] != own[cid]["decl"] for cid in wanted):
            return False
        changed = [cid for cid in wanted if _digest(wanted[cid][1]) != self._bound[cid]["value"]]
        if not changed:
            return True
        if not all(self._bound[cid]["live"] for cid in changed) or not self.quiet():
            return False
        for cid in changed:
            self.update(cid, wanted[cid][1], None)
        return True

    # -- registration (a sandbox start) ---------------------------------------------------------
    def _sandbox_runs(self) -> bool:
        return getattr(self, "_name", None) is not None and getattr(self, "_request", None) is not None

    def _register_providers(self, request: LaunchRequest) -> list[dict]:
        """Before the sandbox is created: the profile's keys as the host-only copy has them, and every
        credential declared by the launcher, each as one provider with its placement and its current value."""
        with self._sink_lock:
            return self._register_providers_locked(request)

    def _register_providers_locked(self, request: LaunchRequest) -> list[dict]:
        found = discover_routes(request.home, request.secrets, request.pins)
        self._changed, notes = found.changed, list(found.notes)
        for cid in [cid for cid, held in self._decls.items() if held["own"]]:
            del self._decls[cid]  # the keys of the start before; what the launcher declared stays
        for decl, env in key_declarations(found.routes):
            if any(held["env"] == env for held in self._decls.values()):
                notes.append(f"{env} is already declared by the launcher; the key in the profile is not used")
                continue
            self.declare(decl, request.secrets[env], None, own=True)
        groups = provider_groups([(held["decl"], held["env"]) for held in self._decls.values()])
        for group in groups[MAX_SANDBOX_PROVIDERS:]:
            for decl, env in group:
                notes.append(f"{env} is not handed in: a sandbox takes {MAX_SANDBOX_PROVIDERS} providers")
                del self._decls[decl.id]
        groups = groups[:MAX_SANDBOX_PROVIDERS]
        handed = {held["env"] for held in self._decls.values()}
        self._withheld = sorted(k for k in request.secrets if k not in handed)
        prefix = sandbox_name(request.profile)
        want_stable = [any(decl.expires or self._decls[decl.id]["own"] for decl, _env in group)
                       and group[0][0].placement != "sigv4" for group in groups]
        stable_ok = self._gw_stable_supported() if any(want_stable) else True
        if not stable_ok:
            needs = [decl.label for group in groups for decl, _env in group if decl.expires]
            if needs:
                raise DriverUnavailable(
                    "this OpenShell gateway does not support stable placeholders, which a sign-in that is kept "
                    f"current while the sandbox runs needs ({', '.join(needs)}). Update OpenShell.")
            notes.append("this OpenShell gateway does not support stable placeholders: a key saved while the "
                         "sandbox runs is used after a restart")
        self._providers, self._bound = [], {}
        for i, (group, wanted) in enumerate(zip(groups, want_stable)):
            stable = bool(wanted and stable_ok)
            pid = provider_id(prefix, group, stable)
            profile_action = self._gw_profile(credential_profile(pid, group, self._binaries, stable), i)
            values = {env: self._decls[decl.id]["value"] for decl, env in group}
            expires = {env: float(self._decls[decl.id]["expires_at"]) for decl, env in group
                       if self._decls[decl.id]["expires_at"] is not None}
            # The values travel over the gateway's own channel into its credential store; never into an
            # argv, a file or the sandbox.
            action = self._gw_provider(pid, values, expires)
            first = group[0][0]
            endpoints = [f"{ep.host}:{ep.port}" for ep in first.endpoints]
            for decl, env in group:
                # "live": a new value reaches the running sandbox. The values of a request signature need no
                # placeholder for that: the signer reads the current ones by name.
                self._bound[decl.id] = {"provider": pid, "env": env, "stable": stable, "expires": env in expires,
                                        "live": stable or first.placement == "sigv4",
                                        "value": _digest(values[env])}  # what the sandbox has, as a digest
            self._providers.append({
                "name": pid, "env": group[0][1], "envs": [env for _decl, env in group], "label": first.label,
                "endpoint": endpoints[0], "endpoints": endpoints,
                "placement": first.placement, "header": first.name, "stable": stable,
                "loopback_rewrite": any(ep.host == HOST_GATEWAY for ep in first.endpoints),
                "action": action, "profile": profile_action})
        self._provider_notes = notes
        for note in notes:
            self._note(note)
        self._forget_old(Path(request.config_dir), [p["name"] for p in self._providers])
        self._forget_first_names(Path(request.config_dir), prefix, request.secrets,
                                 [p["name"] for p in self._providers])
        return self._providers

    def _forget_first_names(self, config_dir: Path, prefix: str, secrets: dict, names: list) -> None:
        """Once per profile: delete the providers an earlier version of this plugin registered, with their keys.

        That version gave a provider, and its profile, the name ``<sandbox name>-<variable in lower case with
        dashes>``, one per key of the profile. Only names of exactly that form are deleted, made from this
        profile's own sandbox name and the variables of its own keys: nothing is listed, and a provider anyone
        else put into the gateway is never touched. A key that was taken out of the profile since is not found
        this way. Best effort: what could not be deleted is tried again at the next start."""
        record = config_dir / "providers-first-names.json"
        if record.exists():
            try:
                left = [str(n) for n in json.loads(record.read_text(encoding="utf-8"))]
            except (OSError, ValueError, TypeError):
                left = []
        else:
            left = sorted({f"{prefix}-{str(env).lower().replace('_', '-')}"[:63] for env in secrets})
        still = []
        for name in left:
            if name in names:
                continue
            try:
                self._gw_forget(name)
            except Exception as exc:
                still.append(name)
                self._note(f"could not delete the provider {name} of an earlier version: {exc}")
        if left:
            self._note(f"providers of an earlier version deleted where they existed: {len(left) - len(still)} names")
        try:
            record.write_text(json.dumps(still), encoding="utf-8")
        except OSError as exc:
            self._note(f"could not record the cleanup of earlier providers: {exc}")

    def _forget_old(self, config_dir: Path, names: list) -> None:
        """A provider's name changes with what its profile says, so the ones this sandbox no longer uses are
        deleted from the gateway (they hold a key). The names of the last start are kept in the launcher's
        state folder. Best effort: a provider that cannot be deleted is tried again at the next start."""
        record = config_dir / "providers.json"
        try:
            before = [str(n) for n in json.loads(record.read_text(encoding="utf-8"))]
        except (OSError, ValueError, TypeError):
            before = []
        left = []
        for name in before:
            if name in names:
                continue
            try:
                self._gw_forget(name)
                self._note(f"provider {name} is no longer used: deleted from the gateway")
            except Exception as exc:
                left.append(name)
                self._note(f"could not delete the unused provider {name}: {exc}")
        try:
            record.write_text(json.dumps([*names, *left]), encoding="utf-8")
        except OSError as exc:
            self._note(f"could not record the providers of this start: {exc}")

    def _check_readiness(self) -> None:
        """After the sandbox is up: what it did with each provider that carries a stable placeholder, asked
        until every one is ready. The start fails with the reason when the gateway withheld a credential or
        the sandbox could not take it, and when one is still on its way after ``_READINESS_WAIT``: the model
        requests that need it would all fail. An answer that cannot be had, or that does not say, is noted
        once and the start goes on."""
        waiting = [row for row in self._providers if row.get("stable")]
        said: dict = {}
        deadline, asked = time.monotonic() + _READINESS_WAIT, 0
        while waiting:
            for row in list(waiting):
                try:
                    state, reason = self._gw_provider_state(self._name, row["name"])
                except Exception as exc:  # the question is best effort; the gateway's answer is what counts
                    self._note(f"could not ask what the sandbox did with provider {row['name']}: {exc}")
                    row["state"] = None
                    waiting.remove(row)
                    continue
                row["state"], said[row["name"]] = state, reason
                if state == "READY":
                    waiting.remove(row)
                elif state in _READINESS_REFUSED:
                    raise DriverUnavailable(_not_ready(row["label"], state, reason))
                elif state not in _READINESS_WAITING:
                    # no state, or one this plugin does not know: asking again would say no more
                    self._note(f"the gateway did not say what the sandbox did with provider {row['name']} "
                               f"(state {state}, reason {reason})")
                    row["state"] = None
                    waiting.remove(row)
            if not waiting:
                break
            if time.monotonic() >= deadline:
                row = waiting[0]
                raise DriverUnavailable(
                    f"{row['label']} was not ready in the sandbox after {_READINESS_WAIT:.0f} s "
                    f"({str(row['state']).lower()}: {_reason_words(said.get(row['name'])) or 'no reason given'}).")
            time.sleep(min(1.0, 0.25 * 2 ** (asked // 2)))
            asked += 1


def _reason_words(reason) -> str:
    """A readiness reason as words (``CREDENTIALS_WITHHELD`` -> ``credentials withheld``); empty for none."""
    text = str(reason or "").strip().upper()
    return "" if text in ("", "UNSPECIFIED", "UNKNOWN") else text.replace("_", " ").lower()


def _not_ready(label: str, state: str, reason) -> str:
    """Why a start fails for a credential the sandbox will not get."""
    if state == "WITHHELD" and reason == "UNSUPPORTED_SUPERVISOR":
        return (f"this OpenShell sandbox does not support stable placeholders, so the gateway withheld {label}. "
                f"Update OpenShell.")
    words = _reason_words(reason) or state.lower()
    if state == "WITHHELD":
        return f"the gateway withheld {label} from the sandbox ({words})."
    return f"the sandbox could not take {label} ({words})."


# -- network rules <-> policy ------------------------------------------------------------------------

def rule_name(kind: str, target: str, port: int, binary: Optional[str] = None) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", target.lower()).strip("_")[:40]
    name = f"{RULE_PREFIX}{kind}_{slug}_{port}"
    if binary:
        name += "_" + hashlib.sha256(binary.encode()).hexdigest()[:8]
    return name


def network_rules(network: dict, binaries) -> dict:
    """Spec network -> OpenShell ``network_policies``: one rule per destination, usable by Hermes's
    interpreter and everything it starts (OpenShell matches a rule's binaries against ancestors), or
    by one program when the rule names it. Rules the enforcer added on approval pass through."""
    rules = {}
    for r in network.get("allow") or []:
        bins = [r["binary"]] if r.get("binary") else list(binaries)
        if r.get("host"):
            name = rule_name("site", r["host"], r["port"], r.get("binary"))
            endpoint = {"host": r["host"], "port": int(r["port"])}
        else:
            name = rule_name("addr", r["cidr"], r["port"])
            endpoint = {"port": int(r["port"]), "allowed_ips": [r["cidr"]]}
        rules[name] = {"name": name, "endpoints": [endpoint], "binaries": [{"path": b} for b in bins]}
    for name, rule in (network.get("approved") or {}).items():
        # A tool category whose services all carry a credential is approved by a rule without endpoints (the
        # credential's provider opens its hosts): it stands for the approval and is no rule of the policy.
        if rule.get("endpoints"):
            rules.setdefault(name, rule)
    return rules


# -- TLS: plain host grants are tunnels to the site itself ---------------------------------------------------
# OpenShell's proxy terminates TLS on every allowed CONNECT by default (``tls`` unset = auto-detect: it peeks the
# ClientHello and presents a certificate from the sandbox's own CA), so a client that does not trust that CA
# (Windows curl.exe on Schannel, git, Node's bundled roots) fails verification on a site the user allowed, and
# the agent learns to switch verification off. ``tls: skip`` makes the endpoint a raw tunnel: the client
# talks TLS with the site and checks its real certificate. The plugin's own host rules carry nothing that needs
# the proxy inside TLS (no credential placeholders, no L7 rules), so they get it; provider endpoints and rules
# OpenShell drafted keep the default. OpenShell refuses a policy whose overlapping endpoints disagree on
# ``tls``, so an endpoint another non-skip endpoint overlaps (same port, host patterns that can match the same
# name) keeps the default too.
PASSTHROUGH_PREFIXES = (RULE_PREFIX + "site_", "allowed_host_", "allowed_tool_", usage_data.BUILTIN_PREFIX)
_PLAIN_KEYS = frozenset({"host", "port", "ports"})


def _glob_re(pattern: str) -> "re.Pattern":
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".+")
            i += 2
        elif pattern[i] == "*":
            out.append("[^.]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^.]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def hosts_overlap(left: str, right: str) -> bool:
    """Whether two endpoint host selectors can match the same name (OpenShell's ``host_patterns_overlap``;
    conservative: two wildcard patterns, or an empty host, overlap)."""
    a, b = str(left or "").lower().rstrip("."), str(right or "").lower().rstrip(".")
    if not a or not b:
        return True
    wild_a, wild_b = any(c in a for c in "*?["), any(c in b for c in "*?[")
    if not wild_a and not wild_b:
        return a == b
    if wild_a and wild_b:
        return True
    pattern, name = (a, b) if wild_a else (b, a)
    return "[" in pattern or bool(_glob_re(pattern).fullmatch(name))


def _endpoint_ports(ep: dict) -> set:
    ports = [p for p in (ep.get("ports") or []) if p] or ([ep["port"]] if ep.get("port") else [])
    return {int(p) for p in ports}


def _is_skip(tls) -> bool:
    """``tls: skip`` as a policy file spells it, or as the gateway's JSON may (``NETWORK_TLS_MODE_SKIP``)."""
    return "skip" in str(tls or "").lower()


def passthrough(rules: dict, reserved=()) -> dict:
    """*rules* with ``tls: skip`` on every endpoint of the plugin's own host rules (``PASSTHROUGH_PREFIXES``:
    page destinations and card grants) that carries nothing but host and port, unless another endpoint that
    terminates TLS overlaps it (another rule's, or a provider's: *reserved* ``(host, port)`` pairs). Rules
    OpenShell drafted and provider rules are left as they are. *reserved* None: this runtime cannot tunnel
    (its CA bundle lacks the system roots), so the plugin's own endpoints lose any ``tls: skip`` instead."""
    out = json.loads(json.dumps(rules or {}))
    candidates: list[tuple[str, int]] = []
    fixed: list[tuple[str, set]] = []  # endpoints whose TLS stays terminated (not skip)
    for name, rule in out.items():
        for i, ep in enumerate(rule.get("endpoints") or []):
            plain = (name.startswith(PASSTHROUGH_PREFIXES) and ep.get("host") and set(ep) - {"tls"} <= _PLAIN_KEYS
                     and (not ep.get("tls") or _is_skip(ep.get("tls"))))
            if plain:
                ep.pop("tls", None)
                candidates.append((name, i))
            elif not _is_skip(ep.get("tls")):
                fixed.append((str(ep.get("host") or ""), _endpoint_ports(ep)))
    if reserved is None:
        return out
    for host, port in reserved:
        if port:
            fixed.append((str(host or ""), {int(port)}))
    keep = set()  # candidates that must keep TLS termination
    changed = True
    while changed:
        changed = False
        others = fixed + [(out[n]["endpoints"][i]["host"], _endpoint_ports(out[n]["endpoints"][i])) for n, i in keep]
        for name, i in candidates:
            if (name, i) in keep:
                continue
            ep = out[name]["endpoints"][i]
            ports = _endpoint_ports(ep)
            if any(ports & p and hosts_overlap(ep["host"], h) for h, p in others):
                keep.add((name, i))
                changed = True
    for name, i in candidates:
        if (name, i) not in keep:
            out[name]["endpoints"][i]["tls"] = "skip"
    return out


def network_from_policy(policy: dict, binaries) -> dict:
    """OpenShell base policy -> spec network (inverse of network_rules)."""
    allow, approved = [], {}
    for name, rule in sorted((policy.get("network_policies") or {}).items()):
        if name.startswith("_provider_"):
            continue  # contributed by an attached provider (effective views only), not the sandbox's own
        if name.startswith(usage_data.BUILTIN_PREFIX):
            continue  # the launcher's own (usage_data.py): never a destination or a grant of the user's
        if not name.startswith(RULE_PREFIX):
            approved[name] = rule
            continue
        bins = [b.get("path") for b in rule.get("binaries") or []]
        binary = bins[0] if len(bins) == 1 and bins != list(binaries) else None
        for ep in rule.get("endpoints") or []:
            port = int(ep.get("port") or 0)
            if ep.get("host"):
                entry = {"host": ep["host"], "port": port}
                if binary:
                    entry["binary"] = binary
                if entry not in allow:
                    allow.append(entry)
            for ip in ep.get("allowed_ips") or []:
                if not ep.get("host") and {"cidr": ip, "port": port} not in allow:
                    allow.append({"cidr": ip, "port": port})
    out = {"egress": "deny", "allow": allow}
    if approved:
        out["approved"] = approved
    return out


def build_policy(cfg: OpenShellConfig, plan: MountPlan, network: dict, binaries=None) -> dict:
    """The create-time policy in proto-JSON field names (SandboxPolicy)."""
    read_only = list(dict.fromkeys([*_BASE_READ_ONLY, *plan.read_only]))
    read_write = list(dict.fromkeys([*_BASE_READ_WRITE, *plan.read_write]))
    return {
        "version": 1,
        "filesystem": {"include_workdir": True, "read_only": read_only, "read_write": read_write},
        "landlock": {"compatibility": "hard_requirement"},
        "process": {"run_as_user": cfg.run_as[0], "run_as_group": cfg.run_as[1]},
        "network_policies": network_rules(network, binaries if binaries is not None else cfg.binaries),
    }


def _require_version(what: str, text: str) -> None:
    """Linux preflight only (see MIN_OPENSHELL)."""
    found = parse_version(text)
    if found is None or found < MIN_OPENSHELL:
        want = ".".join(map(str, MIN_OPENSHELL))
        raise DriverUnavailable(f"{what} reports {str(text).strip()[:60] or 'no version'}; OpenShell v{want} or newer "
                                f"is required (supervisor OCSF JSON audit, host-alias pinning)")


# -- audit events ------------------------------------------------------------------------------------

def parse_event(line: dict) -> dict:
    """One gateway log line -> an event; OCSF shorthand (``NET:OPEN [MED] DENIED ...``) is split into
    class, activity, severity, action and bracketed context."""
    msg = str(line.get("message") or "")
    event = {"time": line.get("time"), "source": line.get("source") or "gateway", "level": line.get("level"),
             "message": msg, "fields": dict(line.get("fields") or {})}
    if str(line.get("level") or "").strip().upper() != "OCSF" and line.get("target") != "ocsf":
        return event
    m = _OCSF_RE.match(msg)
    if not m:
        return {**event, "ocsf": True}
    rest = m.group("rest")
    first = rest.split(" ", 1)[0]
    action = first if first in ("ALLOWED", "DENIED", "BLOCKED") else None
    context: dict = {}
    detail = _split_context(rest[len(first):] if action else rest, context)
    return {**event, "ocsf": True, "class": m.group("cls"), "activity": m.group("act"), "severity": m.group("sev"),
            "action": action, "detail": detail, "context": context}


def _bracket_groups(text: str) -> tuple[list[str], str]:
    """Top-level ``[...]`` groups (nesting-aware) and the text outside them."""
    groups, outside, depth, start, last = [], [], 0, 0, 0
    for i, ch in enumerate(text):
        if ch == "[":
            if depth == 0:
                outside.append(text[last:i])
                start = i + 1
            depth += 1
        elif ch == "]" and depth:
            depth -= 1
            if depth == 0:
                groups.append(text[start:i])
                last = i + 1
    outside.append(text[last:] if depth == 0 else text[start - 1:])
    return groups, "".join(outside)


def _split_context(text: str, context: dict) -> str:
    """Move ``[key:value ...]`` groups (nested ones too: ``[reason:... [a:1 b:2]]``) into ``context``;
    what is left is the event detail. Bracketed text that is not key:value stays in the detail."""
    groups, outside = _bracket_groups(text)
    kept = [outside]
    for group in groups:
        inner, flat = _bracket_groups(group)
        flat = flat.strip()
        if not re.match(r"[a-z_]+:", flat):
            kept.append(f"[{group}]")
            continue
        for g in inner:
            _split_context(f"[{g}]", context)
        free = re.match(rf"({'|'.join(_FREE_TEXT_KEYS)}):\s*(.*)$", flat, re.S)
        if free:
            context[free.group(1)] = free.group(2).strip()
        else:
            context.update(dict(_PAIR_RE.findall(flat)))
    return " ".join(" ".join(kept).split())


def proposal_view(chunk: dict) -> dict:
    """A PolicyChunk (proto-JSON) as the settings page shows it; the review token and the full
    candidate policies stay with the driver."""
    rule = chunk.get("proposed_rule") or {}
    endpoints = [{k: ep[k] for k in ("host", "port", "protocol", "access", "allowed_ips") if ep.get(k)}
                 for ep in rule.get("endpoints") or []]
    # The HTTP requests an L7 chunk allows (agent proposals carry them; drafts from blocked
    # connections are host:port only): the in-chat card names the first one.
    requests = [{"method": str(a.get("method") or "").upper() or "*", "path": a.get("path") or "/"}
                for ep in rule.get("endpoints") or [] for r in ep.get("rules") or []
                if isinstance(r, dict) and isinstance((a := r.get("allow")), dict)]
    out = {
        "id": chunk.get("id"), "status": chunk.get("status"), "rule_name": chunk.get("rule_name"),
        "binary": chunk.get("binary") or None, "endpoints": endpoints, "requests": requests or None,
        "binaries": [b.get("path") for b in rule.get("binaries") or []],
        "rationale": chunk.get("rationale") or "", "security_notes": chunk.get("security_notes") or "",
        "validation": chunk.get("validation_result") or "", "application_error": chunk.get("application_error") or "",
        "rejection_reason": chunk.get("rejection_reason") or "", "hit_count": int(chunk.get("hit_count") or 0),
        "stage": chunk.get("stage") or "", "first_seen": chunk.get("first_seen_time"),
        "last_seen": chunk.get("last_seen_time"), "created": chunk.get("created_time"),
        "decided": chunk.get("decided_time"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")} | {"id": out["id"], "status": out["status"]}


# -- the OCSF JSON archive (supervisor stderr -> host-only JSONL) -------------------------------------

_OCSF_JSON_MARK = "OCSF-JSON "


def ocsf_json_record(line: str) -> Optional[dict]:
    """One supervisor stderr line -> its full OCSF record (``<UTC time> OCSF-JSON {...}``), else None.
    The shorthand copy of each event (``OCSF NET:OPEN ...``) is skipped."""
    i = line.find(_OCSF_JSON_MARK)
    if i < 0:
        return None
    try:
        record = json.loads(line[i + len(_OCSF_JSON_MARK):].strip())
    except ValueError:
        return None
    return record if isinstance(record, dict) else None


def ocsf_event(record: dict) -> dict:
    """An archived OCSF JSON record in the shape ``events()`` returns for shorthand lines."""
    t = record.get("time")
    t = t / 1000.0 if isinstance(t, (int, float)) and t > 1e11 else t
    uid = record.get("class_uid")
    dst = record.get("dst_endpoint") or {}
    proc = (record.get("actor") or {}).get("process") or {}
    exe = (proc.get("file") or {}).get("path") if isinstance(proc.get("file"), dict) else proc.get("name")
    host = dst.get("domain") or dst.get("hostname") or dst.get("ip")
    context = {"dst": f"{host}:{dst.get('port')}" if host else None, "binary": exe,
               "reason": record.get("status_detail"), "policy": (record.get("firewall_rule") or {}).get("name")}
    return {"time": t, "source": "supervisor", "level": "OCSF", "ocsf": True, "archived": True,
            "class": _OCSF_CLASSES.get(uid, str(uid)), "class_uid": uid,
            "activity": str(record.get("activity_name") or "").upper().replace(" ", "_") or None,
            "severity": record.get("severity"), "action": str(record.get("action") or "").upper() or None,
            "detail": record.get("message") or "", "context": {k: v for k, v in context.items() if v},
            "uid": (record.get("metadata") or {}).get("uid")}


def refusal_row(record: dict) -> Optional[dict]:
    """The refused connection an OCSF record reports, as ``{"time", "host", "port"}`` (epoch seconds; the name the
    program asked for), or None: any other record, an allowed connection, a destination given only by address,
    and a Denied record that names no program and port (a refused name lookup; a tunnel OpenShell closed because
    the policy changed, which is no refusal of its host)."""
    if record.get("class_uid") not in (4001, 4002) or str(record.get("action") or "").upper() not in ("DENIED", "BLOCKED"):
        return None
    dst = record.get("dst_endpoint") if isinstance(record.get("dst_endpoint"), dict) else {}
    host, port, t = dst.get("domain") or dst.get("hostname"), dst.get("port"), record.get("time")
    if not isinstance(host, str) or not host or isinstance(port, bool) or not isinstance(port, int):
        return None
    actor = record.get("actor") if isinstance(record.get("actor"), dict) else {}
    process = actor.get("process") if isinstance(actor.get("process"), dict) else {}
    if not process.get("name"):
        return None
    if isinstance(t, bool) or not isinstance(t, (int, float)) or t <= 0:
        return None
    return {"time": t / 1000.0 if t > 1e11 else float(t), "host": host.lower(), "port": port}


# How long after a refused connection its record can still be on its way into the verdict file (what the hook of a
# program call that named a host waits before it returns the call as it came). Measured on this driver over 48
# refused connections: the record was in the verdict file 0.003 to 0.015 s after OpenShell's own time for the refusal
# (median 0.006 s). 0.1 s leaves room for a busy launcher and stays unnoticed on a call that reached its site.
REFUSALS_SETTLE = 0.1


class AuditArchive:
    """Follows one sandbox supervisor's stderr through the container CLI and appends its OCSF JSON
    records to host-only files, ``<dir>/ocsf-<sandbox>-<UTC date>.jsonl``. The files outlive the
    sandbox: OpenShell keeps the supervisor's own JSONL on a tmpfs that dies with it, and the
    gateway's log API is a short in-memory tail. ``docker logs`` replays from container start, so
    records written before the follower attached are kept too; ``metadata.uid`` dedupes a re-follow.
    The refused connections among the last records also stay in memory (``recent``): the stream delivers a
    record within milliseconds of the refusal, well before the gateway's log tail shows it."""

    LOCATE_TIMEOUT = 60.0
    RECENT = 256

    def __init__(self, directory: Path, sandbox: str, container_cli: str, *, run=subprocess.run,
                 popen=subprocess.Popen, note=None):
        self.dir, self.sandbox, self.cli = Path(directory), sandbox, container_cli
        self._run, self._popen, self._note = run, popen, note or (lambda m: log.info("%s", m))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._proc = None
        self._seen: set = set()
        self.container: Optional[str] = None
        self.written = 0
        self.error: Optional[str] = None
        self.recent: collections.deque = collections.deque(maxlen=self.RECENT)  # refusal_row of the last records

    def _locate(self) -> Optional[str]:
        done = self._run([self.cli, "ps", "-a", "-q", "--no-trunc", "--filter", f"label=openshell.ai/sandbox-name={self.sandbox}",
                          "--filter", "label=openshell.ai/isolation-role=supervisor"],
                         capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        ids = (done.stdout or "").split() if done.returncode == 0 else []
        return ids[0] if ids else None

    def start(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Thread(target=self._follow, name=f"ocsf-archive-{self.sandbox}", daemon=True)
        self._thread.start()

    def _follow(self) -> None:
        deadline = time.monotonic() + self.LOCATE_TIMEOUT
        while not self._stop.is_set() and self.container is None:
            try:
                self.container = self._locate()
            except Exception as exc:  # no CLI, no daemon access: report, don't break the sandbox
                self.error = f"cannot list containers with {self.cli}: {exc}"
                return
            if self.container is None:
                if time.monotonic() > deadline:
                    self.error = f"no supervisor container labelled for sandbox {self.sandbox}"
                    return
                self._stop.wait(1.0)
        while not self._stop.is_set():
            self._proc = self._popen([self.cli, "logs", "--follow", self.container], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, errors="replace")
            for line in self._proc.stdout:
                record = ocsf_json_record(line)
                if record is not None:
                    self._write(record)
            self._proc.wait()
            # The stream ends when the container goes (sandbox deleted); anything else is a hiccup.
            try:
                still_there = self._locate() == self.container
            except Exception:
                still_there = False
            if self._stop.is_set() or not still_there:
                return
            self._stop.wait(1.0)

    def _write(self, record: dict) -> None:
        uid = (record.get("metadata") or {}).get("uid")
        if uid:
            if uid in self._seen:
                return
            self._seen.add(uid)
        t = record.get("time")
        secs = t / 1000.0 if isinstance(t, (int, float)) and t > 1e11 else (t if isinstance(t, (int, float)) else time.time())
        path = self.dir / f"ocsf-{self.sandbox}-{time.strftime('%Y-%m-%d', time.gmtime(secs))}.jsonl"
        fresh = not path.exists()
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        if fresh:
            try:
                path.chmod(0o600)
            except OSError:
                pass
        self.written += 1
        row = refusal_row(record)
        if row is not None:
            self.recent.append(row)

    def stop(self, timeout: float = 15.0) -> None:
        """Wait for the stream to drain (it ends once the sandbox is deleted), then stop following."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
        self._stop.set()
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
        if thread is not None:
            thread.join(5)

    def status(self) -> dict:
        return {"dir": str(self.dir), "container": self.container, "records_written": self.written,
                "files": [str(p) for p in archive_files(self.dir, self.sandbox)], "error": self.error}


def archive_files(directory: Path, sandbox: str) -> list[Path]:
    return sorted(Path(directory).glob(f"ocsf-{sandbox}-*.jsonl"))


def read_archive(directory: Path, sandbox: str, *, since: float | None = None, until: float | None = None,
                 limit: int = 200, classes: tuple = ()) -> list[dict]:
    out = []
    for path in archive_files(directory, sandbox):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    event = ocsf_event(json.loads(line))
                except (ValueError, AttributeError):
                    continue
                t = event.get("time") or 0
                if (since is not None and t < since) or (until is not None and t > until):
                    continue
                if classes and event.get("class") not in classes:
                    continue
                out.append(event)
    out.sort(key=lambda e: e.get("time") or 0)
    return out[-limit:]


# -- the gateway API (SDK + the SDK's generated stub), plain dicts in and out -----------------------

class GatewayApi:
    """Everything the driver asks the gateway, over one mTLS channel. Tests substitute a fake."""

    def __init__(self, cfg: OpenShellConfig):
        if cfg.sdk_path is not None and str(cfg.sdk_path) not in sys.path and Path(cfg.sdk_path).is_dir():
            # The managed SDK (openshell_install): appended, so the Hermes environment's packages win.
            sys.path.append(str(cfg.sdk_path))
        try:
            import grpc
            from google.protobuf import json_format, struct_pb2, timestamp_pb2
            from openshell import SandboxClient, TlsConfig
            from openshell._proto import datamodel_pb2, openshell_pb2, sandbox_pb2
        except ImportError as exc:
            raise DriverUnavailable(f"the OpenShell Python SDK is not installed ({exc}); `pip install openshell`") from exc
        self.grpc, self.json_format, self.struct_pb2, self.timestamp_pb2 = grpc, json_format, struct_pb2, timestamp_pb2
        self.pb, self.spb, self.dpb = openshell_pb2, sandbox_pb2, datamodel_pb2
        self.cfg = cfg
        endpoint, tls = gateway_endpoint(cfg)
        self.endpoint = endpoint
        self.client = SandboxClient(endpoint, tls=TlsConfig(**tls), timeout=30.0, cluster_name=cfg.gateway)
        # SDK 0.1.2 exposes sandbox lifecycle only; providers, policy, drafts, settings and logs go
        # through the SDK's own generated stub (error-mapped, same channel and mTLS identity).
        self.stub = self.client._stub

    def close(self) -> None:
        self.client.close()

    def _scope(self):
        return self.dpb.WorkspaceSelector(workspace=self.cfg.workspace)

    def _dict(self, message) -> dict:
        return self.json_format.MessageToDict(message, preserving_proto_field_name=True)

    def _code(self, exc) -> Optional[str]:
        code = getattr(exc, "code", lambda: None)()
        return getattr(code, "name", None)

    def health(self) -> str:
        return self.client.health().version

    def create_sandbox(self, name: str, spec: dict, labels: dict) -> None:
        message = self.json_format.ParseDict(spec, self.pb.SandboxSpec())
        self.client.create(workspace=self.cfg.workspace, spec=message, name=name, labels=labels)

    def wait_ready(self, name: str, timeout: float) -> None:
        self.client.wait_ready(name, workspace=self.cfg.workspace, timeout_seconds=timeout)

    def sandbox_state(self, name: str) -> Optional[dict]:
        try:
            ref = self.client.get(name, workspace=self.cfg.workspace)
        except self.grpc.RpcError as exc:
            if self._code(exc) == "NOT_FOUND":
                return None
            raise
        phase = self.pb.SandboxPhase.Name(ref.status.phase).replace("SANDBOX_PHASE_", "")
        return {"phase": phase, "exit_code": ref.status.exit_code, "policy_version": ref.status.current_policy_version}

    def delete_sandbox(self, name: str, timeout: float) -> None:
        result = self.client.delete(name, workspace=self.cfg.workspace, allow_missing=True)
        if getattr(result.outcome, "name", "") != "ALREADY_ABSENT":
            self.client.wait_deleted(name, workspace=self.cfg.workspace, timeout_seconds=timeout,
                                     expected_sandbox_id=result.sandbox_id)

    def upsert_provider(self, name: str, profile_id: str, credentials: dict) -> str:
        provider = self.dpb.Provider(metadata=self.dpb.ObjectMeta(name=name), type=profile_id,
                                     credentials=credentials, profile_workspace=self.cfg.workspace)
        try:
            self.stub.CreateProvider(self.pb.CreateProviderRequest(workspace_scope=self._scope(), provider=provider))
            return "created"
        except self.grpc.RpcError as exc:
            if self._code(exc) != "ALREADY_EXISTS":
                raise
        self.stub.UpdateProvider(self.pb.UpdateProviderRequest(workspace_scope=self._scope(), provider=provider))
        return "updated"

    def update_provider(self, name: str, credentials: dict, expires: Optional[dict] = None, clear=()) -> None:
        """A value-only update of provider *name* (its profile carries the same name): the given values, the
        expiry of each (*expires*: variable -> epoch seconds), and the expiries to take off (*clear*)."""
        provider = self.dpb.Provider(metadata=self.dpb.ObjectMeta(name=name), type=name,
                                     credentials=credentials, profile_workspace=self.cfg.workspace)
        request = self.pb.UpdateProviderRequest(workspace_scope=self._scope(), provider=provider)
        for env, when in (expires or {}).items():
            request.credential_expiration_times[env].FromNanoseconds(int(float(when) * 1e9))
        request.clear_credential_expiration_keys.extend(clear)
        self.stub.UpdateProvider(request)

    def delete_provider(self, name: str) -> None:
        """Delete provider *name* and the profile of the same name; neither has to exist."""
        self.stub.DeleteProvider(self.pb.DeleteProviderRequest(workspace_scope=self._scope(), name=name,
                                                               allow_missing=True))
        self.stub.DeleteProviderProfile(self.pb.DeleteProviderProfileRequest(workspace_scope=self._scope(), id=name,
                                                                             allow_missing=True))

    def supports_stable_placeholder(self) -> bool:
        """Whether this gateway keeps a credential's placeholder across value updates. A gateway that does not
        know the question does not."""
        try:
            answer = self.stub.LintProviderProfiles(self.pb.LintProviderProfilesRequest(workspace_scope=self._scope()))
        except self.grpc.RpcError as exc:
            if self._code(exc) == "UNIMPLEMENTED":
                return False
            raise
        return bool(getattr(answer, "supports_stable_placeholder", False))

    def provider_state(self, sandbox: str, provider: str) -> tuple[Optional[str], Optional[str]]:
        """(state, reason) of what sandbox *sandbox* did with provider *provider*, as the gateway knows it:
        ``READY``, ``PENDING``, ``WITHHELD`` ... and the reason category."""
        status = self.stub.GetSandboxProviderStatus(self.pb.GetSandboxProviderStatusRequest(
            workspace_scope=self._scope(), sandbox=sandbox, provider=provider)).status
        return (self.pb.ProviderReadinessState.Name(status.state).replace("PROVIDER_READINESS_STATE_", ""),
                self.pb.ProviderReadinessReason.Name(status.reason).replace("PROVIDER_READINESS_REASON_", ""))

    def set_setting(self, name: str, key: str, value) -> None:
        setting = self.spb.SettingValue(bool_value=value) if isinstance(value, bool) else self.spb.SettingValue(string_value=str(value))
        self.stub.UpdateConfig(self.pb.UpdateConfigRequest(workspace_scope=self._scope(), sandbox=name, setting_key=key,
                                                           setting_value=setting))

    def policy_status(self, name: str, version: int = 0) -> dict:
        resp = self.stub.GetSandboxPolicyStatus(self.pb.GetSandboxPolicyStatusRequest(
            workspace_scope=self._scope(), sandbox=name, version=version))
        rev = self._revision(resp.revision)
        rev["policy"] = self._dict(resp.revision.policy) if resp.revision.HasField("policy") else None
        return {**rev, "active_version": resp.active_version}

    def _revision(self, rev) -> dict:
        d = self._dict(rev)
        d.pop("policy", None)
        d["status"] = str(d.get("status", "")).replace("POLICY_STATUS_", "").lower()
        return d

    def list_policies(self, name: str) -> list[dict]:
        out, token = [], ""
        while True:
            resp = self.stub.ListSandboxPolicies(self.pb.ListSandboxPoliciesRequest(
                workspace_scope=self._scope(), sandbox=name, page_size=100, page_token=token))
            out += [self._revision(r) for r in resp.revisions]
            token = resp.next_page_token
            if not token:
                return out

    def update_policy(self, name: str, policy: dict, annotations: dict) -> dict:
        message = self.json_format.ParseDict(policy, self.spb.SandboxPolicy())
        resp = self.stub.UpdateConfig(self.pb.UpdateConfigRequest(workspace_scope=self._scope(), sandbox=name,
                                                                  policy=message, annotations=annotations))
        return {"version": resp.version, "policy_hash": resp.policy_hash}

    def drafts(self, name: str, status: str = "") -> list[dict]:
        resp = self.stub.GetDraftPolicy(self.pb.GetDraftPolicyRequest(workspace_scope=self._scope(), sandbox=name,
                                                                      status_filter=status))
        return [self._dict(c) for c in resp.chunks]

    def approve_draft(self, name: str, chunk_id: str, review_token: str) -> dict:
        try:
            resp = self.stub.ApproveDraftChunk(self.pb.ApproveDraftChunkRequest(
                workspace_scope=self._scope(), sandbox=name, chunk_id=chunk_id, review_token=review_token))
        except self.grpc.RpcError as exc:
            if self._code(exc) in ("FAILED_PRECONDITION", "ABORTED"):
                raise ProposalChanged(exc.details() or "the request changed since it was listed") from exc
            raise
        return {"policy_version": resp.policy_version, "policy_hash": resp.policy_hash}

    def reject_draft(self, name: str, chunk_id: str, reason: str) -> None:
        self.stub.RejectDraftChunk(self.pb.RejectDraftChunkRequest(workspace_scope=self._scope(), sandbox=name,
                                                                   chunk_id=chunk_id, reason=reason))

    def logs(self, name: str, *, since: Optional[float], lines: int, sources=("sandbox",)) -> list[dict]:
        req = self.pb.GetSandboxLogsRequest(workspace_scope=self._scope(), sandbox=name, lines=lines,
                                            sources=list(sources))
        if since:
            req.since_time.FromNanoseconds(int(since * 1e9))
        resp = self.stub.GetSandboxLogs(req)
        return [{"time": line.event_time.ToNanoseconds() / 1e9 if line.HasField("event_time") else None,
                 "level": line.level.strip(), "target": line.target, "message": line.message, "source": line.source,
                 "fields": dict(line.fields)} for line in resp.logs]


def gateway_endpoint(cfg: OpenShellConfig) -> tuple[str, dict]:
    """The registered gateway's host:port and mTLS files. Refuses anything but https with client
    certificates."""
    meta_path = cfg.gateway_dir / "metadata.json"
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DriverUnavailable(f"gateway '{cfg.gateway}' is not registered under {cfg.config_home} ({exc})") from exc
    parts = urllib.parse.urlsplit(str(meta.get("gateway_endpoint") or ""))
    mtls = cfg.gateway_dir / "mtls"
    files = {"ca_path": mtls / "ca.crt", "cert_path": mtls / "tls.crt", "key_path": mtls / "tls.key"}
    if parts.scheme != "https" or meta.get("auth_mode") != "mtls" or not all(p.is_file() for p in files.values()):
        raise DriverUnavailable(f"gateway '{cfg.gateway}' must use mTLS (https endpoint, auth_mode mtls, client "
                                f"certificate in {mtls}); found {parts.scheme or '?'} / {meta.get('auth_mode')!r}")
    return f"{parts.hostname}:{parts.port or 443}", files


# -- the driver ----------------------------------------------------------------------------------------

class OpenShellDriver(CredentialSinkMixin, SandboxDriver):
    name = "openshell"
    uses_host_shell = False
    asks_gateway = True  # ``exit_code`` is a call to the gateway
    capabilities_info = {"label": "OpenShell sandbox", "requests_supported": True, "credentials": "placeholders",
                         "host_loopback": "closed", "network_rules": ["host", "cidr"], "network_live": True,
                         "egress_allow_all": False, "policy_revisions": True, "audit_events": True,
                         "model_endpoints": "provider",
                         # On v0.1.5 a policy change closes open proxied connections, including a model reply
                         # being streamed; Hermes retries it, so the turn finishes but the partial generation is lost.
                         # Apply network changes when the turn ends; say so before applying mid-turn.
                         "network_live_interrupts": True}

    def __init__(self, cfg: OpenShellConfig, *, api=None, run=subprocess.run, popen=subprocess.Popen):
        self.cfg = cfg
        self._api = api
        self._run, self._popen = run, popen
        self._name: Optional[str] = None
        self._request: Optional[LaunchRequest] = None
        self._forward: Optional[subprocess.Popen] = None
        self._forward_started = 0.0
        self._log = None
        self._plan: Optional[MountPlan] = None
        self._launch_policy: dict = {}
        self._providers: list[dict] = []
        self._provider_notes: list[str] = []
        self._withheld: list[str] = []
        self._changed: list[dict] = []
        self._sink_state()
        self._model_overrides: dict = {}  # managed-scope model URL for a host-loopback model server
        self._final_code: Optional[int] = -1
        self._cached: Optional[int] = None
        self._checked = 0.0
        self._starting = False  # ``start`` is under way (see ``exit_code``)
        self._runtime: Optional[HostRuntime] = None
        self._binaries: tuple = tuple(cfg.binaries)
        self._audit: Optional[AuditArchive] = None
        self._audit_dir: Optional[Path] = None  # kept after stop: the archive is read from here
        self._gone = True  # False after a stop whose delete failed: the sandbox may still run
        self._gateway = GatewayWatch(cfg)  # whether the gateway is still there (gateway_watch.py)
        self._own_api = api is None  # the driver makes its connection to the gateway itself

    @classmethod
    def from_spec(cls, spec: dict) -> "OpenShellDriver":
        if os.name == "nt":  # Windows: the gateway's MXC driver, through the CLI (openshell_windows.py)
            from .openshell_windows import OpenShellWindowsDriver

            return OpenShellWindowsDriver.from_spec(spec)
        return cls(config_from_spec(spec))

    # -- plumbing ------------------------------------------------------------------------------
    @property
    def api(self):
        if self._api is None:
            self._api = GatewayApi(self.cfg)
        return self._api

    def _cli_env(self) -> dict:
        from .gateway_service import TELEMETRY_OFF

        return {**os.environ, "XDG_CONFIG_HOME": str(self.cfg.config_home), "OPENSHELL_GATEWAY": self.cfg.gateway,
                "OPENSHELL_WORKSPACE": self.cfg.workspace, "NO_COLOR": "1", **TELEMETRY_OFF}

    def _cli(self, *args: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
        return self._run([str(self.cfg.cli), *args], env=self._cli_env(), capture_output=True, text=True,
                         timeout=timeout, stdin=subprocess.DEVNULL)

    def _note(self, message: str) -> None:
        log.info("%s", message)
        if self._log is not None:
            self._log.write(f"[openshell-driver {time.strftime('%H:%M:%S')}] {message}\n".encode())
            self._log.flush()

    def _require(self) -> str:
        if self._name is None or self._request is None:
            raise NotSupported("the sandbox is not running")
        return self._name

    # -- lifecycle -----------------------------------------------------------------------------
    def _ensure_managed(self) -> Optional[dict]:
        """The plugin-managed gateway, installed, running and healthy (no-op for a named gateway)."""
        before = (self.cfg.gateway, str(self.cfg.config_home))
        info = ensure_managed(self.cfg)
        if info is not None and before != (self.cfg.gateway, str(self.cfg.config_home)) and self._api is not None:
            self._api.close()
            self._api = None
        return info

    def preflight(self) -> dict:
        if os.name == "nt":
            raise DriverUnavailable("the OpenShell gateway driver runs Linux sandboxes; on Windows the launcher "
                                    "uses OpenShellWindowsDriver (OpenShell's MXC driver).")
        managed = self._ensure_managed()
        probe = self._cli("--version", timeout=30)
        if probe.returncode != 0:
            raise DriverUnavailable(f"{self.cfg.cli} --version failed: {(probe.stderr or probe.stdout).strip()[-300:]}")
        _require_version("the openshell CLI", probe.stdout)
        endpoint, _ = gateway_endpoint(self.cfg)
        try:
            version = self.api.health()
        except DriverUnavailable:
            raise
        except Exception as exc:
            raise DriverUnavailable(f"gateway '{self.cfg.gateway}' at {endpoint} did not answer: {exc}") from exc
        _require_version(f"gateway '{self.cfg.gateway}'", version)
        out = {"driver": self.name, "cli": probe.stdout.strip(), "gateway": self.cfg.gateway, "endpoint": endpoint,
               "gateway_version": version, "image": self.cfg.image, "audit_archive": bool(self.cfg.container_cli)}
        if managed is not None:
            out["managed_gateway"] = {k: str(v) if isinstance(v, Path) else v for k, v in managed.items()}
        return out

    def drop_leftover(self, profile: str) -> bool:
        name = sandbox_name(profile)
        if self.api.sandbox_state(name) is None:
            return False
        self._note(f"deleting leftover sandbox {name} before the profile's folder is reviewed")
        self.api.delete_sandbox(name, timeout=120)
        return True

    def start(self, request: LaunchRequest) -> None:
        if self._name is not None and self.exit_code() is None:
            raise RuntimeError("sandbox already running")
        self._starting = True
        self._fresh_connection()
        self._gateway.reset()  # the start brings the gateway back, or fails
        try:
            self._start(request)
        finally:
            self._starting = False

    def _fresh_connection(self) -> None:
        """Before a start that follows a gateway that did not answer: the connection to it is dropped. A
        connection that was refused waits before it tries again and answers "refused" meanwhile, also once the
        gateway this start brings back is listening; the next call makes a new one."""
        if self._gateway.silent and self._own_api and self._api is not None:
            try:
                self._api.close()
            except Exception:
                log.debug("the connection to the gateway could not be closed", exc_info=True)
            self._api = None

    def _start(self, request: LaunchRequest) -> None:
        if request.home is None or not request.inner_port or not request.inner_token:
            raise RuntimeError("the OpenShell driver needs the profile home, inner port and inner token")
        runtime = host_runtime(request)  # refuses before anything is created
        self._ensure_managed()  # the shared gateway is healthy before a sandbox is created on it
        self._request, self._final_code, self._cached, self._checked = request, None, None, 0.0
        self._log = open(request.log_path, "ab")
        name = sandbox_name(request.profile or request.sandbox_id)
        # A sandbox under this name is a leftover from a launcher that died: replace it.
        if self.api.sandbox_state(name) is not None:
            self._note(f"deleting leftover sandbox {name}")
            self.api.delete_sandbox(name, timeout=120)
        self._name, self._runtime = name, runtime
        # Website rules and model keys are usable by Hermes's interpreter (and, through OpenShell's
        # ancestor match, by what it starts); the executable is the resolved store Python.
        self._binaries = tuple(self.cfg.binaries) or (str(runtime.real_python),)
        self._model_overrides = loopback_model_override(request)
        self._network_settings = sandbox_network_settings(request)
        self._hold(request)
        self._plan = plan_mounts(request, ensure_masks(Path(request.config_dir)), runtime)
        providers = self._register_providers(request)
        network = request.network
        if network.get("egress") == "allow":
            raise DriverUnavailable("OpenShell has no rule for all internet access; list the websites instead.")
        self._launch_policy = build_policy(self.cfg, self._plan, network, self._binaries)
        self._launch_policy["network_policies"] = self._with_builtin(self._launch_policy["network_policies"])
        writable = [*self._plan.read_write, "/sandbox", "/tmp"]
        env = {
            "HERMES_HOME": str(request.home),
            "HERMES_DASHBOARD_SESSION_TOKEN": request.inner_token,  # inner token: the sandbox holds it by design
            "HERMES_DISABLE_LAZY_INSTALLS": "1", "HERMES_WRITE_SAFE_ROOT": os.pathsep.join(writable),
            "HOME": "/sandbox", "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8",
            # The host runtime, read-only: the source tree first on sys.path (as installed launchers
            # do), no bytecode writes, the venv's scripts first on PATH.
            "PYTHONPATH": str(runtime.code_dir), "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": os.pathsep.join([str(runtime.python.parent), "/usr/local/bin", "/usr/bin", "/bin"]),
        }
        if runtime.store is not None:
            env["HERMES_RUNTIME_DIR"] = str(runtime.store)
        # What the supervisor hands the backend inside: the card hook's request and verdict folders and its wait
        # (sandbox_hook registers only when both folders are named: without them no card resolves in its turn and
        # a web tool's refusal raises no card at all), and the managed scope (hook timeout, model URL).
        for key in ("HERMES_SANDBOX_VERDICTS", "HERMES_SANDBOX_REQUESTS", "HERMES_SANDBOX_CARD_WAIT",
                    "HERMES_MANAGED_DIR", "HERMES_SHARED_AUTH_DIR", STANDIN_ENV):
            if (request.env or {}).get(key):
                env[key] = str(request.env[key])
        if self.cfg.ocsf_json and self.cfg.container_cli and env.get("HERMES_SANDBOX_VERDICTS"):
            # This driver follows the supervisor's record stream (the archive started below), so the launcher
            # hears of a refusal as it happens and copies it into the verdict file (``recent_refusals``): the hook
            # looks there when a program call that named a host did not fail (sandbox_hook.py, ``REFUSALS_ENV``),
            # for as long as a record can trail the refusal here.
            env["HERMES_SANDBOX_REFUSALS"] = str(REFUSALS_SETTLE)
        rw_folders = [f["path"] for f in request.folders if f.get("access") == "rw"]
        if rw_folders:
            env["TERMINAL_CWD"] = str(rw_folders[0])
        spec = {
            "environment": env,
            "template": {"image": self.cfg.image, "driver_config": {"docker": {"mounts": self._plan.mounts}}},
            "policy": self._launch_policy,
            "providers": [p["name"] for p in providers],
            # The start-up step first when the profile has a sign-in (``request.step``): it writes the stand-in
            # sign-in store and then becomes this command.
            "command": [*[str(part) for part in request.step],
                        str(runtime.python), "-m", "hermes_cli.main", "serve", "--isolated", "--host", "127.0.0.1",
                        "--port", str(self.cfg.serve_port), "--skip-build"],
        }
        self._note(f"creating sandbox {name} from {self.cfg.image} with {len(self._plan.mounts)} mounts "
                   f"(runtime {self._plan.runtime}), providers {[p['name'] for p in providers]}, "
                   f"keys withheld {self._withheld}"
                   + (f", endpoints changed inside (keys withheld) {self._changed}" if self._changed else ""))
        self.api.create_sandbox(name, spec, labels={"hermes.profile": request.profile or "default"})
        self.api.wait_ready(name, timeout=300)
        self._check_readiness()
        if self.cfg.ocsf_json:
            if self.cfg.container_cli:
                self._audit = AuditArchive(Path(request.config_dir) / "audit", name, self.cfg.container_cli,
                                           note=self._note)
                self._audit.start()
            try:
                self.api.set_setting(name, "ocsf_json_enabled", True)
            except Exception as exc:  # audit export is best-effort; the shorthand stream remains
                self._note(f"could not enable OCSF JSON export: {exc}")
        self._start_forward()

    # -- the gateway calls of CredentialSinkMixin -------------------------------------------------
    def _gw_stable_supported(self) -> bool:
        return self.api.supports_stable_placeholder()

    def _gw_profile(self, profile: dict, index: int) -> str:
        pid = profile["id"]
        path = Path(self._request.config_dir) / f"provider-profile-{index}.json"
        path.write_text(json.dumps(profile, indent=1), encoding="utf-8")
        done, action = self._cli("profile", "import", "-f", str(path)), "imported"
        if done.returncode != 0:  # already registered (a restart, a relaunch): replace it in place,
            # under the gateway's optimistic lock (update needs the current resource_version).
            current = self._cli("profile", "export", pid, "-o", "json")
            try:
                version = int(json.loads(current.stdout or "{}").get("resource_version") or 0)
            except (ValueError, AttributeError):
                version = 0
            if current.returncode == 0 and version:
                path.write_text(json.dumps({**profile, "resource_version": version}, indent=1), encoding="utf-8")
                done, action = self._cli("profile", "update", "-f", str(path), pid), "updated"
        if done.returncode != 0:
            raise RuntimeError(f"provider profile {pid}: {(done.stderr or done.stdout).strip()[-400:]}")
        return action

    def _gw_provider(self, name: str, values: dict, expires: dict) -> str:
        action = self.api.upsert_provider(name, name, values)
        if expires:  # a provider is created without expiries; they are merged in by an update
            self.api.update_provider(name, values, expires)
        return action

    def _gw_update(self, name: str, values: dict, expires: dict, clear: list) -> None:
        self.api.update_provider(name, values, expires, clear)

    def _gw_forget(self, name: str) -> None:
        self.api.delete_provider(name)

    def _gw_provider_state(self, sandbox: str, provider: str) -> tuple:
        return self.api.provider_state(sandbox, provider)

    def _start_forward(self) -> None:
        req = self._request
        cmd = [str(self.cfg.cli), "forward", "service", "--target-port", str(self.cfg.serve_port),
               "--local", f"127.0.0.1:{req.inner_port}", self._name]
        self._forward = self._popen(cmd, env=self._cli_env(), stdout=self._log or subprocess.DEVNULL,
                                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        self._forward_started = time.monotonic()

    def _keep_forward(self) -> None:
        if self._forward is not None and self._forward.poll() is not None \
                and time.monotonic() - self._forward_started >= _FORWARD_RETRY:
            self._note(f"forward exited with {self._forward.returncode}; restarting it")
            self._start_forward()

    def exit_code(self) -> Optional[int]:
        if self._starting:
            # The supervisor's watch asks from the event loop while ``start`` runs on a worker thread. Until the
            # sandbox exists on the gateway its name is unknown there (a restart has just deleted the old one),
            # and that answer, kept for ``_STATE_CHECK_INTERVAL``, would be what the supervisor reads right after
            # ``start`` returns: "exited with 1" for a sandbox that has just come up.
            return None
        if self._name is None or self._request is None:
            return self._final_code
        now = time.monotonic()
        if now - self._checked < _STATE_CHECK_INTERVAL or self._gateway.asking:
            return self._cached
        self._checked = now
        try:
            with self._gateway.ask():
                state = self.api.sandbox_state(self._name)
        except Exception:
            # A gateway hiccup is not an exit, and neither is a gateway that is gone (``gateway_lost``). The
            # wait for the next look counts from the end of this one.
            self._checked = time.monotonic()
            return self._cached
        if state is None:
            code = 1
        elif state["phase"] in _LIVE_PHASES:
            code = None
            self._keep_forward()
        elif state["phase"] == "ERROR":
            code = 1
        else:
            code = state.get("exit_code")
            code = 1 if code is None else int(code)
        self._cached = code
        return code

    def stop(self, timeout: float = 20.0) -> None:
        forward, self._forward = self._forward, None
        try:
            if forward is not None and forward.poll() is None:
                forward.terminate()
                try:
                    forward.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    forward.kill()
            self._gone = True
            if self._name is not None and self._gateway_away():
                # Its containers outlive the gateway: they are ended here. When that cannot be done or checked
                # the sandbox may still run, and nothing it must not read goes back under its name.
                self._gone = self._remove_containers()
            elif self._name is not None:
                try:
                    self.api.delete_sandbox(self._name, timeout=max(timeout, 60.0))
                except Exception as exc:
                    # It may still run: nothing it must not read goes back under its name. Unless the gateway
                    # is not there at all: then its containers are ended here, as above.
                    self._gone = self._gateway.down() is not None and self._remove_containers()
                    self._note(f"delete {self._name} failed: {exc}")
            if self._audit is not None:
                # The supervisor's stderr stream ends with its container: drain it into the archive.
                self._audit.stop(timeout=15.0)
                self._audit_dir = self._audit.dir
                self._note(f"OCSF archive: {self._audit.written} records in {self._audit.dir}"
                           + (f" ({self._audit.error})" if self._audit.error else ""))
            self._quarantine()
            self._release()
        finally:
            self._final_code = self._cached if self._cached is not None else 0
            self._request = None
            if self._log is not None:
                self._log.close()
                self._log = None

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
        address. The gateway is then not asked to delete the sandbox (the call would only wait); the record it
        keeps is deleted by the next start, before a sandbox is created."""
        if not self._gateway.silent or self._gateway.down() is None:
            return False
        self._note(f"the gateway is not listening: it was not asked to delete sandbox {self._name}")
        return True

    def _remove_containers(self) -> bool:
        """Without the gateway: end this sandbox's containers through the container program, the ones the
        gateway labelled with the sandbox's name and its own (no other gateway's, no other sandbox's). True
        when none is left; False when there is no container program or it cannot say."""
        cli = self.cfg.container_cli
        if not cli:
            return False
        listing = [cli, "ps", "-a", "-q", "--no-trunc", "--filter", f"label=openshell.ai/sandbox-name={self._name}",
                   "--filter", f"label=openshell.ai/sandbox-namespace={self.cfg.gateway}"]
        try:
            for attempt in (1, 2):
                done = self._run(listing, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
                if done.returncode != 0:
                    return False
                ids = (done.stdout or "").split()
                if not ids:
                    return True
                if attempt == 1:
                    self._note(f"removing {len(ids)} container(s) of sandbox {self._name} left without their gateway")
                    self._run([cli, "rm", "-f", *ids], capture_output=True, text=True, timeout=60,
                              stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError) as exc:
            self._note(f"the containers of sandbox {self._name} could not be removed: {exc}")
        return False

    def _take_out(self, path: Path) -> Path:
        target = held.quarantine(Path(self._request.config_dir), path)
        self._note(f"quarantined {path} (it stood where a held credential file's link belongs) -> {target}")
        return target

    def _hold(self, request: LaunchRequest) -> None:
        """Before the mounts are planned, with no sandbox running: the credential files at the top of the home go
        into the held folder (``held.py``), which is mounted over as a whole. A file hidden by a mount on its
        own name would be readable inside as soon as a process on this computer replaced it by rename."""
        if os.name == "nt":  # this driver runs Linux sandboxes (preflight refuses here); a link needs a privilege
            return
        home = Path(request.home)
        names = [Path(p).name for p in request.grants.denied if Path(p).parent == home]
        try:
            # A sign-in file the sandbox writes a stand-in for is neither moved nor linked: its name stays free.
            linked = held.hold(home, names, self._take_out, leave=request.standin)
        except OSError as exc:
            raise DriverUnavailable(f"the profile's credential files could not be moved out of the sandbox's "
                                    f"reach ({exc})") from exc
        self._note(f"credential files kept in {held.folder(home)} while the sandbox runs: {linked}")

    def sandbox_gone(self) -> bool:
        return self._gone

    def _release(self) -> None:
        """The sandbox is gone: the held files go back under their names. Never raises (the stop goes on). A
        sandbox whose delete failed may still run: the files stay where they are (the next start, which deletes
        a leftover sandbox first, or the next switch-off puts them back)."""
        if self._request is None or self._request.home is None:
            return
        if not self._gone:
            self._note("the sandbox may still run: the held credential files stay in their folder")
            return
        try:
            done = held.release(Path(self._request.home), self._take_out)
        except OSError as exc:
            log.warning("could not put the held credential files back: %s", exc)
            self._note(f"could not put the held credential files back: {exc}")
            return
        if done["restored"] or done["taken_out"]:
            self._note(f"held credential files put back: {done['restored']}; replaced meanwhile and quarantined: "
                       f"{done['taken_out']}")

    def guard(self) -> list:
        """While the sandbox runs: every held name is still the launcher's link; what stands there instead is
        quarantined and the link put back. Returns the names repaired (``Supervisor.watch`` calls this)."""
        if self._request is None or self._request.home is None or self._plan is None or not self._plan.held:
            return []
        return held.guard(Path(self._request.home), self._take_out)

    def _quarantine(self) -> None:
        """Move credential stores the sandbox created (absent and unmasked at start) out of the
        profile, so the host never trusts a file the sandbox wrote."""
        if self._plan is None or self._request is None:
            return
        found = [Path(p) for p in self._plan.unmasked_absent if os.path.lexists(p)]
        if not found:
            return
        dest = Path(self._request.config_dir) / "quarantine" / time.strftime("%Y%m%d-%H%M%S")
        for path in found:
            try:
                rel = path.relative_to(self._request.home) if self._request.home else Path(path.name)
            except ValueError:
                rel = Path(path.name)
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), str(target))
            log.warning("quarantined %s created inside the sandbox -> %s", path, target)
            self._note(f"quarantined credential store created inside the sandbox: {path} -> {target}")

    def endpoint_changed(self) -> list[dict]:
        return [dict(c) for c in self._changed]

    def policy(self) -> dict:
        view = {"sandbox": self._name, "gateway": self.cfg.gateway, "image": self.cfg.image,
                "workspace": self.cfg.workspace, "providers": self._providers, "keys_withheld": self._withheld,
                "endpoint_changed": self._changed, "provider_notes": self._provider_notes,
                "model_overrides": self._model_overrides,
                "managed_gateway": self.cfg.managed_root is not None,
                "mounts": self._plan.mounts if self._plan else [],
                "runtime": self._plan.runtime if self._plan else [],
                "binaries": list(self._binaries),
                "credential_masks": self._plan.masked if self._plan else [],
                "credential_held": self._plan.held if self._plan else [],
                "credential_watch": self._plan.unmasked_absent if self._plan else [],
                "launch_policy": self._launch_policy}
        if self._audit is not None:
            view["audit_archive"] = self._audit.status()
        if self._name is not None and self._request is not None:
            try:
                view["active"] = self.api.policy_status(self._name)
            except Exception as exc:
                view["active_error"] = str(exc)
        return view

    # -- live network, requests, revisions, audit --------------------------------------------------
    def _with_builtin(self, rules: dict) -> dict:
        """*rules* with the launcher's built-in destination as the profile's config says right now
        (usage_data.py): decided at every start, network update and restored revision."""
        home = self._request.home if self._request is not None else None
        out = usage_data.rules(rules, home, self._binaries)
        self.usage_data_open = usage_data.RULE_NAME in out
        return out

    def _base_policy(self) -> dict:
        policy = self.api.policy_status(self._require()).get("policy")
        if not policy:
            raise RuntimeError("the gateway returned no policy for the sandbox")
        return policy

    def _wait_loaded(self, version: int, timeout: float = LOAD_TIMEOUT) -> dict:
        deadline = time.monotonic() + timeout
        status = {}
        while time.monotonic() < deadline:
            status = self.api.policy_status(self._name, version)
            if status.get("status") in ("loaded", "failed", "superseded"):
                return status
            time.sleep(0.5)
        return {**status, "status": status.get("status") or "pending", "timed_out": True}

    def loaded(self, version: int) -> Optional[bool]:
        """Whether revision *version* (or a later one) is the one the sandbox enforces: True loaded, False
        failed, None not yet."""
        status = self.api.policy_status(self._require(), int(version))
        if status.get("status") == "loaded":
            return True
        if status.get("status") == "failed":
            return False
        if status.get("status") == "superseded" and int(status.get("active_version") or 0) >= int(version):
            return True
        return None

    def _update(self, policy: dict, annotations: dict) -> dict:
        result = self.api.update_policy(self._require(), policy, annotations)
        status = self._wait_loaded(int(result["version"]))
        if status.get("status") == "failed":
            raise RuntimeError(f"the sandbox rejected policy revision {result['version']}: {status.get('load_error')}")
        # ``loaded``: the revision (or a later one that superseded it) is in force; False with ``timed_out``
        # means submitted but not confirmed within LOAD_TIMEOUT (the caller says so instead of "in place").
        loaded = status.get("status") == "loaded" or (
            status.get("status") == "superseded" and int(status.get("active_version") or 0) >= int(result["version"]))
        return {"policy_version": int(result["version"]), "status": status.get("status"), "loaded": loaded,
                "timed_out": bool(status.get("timed_out")), "loaded_time": status.get("loaded_time")}

    def apply_network(self, network: dict) -> dict:
        if network.get("egress") == "allow":
            raise DriverUnavailable("OpenShell has no rule for all internet access; list the websites instead.")
        policy = self._base_policy()
        policy["network_policies"] = self._with_builtin(network_rules(network, self._binaries))
        return self._update(policy, {"hermes.change": "network"})

    def current_network(self) -> Optional[dict]:
        return network_from_policy(self._base_policy(), self._binaries)

    def proposals(self, status: str = "pending") -> list[dict]:
        status = "" if status in ("", "all") else status
        return [proposal_view(c) for c in self.api.drafts(self._require(), status)]

    def _chunk(self, proposal_id: str) -> dict:
        for chunk in self.api.drafts(self._require(), ""):
            if chunk.get("id") == proposal_id:
                return chunk
        raise KeyError(proposal_id)

    def approve(self, proposal_id: str) -> dict:
        chunk = self._chunk(proposal_id)
        if chunk.get("status") != "pending":
            raise ProposalChanged(f"request {proposal_id} is already {chunk.get('status')}", proposal_view(chunk))
        try:
            result = self.api.approve_draft(self._name, proposal_id, chunk.get("review_token") or "")
        except ProposalChanged as exc:
            raise ProposalChanged(str(exc), proposal_view(self._chunk(proposal_id))) from exc
        status = self._wait_loaded(int(result["policy_version"]))
        return {"approved": proposal_id, "policy_version": int(result["policy_version"]),
                "status": status.get("status"), "rule": proposal_view(chunk)}

    def reject(self, proposal_id: str, reason: str) -> dict:
        chunk = self._chunk(proposal_id)
        if chunk.get("status") != "pending":
            raise ProposalChanged(f"request {proposal_id} is already {chunk.get('status')}", proposal_view(chunk))
        self.api.reject_draft(self._name, proposal_id, reason)
        return {"rejected": proposal_id, "reason": reason}

    def revisions(self) -> dict:
        name = self._require()
        latest = self.api.policy_status(name)
        return {"active_version": latest.get("active_version"),
                "revisions": sorted(self.api.list_policies(name), key=lambda r: -int(r.get("version") or 0))}

    def revision(self, version: int) -> dict:
        status = self.api.policy_status(self._require(), int(version))
        if int(status.get("version") or 0) != int(version):
            raise KeyError(version)
        return status

    def rollback(self, version: int) -> dict:
        old = self.revision(version)
        if not old.get("policy"):
            raise RuntimeError(f"revision {version} has no stored policy")
        # The built-in destination follows the profile's config today, not what that revision held.
        policy = {**old["policy"], "network_policies": self._with_builtin(old["policy"].get("network_policies") or {})}
        result = self._update(policy, {"hermes.change": "rollback", "hermes.rollback_of": str(version)})
        return {**result, "restored": int(version)}

    def events(self, *, since: float | None = None, until: float | None = None, limit: int = 200,
               classes: tuple[str, ...] = ()) -> list[dict]:
        """Recent OCSF events from the gateway's log tail (shorthand); once the sandbox has stopped,
        the host archive of full OCSF records instead."""
        if self._name is None or self._request is None:
            return self.audit_records(since=since, until=until, limit=limit, classes=classes)
        lines = self.api.logs(self._require(), since=since, lines=min(max(limit * 4, 200), 2000))
        out = []
        for line in lines:
            event = parse_event(line)
            if not event.get("ocsf"):
                continue
            if until is not None and (event.get("time") or 0) > until:
                continue
            if classes and event.get("class") not in classes:
                continue
            out.append(event)
        return out[-limit:]

    def recent_refusals(self, since: float) -> list[dict]:
        """Connections the sandbox was refused at or after *since*, from the supervisor's own record stream as it
        arrives (``AuditArchive.recent``): ``[{"time", "host", "port"}]``, oldest first. In memory, no call to
        the gateway: cheap enough to ask many times a second while a tool call runs."""
        audit = self._audit
        if audit is None:
            return []
        for _ in range(3):
            try:
                return [dict(row) for row in list(audit.recent) if row["time"] >= since]
            except RuntimeError:  # the follower thread appended while the tail was copied
                continue
        return []

    def audit_records(self, *, since: float | None = None, until: float | None = None, limit: int = 200,
                      classes: tuple[str, ...] = ()) -> list[dict]:
        """Full OCSF records from the host archive (running or stopped sandbox)."""
        directory = self._audit.dir if self._audit is not None else self._audit_dir
        if directory is None or self._name is None:
            raise NotSupported("no OCSF archive: the sandbox has not run with OCSF JSON export and a container CLI")
        return read_archive(directory, self._name, since=since, until=until, limit=limit, classes=classes)


def _read_yaml(path: Path) -> dict:
    """A profile's config.yaml, read through Hermes's config backend; {} when absent or broken."""
    from hermes_cli.config_backend import config_exists, read_config_doc

    try:
        data = read_config_doc(path) if config_exists(path) else {}
    except Exception:  # OSError or a YAML error
        return {}
    return data if isinstance(data, dict) else {}
