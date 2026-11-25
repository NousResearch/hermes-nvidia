"""The sandbox spec and outer token, both host-only (under the launcher's state dir).

spec.yaml::

    port: 47811            # fixed outer loopback port the desktop connects to
    driver: openshell      # the only driver (OpenShell on every OS)
    wxc_exec: C:/...       # Windows, optional: your own wxc-exec (MXC 1.0 or newer); else OPENSHELL_WXC_EXEC_PATH,
                           # else the one the plugin installs (windows_programs.py)
    busybox: C:/...        # Windows, optional: your own busybox-w32 for the sandbox's shell; else
                           # OPENSHELL_BUSYBOX, else the one the plugin installs
    openshell:             # openshell driver only; every key optional (see openshell_driver.config_from_spec)
      gateway: hermes-gw   # registered gateway (mTLS required); else OPENSHELL_GATEWAY, else the active one
      config_home: ~/.config   # XDG_CONFIG_HOME holding openshell/gateways/<gateway>
      cli: /usr/local/bin/openshell
      image: hermes-agent:openshell
    egress: deny           # deny | allow (all internet: no OpenShell engine has it, so the drivers refuse it)
    policy:                # the stored sandbox configuration: an OpenShell sandbox policy, every OS
      version: 1
      filesystem_policy:   # the user's folders; the launcher adds the profile home, the Hermes runtime
        read_write: [C:/Users/me/Hermes]   # and the credential deny list per launch
        read_only: []
        # deny: [...]      # optional extra paths to hide. Windows hides them with the launcher's own
                           # through driver_config.mxc.denied_paths and never sends this key to OpenShell.
      network_policies:    # websites and addresses; rules named hermes_<kind>_<target>_<port> are the
        hermes_site_api_example_com_443:   # page's own, any other rule (an approved request) is kept
          name: hermes_site_api_example_com_443   # as it is
          endpoints: [{host: api.example.com, port: 443}]
          binaries: [{path: <Hermes's interpreter>}]   # rebound by each driver to the one it runs

In memory, ``load_spec`` also gives the page's view of the policy (``folders`` and ``network``:
``{egress, allow: [{host|cidr, port[, binary]}], approved: {name: rule}}``); ``save_spec`` writes the
view back into the policy, keeping what the view does not model (other sections, deny paths, the full
text of every rule still listed). A spec saved before the policy format (``folders``/``network`` keys)
is read once and rewritten on the next save.
"""
from __future__ import annotations

import copy
import ipaddress
import os
import re
import secrets
import socket
from pathlib import Path

from .layout import LayoutError, ProfileLayout, validate_folder

_ACCESS = ("ro", "rw")
_EGRESS = ("deny", "allow")
# The refusal of "all internet" for a driver that has no such rule, wherever the setting is made.
NO_ALL_INTERNET = "This sandbox has no rule for all internet access; add the websites it needs."
MAX_FOLDERS = 32
MAX_ALLOWS = 64
_LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


def default_driver() -> str:
    # OpenShell on every OS: keys reach the sandbox only as provider placeholders.
    return "openshell"


# Launcher settings stored beside the policy (not sandbox configuration).
_SETTINGS = ("port", "driver", "wxc_exec", "busybox", "openshell")


def default_spec() -> dict:
    return {"port": None, "driver": default_driver(), "wxc_exec": None, "busybox": None, "openshell": {},
            "folders": [], "network": {"egress": "deny", "allow": []}, "policy": None}


def load_spec(layout: ProfileLayout) -> dict:
    import hermes_yaml

    spec = default_spec()
    if layout.spec_path.is_file():
        data = hermes_yaml.safe_load(layout.spec_path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise LayoutError(f"{layout.spec_path} is not a mapping")
        spec.update({k: v for k, v in data.items() if k in _SETTINGS})
        if data.get("policy") is not None:
            try:
                folders, network = view_from_policy(data["policy"])
            except LayoutError as exc:
                raise LayoutError(f"{layout.spec_path}: {exc}") from None
            network["egress"] = str(data.get("egress") or "deny").lower()
            spec.update(folders=folders, network=network, policy=data["policy"])
        else:  # saved before the policy format: read once, rewritten as a policy on the next save
            spec.update({k: data[k] for k in ("folders", "network") if data.get(k) is not None})
    return spec


def save_spec(layout: ProfileLayout, spec: dict) -> None:
    """Write the launcher settings and the policy (the view folded back into the stored document)."""
    import hermes_yaml

    doc = policy_document(spec)
    check_policy_document(doc)
    out = {k: spec.get(k) for k in _SETTINGS}
    out["egress"] = network_policy(spec)["egress"]
    out["policy"] = doc
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    tmp = layout.spec_path.with_suffix(".tmp")
    tmp.write_text(hermes_yaml.safe_dump(out, sort_keys=False, width=YAML_WIDTH), encoding="utf-8")
    os.replace(tmp, layout.spec_path)
    spec["policy"] = doc


def parse_folder_arg(raw: str, layout: ProfileLayout) -> dict:
    """``PATH`` or ``PATH:ro`` / ``PATH:rw`` (default rw); a drive-letter colon is part of the path.
    A relative PATH is taken from the current directory (the CLI's; the HTTP routes demand full paths)."""
    path, access = raw, "rw"
    head, sep, tail = raw.rpartition(":")
    if sep and tail.lower() in _ACCESS and head:
        path, access = head, tail.lower()
    return {"path": str(validate_folder(str(Path(path).expanduser().absolute()), layout)), "access": access}


def checked_folders(spec: dict, layout: ProfileLayout) -> list[dict]:
    out = []
    for entry in spec.get("folders") or []:
        access = str(entry.get("access", "rw")).lower()
        if access not in _ACCESS:
            raise LayoutError(f"folder access must be ro or rw: {entry}")
        out.append({"path": str(validate_folder(str(entry["path"]), layout)), "access": access})
    return out


def ensure_token(layout: ProfileLayout, *, rotate: bool = False) -> str:
    """The outer token: minted once and kept so a client's stored copy survives restarts. Lives only
    in the host state dir, which no sandbox is granted."""
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    if not rotate and layout.token_path.is_file():
        token = layout.token_path.read_text(encoding="utf-8").strip()
        if len(token) >= 32:
            return token
    token = secrets.token_urlsafe(32)
    fd = os.open(layout.token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    return token


def free_loopback_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def network_policy(spec: dict) -> dict:
    net = spec.get("network") or {}
    egress = str(net.get("egress", "deny")).lower()
    if egress not in _EGRESS:
        raise LayoutError(f"network.egress must be deny or allow, not {egress!r}")
    allow = [_saved_rule(r) for r in net.get("allow") or []]
    out = {"egress": egress, "allow": allow}
    approved = net.get("approved") or {}
    if not isinstance(approved, dict):
        raise LayoutError("network.approved must be a mapping of rule name to rule")
    if approved:
        out["approved"] = {str(k): v for k, v in approved.items()}
    return out


def _saved_rule(rule: dict) -> dict:
    if rule.get("host"):
        out = {"host": str(rule["host"]).strip().lower(), "port": int(rule["port"])}
        if rule.get("binary"):
            out["binary"] = str(rule["binary"])
        return out
    return {"cidr": str(rule["cidr"]), "port": int(rule["port"])}


# -- edits from the settings page (validated here, on the host, whatever the client checked) ---------

def folders_from_body(body, layout: ProfileLayout) -> list[dict]:
    """``{"folders": [{"path", "access"}, ...]}`` -> the validated, normalized folder list."""
    entries = body.get("folders") if isinstance(body, dict) else None
    if not isinstance(entries, list):
        raise LayoutError("Expected {\"folders\": [...]}.")
    if len(entries) > MAX_FOLDERS:
        raise LayoutError(f"At most {MAX_FOLDERS} folders.")
    out, seen = [], set()
    for entry in entries:
        folder = folder_from_entry(entry, layout)
        key = os.path.normcase(folder["path"])
        if key in seen:
            raise LayoutError(f"Listed twice: {folder['path']}")
        seen.add(key)
        out.append(folder)
    return out


def folder_from_entry(entry, layout: ProfileLayout) -> dict:
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
        raise LayoutError("Each folder needs a path.")
    access = str(entry.get("access", "")).lower()
    if access not in _ACCESS:
        raise LayoutError("Access must be ro or rw.")
    return {"path": str(validate_folder(entry["path"], layout)), "access": access}


def allow_entry(entry, *, host_loopback: str = "unknown", rules=("cidr",)) -> dict:
    """One allowed destination: an IP address or CIDR block, or (where the driver filters by
    hostname, ``"host" in rules``) a website's hostname, and a TCP port.

    Where the driver leaves every host loopback port reachable (``host_loopback == "open"``), a
    loopback rule would show a limit the sandbox does not enforce, so it is refused; where loopback
    is never reachable (``"closed"``), the rule could never work, so it is refused too.
    """
    if not isinstance(entry, dict):
        raise LayoutError("Each destination needs an address and a port.")
    port = _port(entry)
    if str(entry.get("host") or "").strip():
        if "host" not in rules:
            raise LayoutError("This sandbox filters by IP address only; enter an address or CIDR block.")
        _loopback_name(str(entry["host"]), host_loopback)
        rule = {"host": _hostname(str(entry["host"])), "port": port}
        binary = str(entry.get("binary") or "").strip()
        if binary:
            if not binary.startswith("/") or any(c.isspace() for c in binary):
                raise LayoutError(f"A program must be a full path inside the sandbox: {binary}")
            rule["binary"] = binary
        return rule
    raw = str(entry.get("cidr") or "").strip()
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise LayoutError(f"Not an IP address or CIDR block: {raw or '(empty)'}") from None
    if host_loopback == "open" and network.is_loopback:
        raise LayoutError("Loopback is always reachable from this sandbox, on every port.")
    if host_loopback == "closed" and (network.is_loopback or network.is_link_local):
        raise LayoutError("Loopback and link-local addresses are never reachable from this sandbox; "
                          "reach host services as host.openshell.internal.")
    return {"cidr": str(network), "port": port}


def _loopback_name(raw: str, host_loopback: str) -> None:
    """``localhost`` (or a name under it) entered as a website gets the answer a loopback address gets, where the
    driver says how it treats loopback; otherwise ``_hostname`` answers as before."""
    host = raw.strip().lower().rstrip(".")
    if host != "localhost" and not host.endswith(".localhost"):
        return
    if host_loopback == "open":
        raise LayoutError("Loopback is always reachable from this sandbox, on every port.")
    if host_loopback == "closed":
        raise LayoutError("Loopback is never reachable from this sandbox; reach host services as "
                          "host.openshell.internal.")


def _port(entry: dict) -> int:
    port = entry.get("port")
    if isinstance(port, str) and port.strip().isdigit():
        port = int(port.strip())
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise LayoutError(f"Port must be a number from 1 to 65535, not {entry.get('port')!r}.")
    return port


def _hostname(raw: str) -> str:
    """A website's hostname as OpenShell accepts it: DNS labels, optionally a whole-label ``*`` or
    ``**`` first label with at least two labels after it. IP literals belong in a CIDR rule."""
    host = raw.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise LayoutError(f"Enter an IP address as an address rule, not a website: {host}")
    labels = host.split(".")
    if not host or len(host) > 253 or len(labels) < 2:
        raise LayoutError(f"Not a website hostname: {raw.strip() or '(empty)'}")
    first, rest = labels[0], labels[1:]
    if first in ("*", "**"):
        if len(rest) < 2:
            raise LayoutError(f"A wildcard needs at least two labels after it: {host}")
    elif not _LABEL_RE.fullmatch(first):
        raise LayoutError(f"Not a website hostname: {host}")
    if not all(_LABEL_RE.fullmatch(label) for label in rest) or rest[-1].isdigit():
        raise LayoutError(f"Not a website hostname: {host}")
    if host == "localhost" or host.endswith(".localhost"):
        raise LayoutError("Loopback is never reachable from this sandbox; reach host services as "
                          "host.openshell.internal.")
    return host


def network_from_body(body, *, host_loopback: str = "unknown", rules=("cidr",), allow_all: bool = True,
                      approved: dict | None = None) -> dict:
    """``{"egress": "deny"|"allow", "allow": [{"cidr"|"host", "port"}, ...]}`` -> the normalized
    policy. Rules the enforcer added on approval (*approved*, from the saved spec) are kept unless
    the body names the ones to keep (``"approved": [names]``), which removes the others. A body that hands
    ``approved`` back as the config answer gave it (a mapping of rules by name) names them by its keys: a
    rule's content always comes from the saved spec, never from the body."""
    if not isinstance(body, dict):
        raise LayoutError("Expected {\"egress\": ..., \"allow\": [...]}.")
    egress = str(body.get("egress", "")).lower()
    if egress not in _EGRESS:
        raise LayoutError("Internet access must be deny or allow.")
    if egress == "allow" and not allow_all:
        raise LayoutError(NO_ALL_INTERNET)
    entries = body.get("allow", [])
    if not isinstance(entries, list):
        raise LayoutError("allow must be a list.")
    if len(entries) > MAX_ALLOWS:
        raise LayoutError(f"At most {MAX_ALLOWS} destinations.")
    allow = []
    for entry in entries:
        rule = allow_entry(entry, host_loopback=host_loopback, rules=rules)
        if rule not in allow:
            allow.append(rule)
    out = {"egress": egress, "allow": allow}
    kept = dict(approved or {})
    if "approved" in body:
        names = body["approved"]
        if isinstance(names, dict):
            names = list(names)
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise LayoutError("approved must be a list of rule names to keep.")
        unknown = [n for n in names if n not in kept]
        if unknown:
            raise LayoutError(f"No approved rule named {unknown[0]!r}.")
        kept = {n: kept[n] for n in names}
    if kept:
        out["approved"] = kept
    return out


def update_spec(layout: ProfileLayout, **changes) -> dict:
    """Re-read the saved spec, apply *changes* and save it atomically; returns the new spec."""
    spec = load_spec(layout)
    spec.update(changes)
    network_policy(spec)
    save_spec(layout, spec)
    return spec


# -- the stored sandbox configuration: an OpenShell sandbox policy -------------------------------------

POLICY_VERSION = 1
# No line folding: OpenShell's YAML parser refuses a long plain scalar (a Windows path with a space)
# continued on the next line ("inconsistent indentation"), which the default width of 80 produces.
YAML_WIDTH = 1 << 16
# OpenShell rejects a policy with unknown fields or a version other than 1; the stored document is
# checked the same way, so whatever is saved is a policy `openshell policy set` would take. One exception:
# ``filesystem_policy.deny`` is accepted as a list of extra paths to hide; the Windows driver moves it into
# ``driver_config.mxc.denied_paths`` at launch and no driver sends it in a policy.
_POLICY_KEYS = ("version", "filesystem_policy", "landlock", "process", "ui", "network_policies",
                "network_middlewares")
_FS_KEYS = ("include_workdir", "read_only", "read_write", "deny")
_RULE_KEYS = ("name", "endpoints", "binaries")
_PROVIDER_RULE_PREFIX = "_provider_"  # OpenShell reserves it for rules attached providers contribute


def hermes_binaries() -> list[str]:
    """The program a stored rule names when it applies to Hermes and everything Hermes starts.

    Informational in the stored document: a rule's name (``hermes_<kind>_<target>_<port>`` with no
    program suffix) is what marks it, and each driver binds such rules to the interpreter it really
    runs (the image's on Linux; on Windows the host runtime's leaf ``python.exe``, which is the
    process that opens the connection)."""
    if os.name == "nt":
        store = os.environ.get("HERMES_RUNTIME_DIR") or os.path.join(os.environ.get("LOCALAPPDATA", ""), "hermes", "tools")
        return [Path(store).as_posix() + "/python-*/python.exe"]
    from .openshell_driver import DEFAULT_BINARIES

    if DEFAULT_BINARIES:
        return list(DEFAULT_BINARIES)
    store = os.environ.get("HERMES_RUNTIME_DIR") or os.path.join(os.path.expanduser("~"), ".hermes", "tools")
    return [Path(store).as_posix() + "/python-*/bin/python3*"]


def _rule_name(kind: str, target: str, port: int, binary: str | None = None) -> str:
    from .openshell_driver import rule_name

    return rule_name(kind, target, port, binary)


def site_rule(entry: dict) -> tuple[str, dict]:
    """One allowed destination, as the page edits it, -> ``(name, OpenShell network rule)``."""
    binary = entry.get("binary")
    if entry.get("host"):
        name = _rule_name("site", entry["host"], int(entry["port"]), binary)
        endpoint = {"host": entry["host"], "port": int(entry["port"])}
    else:
        name = _rule_name("addr", entry["cidr"], int(entry["port"]))
        endpoint = {"port": int(entry["port"]), "allowed_ips": [entry["cidr"]]}
    binaries = [binary] if binary else hermes_binaries()
    return name, {"name": name, "endpoints": [endpoint], "binaries": [{"path": b} for b in binaries]}


def policy_document(spec: dict) -> dict:
    """The spec's folders and network as the OpenShell sandbox policy ``spec.yaml`` stores.

    The stored document (``spec["policy"]``) supplies what the page does not edit: other sections,
    deny paths, and the full text of every rule still listed, so a rule's L7 settings survive."""
    base = copy.deepcopy(spec.get("policy") or {})
    network = network_policy(spec)
    folders = spec.get("folders") or []
    doc: dict = {"version": POLICY_VERSION}
    fs = dict(base.get("filesystem_policy") or {})
    # The launcher grants the sandbox's working folders itself; a stored workdir grant means nothing.
    fs["include_workdir"] = False
    fs["read_write"] = [str(f["path"]) for f in folders if str(f.get("access", "rw")).lower() == "rw"]
    fs["read_only"] = [str(f["path"]) for f in folders if str(f.get("access", "rw")).lower() == "ro"]
    if not fs.get("deny"):
        fs.pop("deny", None)
    stored_rules = base.get("network_policies") or {}
    rules: dict = {}
    for entry in network["allow"]:
        name, rule = site_rule(entry)
        rules[name] = copy.deepcopy(stored_rules[name]) if isinstance(stored_rules.get(name), dict) else rule
    for name, rule in (network.get("approved") or {}).items():
        rules.setdefault(name, copy.deepcopy(rule))
    for key in _POLICY_KEYS[1:]:
        if key == "filesystem_policy":
            doc[key] = fs
        elif key == "network_policies":
            if rules:
                doc[key] = rules
        elif key in base:
            doc[key] = base[key]
    return doc


def policy_yaml(spec: dict) -> str:
    """The stored policy as YAML, the way ``openshell policy set --policy FILE`` reads it."""
    import hermes_yaml

    return hermes_yaml.safe_dump(policy_document(spec), sort_keys=False, width=YAML_WIDTH)


def check_policy_document(doc) -> None:
    """Refuse a document OpenShell would refuse (shape only; the gateway validates the rest)."""
    if not isinstance(doc, dict):
        raise LayoutError("The sandbox policy must be a mapping.")
    unknown = sorted(set(doc) - set(_POLICY_KEYS))
    if unknown:
        raise LayoutError(f"Unknown sandbox policy field: {unknown[0]}")
    if doc.get("version") != POLICY_VERSION:
        raise LayoutError(f"Sandbox policy version must be {POLICY_VERSION}, not {doc.get('version')!r}.")
    fs = doc.get("filesystem_policy")
    if fs is not None:
        if not isinstance(fs, dict):
            raise LayoutError("filesystem_policy must be a mapping.")
        unknown = sorted(set(fs) - set(_FS_KEYS))
        if unknown:
            raise LayoutError(f"Unknown filesystem_policy field: {unknown[0]}")
        for key in ("read_only", "read_write", "deny"):
            paths = fs.get(key) or []
            if not isinstance(paths, list) or not all(isinstance(p, str) and p.strip() for p in paths):
                raise LayoutError(f"filesystem_policy.{key} must be a list of paths.")
    rules = doc.get("network_policies")
    if rules is None:
        return
    if not isinstance(rules, dict):
        raise LayoutError("network_policies must be a mapping of rule name to rule.")
    for name, rule in rules.items():
        if not isinstance(name, str) or not name or name.startswith(_PROVIDER_RULE_PREFIX):
            raise LayoutError(f"Not a usable rule name: {name!r} (OpenShell reserves {_PROVIDER_RULE_PREFIX}).")
        if not isinstance(rule, dict) or set(rule) - set(_RULE_KEYS):
            raise LayoutError(f"Rule {name} must have only name, endpoints and binaries.")
        endpoints, binaries = rule.get("endpoints") or [], rule.get("binaries") or []
        if not isinstance(endpoints, list) or not all(isinstance(e, dict) for e in endpoints):
            raise LayoutError(f"Rule {name}: endpoints must be a list of mappings.")
        if not isinstance(binaries, list) or not all(isinstance(b, dict) and isinstance(b.get("path"), str)
                                                     for b in binaries):
            raise LayoutError(f"Rule {name}: binaries must be a list of {{path: ...}}.")


def view_from_policy(doc) -> tuple[list[dict], dict]:
    """A stored OpenShell policy -> ``(folders, network)`` as the settings page edits them.

    A ``hermes_`` rule becomes a destination only when regenerating it from that destination gives the
    same name; anything else (approved requests, hand-written rules) passes through as ``approved``."""
    check_policy_document(doc)
    fs = doc.get("filesystem_policy") or {}
    folders = ([{"path": str(p), "access": "rw"} for p in fs.get("read_write") or []]
               + [{"path": str(p), "access": "ro"} for p in fs.get("read_only") or []])
    allow, approved = [], {}
    for name, rule in (doc.get("network_policies") or {}).items():
        entries = _destinations(name, rule)
        if entries is None:
            approved[name] = rule
            continue
        allow += [e for e in entries if e not in allow]
    network = {"egress": "deny", "allow": allow}
    if approved:
        network["approved"] = approved
    return folders, network


def _destinations(name: str, rule: dict) -> list[dict] | None:
    from .openshell_driver import RULE_PREFIX

    if not name.startswith(RULE_PREFIX):
        return None
    paths = [b.get("path") for b in rule.get("binaries") or []]
    out = []
    for ep in rule.get("endpoints") or []:
        try:
            port = int(ep.get("port") or 0)
        except (TypeError, ValueError):
            return None
        if ep.get("host") and not ep.get("allowed_ips"):
            entry = {"host": str(ep["host"]).lower(), "port": port}
            if len(paths) == 1 and _rule_name("site", entry["host"], port, paths[0]) == name:
                entry["binary"] = paths[0]
            elif _rule_name("site", entry["host"], port) != name:
                return None
        elif not ep.get("host") and len(ep.get("allowed_ips") or []) == 1:
            entry = {"cidr": str(ep["allowed_ips"][0]), "port": port}
            if _rule_name("addr", entry["cidr"], port) != name:
                return None
        else:
            return None
        out.append(entry)
    return out or None


def set_policy(layout: ProfileLayout, doc) -> dict:
    """Replace the stored policy with *doc* (an OpenShell sandbox policy), through the same host
    checks as the page's own edits; returns the new spec."""
    check_policy_document(doc)
    folders, network = view_from_policy(doc)
    spec = load_spec(layout)
    network["egress"] = network_policy(spec)["egress"]
    folders = folders_from_body({"folders": folders}, layout)
    spec.update(folders=folders, network=network, policy=copy.deepcopy(doc))
    network_policy(spec)
    save_spec(layout, spec)
    return spec
