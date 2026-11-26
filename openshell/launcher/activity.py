"""Activity: one timeline of what a profile's sandbox allowed and refused, kept on the host.

Three sources, merged by time (newest first) for the Sandbox page's Activity tab and exported as OCSF:

* **Network** (OpenShell's audit: connections, HTTP requests, policy loads, findings): OCSF JSON records
  in ``<state>/audit/ocsf-<sandbox>-<UTC date>.jsonl``. On Linux the driver's ``AuditArchive`` writes
  them from the supervisor's ``OCSF-JSON`` stderr records. On Windows nothing is saved (``openshell
  logs`` is the gateway's in-memory tail, and the supervisor keeps no file on the host), so
  ``AuditCollector`` polls the driver's events while the sandbox runs and appends each one, converted
  from OpenShell's shorthand to an OCSF record of the same class (``ocsf_from_shorthand``). It drains
  once more just before the driver deletes the sandbox, so history survives stops and restarts.
* **Files**: refused file accesses (and the file tools' writes) from Hermes's own tool results in the
  profile's ``state.db``, read-only, limited to the times the sandbox ran (``<state>/activity/
  runs.jsonl``, written by the collector). OpenShell logs no per-file events.
* **Decisions**: answers to the in-chat access cards and their outcomes, from ``<state>/cards.jsonl``.

Every file above sits in the launcher's host-only state dir, which the sandbox cannot read or write.
Rows link to their chat: decisions and file rows carry the chat they came from; a network row is
attributed to a chat only when exactly one chat had a turn running at that moment.

OCSF mapping for the export (schema 1.8.0, one record per line), documented in docs/activity-log.md:
OpenShell records verbatim (network); File System Activity (1001) for file rows; User Access
Management (3005) for card decisions; Application Lifecycle (6002) for sandbox start and stop.
"""
from __future__ import annotations

import asyncio
import getpass
import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.parse
from collections import OrderedDict
from pathlib import Path
from typing import Callable, Iterable, Optional

log = logging.getLogger("openshell.activity")

AUDIT_DIRNAME = "audit"
ACTIVITY_DIRNAME = "activity"
RUNS_FILE = "runs.jsonl"
CARDS_FILE = "cards.jsonl"
POLL_INTERVAL = 3.0        # seconds between collector polls while the sandbox runs
FRESH_POLL = 1.5           # a page request polls first when the last poll is older than this
OVERLAP = 20.0             # each poll re-reads this many seconds (the supervisor flushes late)
MAX_SEEN = 200_000
DEFAULT_WINDOW = 24 * 3600.0
MAX_LIMIT = 2000
KINDS = ("network", "files", "decisions")
OCSF_VERSION = "1.8.0"
_OPENSHELL_PRODUCT = {"name": "OpenShell Sandbox Supervisor", "vendor_name": "OpenShell"}
_HERMES_PRODUCT = {"name": "Hermes Agent", "vendor_name": "Nous Research"}

_CLASSES = {  # shorthand class -> (class_uid, class_name, category_uid, category_name)
    "NET": (4001, "Network Activity", 4, "Network Activity"),
    "HTTP": (4002, "HTTP Activity", 4, "Network Activity"),
    "SSH": (4007, "SSH Activity", 4, "Network Activity"),
    "PROC": (1007, "Process Activity", 1, "System Activity"),
    "FINDING": (2004, "Detection Finding", 2, "Findings"),
    "CONFIG": (5019, "Device Config State Change", 5, "Discovery"),
    "LIFECYCLE": (6002, "Application Lifecycle", 6, "Application Activity"),
    "EVENT": (0, "Base Event", 0, "Uncategorized"),
}
_CLASS_BY_UID = {v[0]: k for k, v in _CLASSES.items()}
_NET_ACTIVITIES = {"OPEN": 1, "CLOSE": 2, "RESET": 3, "FAIL": 4, "REFUSE": 5, "TRAFFIC": 6, "LISTEN": 7}
_HTTP_ACTIVITIES = {"CONNECT": 1, "DELETE": 2, "GET": 3, "HEAD": 4, "OPTIONS": 5, "POST": 6, "PUT": 7,
                    "TRACE": 8, "PATCH": 9}
_SEVERITIES = {"INFO": (1, "Informational"), "LOW": (2, "Low"), "MED": (3, "Medium"), "MEDIUM": (3, "Medium"),
               "HIGH": (4, "High"), "CRIT": (5, "Critical"), "CRITICAL": (5, "Critical"), "FATAL": (6, "Fatal")}
_DETAIL_RE = re.compile(r"^(?P<bin>.+?)\((?P<pid>-?\d+)\)\s*->\s*(?P<rest>.+)$")
_HOSTPORT_RE = re.compile(r"^\[?(?P<host>[^\s\]/]+?)\]?:(?P<port>\d+)(?:/(?P<proto>[a-z]+))?$")
_FILE_DATE_RE = re.compile(r"-(\d{4}-\d{2}-\d{2})\.jsonl$")
_CONFIG_KEPT = ("loaded", "rejected", "failed", "error", "denied")
_FILE_WRITE_TOOLS = ("write_file", "patch", "edit_file", "apply_patch", "str_replace", "create_file")
_CHOICE_LABEL = {"allow": "Allowed", "always": "Always allowed", "deny": "Denied",
                 # other choice ids a card log may hold
                 "once": "Allowed", "session": "Allowed"}


# -- small helpers -------------------------------------------------------------------------------------

def _leaf(path: str) -> str:
    return re.split(r"[\\/]", str(path or ""))[-1] or str(path or "")


def _uid(*parts) -> str:
    h = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _endpoint(host: Optional[str], port) -> dict:
    out: dict = {}
    if host:
        out["ip" if _is_ip(host) else "domain"] = host.strip("[]")
    if port not in (None, ""):
        try:
            out["port"] = int(port)
        except (TypeError, ValueError):
            pass
    return out


def _secs(t) -> Optional[float]:
    """OCSF ``time`` (ms) or launcher seconds -> seconds."""
    if not isinstance(t, (int, float)):
        return None
    return t / 1000.0 if t > 1e11 else float(t)


def _append(path: Path, records: Iterable[dict]) -> int:
    lines = [json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in records]
    if not lines:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    fresh = not path.exists()
    with open(path, "a", encoding="utf-8") as fh:
        fh.writelines(lines)
    if fresh:
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return len(lines)


def _read_jsonl(path: Path) -> list[dict]:
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if isinstance(item, dict):
                    out.append(item)
    except OSError:
        pass
    return out


# -- OpenShell shorthand -> OCSF JSON -----------------------------------------------------------------

def ocsf_from_shorthand(event: dict, sandbox: str) -> dict:
    """One parsed shorthand event (``openshell_driver.parse_event``) as an OCSF 1.8.0 record of the class
    OpenShell itself uses for it. Marked in ``metadata.log_source`` and ``unmapped`` as converted by the
    launcher; the original line is kept in ``unmapped.shorthand``."""
    cls = str(event.get("class") or "EVENT").upper()
    class_uid, class_name, category_uid, category_name = _CLASSES.get(cls, _CLASSES["EVENT"])
    act = str(event.get("activity") or "").upper()
    detail = str(event.get("detail") or "")
    context = dict(event.get("context") or {})
    message = str(event.get("message") or "")
    t = float(event.get("time") or time.time())
    record: dict = {}

    actor = None
    target = detail
    m = _DETAIL_RE.match(detail)
    if m:
        actor = {"process": {"name": m.group("bin").strip(), "pid": int(m.group("pid"))}}
        target = m.group("rest").strip()
    method = None
    if cls == "HTTP":
        parts = target.split(None, 1)
        if len(parts) == 2 and parts[0].isalpha() and parts[0].isupper():
            method, target = parts[0], parts[1]
        method = method or (act if act in _HTTP_ACTIVITIES else None)
        url = urllib.parse.urlsplit(target if "://" in target else f"http://{target}")
        default = 443 if url.scheme == "https" else 80
        record["http_request"] = {"http_method": method or act or "GET", "url": {
            "scheme": url.scheme, "hostname": url.hostname, "path": url.path or "/",
            "port": url.port or default, "url_string": target}}
        record["dst_endpoint"] = _endpoint(url.hostname, url.port or default)
        activity_id = _HTTP_ACTIVITIES.get((method or act or "").upper(), 99)
    else:
        hp = _HOSTPORT_RE.match(target.split()[0]) if target else None
        if hp:
            record["dst_endpoint"] = _endpoint(hp.group("host"), hp.group("port"))
            if hp.group("proto"):
                record["connection_info"] = {"protocol_name": hp.group("proto")}
        activity_id = _NET_ACTIVITIES.get(act, 99) if cls in ("NET", "SSH") else 99
    activity_name = act.replace("_", " ").title() if act else "Other"
    sev_id, sev = _SEVERITIES.get(str(event.get("severity") or "INFO").upper(), (1, "Informational"))
    record = {
        "class_uid": class_uid, "class_name": class_name, "category_uid": category_uid,
        "category_name": category_name, "activity_id": activity_id, "activity_name": activity_name,
        "type_uid": class_uid * 100 + activity_id, "type_name": f"{class_name}: {activity_name}",
        "time": int(round(t * 1000)), "severity_id": sev_id, "severity": sev,
        "message": detail or message,
        "metadata": {"version": OCSF_VERSION, "product": dict(_OPENSHELL_PRODUCT),
                     "uid": _uid(f"{t:.3f}", message), "log_source": "openshell logs (shorthand)"},
        "container": {"name": sandbox},
        **record,
    }
    if actor:
        record["actor"] = actor
    action = str(event.get("action") or "").upper()
    if action == "ALLOWED":
        record.update(action_id=1, action="Allowed", disposition_id=1, disposition="Allowed",
                      status_id=1, status="Success")
    elif action in ("DENIED", "BLOCKED"):
        record.update(action_id=2, action="Denied", disposition_id=2, disposition="Blocked",
                      status_id=2, status="Failure")
    if context.get("reason"):
        record["status_detail"] = str(context["reason"])
    if context.get("policy") or context.get("engine"):
        record["firewall_rule"] = {"name": str(context.get("policy") or "-"), "type": str(context.get("engine") or "")}
    record["unmapped"] = {"shorthand": message, "converted_by": "hermes-openshell-launcher",
                          **{k: v for k, v in context.items() if k not in ("reason", "policy", "engine")}}
    return record


# -- runs (when the sandbox ran) ----------------------------------------------------------------------

def runs(state_dir: Path) -> list[dict]:
    """Sandbox runs, oldest first: {"start", "end" (None while open), "sandbox", "driver"}. A run a crash
    left open ends where the next one starts."""
    out: list[dict] = []
    for entry in _read_jsonl(Path(state_dir) / ACTIVITY_DIRNAME / RUNS_FILE):
        t = entry.get("t")
        if not isinstance(t, (int, float)):
            continue
        if entry.get("event") == "start":
            if out and out[-1]["end"] is None:
                out[-1]["end"] = t
                out[-1]["unclean"] = True
            out.append({"start": t, "end": None, "sandbox": entry.get("sandbox"), "driver": entry.get("driver")})
        elif entry.get("event") == "stop" and out and out[-1]["end"] is None:
            out[-1]["end"] = t
    return out


def _in_runs(t: float, spans: list[tuple[float, float]]) -> bool:
    return any(a <= t <= b for a, b in spans)


# -- network rows --------------------------------------------------------------------------------------

_FILE_CACHE: dict[str, dict] = {}
_CACHE_LOCK = threading.Lock()


def _keep_network(record: dict) -> bool:
    """Rows a person reads: decisions on connections and requests, policy loads and rejections,
    findings. Relay plumbing (unattributed loopback opens and closes) stays in the archive only."""
    uid = record.get("class_uid")
    action = record.get("action_id")
    if uid in (4001, 4002):
        return action in (1, 2) and (bool(record.get("actor")) or action == 2 or uid == 4002)
    if uid == 4007:
        return action == 2
    if uid == 1007:
        return action == 2
    if uid == 2004:
        return True
    if uid == 5019:
        name = str(record.get("activity_name") or "").lower()
        return name in _CONFIG_KEPT or record.get("status_id") == 2 or action == 2
    return False


def network_row(record: dict) -> dict:
    uid = record.get("class_uid")
    cls = _CLASS_BY_UID.get(uid, str(uid))
    t = _secs(record.get("time")) or 0.0
    dst = record.get("dst_endpoint") or {}
    proc = ((record.get("actor") or {}).get("process") or {})
    binary = (proc.get("file") or {}).get("path") if isinstance(proc.get("file"), dict) else proc.get("name")
    if binary in ("-", ""):
        binary = None
    req = record.get("http_request") or {}
    url = req.get("url") or {}
    host = dst.get("domain") or dst.get("hostname") or dst.get("ip") or url.get("hostname")
    port = dst.get("port") or url.get("port")
    action = record.get("action_id")
    outcome = "allowed" if action == 1 else "denied" if action == 2 else "info"
    method = req.get("http_method")
    path = url.get("path")
    rule = (record.get("firewall_rule") or {}).get("name")
    if cls == "HTTP" and host:
        title = f"{method or ''} {host}{'' if port in (80, 443, None) else f':{port}'}{path or ''}".strip()
    elif host:
        title = f"{host}:{port}" if port else host
    else:
        title = str(record.get("message") or record.get("activity_name") or cls)
    if cls == "CONFIG":
        title = str(record.get("message") or "Policy changed")
        outcome = "denied" if record.get("status_id") == 2 or action == 2 else "info"
    row = {"id": (record.get("metadata") or {}).get("uid") or _uid(record.get("time"), record.get("message")),
           "t": t, "kind": "network", "class": cls, "outcome": outcome, "title": title,
           "program": _leaf(binary) if binary else None, "binary": binary, "host": host, "port": port,
           "method": method, "path": path, "rule": None if rule in (None, "-", "") else rule,
           "reason": record.get("status_detail"), "chat": None}
    return {k: v for k, v in row.items() if v is not None or k in ("chat",)}


def _audit_files(audit_dir: Path, since: Optional[float], until: Optional[float]) -> list[Path]:
    files = sorted(Path(audit_dir).glob("ocsf-*.jsonl"))
    lo = time.strftime("%Y-%m-%d", time.gmtime(since - 86400)) if since and since > 86400 else None
    hi = time.strftime("%Y-%m-%d", time.gmtime(until + 86400)) if until else None
    out = []
    for f in files:
        m = _FILE_DATE_RE.search(f.name)
        if m and ((lo and m.group(1) < lo) or (hi and m.group(1) > hi)):
            continue
        out.append(f)
    return out


def _file_rows(path: Path) -> list[dict]:
    """Rows of one archive file, parsed incrementally (the file only grows)."""
    key = os.path.normcase(str(path))
    try:
        size = path.stat().st_size
    except OSError:
        return []
    with _CACHE_LOCK:
        entry = _FILE_CACHE.get(key)
        if entry is None or entry["offset"] > size:
            entry = {"offset": 0, "rows": [], "seen": set()}
            _FILE_CACHE[key] = entry
        if entry["offset"] < size:
            with open(path, "rb") as fh:
                fh.seek(entry["offset"])
                chunk = fh.read(size - entry["offset"])
            end = chunk.rfind(b"\n") + 1  # a line still being written waits for the next read
            for raw in chunk[:end].splitlines():
                try:
                    record = json.loads(raw.decode("utf-8", "replace"))
                except ValueError:
                    continue
                if not isinstance(record, dict) or not _keep_network(record):
                    continue
                row = network_row(record)
                if row["id"] in entry["seen"]:
                    continue
                entry["seen"].add(row["id"])
                row["_record"] = record
                entry["rows"].append(row)
            entry["offset"] += end
        return list(entry["rows"])


def _collapse(rows: list[dict]) -> list[dict]:
    """OpenShell logs one HTTP request once per engine (L7 and OPA): one row each, kept as one."""
    out, last = [], {}
    for row in sorted(rows, key=lambda r: r["t"]):
        key = (row.get("class"), row.get("outcome"), row.get("binary"), row.get("title"))
        prev = last.get(key)
        if prev is not None and row["t"] - prev["t"] < 1.0:
            prev.setdefault("_also", []).append(row["_record"])
            continue
        row = dict(row)
        last[key] = row
        out.append(row)
    return out


def network_rows(state_dir: Path, since: Optional[float], until: Optional[float]) -> list[dict]:
    rows: list[dict] = []
    for path in _audit_files(Path(state_dir) / AUDIT_DIRNAME, since, until):
        rows.extend(r for r in _file_rows(path)
                    if (since is None or r["t"] >= since) and (until is None or r["t"] <= until))
    return _collapse(rows)


# -- file rows (Hermes tool results in state.db) --------------------------------------------------------

def _connect_ro(db: Path) -> sqlite3.Connection:
    uri = "file:" + urllib.parse.quote(Path(db).resolve().as_posix(), safe="/:") + "?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=2.0)
    con.execute("PRAGMA query_only = 1")
    return con


def _tool_calls(raw) -> list[dict]:
    try:
        calls = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return []
    return [c for c in calls or [] if isinstance(c, dict)]


def _args(call: dict) -> dict:
    fn = call.get("function") if isinstance(call.get("function"), dict) else call
    raw = fn.get("arguments")
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _result(content) -> object:
    if isinstance(content, str):
        try:
            return json.loads(content)
        except ValueError:
            return content
    return content


def _error_line(result) -> str:
    """The line of a tool result that reports the refusal (``cat: can't open '…': Permission denied``)."""
    from .cards import _DENIED_RE, _MISSING_RE

    if isinstance(result, dict):
        texts = [v for v in result.values() if isinstance(v, str)]
    else:
        texts = [result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)]
    for text in texts:
        for line in text.splitlines():
            if _DENIED_RE.search(line) or _MISSING_RE.search(line):
                return line.strip()[:240]
    return ""


def _written_paths(name: str, args: dict, result) -> list[str]:
    if name not in _FILE_WRITE_TOOLS or not isinstance(result, dict) or result.get("error"):
        return []
    paths = result.get("files_modified") or ([result["resolved_path"]] if result.get("resolved_path") else [])
    if not paths:
        paths = [args.get(k) for k in ("path", "file_path") if isinstance(args.get(k), str)][:1]
    return [str(p) for p in paths if isinstance(p, str) and p]


def file_rows(home: Path, spans: list[tuple[float, float]], since: Optional[float], until: Optional[float],
              *, limit: int = MAX_LIMIT) -> tuple[list[dict], list[tuple[float, float, str]]]:
    """Refused file accesses and file-tool writes from the profile's tool results while the sandbox ran,
    plus each chat's turn spans (for attributing network rows)."""
    db = Path(home) / "state.db"
    if not db.is_file() or not spans:
        return [], []
    lo = max(since if since is not None else spans[0][0], spans[0][0])
    hi = min(until if until is not None else time.time() + 60, max(b for _, b in spans))
    if hi < lo:
        return [], []
    from .cards import refused_paths
    from .layout import on_this_computer
    from .refusals import failed_result

    try:
        con = _connect_ro(db)
    except sqlite3.Error as exc:
        log.debug("state.db unreadable: %s", exc)
        return [], []
    try:
        # Only tool results carry content worth reading here, and only assistant rows carry tool calls.
        msgs = con.execute(
            "SELECT id, session_id, role, tool_call_id, tool_name, CASE WHEN role = 'tool' THEN content END, "
            "CASE WHEN role = 'assistant' THEN tool_calls END, timestamp FROM messages "
            "WHERE timestamp BETWEEN ? AND ? AND role IN ('user', 'assistant', 'tool') ORDER BY timestamp, id",
            (lo - 600, hi)).fetchall()
    except sqlite3.Error as exc:
        log.debug("state.db query failed: %s", exc)
        return [], []
    finally:
        con.close()
    calls: dict[str, tuple[str, dict]] = {}
    turns: dict[str, list[list[float]]] = {}
    rows: list[dict] = []
    for mid, sid, role, call_id, tool_name, content, tool_calls, ts in msgs:
        spans_of = turns.setdefault(sid, [])
        if role == "user" or not spans_of:
            spans_of.append([ts, ts])
        else:
            spans_of[-1][1] = ts
        if role == "assistant" and tool_calls:
            for call in _tool_calls(tool_calls):
                cid = call.get("id") or call.get("call_id")
                fn = call.get("function") if isinstance(call.get("function"), dict) else call
                if cid:
                    calls[cid] = (str(fn.get("name") or ""), _args(call))
            continue
        if role != "tool" or ts < lo or ts > hi or not _in_runs(ts, spans):
            continue
        name, args = calls.get(call_id or "", (tool_name or "", {}))
        name = tool_name or name
        result = _result(content)
        base = {"t": ts, "kind": "files", "tool": name, "chat": sid, "message_id": mid}
        # Refusals are listed for failed calls only. What a call that did not fail printed about a path it named
        # is a candidate the launcher checks against the sandbox's folders before any card. This log cannot repeat
        # that check for a past run, and the card's own rows show the decision.
        refused = refused_paths(name, args, result) if failed_result(name, result) else []
        for path, access, missing in refused:
            if missing and not (on_this_computer(path) and Path(path).exists()):
                continue  # really absent, or not to be looked at (a link leads off this computer): not a refusal
            rows.append({**base, "id": _uid("file", mid, str(path), access), "outcome": "denied",
                         "title": str(path), "path": str(path), "access": "write" if access == "read_write" else "read",
                         "reason": _error_line(result)})
        if not refused:
            for path in _written_paths(name, args, result):
                rows.append({**base, "id": _uid("file", mid, path, "write"), "outcome": "allowed", "title": path,
                             "path": path, "access": "write"})
    spans_out = [(a - 1.0, b + 5.0, sid) for sid, ss in turns.items() for a, b in ss]
    return rows[-limit:], spans_out


def chat_titles(home: Path, ids: Iterable[str]) -> dict[str, str]:
    ids = sorted({i for i in ids if i})
    db = Path(home) / "state.db"
    if not ids or not db.is_file():
        return {}
    try:
        con = _connect_ro(db)
        try:
            marks = ",".join("?" * len(ids))
            return {sid: title for sid, title in con.execute(
                f"SELECT id, title FROM sessions WHERE id IN ({marks})", ids).fetchall() if title}
        finally:
            con.close()
    except sqlite3.Error:
        return {}


# -- decision rows (cards.jsonl) ------------------------------------------------------------------------

def _target(item: dict) -> str:
    if item.get("host"):
        if str(item["host"]).startswith("tool:"):  # a tool category's card or its removal: the category's name
            from . import categories

            category = categories.by_id(str(item["host"])[len("tool:"):])
            if item.get("label") or category is not None:
                return str(item.get("label") or category.label)
        return f"{item['host']}:{item.get('port')}" if item.get("port") else str(item["host"])
    return str(item.get("path") or "")


def decision_rows(state_dir: Path, since: Optional[float], until: Optional[float]) -> list[dict]:
    entries = _read_jsonl(Path(state_dir) / CARDS_FILE)
    raised: dict[str, dict] = {}
    outcome: dict[str, dict] = {}
    rows: list[dict] = []
    for e in entries:
        ev, rid = e.get("event"), e.get("request_id")
        if ev == "raised" and rid:
            raised[rid] = e
        elif ev in ("granted", "grant failed", "rejected", "reject failed", "denied") and rid:
            outcome[rid] = e
    for e in entries:
        ev = e.get("event")
        t = e.get("answered_at") or e.get("t")
        if not isinstance(t, (int, float)) or (since is not None and t < since) or (until is not None and t > until):
            continue
        if ev == "answered":
            card = {**raised.get(e.get("request_id"), {}), **(e.get("target") or {})}
            choice = e.get("choice") or "deny"
            done = outcome.get(e.get("request_id"))
            status = None
            if choice != "deny":
                status = "failed" if done and done.get("event") == "grant failed" else "applied" if done else "pending"
            rows.append({
                "id": _uid("decision", e.get("request_id"), t), "t": t, "kind": "decisions",
                "outcome": "denied" if choice == "deny" else "allowed", "choice": choice,
                "label": _CHOICE_LABEL.get(choice, choice), "card": e.get("kind") or card.get("kind"),
                "title": _target(card), "host": card.get("host"), "port": card.get("port"),
                "path": card.get("path"), "access": card.get("access"), "binary": card.get("binary"),
                "program": card.get("label") or (_leaf(card["binary"]) if card.get("binary") else None),
                "reason": e.get("reason"), "who": "you", "chat": e.get("chat") or card.get("chat"),
                "raised_at": card.get("raised_at"), "status": status,
                "applied_at": done.get("t") if done else None,
                "error": (done or {}).get("error") if status == "failed" else None,
                "request_id": e.get("request_id")})
        elif ev in ("revoked", "removed"):
            rows.append({"id": _uid(ev, t, _target(e), e.get("chat")), "t": t, "kind": "decisions",
                         "outcome": "info", "choice": "ended", "label": "Access removed" if ev == "removed"
                         else "Access ended", "card": e.get("kind"),
                         "title": _target(e), "host": e.get("host"), "port": e.get("port"), "path": e.get("path"),
                         "scope": e.get("scope"), "why": e.get("why"), "who": "you" if ev == "removed" else "sandbox",
                         "chat": e.get("chat")})
    return [{k: v for k, v in r.items() if v is not None or k == "chat"} for r in rows]


# -- the merged view ------------------------------------------------------------------------------------

def lifecycle_rows(all_runs: list[dict], since: Optional[float], until: Optional[float]) -> list[dict]:
    rows = []
    for run in all_runs:
        for what, t in (("started", run["start"]), ("stopped", run.get("end"))):
            if t is None or (since is not None and t < since) or (until is not None and t > until):
                continue
            rows.append({"id": _uid("run", what, t), "t": t, "kind": "lifecycle", "outcome": "info",
                         "title": f"Sandbox {what}", "event": what, "sandbox": run.get("sandbox"), "chat": None})
    return rows


def parse_params(get: Callable[[str], list[str]], now: Optional[float] = None) -> dict:
    """Query values -> query() keyword arguments; raises ValueError with the reason."""
    now = time.time() if now is None else now

    def one(key):
        values = get(key) or []
        return values[0] if values and values[0] != "" else None

    since, until = one("since"), one("until")
    since = float(since) if since is not None else now - DEFAULT_WINDOW
    until = float(until) if until is not None else None
    limit = int(one("limit") or 500)
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit is 1 to {MAX_LIMIT}")
    kinds = tuple(k.strip() for k in ",".join(get("kinds") or []).split(",") if k.strip()) or KINDS
    if any(k not in KINDS for k in kinds):
        raise ValueError(f"kinds is any of {', '.join(KINDS)}")
    denied = (one("denied") or "").lower() in ("1", "true", "yes")
    return {"since": since, "until": until, "limit": limit, "kinds": kinds, "denied_only": denied}


def _tool_use(row: dict) -> Optional[str]:
    """The tool category a request through a credential's rule belongs to (categories.py): the label of the
    category whose approval opened the host. None for a model's host and for any other rule."""
    if not str(row.get("rule") or "").startswith("_provider_") or not row.get("host"):
        return None
    try:
        from . import categories
        from .openshell_driver import WEB_BACKENDS

        host = str(row["host"]).lower()
        port = int(row["port"]) if str(row.get("port") or "").isdigit() else None
        env = next((name for name, (_label, at, _port, _how, _name) in WEB_BACKENDS.items() if at == host), None)
        return categories.use_label(host, port, env)
    except Exception:  # the row then says what it said before
        log.debug("the tool category of an activity row could not be worked out", exc_info=True)
        return None


def query(layout, *, since: Optional[float] = None, until: Optional[float] = None, kinds: tuple = KINDS,
          denied_only: bool = False, limit: int = 500, keep_records: bool = False) -> dict:
    """The Activity timeline for *layout*'s profile, newest first."""
    state_dir = Path(layout.state_dir)
    all_runs = runs(state_dir)
    now = time.time()
    spans = [(r["start"], r["end"] if r["end"] is not None else now + 60) for r in all_runs]
    rows: list[dict] = []
    files, turns = file_rows(layout.home, spans, since, until)
    if "network" in kinds:
        net = network_rows(state_dir, since, until)
        for row in net:
            hits = {sid for a, b, sid in turns if a <= row["t"] <= b}
            if len(hits) == 1:
                row["chat"] = hits.pop()
            use = _tool_use(row)
            if use:
                row["use"] = use
        rows.extend(net)
    if "files" in kinds:
        rows.extend(files)
    if "decisions" in kinds:
        rows.extend(decision_rows(state_dir, since, until))
    if set(kinds) == set(KINDS) and not denied_only:
        rows.extend(lifecycle_rows(all_runs, since, until))
    if denied_only:
        rows = [r for r in rows if r.get("outcome") == "denied"]
    rows.sort(key=lambda r: r["t"], reverse=True)
    truncated = len(rows) > limit
    rows = rows[:limit]
    titles = chat_titles(layout.home, (r.get("chat") for r in rows))
    for r in rows:
        if r.get("chat") in titles:
            r["chat_title"] = titles[r["chat"]]
        if not keep_records:
            r.pop("_record", None)
            r.pop("_also", None)
    audit_dir = state_dir / AUDIT_DIRNAME
    return {"rows": rows, "truncated": truncated, "since": since, "until": until, "now": now,
            "kinds": list(kinds), "denied_only": denied_only,
            "sources": {"network": {"kept": any(audit_dir.glob("ocsf-*.jsonl")) if audit_dir.is_dir() else False},
                        "files": {"kept": (Path(layout.home) / "state.db").is_file() and bool(all_runs)},
                        "decisions": {"kept": (state_dir / CARDS_FILE).is_file()}},
            "running": bool(all_runs and all_runs[-1]["end"] is None)}


# -- OCSF export ------------------------------------------------------------------------------------------

def _base(class_uid: int, class_name: str, category_uid: int, category_name: str, activity_id: int,
          activity_name: str, t: float, uid: str, product: dict, log_source: str) -> dict:
    return {"class_uid": class_uid, "class_name": class_name, "category_uid": category_uid,
            "category_name": category_name, "activity_id": activity_id, "activity_name": activity_name,
            "type_uid": class_uid * 100 + activity_id, "type_name": f"{class_name}: {activity_name}",
            "time": int(round(t * 1000)),
            "metadata": {"version": OCSF_VERSION, "product": dict(product), "uid": uid, "log_source": log_source}}


def ocsf_record(row: dict, profile: str, user: str) -> list[dict]:
    """One timeline row as OCSF records (a collapsed network row gives back every original)."""
    kind = row.get("kind")
    if kind == "network":
        return [r for r in [row.get("_record"), *(row.get("_also") or [])] if r]
    if kind == "files":
        denied = row["outcome"] == "denied"
        read = row.get("access") == "read"
        rec = _base(1001, "File System Activity", 1, "System Activity", 2 if read else 3, "Read" if read else "Update",
                    row["t"], row["id"], _HERMES_PRODUCT, "state.db tool results")
        rec.update({
            "severity_id": 3 if denied else 1, "severity": "Medium" if denied else "Informational",
            "action_id": 2 if denied else 1, "action": "Denied" if denied else "Allowed",
            "disposition_id": 2 if denied else 1, "disposition": "Blocked" if denied else "Allowed",
            "status_id": 2 if denied else 1, "status": "Failure" if denied else "Success",
            "message": f"{row.get('tool')} {'could not ' if denied else ''}{'read' if read else 'write'} {row['path']}",
            "file": {"path": row["path"], "name": _leaf(row["path"]), "type_id": 1, "type": "Regular File"},
            "actor": {"app_name": "Hermes Agent", "user": {"name": profile, "type": "Other"}},
            "unmapped": {"hermes": {"profile": profile, "chat": row.get("chat"), "tool": row.get("tool"),
                                    "message_id": row.get("message_id"), "access": row.get("access")}}})
        if row.get("reason"):
            rec["status_detail"] = row["reason"]
        return [rec]
    if kind == "decisions":
        choice = row.get("choice")
        if choice == "ended":
            activity_id, activity_name, action = 2, "Revoke Privileges", None
        elif choice == "deny":
            activity_id, activity_name, action = 99, "Deny", (2, "Denied")
        else:
            activity_id, activity_name, action = 1, "Assign Privileges", (1, "Allowed")
        rec = _base(3005, "User Access Management", 3, "Identity & Access Management", activity_id, activity_name,
                    row["t"], row["id"], _HERMES_PRODUCT, "sandbox launcher cards.jsonl")
        privilege = (f"network:{row.get('title')}" if row.get("host") else
                     f"files:{row.get('access') or 'read'}:{row.get('path')}")
        rec.update({"severity_id": 1, "severity": "Informational",
                    "message": f"{row.get('label')}: {row.get('title')}",
                    "user": {"name": profile, "type": "Other"},  # the agent's profile whose access changed
                    "privileges": [privilege],
                    "resource": {"name": row.get("title"), "type": "network destination" if row.get("host") else "folder"},
                    "unmapped": {"hermes": {k: row.get(k) for k in ("chat", "choice", "label", "card", "program",
                                                                     "reason", "status", "why", "request_id",
                                                                     "raised_at", "applied_at") if row.get(k) is not None}}})
        if row.get("who") == "you":
            rec["actor"] = {"user": {"name": user, "type": "User"}}
        if action:
            rec.update(action_id=action[0], action=action[1])
        return [rec]
    if kind == "lifecycle":
        started = row.get("event") == "started"
        rec = _base(6002, "Application Lifecycle", 6, "Application Activity", 3 if started else 4,
                    "Start" if started else "Stop", row["t"], row["id"], _HERMES_PRODUCT, "sandbox launcher runs.jsonl")
        rec.update({"severity_id": 1, "severity": "Informational", "message": row.get("title"),
                    "app": {"name": "Hermes sandbox", "uid": row.get("sandbox") or profile}})
        return [rec]
    return []


def export(layout, **params) -> dict:
    """The rows query() returns for *params*, oldest first, as OCSF JSON records (one per JSONL line)."""
    view = query(layout, keep_records=True, **params)
    try:
        user = getpass.getuser()
    except Exception:
        user = "desktop user"
    records = [rec for row in reversed(view["rows"]) for rec in ocsf_record(row, layout.name, user)]
    records.sort(key=lambda r: r.get("time") or 0)  # stable: a collapsed row's copies stay together
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(view["now"]))
    return {"records": records, "count": len(records), "truncated": view["truncated"],
            "filename": f"sandbox-activity-{layout.name}-{stamp}.jsonl", "format": "ocsf-jsonl",
            "ocsf_version": OCSF_VERSION}


# -- the collector (runs in the launcher) -----------------------------------------------------------------

class AuditCollector:
    """Keeps the sandbox's audit on the host while it runs, and records when it ran.

    For a driver that archives its own audit (``audit_records``: the Linux driver), only the runs are
    recorded. Otherwise, when the driver reports audit events (``audit_events``), the collector polls
    them every ``interval`` seconds and appends new ones to ``<state>/audit/ocsf-<sandbox>-<date>.jsonl``
    as OCSF records, deduplicated by ``metadata.uid``. The driver's ``stop`` is wrapped so a last poll
    runs before the sandbox is deleted (Windows keeps nothing after that)."""

    def __init__(self, sup, layout=None, *, interval: float = POLL_INTERVAL, clock=time.time):
        self._sup = sup
        self._layout = layout if layout is not None else sup.layout
        self._interval = interval
        self._clock = clock
        self.state_dir = Path(self._layout.state_dir)
        self.audit_dir = self.state_dir / AUDIT_DIRNAME
        driver = sup.driver
        self.collects = bool(driver.can("audit_events")) and not callable(getattr(driver, "audit_records", None))
        self._lock = threading.RLock()
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._cursor: Optional[float] = None
        self._run_open = False
        self._run_start: Optional[float] = None
        self._task: Optional[asyncio.Task] = None
        self.last_poll = 0.0
        self.written = 0
        self.error: Optional[str] = None
        self._load_seen()
        self._wrap_stop(driver)

    # -- lifecycle -------------------------------------------------------------------------------
    def start(self) -> None:
        self._task = asyncio.ensure_future(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        self._close_run("launcher stopped")

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self._interval)
                if self._sup.running():
                    if not self._run_open:
                        self._open_run()
                    if self.collects:
                        await asyncio.to_thread(self.poll)
                elif self._run_open and self._sup.state in ("stopped", "exited", "failed"):
                    self._close_run(self._sup.state)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # never break the launcher over the audit trail
                self.error = str(exc)
                log.debug("activity collector tick failed", exc_info=True)

    def _wrap_stop(self, driver) -> None:
        original = driver.stop

        def stop(*args, **kwargs):
            try:
                if self._run_open and self.collects:
                    self.poll()
            except Exception as exc:
                self.error = f"last poll before stop failed: {exc}"
            try:
                return original(*args, **kwargs)
            finally:
                self._close_run("stopped")

        driver.stop = stop

    # -- runs -------------------------------------------------------------------------------------
    def _sandbox(self) -> str:
        name = getattr(self._sup.driver, "_name", None)
        if name:
            return str(name)
        from .openshell_driver import sandbox_name

        return sandbox_name(self._layout.name)

    def _open_run(self) -> None:
        with self._lock:
            if self._run_open:
                return
            start = getattr(self._sup, "_started_at", None) or self._clock()
            self._run_open, self._run_start = True, float(start)
            _append(self.state_dir / ACTIVITY_DIRNAME / RUNS_FILE, [{
                "event": "start", "t": float(start), "sandbox": self._sandbox(), "driver": self._sup.driver.name}])

    def _close_run(self, why: str) -> None:
        with self._lock:
            if not self._run_open:
                return
            self._run_open = False
            _append(self.state_dir / ACTIVITY_DIRNAME / RUNS_FILE, [{"event": "stop", "t": self._clock(), "why": why}])

    # -- the audit ---------------------------------------------------------------------------------
    def _load_seen(self) -> None:
        """Uids already archived in the last two days' files: a restarted launcher re-reads the
        gateway's tail without writing the same events twice."""
        cutoff = time.strftime("%Y-%m-%d", time.gmtime(self._clock() - 2 * 86400))
        for path in sorted(self.audit_dir.glob("ocsf-*.jsonl")) if self.audit_dir.is_dir() else []:
            m = _FILE_DATE_RE.search(path.name)
            if m and m.group(1) < cutoff:
                continue
            for record in _read_jsonl(path):
                uid = (record.get("metadata") or {}).get("uid")
                if uid:
                    self._remember(uid)
                t = _secs(record.get("time"))
                if t and (self._cursor is None or t > self._cursor):
                    self._cursor = t

    def _remember(self, uid: str) -> bool:
        if uid in self._seen:
            return False
        self._seen[uid] = None
        while len(self._seen) > MAX_SEEN:
            self._seen.popitem(last=False)
        return True

    def poll(self) -> int:
        """Append the driver's new audit events; returns how many were new. Blocking (a CLI call on
        Windows): run off the event loop."""
        if not self.collects:
            return 0
        with self._lock:
            now = self._clock()
            floor = self._run_start if self._run_start is not None else now - 120
            since = max(floor, self._cursor or floor) - OVERLAP
            events = self._sup.driver.events(since=since, limit=1000)
            sandbox = self._sandbox()
            by_file: dict[Path, list[dict]] = {}
            for event in events:
                if not event.get("ocsf") or not event.get("class"):
                    continue
                record = ocsf_from_shorthand(event, sandbox)
                if not self._remember(record["metadata"]["uid"]):
                    continue
                secs = record["time"] / 1000.0
                if self._cursor is None or secs > self._cursor:
                    self._cursor = secs
                day = time.strftime("%Y-%m-%d", time.gmtime(secs))
                by_file.setdefault(self.audit_dir / f"ocsf-{sandbox}-{day}.jsonl", []).append(record)
            n = sum(_append(path, recs) for path, recs in by_file.items())
            self.written += n
            self.last_poll = self._clock()
            self.error = None
            return n

    def status(self) -> dict:
        return {"collects": self.collects, "dir": str(self.audit_dir), "written": self.written,
                "last_poll": self.last_poll or None, "run_open": self._run_open, "error": self.error}

    # -- host routes (merged into HostRoutes like the cards' routes) ----------------------------------
    def routes(self) -> dict:
        return {("GET", "activity"): self._route_activity, ("GET", "activity/export"): self._route_export}

    async def _fresh(self) -> None:
        if self.collects and self._run_open and self._clock() - self.last_poll > FRESH_POLL:
            try:
                await asyncio.to_thread(self.poll)
            except Exception as exc:
                self.error = str(exc)

    async def _route_activity(self, req, body: bytes):
        try:
            params = parse_params(req.query_values if req is not None else (lambda k: []))
        except ValueError as exc:
            return 422, {"detail": str(exc)}, {}
        await self._fresh()
        view = await asyncio.to_thread(query, self._layout, **params)
        return 200, {**view, "collector": self.status()}, {}

    async def _route_export(self, req, body: bytes):
        try:
            params = parse_params(req.query_values if req is not None else (lambda k: []))
        except ValueError as exc:
            return 422, {"detail": str(exc)}, {}
        await self._fresh()
        return 200, await asyncio.to_thread(export, self._layout, **params), {}
