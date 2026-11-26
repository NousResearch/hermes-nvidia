"""The channel between the in-sandbox hook (sandbox_hook.py) and the launcher, on the host side.

* **Requests** (sandbox -> host): the hook relays a refusal it saw in a tool result (or, for a failed
  program call that printed none, the hosts it named: ``strength: candidate``) as a small JSON file
  in ``<box>/requests`` (granted read & write to the sandbox). The launcher treats each one like any
  other relayed refusal: untrusted input, checked on the host by the same rules as the cards it raises
  from relayed tool results and OpenShell proposals, size- and rate-limited, deleted once read. A path
  in it counts only when it is written as a full path of this computer (``layout.names_local_path``).
* **Verdicts** (host -> sandbox): ``<state dir>/verdicts/verdicts.json``, written only by the launcher
  (atomically) into a folder granted read-only to the sandbox, so the hook can wait for an answer but
  never forge one. It answers each request (``requests[rid]``: which card targets it waits for, or why
  there is no card) and carries each card target's state (``targets[key]``: asking, applying, allowed,
  allowed_later, restarting, unconfirmed, denied, failed, stopped). ``allowed`` is written only once the
  policy revision carrying the rule reports loaded; ``unconfirmed``: answered and submitted, but not loaded
  when the driver's bounded wait ended.

Forging a verdict would only change what the model is told; what the sandbox may reach is enforced by
OpenShell from the launcher's policy either way.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Optional

VERDICTS_FILE = "verdicts.json"
FORMAT = 1
MAX_REQUEST_BYTES = 16 * 1024
MAX_REQUESTS_PER_POLL = 20
DEFAULT_WAIT = 120.0           # a request that does not say how long its hook waits
MAX_WAIT = 600.0
REQUEST_TTL = 600.0          # request answers are kept this long (the hook waits at most a few minutes)
_RID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
FINAL = frozenset({"allowed", "allowed_later", "restarting", "unconfirmed", "denied", "failed", "stopped"})
# Final answers after which the agent must end its reply (a retry in it fails the same way); the launcher
# continues the chat once the change is in place.
END_REPLY = frozenset({"allowed_later", "restarting", "unconfirmed"})
# ``refused``: what OpenShell's records showed its proxy refusing a program while a terminal / execute_code call was
# open (host -> the refusal's time), written as the records come in. The hook reads it when such a call SUCCEEDED and
# named a host: it asks for a card, and holds the call, only when a host it named is here with a time inside the call.
# The newest REFUSED_MAX entries, each for REFUSED_TTL seconds. A host refused again is written again only when its
# time is REFUSED_STEP newer (a program retrying in a loop does not rewrite the file many times a second; the step
# is well under the hook's allowance for the start of its call, ``refusals.ZERO_WAIT_SKEW``).
REFUSED_MAX = 32
REFUSED_TTL = 120.0
REFUSED_STEP = 0.1


def net_key(host: str) -> str:
    return "net:" + str(host).lower()


def dir_key(path) -> str:
    return "dir:" + os.path.normcase(os.path.abspath(str(path)))


class Verdicts:
    """The verdict file, rewritten whole on every change (it stays small)."""

    def __init__(self, directory: Optional[Path], clock=time.time):
        self.dir = Path(directory) if directory is not None else None
        self._clock = clock
        self.launch = secrets.token_hex(6)
        self.requests: dict[str, dict] = {}
        self.targets: dict[str, dict] = {}
        self.refused: dict[str, float] = {}
        self.write_errors = 0

    @property
    def path(self) -> Optional[Path]:
        return self.dir / VERDICTS_FILE if self.dir is not None else None

    def reset(self) -> None:
        self.requests, self.targets, self.refused = {}, {}, {}
        self.launch = secrets.token_hex(6)
        self._write()

    def note_refused(self, times: dict) -> bool:
        """Refusals OpenShell's records show (host -> time, epoch seconds): kept for the hook, the file rewritten
        only when a host is new or was refused again at least ``REFUSED_STEP`` later. Returns whether anything
        changed."""
        changed = False
        for host, t in (times or {}).items():
            if not isinstance(host, str) or isinstance(t, bool) or not isinstance(t, (int, float)):
                continue
            known = self.refused.get(host)
            if known is None or t >= known + REFUSED_STEP:
                self.refused[host] = float(t)
                changed = True
        if changed:
            cutoff = self._clock() - REFUSED_TTL
            newest = sorted(self.refused.items(), key=lambda kv: kv[1], reverse=True)[:REFUSED_MAX]
            self.refused = {h: t for h, t in newest if t >= cutoff}
            self._write()
        return changed

    def target(self, key: str, **fields) -> dict:
        entry = self.targets.setdefault(key, {})
        entry.update({k: v for k, v in fields.items()})
        entry["t"] = self._clock()
        self._write()
        return entry

    def get(self, key: str) -> Optional[dict]:
        return self.targets.get(key)

    def drop(self, key: str) -> None:
        if self.targets.pop(key, None) is not None:
            self._write()

    def answer(self, rid: str, status: str, keys=(), detail: Optional[str] = None) -> None:
        """``card``: the hook waits for *keys*; ``refused``: there is no card (*detail* says why)."""
        prior = self.requests.get(rid) or {}
        self.requests[rid] = {"status": status, "keys": list(keys), "detail": detail, "t": self._clock(),
                              **({"stopped": True} if prior.get("stopped") else {})}
        cutoff = self._clock() - REQUEST_TTL
        self.requests = {k: v for k, v in self.requests.items() if v["t"] >= cutoff}
        self._write()

    def stop(self, rid: str) -> None:
        """The user stopped the turn the hook waits in: it stops waiting (the card stays open)."""
        entry = self.requests.setdefault(rid, {"status": "card", "keys": [], "detail": None, "t": self._clock()})
        entry["stopped"] = True
        self._write()

    def snapshot(self) -> dict:
        return {"format": FORMAT, "launch": self.launch, "updated": self._clock(), "requests": self.requests,
                "targets": self.targets, "refused": self.refused}

    def _write(self) -> None:
        if self.dir is None:
            return
        data = json.dumps(self.snapshot(), ensure_ascii=False, default=str)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            tmp = self.dir / f".{VERDICTS_FILE}.{os.getpid()}.tmp"
            tmp.write_text(data, encoding="utf-8")
            # The hook may hold the file open for a moment (Windows refuses to replace an open file).
            for attempt in range(40):
                try:
                    os.replace(tmp, self.path)
                    return
                except PermissionError:
                    time.sleep(0.025)
            self.write_errors += 1
        except OSError:
            self.write_errors += 1


def read_requests(directory: Optional[Path], now: Optional[float] = None) -> list[dict]:
    """Take (read and delete) the hook's request files, oldest first; malformed ones are dropped."""
    if directory is None:
        return []
    now = time.time() if now is None else now
    try:
        entries = [e for e in os.scandir(directory) if e.is_file()]
    except OSError:
        return []
    out = []
    taken = 0
    for entry in sorted(entries, key=lambda e: e.stat().st_mtime):
        name = entry.name
        if name.endswith(".tmp"):
            if now - entry.stat().st_mtime > 60:  # a writer that died mid-write
                _unlink(entry.path)
            continue
        if taken >= MAX_REQUESTS_PER_POLL:
            break
        taken += 1
        rid = name[:-5] if name.endswith(".json") else ""
        try:
            raw = b"" if entry.stat().st_size > MAX_REQUEST_BYTES else Path(entry.path).read_bytes()
        except OSError:
            raw = b""
        _unlink(entry.path)
        request = parse_request(rid, raw)
        if request is not None:
            out.append(request)
    return out


def parse_request(rid: str, raw: bytes) -> Optional[dict]:
    if not _RID_RE.match(rid or "") or not raw:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict) or data.get("kind") not in ("access", "network"):
        return None
    # ``candidate``: a failed program call that printed no refusal; its hosts are only where it may have gone
    out = {"id": rid, "kind": data["kind"], "session_id": _short(data.get("session_id"), 128),
           "tool": _short(data.get("tool"), 64), "strength": data.get("strength") if data.get("strength") in
           ("strong", "weak", "candidate") else "strong"}
    try:
        out["t"] = float(data.get("t") or 0.0)
    except (TypeError, ValueError):
        out["t"] = 0.0
    try:  # how long the hook waits (its budget under core's hook timeout)
        out["wait"] = min(max(float(data.get("wait")), 0.0), MAX_WAIT)
    except (TypeError, ValueError):
        out["wait"] = DEFAULT_WAIT
    if data.get("zero_wait") is True and out["strength"] == "candidate":
        # a call that SUCCEEDED: the launcher looks at OpenShell's records once and never waits for one to come
        out["zero_wait"] = True
        try:  # when the call ended (the hook's clock): its own time window is ``t`` .. ``until``
            out["until"] = float(data.get("until") or 0.0)
        except (TypeError, ValueError):
            out["until"] = 0.0
    if data["kind"] == "access":
        if data.get("succeeded") is True:
            # A call that did not fail: the launcher asks only for a path the host has (``Cards.raise_access``).
            out["succeeded"] = True
        from .layout import names_local_path

        paths = []
        for item in (data.get("paths") or [])[:4]:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str) or len(item["path"]) > 1024:
                continue
            if not names_local_path(item["path"]):
                continue  # the sandbox wrote this: a path named any other way is never opened, and gets no card
            # ``assumed``: nothing showed what a failed call did to the path (``Cards.raise_access``).
            paths.append({"path": item["path"], "access": "read_write" if item.get("access") == "read_write" else "read",
                          "missing": bool(item.get("missing")),
                          **({"assumed": True} if item.get("assumed") is True else {})})
        if not paths:
            return None
        out["paths"] = paths
    else:
        hosts = []
        for item in (data.get("hosts") or [])[:4]:
            if not isinstance(item, dict) or not isinstance(item.get("host"), str) or len(item["host"]) > 253:
                continue
            port = item.get("port")
            port = port if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536 else None
            # where the hook found it: named by the refusal itself, or only in the result's text (a candidate the
            # launcher checks against OpenShell's records before any card)
            source = item.get("source") if item.get("source") in ("refusal", "text") else None
            hosts.append({"host": item["host"], "port": port, "source": source})
        out["hosts"] = hosts
    return out


def _short(value, limit: int) -> Optional[str]:
    return value[:limit] if isinstance(value, str) and value else None


def _unlink(path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
