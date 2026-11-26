"""Inside the sandbox: a card resolves in the turn that raised it.

Registered by the plugin only in a sandboxed backend (the launcher sets ``HERMES_SANDBOX_VERDICTS`` and
``HERMES_SANDBOX_REQUESTS``). ``transform_tool_result`` looks at every tool result; most stop at a
cheap regex. When one shows a sandbox refusal (OpenShell's proxy: ``policy_denied`` / a refused
CONNECT; Windows or Linux: access denied, or "not found", on a path outside the grants), or a terminal /
execute_code call failed without showing one and named a host (``curl -s`` prints nothing when the proxy
refuses it: the hosts go as candidates, which the launcher checks against OpenShell's own records), the hook

1. relays it to the launcher as a request file in the sandbox's writable box (the launcher checks it on
   the host by the same rules as any relayed refusal and raises the card, or says why there is none);
2. waits, bounded, for the host's verdict on that card in the read-only verdict folder;
3. replaces the tool result: the original refusal plus the outcome. Allowed: retry now (the launcher
   writes ``allowed`` only once the policy revision carrying the rule reports loaded, a few seconds after
   the answer). End the reply (one instruction, put first in the result, and given again
   at once if the agent retries anyway): the sandbox restarts (folders), applies the rule when the reply
   ends (builds whose policy reload cuts open connections), or had not loaded the rule when the
   launcher's bounded wait ended (``unconfirmed``); the launcher then steers the agent or sends the chat a
   continuation once the change is in place. Denied: the user's reason. No answer in time: the refusal
   plus "the user has not answered".

A terminal / execute_code call that did not fail and named a host (``curl -s URL | head``, ``curl URL; echo done``:
exit 0 whatever the proxy did, with curl's refusal line in the output or with nothing) is judged by OpenShell's
records, not by its text. Where the launcher copies the records of refusals into the verdict file while such a call
runs (``refused``; the driver says so with ``HERMES_SANDBOX_REFUSALS``, whose value is how many seconds its feed
can trail a refusal), the hook looks there for a host the call named, refused inside the call, for at most that
long (``RECORD_SETTLE_SHOWN`` when the command named a host and the output shows a network refusal's words). With
one it relays those hosts, marked ``zero_wait``; the launcher looks at the records once and the call is held on the
card like any refused one. Where the launcher copies nothing (a driver without such a feed), only a call whose
output shows a network refusal's words relays the hosts its command named, as candidates the launcher checks
against the records. A call that
named no host is never held for a website, and a successful result of any other tool that shows a refusal's words and names no
host is not relayed (a skill's or a note's text; a Hermes tool with services of its own still is: the launcher
knows them).

A terminal / execute_code call that did not fail can also have been refused a folder (``ls A; ls B`` exits 0 when
only A was refused; code that catches its error ends normally). OpenShell records no per-file events, so here the
output is read, narrowly: a line that says access was denied counts when it names a path the call's own command or
code named (``refusals.named_refusals``). The request is marked ``succeeded``: the launcher raises the card only
for a path the host has outside the sandbox's grants, and the call is held on the card like a failed one. Text such
a call prints about any other path is data.

A refused path is relayed with the access it needs itself (``refusals.refused_paths``): a write to another path in
the same command asks for no more. Where a failed call does not show what it did to the path (a script, a variable,
code), the path is relayed to read and marked ``assumed``: the launcher asks for read & write when the sandbox can
already read it.

The wait stays under core's hook timeout (``plugins.hook_callback_timeout``; a callback that times out
is abandoned and suppressed for a minute): ``min(HERMES_SANDBOX_CARD_WAIT, timeout - 10 s)``. The
launcher raises that timeout for the sandboxed backend in its managed scope so the default 120 s wait
fits.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Optional

from .launcher import categories
from .launcher.refusals import (CANDIDATE, NAMED_SCAN, PROGRAM_TOOLS, RECORD_POLL, RECORD_SETTLE_MAX,
                                RECORD_SETTLE_SHOWN, ZERO_WAIT_SKEW, candidate_destinations, failed_result,
                                maybe_refused, named_destinations, refused_accesses, refused_destinations,
                                shows_network_refusal)
from .launcher.verdicts import END_REPLY, FINAL, VERDICTS_FILE

log = logging.getLogger("openshell.sandbox_hook")

VERDICTS_ENV = "HERMES_SANDBOX_VERDICTS"
REQUESTS_ENV = "HERMES_SANDBOX_REQUESTS"
WAIT_ENV = "HERMES_SANDBOX_CARD_WAIT"
# Set by a driver whose launcher hears of refusals as they happen and copies them into the verdict file (a driver
# that follows OpenShell's record stream). Only then does a program call that did not fail look there. Its value:
# for how many seconds after such a call returned a record of a refusal inside it can still arrive (``feed_settle``).
REFUSALS_ENV = "HERMES_SANDBOX_REFUSALS"
DEFAULT_WAIT = 120.0
MARGIN = 10.0       # stay this far under core's hook timeout
ACK_WAIT = 8.0      # the launcher answers a request within about a second; silence means no launcher cards
POLL = 0.4
HOOK_TIMEOUT_PIN = 135  # what the launcher pins plugins.hook_callback_timeout to (DEFAULT_WAIT + margin)
RELAYED_PATHS = 4   # how many paths of one request the launcher reads (verdicts.parse_request)


def active() -> bool:
    return bool(os.environ.get(VERDICTS_ENV)) and bool(os.environ.get(REQUESTS_ENV))


def register(ctx) -> None:
    if active():
        ctx.register_hook("transform_tool_result", on_tool_result)


def on_tool_result(tool_name: str = "", args=None, result=None, session_id: str = "", tool_call_id: str = "",
                   duration_ms=None, status=None, **_) -> Optional[str]:
    try:
        return resolve(tool_name, args, result, session_id=session_id, duration_ms=duration_ms,
                       tool_call_id=tool_call_id, status=status)
    except Exception:  # never break a tool result over a card
        log.debug("sandbox card hook failed", exc_info=True)
        return None


# -- the wait -----------------------------------------------------------------------------------------

def budget() -> float:
    try:
        want = float(os.environ.get(WAIT_ENV) or DEFAULT_WAIT)
    except ValueError:
        want = DEFAULT_WAIT
    try:
        from hermes_cli.plugins import _resolve_hook_callback_timeout

        core = float(_resolve_hook_callback_timeout())
    except Exception:
        core = 30.0
    if core <= 0:  # hooks run unbounded on the caller's thread
        return max(0.0, want)
    return max(0.0, min(want, core - MARGIN))


def resolve(tool_name: str, args, result, *, session_id: str = "", duration_ms=None, tool_call_id: str = "",
            status=None, sleep=time.sleep, clock=time.monotonic) -> Optional[str]:
    """*status*: core's verdict on the call (``ok`` / ``error``) where core passes one. A successful call's
    output is read for refused paths only where a terminal or execute_code call named the path itself
    (``refusals.named_refusals``)."""
    if result is None:
        return None
    ended = time.time()
    refused = maybe_refused(result)
    if not refused and tool_name not in PROGRAM_TOOLS:
        return None
    args = args if isinstance(args, dict) else {}
    requests = []
    # The refused paths in the order the result names them, as many as the launcher reads of one request. The
    # launcher leaves out those the sandbox already has and raises two cards at most.
    paths = [found for found in refused_accesses(tool_name, args, result, status=status)
             if not (found[2] and _visible_parent(found[0]))][:RELAYED_PATHS] if refused else []
    started = ended - (float(duration_ms) / 1000.0 if isinstance(duration_ms, (int, float)) else 0.0)
    base = {"session_id": session_id or None, "tool": tool_name or None, "t": started}
    if paths:
        # A call that did not fail is marked: its paths come from what it printed about paths it named, and the
        # launcher asks only for one the host has. A path whose access is assumed is marked too.
        requests.append({**base, "kind": "access",
                         "paths": [{"path": str(p), "access": a, "missing": m,
                                    **({"assumed": True} if assumed else {})} for p, a, m, assumed in paths],
                         **({} if failed_result(tool_name, result, status) else {"succeeded": True})})
    hosts, strength = refused_destinations(tool_name, args, result, status=status) if refused else ([], None)
    unsaid = False
    if strength and (hosts or (strength == "strong" and _asks_unnamed(tool_name, result, status))):
        requests.append({**base, "kind": "network", "strength": strength,
                         "hosts": [{"host": h, "port": p, "source": s} for h, p, s in hosts]})
    else:
        # A failed program call whose result shows no refusal (``curl -s``: exit 7 and "HTTP 000"): the hosts it
        # named go to the launcher as candidates. It answers within a few seconds: a card (this call is then held
        # like any refused one) when OpenShell's records show one of them refused, else nothing.
        named = candidate_destinations(tool_name, args, result, status=status)
        if named:
            unsaid = True
            requests.append({**base, "kind": "network", "strength": CANDIDATE,
                             "hosts": [{"host": h, "port": p, "source": s} for h, p, s in named]})
        else:
            # A program call that did not fail (``curl URL; echo done`` exits 0 whatever the proxy did). What it
            # printed does not decide: the hosts it named are relayed when OpenShell's records show one refused
            # inside the call. A call that named no host waits for nothing.
            named = named_destinations(tool_name, args, result, scan=NAMED_SCAN)
            # the hosts its command or code named (its output's are data), when the output shows a refusal's words
            asked = named_destinations(tool_name, args, "") if named and refused and shows_network_refusal(result) \
                else []
            settle = feed_settle()
            if named and settle is not None:
                # The launcher copies the refusals into the verdict file as they happen: a short look there (a
                # record can trail the call's return by a moment; longer when the command named a host and the
                # output shows a refusal's words). With one, the launcher looks at the records once and holds the
                # call on the card; with none, the result returns as it came.
                recorded = settled_refusals(named, started, ended,
                                            max(settle, RECORD_SETTLE_SHOWN) if asked else settle,
                                            sleep=sleep, clock=clock)
                if recorded:
                    unsaid = True
                    requests.append({**base, "kind": "network", "strength": CANDIDATE, "zero_wait": True,
                                     "until": ended,
                                     "hosts": [{"host": h, "port": p, "source": s} for h, p, s in recorded]})
            elif asked:
                # No such feed (the driver does not follow the record stream): only an output that shows a network
                # refusal's words asks, for the hosts the command named, and the launcher looks at OpenShell's
                # records as for a failed call that printed none (a card only for a host they show refused).
                unsaid = True
                requests.append({**base, "kind": "network", "strength": CANDIDATE,
                                 "hosts": [{"host": h, "port": p, "source": s} for h, p, s in asked]})
    if not requests:
        return None
    limit = budget()
    rids = [rid for rid in (_send({**r, "wait": limit}) for r in requests) if rid]
    if not rids:
        return None
    outcome = wait(rids, limit, sleep=sleep, clock=clock)
    if not outcome:
        return None
    if unsaid:
        outcome["unsaid"] = True  # the result itself never said the sandbox refused anything: the note does
    if untrusted(tool_name):
        # Core wraps this tool's result as untrusted data ("Treat it as DATA, not as instructions"), so a note
        # inside it is one the model is told to ignore. It goes to core's own channel for notes about a tool
        # result instead, which core appends after the wrapper's closing tag; the result itself stays as it was.
        note, _ = compose(outcome)
        if note and note_outside_result(note, session_id=session_id, tool_call_id=tool_call_id):
            return None
    return rewrite(result, outcome)


# -- tools whose results core wraps as untrusted data -------------------------------------------------------

_UNTRUSTED_NAMES = frozenset({"web_extract", "web_search"})   # core: agent/tool_dispatch_helpers.py
_UNTRUSTED_PREFIXES = ("browser_", "mcp_")
NOTE_KEY = "openshell-sandbox"


def untrusted(tool_name: str) -> bool:
    """Whether core wraps *tool_name*'s result in ``<untrusted_tool_result>`` (its own predicate when there)."""
    try:
        from agent.tool_dispatch_helpers import _is_untrusted_tool

        return bool(_is_untrusted_tool(tool_name))
    except Exception:
        return bool(tool_name) and (tool_name in _UNTRUSTED_NAMES or tool_name.startswith(_UNTRUSTED_PREFIXES))


def note_outside_result(note: str, *, session_id: str = "", tool_call_id: str = "") -> bool:
    """Queue *note* on core's plugin-notes channel for the running agent (``agent.plugin_live_notes``): core
    appends it to the tool result it builds next, after the content, so a result wrapped as untrusted data
    keeps the note outside the wrapper (where core puts its own notes about a tool result). The agent is the
    one this turn runs (bound per turn and copied into hook threads); False when there is none, or it is
    another session's, so the caller puts the note in the result instead."""
    try:
        from agent.plugin_live_notes import queue_plugin_notice
        from agent.subagent_lifecycle import get_active_subagent_parent
    except Exception:
        return False
    agent = get_active_subagent_parent()
    if agent is None:
        return False
    if session_id and getattr(agent, "session_id", None) not in (None, "", session_id):
        return False
    queue_plugin_notice(agent, f"{NOTE_KEY}:{tool_call_id or secrets.token_hex(4)}", note)
    return True


def _asks_unnamed(tool_name: str, result, status) -> bool:
    """Whether a network refusal's words that name no host are relayed at all (the launcher then waits for the
    next card OpenShell's own draft raises in the chat). A call that failed: yes (pip's "Tunnel connection failed:
    403" names no host). A Hermes tool with services of its own: yes, its refused service comes back inside a
    successful-shaped result and the launcher knows its hosts. Any other successful result is data that happens to
    hold such words (a skill's text, a note): nothing is relayed and the call is not held."""
    return failed_result(tool_name, result, status) or categories.of_tool(tool_name) is not None


def _visible_parent(path: Path) -> bool:
    """A "not found" whose folder the sandbox can list is a real miss, not a path outside the grants."""
    try:
        parent = Path(path).parent
        return parent.is_dir() and os.listdir(parent) is not None
    except OSError:
        return False


def _send(request: dict) -> Optional[str]:
    directory = Path(os.environ[REQUESTS_ENV])
    rid = f"{int(time.time() * 1000):x}-{secrets.token_hex(4)}"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        tmp = directory / f"{rid}.tmp"
        tmp.write_text(json.dumps(request, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, directory / f"{rid}.json")
        return rid
    except OSError:
        log.debug("could not relay a refusal to the launcher", exc_info=True)
        return None


def read_verdicts() -> dict:
    path = Path(os.environ.get(VERDICTS_ENV) or ".") / VERDICTS_FILE
    for _ in range(3):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            time.sleep(0.02)  # the launcher replaces the file atomically; a read can race the rename
    return {}


def feed_settle() -> Optional[float]:
    """How long the launcher's copy of OpenShell's refusals can trail a refusal, in seconds, as the driver said
    (``REFUSALS_ENV``; at most ``RECORD_SETTLE_MAX``). None: the launcher copies nothing (no such feed)."""
    raw = os.environ.get(REFUSALS_ENV)
    if not raw:
        return None
    try:
        return min(max(float(raw), 0.0), RECORD_SETTLE_MAX)
    except ValueError:
        return None


def settled_refusals(hosts: list, started: float, ended: float, limit: float, *, sleep=time.sleep,
                     clock=time.monotonic) -> list:
    """``recorded_refusals``, looked for until one shows or *limit* seconds have passed since the call returned
    (the record of a refusal at the end of a call can reach the verdict file a moment after it)."""
    begun = clock()
    while True:
        found = recorded_refusals(hosts, started, ended)
        if found or clock() - begun >= limit:
            return found
        sleep(RECORD_POLL)


def recorded_refusals(hosts: list, started: float, ended: Optional[float] = None) -> list:
    """Those of *hosts* (``(host, port, source)``) the verdict file lists as refused between *started* and *ended*
    (no later bound when None), give or take ``ZERO_WAIT_SKEW``: what OpenShell's records show for the time the
    call ran (asked only where the launcher copies them there: ``REFUSALS_ENV``). One read of the file: one that
    cannot be read this instant, like one with no such list, shows nothing."""
    if not hosts:
        return []
    try:
        data = json.loads((Path(os.environ.get(VERDICTS_ENV) or ".") / VERDICTS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    table = data.get("refused") if isinstance(data, dict) else None
    if not isinstance(table, dict):
        return []
    out = []
    for item in hosts:
        t = table.get(item[0])
        if isinstance(t, (int, float)) and not isinstance(t, bool) and t >= started - ZERO_WAIT_SKEW \
                and (ended is None or t <= ended + ZERO_WAIT_SKEW):
            out.append(item)
    return out


def wait(rids: list[str], limit: float, *, sleep=time.sleep, clock=time.monotonic) -> Optional[dict]:
    """The verdicts for *rids*: ``{"targets": [...], "timed_out": bool, "stopped": bool, "details": [...]}``,
    or None when the launcher raised no card for any of them (nothing to tell the model)."""
    start = clock()
    keys: list[str] = []
    while True:
        elapsed = clock() - start
        snap = read_verdicts()
        answers = [(snap.get("requests") or {}).get(rid) for rid in rids]
        targets = snap.get("targets") or {}
        if all(isinstance(a, dict) for a in answers):
            keys = list(dict.fromkeys(k for a in answers if a.get("status") == "card" for k in a.get("keys") or []))
            if not keys:
                return None
            found = [targets.get(k) or {"key": k, "status": "asking"} for k in keys]
            if any(a.get("stopped") for a in answers):
                return {"targets": found, "timed_out": False, "stopped": True}
            if all(t.get("status") in FINAL for t in found):
                return {"targets": found, "timed_out": False, "stopped": False}
        elif elapsed >= ACK_WAIT:
            return None
        if elapsed >= limit:
            if not keys:
                return None
            return {"targets": [targets.get(k) or {"key": k, "status": "asking"} for k in keys], "timed_out": True,
                    "stopped": False}
        sleep(POLL)


# -- what the model is told ---------------------------------------------------------------------------

def _what(t: dict) -> str:
    if t.get("kind") == "access":
        verb = "read & write" if t.get("access") == "read_write" else "read"
        return f"{verb} access to {t.get('path')}"
    label = t.get("label")
    if t.get("tool"):  # one card for a Hermes web tool: every service it rotates through
        hosts = ", ".join(t.get("hosts") or [])
        return f"Hermes's {label or t['tool']} tool to reach its web services" + (f" ({hosts})" if hosts else "")
    return f"network access to {t.get('host')}" + (f" ({label})" if label else "")


def _retry(t: dict) -> str:
    """What to retry: the web tool by name (it picks its service itself), else the refused request."""
    tool = t.get("name") if "name" in t else t.get("tool")  # the tool that asked, where the launcher names it
    return f"call {tool} again now with the same arguments" if tool else "retry the request now"


def _scope(t: dict) -> str:
    return ("and saved it to the sandbox's policy" if t.get("scope") == "always"
            else "until the sandbox is switched off")


# The one instruction an end-the-reply answer carries: a retry in this reply fails the same way, and the
# launcher continues the chat by itself.
STOP_NOW = "End your reply now in one short sentence and call no more tools"


def _seconds(value) -> str:
    try:
        return f"{float(value):.0f} seconds"
    except (TypeError, ValueError):
        return "a while"


def note_for(t: dict) -> str:
    status, what = t.get("status"), _what(t)
    if status == "allowed":
        if t.get("kind") == "access":
            return f"The sandbox has {what} now. Retry."
        how = "" if t.get("tool") else " (http and https, any program in the sandbox)"
        return f"The user allowed {what}{how} {_scope(t)}. The sandbox has loaded the rule: {_retry(t)}."
    if status == "allowed_later":
        return (f"The user allowed {what} {_scope(t)}. This sandbox applies it after your reply, so retrying now "
                f"fails. {STOP_NOW}; the chat continues by itself once it is in place.")
    if status == "restarting":
        # The launcher interrupts the turn itself as the user answers (cards.Cards._restart_soon), so the agent
        # normally reads this only in the history of the continuation; the instruction stays for a turn the
        # launcher could not reach.
        return (f"The user allowed {what} {_scope(t)}. The sandbox restarts now to add it, which ends this reply, so "
                f"retrying now fails. {STOP_NOW}; the chat continues by itself after the restart.")
    if status == "unconfirmed":
        return (f"The user allowed {what} {_scope(t)}, but the sandbox had not loaded the new rule after "
                f"{_seconds(t.get('waited'))}, so retrying now may fail. {STOP_NOW}; the chat continues by itself "
                f"once it is in place.")
    if status == "applying":  # the hook's own wait ended while the rule was loading
        return (f"The user allowed {what} {_scope(t)}; the sandbox is still loading the new rule, so retrying "
                f"now may fail. {STOP_NOW}; the chat continues by itself once it is in place.")
    if status == "denied":
        reason = _one_line(t.get("reason") or "") or "The user declined this in the chat."
        return f"The user denied {what}. Reason: {reason} Don't retry it; continue without it or ask the user."
    if status == "failed":
        return (f"The user allowed {what}, but the sandbox could not apply it: "
                f"{_one_line(t.get('error') or '') or 'unknown error'}.")
    return ""


def _one_line(text: str) -> str:
    return " ".join(str(text).split())


def compose(outcome: dict) -> tuple[str, bool]:
    """The ``[Sandbox] `` note for *outcome* (empty when there is nothing to say) and whether it ends the
    reply (then it goes first, so the instruction is what the model reads first)."""
    targets = outcome.get("targets") or []
    stop = False
    lead = ""
    if outcome.get("unsaid") and not outcome.get("timed_out"):
        blocked = ", ".join(str(t["host"]) for t in targets if t.get("kind") != "access" and t.get("host"))
        lead = f"The sandbox blocked this call's connection to {blocked}. " if blocked else ""
    if outcome.get("stopped"):
        note = "The user stopped this turn before answering the sandbox's card."
    elif outcome.get("timed_out"):
        loading = [t for t in targets if t.get("status") == "applying"]
        open_ = [t for t in targets if t.get("status") not in FINAL and t.get("status") != "applying"]
        done = [note_for(t) for t in targets if t.get("status") in FINAL or t.get("status") == "applying"]
        stop = bool(loading) or any(t.get("status") in END_REPLY for t in targets)
        tail = []
        if open_:
            asked = ", ".join(_what(t) for t in open_)
            tail = [f"The sandbox refused this; a card in the chat asks the user for {asked}, and the user has "
                    f"not answered. Tell the user what you need and why, then stop; if they allow it, the chat "
                    f"continues by itself."]
        note = " ".join([*done, *tail]).strip()
    else:
        note = " ".join(n for n in (note_for(t) for t in targets) if n)
        stop = any(t.get("status") in END_REPLY for t in targets)
    return ("[Sandbox] " + lead + note if note else ""), stop


def rewrite(result, outcome: dict) -> str:
    note, stop = compose(outcome)
    if not note:
        return result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
    text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        data = None
    if isinstance(data, dict):
        rest = {k: v for k, v in data.items() if k != "sandbox"}
        return json.dumps({"sandbox": note, **rest} if stop else {**rest, "sandbox": note}, ensure_ascii=False)
    return f"{note}\n\n{text}" if stop else f"{text}\n\n{note}"
