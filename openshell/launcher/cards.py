"""In-chat sandbox cards: blocked network requests and folder refusals become approval cards in the
active chat, and the card resolves inside the turn that raised it.

Sources (all on the host; the sandbox can trigger a card only through what its enforcer refused):

* Relayed refusals from the in-sandbox hook (``sandbox_hook.py``, ``verdicts.py``): a tool result that
  shows a refusal is relayed as a request file the moment the tool returns; the launcher checks it here
  and raises the card (or answers why there is none) while the hook waits for the verdict. A terminal or
  execute_code call that failed without showing one (``curl -s``) relays the hosts it named as candidates:
  a card, with the call held, only for one OpenShell's own records show refused (``CANDIDATE_WAIT``). One that
  did not fail although a program in it was refused (``curl -s URL | head``, ``curl URL; echo done``: exit 0)
  relays when the launcher's record feed shows a host it named refused inside the call (the hook looks for a
  moment, as long as the driver says its feed can trail a refusal), and the launcher then looks at the records
  once (``ZERO_WAIT_SKEW``).
  Under a driver with no such feed, only such a call whose output shows a network refusal's words relays the
  hosts its command named, as candidates. Every other successful call returns as it came, except one that was
  refused a path its own command or code named (Folders, below).
* Network: OpenShell drafts a proposal for every connection it blocks. While a turn runs the launcher
  lists the driver's proposals and folds them into host cards (Hermes's own fetches outside tool calls
  stay on the Sandbox page without a card). A card raised this way for a program the agent ran has no tool
  call held on it, so the launcher pauses that chat's turn until the user answers (``PAUSE_WAIT``).
* Folders: a relayed ``tool.complete`` that reports a refused path (permission denied; "no such file" /
  "file not found" for a path that exists on the host) raises a ``kind: "access"`` card for the nearest
  existing host folder, checked by the same rules as Add folder and against the running sandbox's
  grants (never a credential path, never something already granted). A terminal or execute_code call that did
  not fail reports only a denied path its own command or code named (``refusals.named_refusals``; the hook marks
  its request ``succeeded``), and gets a card only when the host has that path: nothing but the call's own text
  says it was refused, so no folder above a path the host lacks is asked for.

One card per host: http and https (80 and 443, plus any other port seen for it), any program in the
sandbox. Hermes's own tool backends are labelled by the tool that uses them ("Web search
(api.keenable.ai)").

Answers come only from the desktop's side of the relayed chat socket: a JSON-RPC response to the card's
server request id, or ``approval.respond`` / ``request.answer`` naming it (a replayed card). Frames the
sandbox sends that claim a launcher card are dropped, and approval frames it sends lose every access
field (``ACCESS_FIELDS``), so the sandbox can neither raise nor answer a launcher card.

Scopes (``SCOPE_OF`` maps the desktop's choice ids): **Allow** lasts until the sandbox is switched off
(``Supervisor.temporary``: part of every launch while this launcher runs, never saved); **Always
allow** is saved in spec.yaml (the stored OpenShell policy); **Deny** carries the user's reason.

Applying an answer:

* ``deny``: OpenShell rejects the host's pending proposals (no policy change); the verdict tells the
  waiting hook, else the reason is steered into the running turn or sent as a continuation.
* network allow: every answer given within ``NET_BATCH_WINDOW`` goes into ONE policy update. Builds
  whose live reload keeps unchanged connections (``network_live_interrupts`` false; Windows: the pinned
  ``policy-reload-keeps-streams`` build) apply it at once, mid-turn. The verdict turns ``allowed`` (the hook
  tells the agent to retry now) only once the driver reports the policy revision carrying the rule
  loaded (a few seconds; the driver waits at most ``LOAD_TIMEOUT``). A revision still not
  loaded then is ``unconfirmed``: the hook ends the reply and says so, no second card is raised for the
  host, and the launcher keeps checking (``LOAD_CONFIRM_MORE``) and then steers or continues the chat, or
  withdraws the grant if the sandbox rejected it. Builds whose reload cuts open connections (the model's
  reply included; Windows without ``policy-reload-keeps-streams``) apply it once the turns it would cut have
  stopped, the way a folder answer restarts: when a hook waits on the card, the launcher sends
  ``session.interrupt`` for the answering chat's turn before the hook gets its verdict (the turn ends at that
  tool result, before another model call; the model is not asked to end its reply), applies the update once
  the backend reports the turn stopped (``SOON_SETTLE`` later; at most ``INTERRUPT_STOP_WAIT``), and the chat
  gets a continuation so the agent resumes by itself. Other chats' turns are not stopped (an interrupted reply
  shows "Response stopped" and its continuation starts over): while one of them streams a model reply, i.e.
  runs with no tool call in flight, the answering chat's tool call keeps waiting (its row still runs) and is
  stopped once that reply ended, at most ``OTHER_REPLIES_WAIT`` and ``HOLD_MARGIN`` before its hook would give
  up. An answer for a card that paused its chat's turn (raised from OpenShell's draft for a program the agent
  ran) loads the same way once that turn has stopped, and the reply continues. Any other answer no hook waits
  for (one given after the hook's wait or the turn ended) and a removal apply when the sandbox is idle; the
  chat that asked is continued with the outcome. Such an update cuts background transfers too: each chat
  whose background processes still run (the backend's ``process.list``) gets one ``BG_CUT_NOTE``, in its
  continuation or else with its next prompt.
* An Allow also resolves the chat's other open cards for hosts the new rule covers (a site card for one of a web
  tool's services when the tool's card is allowed): they are withdrawn and their hooks get the same verdict.
* folder allow (Allow or Always allow, in the turn or answered late): one restart (file rules are fixed at
  start), as soon as the turns it would cut have stopped. The model is never asked to end its reply: if the
  answering chat's turn runs, the launcher sends ``session.interrupt`` for it (before the waiting hook gets
  its verdict, so the turn ends at that tool result, before another model call) and restarts once the
  backend reports the turn stopped (``SOON_SETTLE`` later; at most ``INTERRUPT_STOP_WAIT``). Other chats'
  running turns get ``OTHER_TURNS_WAIT``, then are interrupted too and continued after the restart. A refused
  call that slips in meanwhile gets the same ``restarting`` answer, no new card. ``Supervisor.restart``
  sets ``restarting`` with the reason (``restart: {reason: folder|remove, folder}``) before the backend
  stops; after the backend is ready the chat gets a continuation. A grant removed on the Sandbox page still
  restarts when the sandbox is idle.

Notes for the agent are single ``[Sandbox] `` lines (newlines in a user's reason become spaces), put before
the user's next prompt with one blank line, the format the desktop lifts into a system row.

The relay itself (always on): each authenticated ``/api/ws`` upgrade is relayed frame by frame with no
WebSocket extensions negotiated (the proxy strips ``Sec-WebSocket-Extensions``), so frames stay readable
and dropping or rewriting one cannot desync a compression context. When the backend's side ends, or a
restart or stop begins (``Supervisor.on_down``), the desktop's socket is closed with 1012 at once.
"""
from __future__ import annotations

import asyncio
import calendar
import copy
import fnmatch
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Optional

from . import categories
from .refusals import (DENIED_RE as _DENIED_RE, MISSING_RE as _MISSING_RE, WRITE_TOOLS as _WRITE_TOOLS,  # noqa: F401
                       CANDIDATE, KEYLESS_WEB_HOSTS, ZERO_WAIT_SKEW, card_host, denied_in_events, failed_result,
                       host_path, refused_between, refused_paths)
from .verdicts import FINAL, Verdicts, dir_key, net_key, read_requests

log = logging.getLogger("openshell.cards")

REQUEST_PREFIX = "sandbox-card-"
_RESERVED_PREFIXES = (REQUEST_PREFIX, "sandbox-access-")  # request ids only the launcher may use
_CALL_PREFIX = "sandbox-call-"      # launcher-originated RPCs on a desktop connection (replies swallowed)
# The desktop's choice ids: "once" is its main Allow button. Allow lasts until the sandbox is switched off.
CHOICES = ["once", "always", "deny"]
SCOPE_OF = {"once": "allow", "allow": "allow", "session": "allow", "always": "always", "deny": "deny"}
SCOPE_LABEL = {"allow": "until the sandbox is switched off", "always": "saved to the sandbox's policy"}
DISABLE_ENV = "OPENSHELL_CARDS"     # "0": relay only, no cards
MAX_MESSAGE = 32 * 1024 * 1024
IDLE_SETTLE = 2.0                   # seconds the sandbox must stay idle before a restart
POLL_INTERVAL = 2.0
REQUEST_POLL = 0.3                  # the hook's request files
NET_BATCH_WINDOW = 0.4              # answers clicked within this window share one policy update
POLL_GRACE = 30.0                   # keep listing proposals this long after the last turn ended
USAGE_DATA_HOLD = 10.0              # a changed usage data answer must stand this long before its policy update
# A blocked request becomes a card only when a tool call was running, or ran within this many seconds,
# when the launcher first saw it. Hermes's own fetches (model catalog, update checks the desktop triggers)
# go through the same interpreter but outside tool calls; those stay on the Sandbox page without a card.
TOOL_WINDOW = 15.0
# OpenShell's drafts are its record of every refusal, Hermes's own background fetches included (models.dev,
# raw.githubusercontent.com, hermes-agent.nousresearch.com), and those stay blocked without asking.
# A draft raises a card only when (a) a waiting hook request named its host (the hook relayed the agent's refusal,
# the draft is OpenShell's record confirming it), or (b) a program the agent ran was refused while that call was
# open: a tool in AGENT_TOOLS (its own process tree), the draft's program not the backend's own interpreter (the
# backend runs Hermes's internals and in-process tools like web_extract), and listed no earlier than the call
# started. A call that just ended still counts for AGENT_TOOL_GRACE seconds (the listing trails the refusal), and
# longer when the draft itself says the refusal fell inside the call (AGENT_DRAFT_LATE, below).
# Anything else goes to Activity only: no card, no follow-up message.
AGENT_TOOLS = frozenset({"terminal", "execute_code"})
AGENT_TOOL_GRACE = 5.0
# OpenShell stamps a draft with the time its proxy refused the connection (``first_seen`` / ``last_seen``). Where its
# supervisor reports refusals to the gateway in batches the plugin cannot shorten (the Docker driver builds the
# supervisor's environment itself: every 10 s, measured 4 to 11 s from the refusal to the listing), a short call and
# often its whole turn are over before the draft is listed, and AGENT_TOOL_GRACE with them. A draft whose own
# refusal time lies inside one of the chat's terminal / execute_code calls is that call's however late it is listed,
# for calls that ended at most AGENT_DRAFT_LATE ago (the watch lists drafts for POLL_GRACE after a turn). A time
# without a zone is not used: there the listing-time test above stays the only one.
#
# Which of a draft's times is a refusal's (``_draft_news``). ``first_seen`` is when the refusal that made the draft
# happened; OpenShell never changes it. ``last_seen`` is when the draft was last stored: the latest refusal folded
# into it (the hit count grows), but also every policy change, after which OpenShell evaluates its pending drafts
# again and stores each one with that moment (an Allow is such a change, and it lands inside or just after the call
# that was held on the card). So a draft tells of a new refusal only in the listing that shows it for the first
# time (at ``first_seen``) or with a higher hit count than the listing before (at ``last_seen``). Listed again with
# the same count it says nothing new, whatever its times read, and no call is given it. A ``last_seen`` within
# AGENT_RESTAMP_NEAR of one the same listing shows to be a policy change's (a draft stored again with no new hit)
# is not used as a refusal's time either: one change stamps every pending draft within a moment.
AGENT_DRAFT_LATE = 30.0
AGENT_DRAFT_SKEW = 1.0              # the sandbox's clock against the launcher's
AGENT_CALL_SPANS = 8                # the calls remembered per chat for that test
AGENT_RESTAMP_NEAR = 1.0
RESTART_QUIET = 5.0                 # a restart waits this long after the last tool call (late proposals)
CHAT_GRACE = 600.0                  # a chat no desktop connection has shown for this long has ended
RUNNING_STALE = 900.0               # a turn with no event for this long (its desktop went away) is over
# A turn whose desktop connection went away while it ran (a renderer reload, a crash, a closed window) ends unseen
# when no connection shows its chat afterwards: the launcher asks the backend (``session.active_list``) whether it
# still runs, every DETACHED_POLL seconds while such a turn is counted; an ask unanswered in ACTIVE_LIST_WAIT is ignored.
DETACHED_POLL = 2.0
ACTIVE_LIST_WAIT = 1.5
# A runtime session id the backend refuses as one it does not hold (core's answer to a session-scoped call naming a
# stale id, e.g. the host backend's id of a chat the desktop sent to the sandboxed backend before resuming it there)
# leaves the relay's tracking: no turn counts as running under it and nothing is steered, interrupted or continued
# under it again. A note whose steer or continuation the backend refuses is tried again at most NOTE_RETRIES times,
# NOTE_BACKOFF seconds later the first time and twice as long each time after (at most NOTE_BACKOFF_MAX); then it
# goes with the chat's next prompt.
UNKNOWN_SESSION = (4001, "session not found")
NOTE_RETRIES = 4
NOTE_BACKOFF = 0.5
NOTE_BACKOFF_MAX = 4.0
GATE_TIMEOUT = 120.0
HOOK_WAIT = 120.0                   # a hook request that does not say how long it waits
CONTINUE_WAIT = 120.0               # how long a continuation waits for a desktop connection it can go out on
# A window that shows the chat resumes it by itself once it is connected again. One that shows another page
# resumes nothing: after RESUME_GRACE the launcher resumes the chat on that connection itself.
RESUME_GRACE = 3.0
RESUME_WAIT = 20.0                  # the bound on the backend's answer to that resume
RESUME_RETRY = 5.0                  # the pause before another try after a refusal
# The launcher's resume asks what the desktop asks when a chat is opened; a chat the desktop resumed or created
# before keeps the width, source and profile it named then.
RESUME_PARAMS = {"cols": 96, "source": "desktop", "defer_history": True, "omit_messages": True}
_RESUME_KEPT = ("cols", "source", "profile")
# What a chat says when it is next opened after a continuation that could not go out (no window was connected).
STOPPED_LINE = "This reply stopped when the sandbox restarted. Send your message again."
STOPPED_LINE_DELAY = 1.0            # after the desktop's resume was answered, so the line follows the chat's history
MAX_ACCESS_CARDS_PER_RESULT = 2
DEFAULT_DENY_REASON = "The user declined this in the chat."
MAX_REASON = 500
HOST_RULE_PREFIX = "allowed_host_"  # the rule a host card's answer adds (any program, http and https)
TOOL_RULE_PREFIX = "allowed_tool_"  # the rule a tool card's answer adds (the category's services, https)
TOOL_TARGET_PREFIX = "tool:"        # a tool card's target (``tool:web_extract``) where a site card has its host
TOOL_PORTS = (443,)
ANY_BINARY = "**"                   # OpenShell binary glob: every program in the sandbox
HOST_PORTS = (80, 443)
# A relayed refusal names candidate hosts (from the refusal and from the result's text); a card is raised only for
# one OpenShell's own records show its proxy refused (an OCSF denial event, or a draft it made for the refusal)
# from CONFIRM_LOOKBACK seconds before the tool call started on, looked for at most CONFIRM_WAIT seconds.
CONFIRM_WAIT = 5.0
CONFIRM_POLL = 0.5
CONFIRM_LOOKBACK = 10.0
# A failed terminal / execute_code call that printed no refusal relays the hosts it named as candidates
# (``refusals.candidate_destinations``): the same check, for at most CANDIDATE_WAIT, since most failed commands were
# refused nothing and their result waits for the answer. Measured over 236 confirmed refusals on Windows, OpenShell's
# record showed 0.13-1.74 s after the hook's request (median 0.16 s, 99% within 1 s). A record that comes later
# still raises the card from OpenShell's draft. A candidate is never carded without a record.
CANDIDATE_WAIT = 2.0
CANDIDATE_POLL = 0.25
# A terminal / execute_code call that SUCCEEDED can still have been refused a site: ``curl -s URL | head`` exits 0
# with nothing printed, so nothing above runs, and the card came seconds later from OpenShell's draft, when the
# model was already in its next step. Waiting for a record after every successful call that names a host would
# slow all of them, so nothing waits: while such a call is open the launcher copies what the driver's record feed
# shows refused into the verdict file (``_refusal_feed``, every ZERO_WAIT_FEED seconds; only a driver that hears of
# a refusal as it happens offers one: ``recent_refusals``), the hook reads that file when the call returns, and it
# asks only when a host the call named is there with a time inside the call. The launcher then looks at the
# records once (``_refused_in_call``), and raises the card with the call held when they show that host refused
# between the call's start and its end, give or take ZERO_WAIT_SKEW (refusals.py: the hook uses the same); a record
# from before the call started never counts, and a host is never carded on its name. Any other successful call
# returns as it did before, and the card from OpenShell's draft, which pauses the turn (``PAUSE_WAIT``), stays the
# backstop.
ZERO_WAIT_FEED = 0.01
CONTINUE_TAIL = "Continue where you left off: retry what the sandbox refused."
DENIED_TAIL = "Continue without it, or ask the user."  # ends a denial's note: there is nothing to retry
# A card raised from OpenShell's draft for a program the agent ran (``_draft_owner`` rule b) has no tool call held
# on it: the refusal showed in no failed result the hook could relay (the call exited 0, or named no host). The
# launcher pauses that chat's turn itself (``session.interrupt`` with ``resume``, as for a grant): at once when no
# tool call is in flight, else when the call in flight ends (stopping it earlier would kill the running command).
# The reply stays paused until every card of the pause is answered, at most PAUSE_WAIT, then continues with the
# outcome. The desktop shows a paused reply as continuing for 120 s and as stopped after that, so the wait ends
# well before, with room for the rule to load and the continuation to start.
PAUSE_WAIT = 90.0
UNANSWERED_TAIL = "Tell the user what you need and why, then stop; if they allow it, the chat continues by itself."
_NO_RETRY_TAILS = (DENIED_TAIL, UNANSWERED_TAIL)  # a continuation of only such notes gets no CONTINUE_TAIL
LOAD_CONFIRM_MORE = 60.0            # after the driver's bounded wait, keep checking an unconfirmed rule this long
LOAD_CONFIRM_POLL = 1.0
# A folder grant restarts the sandbox: the launcher interrupts the answering chat's running turn itself (the model
# is not asked to stop) and restarts as soon as it has stopped.
INTERRUPT_STOP_WAIT = 10.0          # the restart waits at most this long for an interrupted turn to stop
OTHER_TURNS_WAIT = 15.0             # ... and this long for other chats' turns, then stops them too (and continues them)
# A network answer on a build whose reload cuts open connections loads once the answering turn stopped, but not while
# another chat streams a model reply (the reload would cut it): it waits for that at most this long.
OTHER_REPLIES_WAIT = 120.0
HOLD_MARGIN = 15.0                  # a held tool call is released this long before its hook would give up
# The waiting hook gets its verdict only once the backend confirmed the interrupt (at most this long): otherwise core
# may start the next model call first and the reply shows "Operation interrupted: waiting for model response".
INTERRUPT_ACK_WAIT = 2.0
# Such a reload cuts background transfers too (a download in another chat can end early and still exit 0).
# Before the update the launcher asks the backend's process registry (``process.list`` for each chat a
# desktop connection shows, at most this long) which chats run background processes; each of them hears it once.
BG_LIST_WAIT = 1.5
BG_CUT_NOTE = "The network rule change closed open connections, including any in background processes."
SOON_QUIET = 3.0                    # late proposals: the managed gateway's denial flush is 2 s (gateway_service)
SOON_SETTLE = 0.5                   # after the last stopped turn (its history written) before the backend goes down
PROPOSALS_BEFORE_RESTART = 1.5      # bound on the last proposal listing before a restart
CLOSE_RESTART = 1012                # WebSocket close code "service restart" (RFC 6455 registry)
_LINE_BREAKS = re.compile(r"[\r\n\v\f\x85\u2028\u2029]+")


def one_line(text: str) -> str:
    """*text* as one line: a [Sandbox] note must not break the desktop's note block."""
    return _LINE_BREAKS.sub(" ", str(text)).strip()


def sandbox_note(text: str) -> str:
    """One ``[Sandbox] <note>`` line, whatever *text* started with."""
    body = one_line(text)
    while body.startswith("[Sandbox]"):
        body = body[len("[Sandbox]"):].lstrip()
    return f"[Sandbox] {body}"

# Access wording and targets on an approval: only the launcher's own cards may carry them. The desktop
# picks access copy from ``kind`` and shows the target fields, so a sandbox that set them could dress a
# command approval up as a folder or network grant the launcher never offered.
ACCESS_FIELDS = frozenset({"kind", "path", "paths", "access", "folder", "target", "host", "port", "hosts",
                           "destination", "binary", "method", "risk", "label", "ports"})
_TURN_EVENTS = frozenset({"message.start", "message.delta", "tool.start", "tool.complete", "tool.generating",
                          "tool.progress", "thinking.delta", "reasoning.delta"})
# Hermes's web tool backends by host (the vendor names match the profile's web.*_backend settings).
WEB_BACKENDS = {"api.keenable.ai": "keenable", "api.firecrawl.dev": "firecrawl", "mcp.exa.ai": "exa",
                "api.exa.ai": "exa", "search.parallel.ai": "parallel", "api.parallel.ai": "parallel",
                "api.tavily.com": "tavily", "api.search.brave.com": "brave", "api.perplexity.ai": "perplexity",
                "html.duckduckgo.com": "ddgs", "lite.duckduckgo.com": "ddgs"}
# Hermes's tools by name (categories.py): what a tool's card calls its category, and the category's id. One card
# and one grant per category, whichever of its tools asked (web_crawl uses web_extract's services).
_TOOL_LABEL = {tool: category.label for category in categories.CATEGORIES for tool in category.tools}
_TOOL_CANON = {tool: category.id for category in categories.CATEGORIES for tool in category.tools}
# The tools whose services Hermes's web tools share (``WEB_BACKENDS``): only such a tool names one of those hosts.
_WEB_TOOLS = frozenset(tool for category in categories.CATEGORIES if category.keyless for tool in category.tools)
# What a grant's row on the Sandbox page says its services let the agent reach beyond the hosts it lists.
_GRANT_NOTES = {"web_search": "Reads any public page through these services.",
                "web_extract": "Reads any public page through these services.",
                "browser": "Opens any public page through this service."}


def enabled() -> bool:
    return os.environ.get(DISABLE_ENV, "1") != "0"


def _without_access_fields(params: dict) -> dict:
    """*params* without access wording; the same object when there was none."""
    if not any(k in params for k in ACCESS_FIELDS):
        return params
    return {k: v for k, v in params.items() if k not in ACCESS_FIELDS}


def _reserved(rid) -> bool:
    return isinstance(rid, str) and rid.startswith(_RESERVED_PREFIXES)


# -- WebSocket framing (RFC 6455; no extensions are negotiated on a relayed connection) ---------------

def _unmask(payload: bytes, mask: bytes) -> bytes:
    if not payload:
        return payload
    key = (mask * (len(payload) // 4 + 1))[:len(payload)]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(key, "big")).to_bytes(len(payload), "big")


async def _read_frame(reader: asyncio.StreamReader):
    """One frame: (fin, opcode, unmasked payload, raw bytes as received)."""
    head = await reader.readexactly(2)
    n, ext = head[1] & 0x7F, b""
    if n == 126:
        ext = await reader.readexactly(2)
        n = int.from_bytes(ext, "big")
    elif n == 127:
        ext = await reader.readexactly(8)
        n = int.from_bytes(ext, "big")
    if n > MAX_MESSAGE:
        raise ConnectionError("frame too large to relay")
    mask = await reader.readexactly(4) if head[1] & 0x80 else b""
    payload = await reader.readexactly(n)
    return bool(head[0] & 0x80), head[0] & 0x0F, (_unmask(payload, mask) if mask else payload), head + ext + mask + payload


def _size(n: int, masked: bool) -> bytes:
    bit = 0x80 if masked else 0
    if n < 126:
        return bytes([bit | n])
    if n < 65536:
        return bytes([bit | 126]) + n.to_bytes(2, "big")
    return bytes([bit | 127]) + n.to_bytes(8, "big")


def server_text_frame(obj) -> bytes:
    """An unmasked text frame (server -> client direction)."""
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return bytes([0x81]) + _size(len(data), False) + data


def client_text_frame(obj) -> bytes:
    """A masked text frame (client -> server direction; RFC 6455 requires the mask)."""
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    mask = secrets.token_bytes(4)
    return bytes([0x81]) + _size(len(data), True) + mask + _unmask(data, mask)


def server_close_frame(code: int = CLOSE_RESTART, reason: str = "service restart") -> bytes:
    """An unmasked close frame with a status code (server -> client)."""
    payload = int(code).to_bytes(2, "big") + reason.encode("utf-8")[:120]
    return bytes([0x88]) + _size(len(payload), False) + payload


async def _messages(reader: asyncio.StreamReader):
    """Yield (kind, opcode, data, raw_frames): kind 'control' for ping/pong/close, else 'data' for one
    whole (possibly fragmented) message. Control frames inside a fragmented message come out first."""
    parts: list[bytes] = []
    raws: list[bytes] = []
    opcode = None
    size = 0
    while True:
        fin, op, data, raw = await _read_frame(reader)
        if op >= 0x8:
            yield "control", op, data, [raw]
            continue
        if op != 0x0:
            opcode, parts, raws, size = op, [], [], 0
        parts.append(data)
        raws.append(raw)
        size += len(data)
        if size > MAX_MESSAGE:
            raise ConnectionError("message too large to relay")
        if fin:
            yield "data", opcode, b"".join(parts), raws
            parts, raws, opcode, size = [], [], None, 0


class _Conn:
    """One relayed desktop connection."""
    _next = 0

    def __init__(self, c_writer=None, u_writer=None):
        _Conn._next += 1
        self.n = _Conn._next
        self.c_writer, self.u_writer = c_writer, u_writer
        self.lock = asyncio.Lock()             # writes toward the desktop
        self.u_lock = asyncio.Lock()           # writes toward the sandbox
        self.sessions: list[str] = []          # live session ids, most recently active last
        self.pending_lists: dict = {}          # approval.pending call id -> live session id
        self.running: set[str] = set()         # kept for the relay's older callers; Cards tracks turns itself
        self.calls: dict = {}                  # desktop call id -> (method, params) awaiting the reply
        self.own_calls: dict = {}              # launcher call id -> what to do with the reply
        self.notice_calls: dict = {}           # desktop prompt.submit id -> (chat, notes it carried)
        self.close_sent = False                # a close frame went to the desktop (relayed or the launcher's)
        self.opened = 0.0                      # when the relay took it (0: not known, which counts as long ago)

    def saw(self, sid) -> None:
        if isinstance(sid, str) and sid:
            if sid in self.sessions:
                self.sessions.remove(sid)
            self.sessions.append(sid)

    async def close_client(self, code: int = CLOSE_RESTART, reason: str = "service restart") -> None:
        """Close the desktop's socket now (once): a close frame with *code*, then both sides. The desktop
        reconnects and asks the launcher's status instead of waiting out a heartbeat on a dead backend."""
        if self.close_sent:
            return
        self.close_sent = True

        async def send() -> None:
            async with self.lock:  # never inside another frame toward the desktop
                self.c_writer.write(server_close_frame(code, reason))
                await self.c_writer.drain()

        try:
            await asyncio.wait_for(send(), 2.0)
        except (ConnectionError, OSError, AttributeError, asyncio.TimeoutError, RuntimeError):
            pass
        for writer in (self.c_writer, self.u_writer):
            try:
                writer.close()
            except (AttributeError, OSError, RuntimeError):
                pass

    async def to_client(self, data: bytes) -> None:
        async with self.lock:
            self.c_writer.write(data)
            await self.c_writer.drain()

    async def to_upstream(self, data: bytes) -> None:
        async with self.u_lock:
            self.u_writer.write(data)
            await self.u_writer.drain()


# -- host-side helpers ------------------------------------------------------------------------------

# OpenShell's own folders on a Windows host, at the drive root its POSIX paths resolve to: the host supervisor
# writes its logs to \var\log, the CLI keeps its system gateway registry in \etc\openshell. A card never asks for
# them, whatever refusal names them: they hold the sandbox runtime's own state, not the user's files, and the agent
# has no business there. Add folder still can, deliberately.
_OPENSHELL_HOST_DIRS = (("var", "log"), ("etc", "openshell"))


def openshell_host_dirs(*, windows: Optional[bool] = None, drive: Optional[str] = None) -> list[Path]:
    if not (os.name == "nt" if windows is None else windows):
        return []  # a POSIX host's /var/log is the system's; the sandbox's own is in its container
    drive = (drive or os.environ.get("SystemDrive") or "C:").rstrip("\\/")
    return [Path(drive + "\\", *parts) for parts in _OPENSHELL_HOST_DIRS]


def _inside(child: Path, parent: Path) -> bool:
    try:
        a, b = os.path.normcase(os.path.abspath(child)), os.path.normcase(os.path.abspath(parent))
    except (OSError, ValueError):
        return False
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def _on_host(path: Path, access: str) -> bool:
    """Whether the host has what a refusal names: the path itself or, for a refused write, the folder a new file
    or folder goes into."""
    return path.exists() or (access == "read_write" and path.parent.is_dir())


def _leaf(binary: str) -> str:
    return re.split(r"[\\/]", binary or "")[-1] or binary


def _risk_line(proposal: Optional[dict]) -> Optional[str]:
    """One short line from OpenShell's checks: destination flags and prover findings."""
    texts = []
    for key in ("flags", "security_notes", "validation"):
        text = str((proposal or {}).get(key) or "").strip()
        if text and text not in texts:
            texts.append(text)
    if not texts:
        return None
    findings = [t for t in texts if not re.fullmatch(r"(prover:\s*)?no new findings\.?", t, re.I)]
    if not findings:
        return "Policy prover: no new risks."
    return ("Policy prover: " + "; ".join(re.sub(r"^prover:\s*", "", t, flags=re.I) for t in findings))[:160]


_STAMP_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(\.\d+)?\s*(Z|UTC|[+-]\d\d:?\d\d)$", re.I)


def _stamp(value) -> Optional[float]:
    """A draft's time as epoch seconds: a number (seconds, or milliseconds), or text with a zone
    (``2026-11-10T22:05:21.5Z``, proto-JSON's Timestamp). None for anything else: a zone is never guessed."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return None if value <= 0 else float(value) / 1000.0 if value > 1e11 else float(value)
    m = _STAMP_RE.match(str(value).strip())
    if not m:
        return None
    year, month, day, hour, minute, second, frac, zone = m.groups()
    try:
        t = float(calendar.timegm((int(year), int(month), int(day), int(hour), int(minute), int(second), 0, 0, 0)))
    except (ValueError, OverflowError):
        return None
    if zone.upper() not in ("Z", "UTC"):
        digits = zone[1:].replace(":", "")
        t -= (-1 if zone[0] == "-" else 1) * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)
    return t + (float(frac) if frac else 0.0)


def _proposal_hosts(p: dict) -> list[tuple[str, Optional[int]]]:
    out = []
    for ep in p.get("endpoints") or []:
        host = card_host(ep.get("host") or "")
        if host:
            out.append((host, ep.get("port") if isinstance(ep.get("port"), int) else None))
    return out


def host_rule(host: str, ports) -> dict:
    """The rule a host card's Allow adds: every port in *ports*, any program in the sandbox."""
    slug = re.sub(r"[^a-z0-9]+", "_", host.lower()).strip("_")[:60]
    name = HOST_RULE_PREFIX + slug
    return {"name": name, "endpoints": [{"host": host, "port": int(p)} for p in sorted(set(ports))],
            "binaries": [{"path": ANY_BINARY}]}


def tool_rule(tool: str, hosts) -> dict:
    """The rule a tool card's Allow adds: every service the tool uses without a credential, https. For a
    category whose services all carry one it has no endpoints and only stands for the approval."""
    name = TOOL_RULE_PREFIX + re.sub(r"[^a-z0-9]+", "_", tool.lower()).strip("_")[:60]
    return {"name": name, "endpoints": [{"host": h, "port": int(p)} for h in hosts for p in TOOL_PORTS],
            "binaries": [{"path": ANY_BINARY}]}


def tool_target(tool: str) -> str:
    return TOOL_TARGET_PREFIX + _TOOL_CANON.get(tool, tool)


def tool_label(tool: str) -> str:
    """What a card and a grant's row call the category of *tool* (a tool's name or a category's id)."""
    category = categories.by_id(_TOOL_CANON.get(tool, tool)) or categories.of_tool(tool)
    return category.label if category is not None else str(tool)


def tool_hosts(host: Optional[str] = None) -> list[str]:
    """The services a Hermes web tool card covers: core's keyless ring, plus the refused backend host."""
    hosts = list(KEYLESS_WEB_HOSTS)
    if host and host not in hosts:
        hosts.append(host)
    return hosts


def _merge_rule(a: Optional[dict], b: Optional[dict]) -> Optional[dict]:
    """Two bodies of one named rule: b's endpoints and binaries added to a's."""
    if not a:
        return copy.deepcopy(b)
    if not b:
        return copy.deepcopy(a)
    out = copy.deepcopy(a)
    for key in ("endpoints", "binaries"):
        items = out.setdefault(key, [])
        for item in b.get(key) or []:
            if item not in items:
                items.append(copy.deepcopy(item))
    return out


def without_grant(approved: dict, target: str) -> Optional[dict]:
    """*approved* (the saved rules by name) without the grant *target* that "Allowed from chat" lists: a tool
    category's rule (``tool:<id>``), or one website. Two websites can be in one saved rule (their names fold to
    one rule name), so only the chosen website's endpoints are taken out, and a rule goes once none is left.
    None when nothing in *approved* is that grant."""
    tool = target[len(TOOL_TARGET_PREFIX):] if target.startswith(TOOL_TARGET_PREFIX) else None
    out, found = {}, False
    for name, rule in (approved or {}).items():
        if tool is not None and name == TOOL_RULE_PREFIX + tool:
            found = True
            continue
        if tool is None and name.startswith(HOST_RULE_PREFIX) and target in _rule_hosts(rule):
            found = True
            left = [ep for ep in rule.get("endpoints") or [] if str(ep.get("host") or "").lower() != target]
            if not left:
                continue
            rule = {**rule, "endpoints": left}
        out[name] = rule
    return out if found else None


def _rule_hosts(rule: dict) -> dict[str, set]:
    out: dict[str, set] = {}
    for ep in (rule or {}).get("endpoints") or []:
        if ep.get("host"):
            out.setdefault(str(ep["host"]).lower(), set()).add(ep.get("port"))
    return out


def _bin_paths(rule: Optional[dict]) -> list[str]:
    return [b.get("path") for b in (rule or {}).get("binaries") or [] if isinstance(b, dict) and b.get("path")]


def _grant_id(kind: str, scope: str, target: str) -> str:
    return f"{'network' if kind == 'network' else 'folder'}:{scope}:{target}"


def saved_tool_row(name: str, rule: dict, bound=(), *, pending: bool = False) -> dict:
    """The row of a tool category saved with Always allow, as "Allowed from chat" lists it whether the
    sandbox is on (``Cards.grants_view``) or off (``settings_view.saved_grants``). *bound*: the addresses a
    sign-in or key of the profile is used at for it, named before the services the rule itself holds."""
    tool = name[len(TOOL_RULE_PREFIX):]
    hosts = _rule_hosts(rule)
    row = {"id": _grant_id("network", "always", tool_target(tool)), "kind": "network",
           "target": ", ".join(dict.fromkeys([*bound, *hosts])), "label": tool_label(tool),
           "ports": sorted({p for ps in hosts.values() for p in ps if p}) or list(TOOL_PORTS),
           "scope": "always", "status": "pending" if pending else "active", "rule_name": name}
    if bound:
        row["bound"] = True
    note = _GRANT_NOTES.get(_TOOL_CANON.get(tool, tool))
    if note:
        row["note"] = note
    return row


# -- the cards ---------------------------------------------------------------------------------------

class Cards:
    """The chat-socket relay plus the cards that ride on it. *sup* is the launcher's Supervisor (None
    in relay-only uses); *layout* its profile layout."""

    def __init__(self, sup=None, layout=None, log_path: Optional[Path] = None, *, cards: bool = True,
                 clock=time.time, settle: float = IDLE_SETTLE, poll_interval: float = POLL_INTERVAL,
                 restart_quiet: float = RESTART_QUIET, batch_window: float = NET_BATCH_WINDOW,
                 request_poll: float = REQUEST_POLL, confirm_poll: float = LOAD_CONFIRM_POLL,
                 interrupt_ack: float = INTERRUPT_ACK_WAIT, bg_wait: float = BG_LIST_WAIT,
                 feed_poll: float = ZERO_WAIT_FEED):
        self._sup = sup
        self._layout = layout if layout is not None else getattr(sup, "layout", None)
        self._log_path = log_path
        self.cards = cards
        self._clock = clock
        self._settle = settle
        self._restart_quiet = restart_quiet
        self._interrupt_ack = interrupt_ack
        self._bg_wait = bg_wait
        self._poll_interval = poll_interval
        self._batch_window = batch_window
        self._request_poll = request_poll
        self._confirm_poll = confirm_poll
        self._feed_poll = feed_poll
        self._feed: Optional[asyncio.Task] = None        # _refusal_feed while a terminal / execute_code call is open
        self._confirming: Optional[asyncio.Task] = None  # _confirm_loading for the latest unconfirmed revision
        self._conns: list[_Conn] = []
        self.open: dict[str, dict] = {}          # server request id -> card
        self.answers: list[dict] = []            # every answer, in order
        self.dropped: list[dict] = []            # sandbox frames that claimed a launcher card
        self.stripped = 0                        # sandbox approval frames whose access wording was removed
        self.grants: list[dict] = []             # Allow grants (until the sandbox is switched off)
        self.history: list[dict] = []            # applied, removed and failed changes
        self._records: list[dict] = []           # the latest card log entries (cards.jsonl), for status and tests
        self.notices: dict[str, list[str]] = {}  # chat -> notes for the agent with the chat's next prompt
        self._chats: dict[str, dict] = {}        # chat key (stored session id) -> {"live", "seen", "turn_started"}
        self._live: dict[str, str] = {}          # live session id -> chat key
        self._running: dict[str, float] = {}     # live session id -> last turn event time
        self._chunks: dict[str, dict] = {}       # proposal id -> what the launcher did with it
        self._proposal_first: dict[str, float] = {}  # proposal id -> when the launcher first listed it
        # "chat|target key" -> {"reason", "t"} (this chat said no). A denied web tool card denies the tool and its
        # services, not the site the tool was asked to fetch: the agent's own request to that site (a curl) asks.
        self._denied: dict[str, dict] = {}
        self._ports: dict[str, set] = {}         # host -> ports seen refused for it
        self._last_turn_end = 0.0
        self._tools: dict[str, int] = {}         # live session id -> tool calls in flight
        self._tool_names: dict[str, list] = {}   # live session id -> names of the tool calls in flight
        self._tool_seen = 0.0                    # last tool.start / tool.complete
        self._idle_since: Optional[float] = None
        self._pending_net: list[dict] = []       # network answers waiting for their policy update
        self._applying_net: list[dict] = []      # ... and the batch whose policy update is being submitted/loaded
        self._loading: dict[str, dict] = {}      # host -> network answer whose rule is submitted, not yet loaded
        self._pending_restart: list[dict] = []   # folder answers / removals waiting for the restart
        # An answer that waits for the turns it would cut to stop (``_stop_turns_soon``): a folder answer's restart,
        # or a network answer's policy update on a build whose reload cuts open connections. {"since", "quiet_from",
        # "chats": {chat: stop deadline}, "interrupted": {chats the launcher interrupted}, "cut": {other chats}}
        self._soon: Optional[dict] = None
        self._net_dirty = False                  # the live policy lacks saved + Allow grants
        self._usage_data_since: Optional[float] = None  # when the profile's usage data answer was first seen changed
        self._bindings: dict[str, dict] = {}     # hook request id -> {"chat", "keys", "t"[, "stopped"]}
        self._unbound: dict[str, dict] = {}      # hook network requests naming no host, by id
        self._asked: dict[str, dict] = {}        # host -> the hook request naming it {"chat", "t", "wait", "tool", "rid"}
        self._relaying: set = set()              # hook request ids on_request is still handling (not answered yet)
        self._hook_asked: dict[str, float] = {}  # "chat|target key" a hook request waited on (follow-ups only for these)
        # chat -> {"keys": {target key: label}, "settling": {target keys}, "since", "state", "deadline"}: a turn
        # paused on cards no tool call is held on. "keys": its cards still unanswered; "settling": answered, the
        # outcome not yet queued for the agent (a rule that is loading). "state": "pending" (the interrupt waits for
        # the tool call in flight), "sent" (interrupted, not yet reported stopped), "paused" (stopped)
        self._pauses: dict[str, dict] = {}
        self._stop_at_boundary: set = set()      # chats whose turn stops for a network grant once their tool call ended
        self._agent_calls: dict[str, dict] = {}  # chat key -> {"open", "since", "ended", "spans"}, its AGENT_TOOLS calls
        self._quiet: set = set()                 # draft ids recorded as Activity-only
        self._unplaced_notes: list = []          # the launcher's own notes while no chat is known (``note``)
        self._lost_said = False                  # the notes still waiting at the stop were named (``_notes_lost``)
        self._seq = 0                            # event order (clock ticks are too coarse to order a listing and a call)
        self._proposal_order: dict[str, int] = {}  # proposal id -> order of the launcher's first listing
        self._draft_seen: dict[str, tuple] = {}  # draft id -> (hit count, last_seen) in the listing before
        self._continuing: dict[str, asyncio.Task] = {}
        self._stopped: dict[str, str] = {}       # chat -> the line it says when next opened (its reply did not go on)
        self._grant_notes: dict[str, list] = {}  # target key -> [(chat, the sentence that told the agent of the grant)]
        self._detached_task: Optional[asyncio.Task] = None  # _detached_loop while a detached turn is counted
        self._continue_text: dict[str, list[str]] = {}
        self._note_tries: dict[str, int] = {}    # chat -> refused deliveries of its notes in a row
        self._no_steer: set = set()              # chats whose running turn refused a steer: notes wait for its end
        self._applying = False
        self._apply_done: Optional[asyncio.Event] = None
        self._wake: Optional[asyncio.Event] = None
        self._tasks: list[asyncio.Task] = []
        state_dir = getattr(self._layout, "state_dir", None)
        box = getattr(self._layout, "box", None)
        self.verdicts = Verdicts(Path(state_dir) / "verdicts" if state_dir is not None else None, clock=clock)
        self._requests_dir: Optional[Path] = Path(box) / "requests" if box is not None else None

    # -- lifecycle (launcher_cli._serve) ------------------------------------------------------------
    def start(self) -> None:
        self._wake = asyncio.Event()
        self._apply_done = asyncio.Event()
        self._apply_done.set()
        if self._sup is not None:
            self._sup.restart_queued = self.restart_queued
        if self.cards and self._sup is not None:
            self.verdicts.reset()
            if self._requests_dir is not None:
                self._requests_dir.mkdir(parents=True, exist_ok=True)
                read_requests(self._requests_dir)  # a previous launcher's leftovers: nobody waits for them
            self._tasks = [asyncio.ensure_future(self._watch_loop()), asyncio.ensure_future(self._apply_loop()),
                           asyncio.ensure_future(self._request_loop())]

    async def stop(self) -> None:
        self._notes_lost("the launcher stopped before the chat's next message")
        extra = [t for t in (self._confirming, self._detached_task, self._feed) if t is not None]
        for t in [*self._tasks, *self._continuing.values(), *extra]:
            t.cancel()
        await asyncio.gather(*self._tasks, *self._continuing.values(), *extra, return_exceptions=True)
        self._tasks, self._continuing, self._confirming, self._detached_task, self._feed = [], {}, None, None, None

    def _notes_lost(self, why: str, chat: Optional[str] = None) -> None:
        """Notes that will not go out any more: one line each in the card log, so a note that was queued and
        never seen can be found there with the reason. With *chat*, that chat's pending continuation (it is
        dropped here); without, everything that still waits when the launcher stops (said once)."""
        if chat is not None:
            waiting = {chat: [sandbox_note(n) for n in self._continue_text.pop(chat, [])]}
        elif self._lost_said:
            return
        else:
            self._lost_said = True
            waiting = {key: [*notes] for key, notes in self.notices.items()}
            for key, notes in self._continue_text.items():
                waiting.setdefault(key, []).extend(sandbox_note(n) for n in notes)
            if self._unplaced_notes:
                waiting[None] = [sandbox_note(n) for n in self._unplaced_notes]
        for key, notes in waiting.items():
            if notes:
                self._record({"event": "notes lost", "chat": key, "notes": notes, "why": why})

    def restart_queued(self) -> bool:
        """A restart of the launcher's own waits (a folder answer, a removal): it happens by itself once the
        sandbox is idle, and the status says so (``Supervisor.status``)."""
        return bool(self._pending_restart)

    def routes(self) -> dict:
        return {("GET", "cards"): self._route_status, ("GET", "grants"): self._route_grants,
                ("DELETE", "grants"): self._route_remove}

    async def _route_status(self, req, body: bytes):
        return 200, self.status(), {}

    def status(self) -> dict:
        return {"enabled": self.cards,
                "open": [{k: v for k, v in c.items() if k != "proposal"} for c in self.open.values()],
                "pending": {"network": [self._brief(h) for h in self._pending_net],
                            "loading": [self._brief(h) for h in self._loading.values()],
                            "restart": [self._brief(h) for h in self._pending_restart]},
                "grants": self.grants, "history": self.history[-50:], "answers": self.answers[-50:],
                "dropped": self.dropped[-20:], "notices": self.notices, "idle": self._idle(),
                "network_apply": "live" if self._net_live() else "turn_end",
                "verdicts": self.verdicts.snapshot(),
                "restart_soon": None if self._soon is None else {
                    "since": self._soon["since"], "chats": sorted(self._soon["chats"]),
                    "interrupted": sorted(self._soon["interrupted"]), "cut": sorted(self._soon["cut"])},
                "chats": {k: {"live": sorted(v["live"]), "running": any(s in self._running for s in v["live"])}
                          for k, v in self._chats.items()},
                "paused": {k: {"state": p["state"], "hosts": sorted(p["keys"].values()), "since": p["since"],
                               "until": p["deadline"]} for k, p in self._pauses.items()},
                "connections": [{"n": c.n, "sessions": c.sessions} for c in self._conns]}

    @staticmethod
    def _brief(entry: dict) -> dict:
        card = entry.get("card") or {}
        return {k: v for k, v in entry.items() if k != "card"} | {"card": card.get("request_id")}

    def _net_live(self) -> bool:
        """Network answers apply at once: the driver changes a running sandbox's network, and its reload
        keeps unchanged connections (the model's streaming reply) open."""
        drv = getattr(self._sup, "driver", None)
        if drv is None:
            return False
        caps = drv.capabilities()
        return bool(caps.get("network_live")) and not caps.get("network_live_interrupts", True)

    def _net_between_turns(self) -> bool:
        """Network answers wait for the turns they would cut: the driver changes a running sandbox's network,
        but its reload closes open connections (the model's streaming reply among them)."""
        drv = getattr(self._sup, "driver", None)
        if drv is None:
            return False
        caps = drv.capabilities()
        return bool(caps.get("network_live")) and bool(caps.get("network_live_interrupts", True))

    # -- chats and turns ------------------------------------------------------------------------
    def _chat_of(self, sid) -> Optional[str]:
        if not isinstance(sid, str) or not sid:
            return None
        return self._live.get(sid, sid)

    def _link(self, live: str, stored: Optional[str]) -> None:
        if not isinstance(live, str) or not live:
            return
        key = stored if isinstance(stored, str) and stored else self._live.get(live, live)
        old = self._live.get(live)
        if old and old != key and old in self._chats:  # a live id first seen before its stored id
            moved = self._chats.pop(old)
            chat = self._chats.setdefault(key, {"live": set(), "seen": self._clock(), "turn_started": None})
            chat["live"] |= moved["live"]
            for card in self.open.values():
                if card["chat"] == old:
                    card["chat"] = key
            if old in self.notices:
                self.notices.setdefault(key, []).extend(self.notices.pop(old))
        self._live[live] = key
        chat = self._chats.setdefault(key, {"live": set(), "seen": self._clock(), "turn_started": None})
        chat["live"].add(live)
        chat["seen"] = self._clock()
        chat.pop("orphaned", None)
        for card in self.open.values():
            if card["chat"] == key:
                card["session_id"] = live

    def _turn_started(self, sid: str) -> None:
        self._link(sid, None)
        first = sid not in self._running
        self._running[sid] = self._clock()
        self._idle_since = None
        chat = self._chats.get(self._chat_of(sid))
        if first and chat is not None and not chat.get("turn_started"):
            chat["turn_started"] = self._clock()

    def _turn_ended(self, sid: str) -> None:
        self._drop_detached_turns(sid)
        if self._running.pop(sid, None) is None and sid not in self._live:
            return
        now = self._clock()
        self._last_turn_end = now
        chat = self._chats.get(self._chat_of(sid))
        if chat is not None:
            chat["turn_started"] = None
        if self._soon is not None and self._chat_of(sid) in self._soon["chats"]:
            self._record({"event": "turn stopped", "chat": self._chat_of(sid), "session_id": sid,
                          "after_answer": round(now - self._soon["since"], 3)})
        self._pause_turn_ended(self._chat_of(sid))
        if not self._running:
            self._idle_since = now
        self._kick()

    def _drop_detached_turns(self, sid: str) -> None:
        """The chat of *sid* reports its turn over (ended, or a resume found it idle). A live id of the same chat
        whose desktop connection went away while its turn ran (``_closed`` keeps it running: the backend may still
        be working) saw that turn end under the resumed id, never under its own: it is not running any more.
        Left in ``_running`` it would count as another chat's running turn until RUNNING_STALE (a folder grant
        elsewhere would wait OTHER_TURNS_WAIT for it, interrupt it and queue a "stopped your reply" note)."""
        key = self._chat_of(sid)
        if key is None:
            return
        held = {s for c in self._conns for s in c.sessions}
        for old in [s for s in self._running if s != sid and s not in held and self._chat_of(s) == key]:
            self._running.pop(old, None)
            self._live.pop(old, None)

    def _detached_turns(self) -> dict:
        """Running turns no desktop connection can relay the end of: chat -> live ids (no connection holds the
        live id or any other live id of its chat)."""
        held = {s for c in self._conns for s in c.sessions}
        shown = {self._chat_of(s) for s in held}
        out: dict = {}
        for sid in self._running:
            key = self._chat_of(sid)
            if key is not None and sid not in held and key not in shown:
                out.setdefault(key, []).append(sid)
        return out

    def _watch_detached(self) -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._detached_task is None or self._detached_task.done():
            self._detached_task = asyncio.ensure_future(self._detached_loop())

    async def _detached_loop(self) -> None:
        """While a detached turn is counted, ask the backend which sessions still run. A detached turn it lists
        as idle, or not at all, ended unseen: it no longer holds a restart (``OTHER_TURNS_WAIT``, then cut and
        continued with a false "which stopped your reply"), a network update that waits for idle, or the idle
        check, until RUNNING_STALE. One it lists as running, or no answer, keeps the turn counted."""
        while self._detached_turns():
            rows = await self._active_sessions()
            if rows is not None:
                self._drop_ended_detached(rows)
            if not self._detached_turns():
                return
            await asyncio.sleep(DETACHED_POLL)

    async def _active_sessions(self) -> Optional[list]:
        """The backend's live sessions (``session.active_list`` rows: ``id``, ``session_key``, ``status``) through
        a relayed desktop connection, or None: no connection, or no answer within ``ACTIVE_LIST_WAIT``."""
        conn = next((c for c in reversed(self._conns) if getattr(c, "u_writer", None) is not None), None)
        if conn is None:
            return None
        rid = _CALL_PREFIX + secrets.token_hex(6)
        reply = asyncio.get_running_loop().create_future()
        conn.own_calls[rid] = {"method": "session.active_list", "reply": reply, "quiet": True}
        frame = client_text_frame({"jsonrpc": "2.0", "id": rid, "method": "session.active_list", "params": {}})
        try:
            await asyncio.wait_for(conn.to_upstream(frame), 1.0)
            obj = await asyncio.wait_for(reply, ACTIVE_LIST_WAIT)
        except (ConnectionError, OSError, asyncio.TimeoutError):
            conn.own_calls.pop(rid, None)
            return None
        result = obj.get("result") if isinstance(obj, dict) else None
        rows = result.get("sessions") if isinstance(result, dict) else None
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else None

    def _drop_ended_detached(self, rows: list) -> None:
        """Drop the detached turns the backend no longer runs (*rows*: ``session.active_list``). A session runs
        unless its status is ``idle``; a chat whose live id and stored id are both absent has no running turn."""
        busy = [r for r in rows if r.get("status") != "idle"]
        busy_ids = {r.get("id") for r in busy}
        busy_keys = {r.get("session_key") for r in busy}
        ended = False
        for key, sids in self._detached_turns().items():
            if key in busy_keys or busy_ids & set(sids):
                continue
            for sid in sids:
                self._running.pop(sid, None)
                self._live.pop(sid, None)
            chat = self._chats.get(key)
            if chat is not None:
                chat["turn_started"] = None
            self._record({"event": "detached turn over", "chat": key, "sessions": sids})
            ended = True
        if ended:
            now = self._clock()
            self._last_turn_end = now
            if not self._running:
                self._idle_since = now
            self._kick()

    @staticmethod
    def _unknown_session(obj: dict) -> bool:
        """*obj*, a backend reply, refuses the call's session id as one the backend does not hold."""
        error = obj.get("error") if isinstance(obj.get("error"), dict) else {}
        return (error.get("code"), error.get("message")) == UNKNOWN_SESSION

    def _forget_session(self, sid, method: str) -> None:
        """The backend does not hold runtime id *sid* (it refused a *method* call naming it): the id leaves the relay's
        tracking. No turn counts as running under it (a phantom turn held policy updates and restarts for
        INTERRUPT_STOP_WAIT and drew its chat's steers), no connection shows it, and it is no live id of its chat. The
        chat, its cards and its notes stay (they are keyed by the stored id), and the id still names the chat."""
        if not isinstance(sid, str) or not sid:
            return
        key = self._chat_of(sid)
        chat = self._chats.get(key)
        shown = [c for c in self._conns if sid in c.sessions]
        if sid not in self._running and not shown and not (chat is not None and sid in chat["live"]):
            return
        for conn in shown:
            conn.sessions.remove(sid)
        if chat is not None:
            chat["live"].discard(sid)
        self._record({"event": "session refused", "chat": key, "session_id": sid, "method": method})
        if self._running.pop(sid, None) is not None:
            self._kick()  # a change that waits for the sandbox to be idle may go ahead now

    async def _resolve_live(self, key: str) -> Optional[str]:
        """Chat *key*'s live session per the backend, once it refused the last one the relay knew: the newest
        ``session.active_list`` row whose ``session_key`` is the chat's stored id, linked to the chat and shown on the
        connection that asked. None: the backend runs no session for the chat (a continuation then waits for a desktop
        to show it, as after a restart)."""
        conn = next((c for c in reversed(self._conns) if getattr(c, "u_writer", None) is not None), None)
        rows = await self._active_sessions() if conn is not None else None
        mine = [r for r in rows or () if r.get("session_key") == key and isinstance(r.get("id"), str) and r["id"]]
        if not mine:
            return None
        live = mine[-1]["id"]
        self._link(live, key)
        conn.saw(live)
        self._record({"event": "session resolved", "chat": key, "session_id": live})
        return live

    def _idle(self) -> bool:
        now = self._clock()
        for sid, t in list(self._running.items()):
            if now - t > RUNNING_STALE:
                self._running.pop(sid, None)
        return not self._running

    def quiet(self) -> bool:
        """True while no chat turn runs: what the sandbox driver asks before it replaces a credential's value,
        because OpenShell closes the sandbox's open connections then (``CredentialSinkMixin.quiet``). A turn
        counts from its first relayed event to its end. What the backend asks a model outside a turn is not
        seen here."""
        return self._idle() and not any(getattr(conn, "running", None) for conn in self._conns)

    def _chat_running(self, key: str) -> bool:
        return any(self._chat_of(s) == key for s in self._running)

    def _kick(self) -> None:
        if self._wake is not None:
            self._wake.set()

    def _target_chat(self) -> Optional[str]:
        running = sorted(self._running.items(), key=lambda kv: kv[1])
        if running:
            return self._chat_of(running[-1][0])
        for conn in reversed(self._conns):
            if conn.sessions:
                return self._chat_of(conn.sessions[-1])
        return None

    def _chat_for_session(self, sid) -> Optional[str]:
        """The chat a hook request names (the agent's stored session id), else the running one."""
        if isinstance(sid, str) and sid and (sid in self._chats or sid in self._live):
            return self._chat_of(sid)
        return self._target_chat()

    def _live_for(self, key: str) -> Optional[str]:
        for conn in reversed(self._conns):
            for sid in reversed(conn.sessions):
                if self._chat_of(sid) == key:
                    return sid
        chat = self._chats.get(key)
        return next(iter(sorted(chat["live"])), None) if chat and chat["live"] else None

    def _conns_for(self, key: str) -> list[_Conn]:
        return [c for c in self._conns if any(self._chat_of(s) == key for s in c.sessions)]

    # -- raising cards ----------------------------------------------------------------------------
    async def _raise(self, kind: str, key: str, target: dict, *, description: str, risk: Optional[str],
                     extra: dict) -> Optional[dict]:
        live = self._live_for(key)
        conns = self._conns_for(key) or list(self._conns)
        if live is None or not conns:
            return None
        srq = f"srq-{secrets.token_hex(6)}"
        card = {"id": srq, "server_request_id": srq, "request_id": REQUEST_PREFIX + secrets.token_hex(6),
                "kind": kind, "chat": key, "session_id": live, **target, "risk": risk, "description": description,
                "raised_at": self._clock(), "turn_running": self._chat_running(key), **extra}
        self.open[srq] = card
        frame = server_text_frame({"jsonrpc": "2.0", "id": srq, "method": "approval", "params": self._params(card)})
        for conn in conns:
            try:
                await conn.to_client(frame)
            except (ConnectionError, OSError, AttributeError):
                pass
        card["delivered_to"] = [c.n for c in conns]
        self._record({"event": "raised", **{k: v for k, v in card.items() if k not in ("rule", "proposal")}})
        return card

    def _params(self, card: dict) -> dict:
        params = {"session_id": card["session_id"], "request_id": card["request_id"], "command": "",
                  "description": card["description"], "choices": list(CHOICES), "allow_permanent": True,
                  "tool_name": "sandbox", "kind": card["kind"]}
        keys = ("path", "access") if card["kind"] == "access" else ("host", "label")
        params.update({k: card[k] for k in keys if card.get(k) not in (None, "")})
        if card.get("risk"):
            params["risk"] = card["risk"]
        return params

    def _pending_entry(self, card: dict) -> dict:
        p = self._params(card)
        p.pop("session_id", None)
        return {**p, "smart_denied": False}

    def _label(self, host: str, key: Optional[str], tool: Optional[str]) -> Optional[str]:
        """'Web search (api.keenable.ai)' for Hermes's own tool backends: the tool that hit it (the hook's
        request, else a web tool in flight in the chat), else the profile's web backend settings."""
        vendor = WEB_BACKENDS.get(host)
        if vendor is None:
            return None
        names = [tool] if tool in _WEB_TOOLS else []
        if not names and key:
            names = [n for s, ns in self._tool_names.items() if self._chat_of(s) == key for n in ns if n in _WEB_TOOLS]
        if not names:
            web = self._web_config()
            if web.get("search_backend") == vendor:
                names.append("web_search")
            if web.get("extract_backend") == vendor:
                names.append("web_extract")
            if not names and web.get("backend") == vendor:
                names = ["web_search", "web_extract"]
        labels = list(dict.fromkeys(_TOOL_LABEL[n] for n in names))
        what = "Web search and extract" if len(labels) > 1 else labels[0] if labels else "Hermes web tools"
        return f"{what} ({host})"

    def _web_config(self) -> dict:
        try:
            from .openshell_driver import _read_yaml

            web = _read_yaml(Path(self._layout.home) / "config.yaml").get("web")
            return web if isinstance(web, dict) else {}
        except Exception:
            return {}

    def _saved_network(self) -> dict:
        from .spec import network_policy

        try:
            return network_policy(getattr(self._sup, "spec", None) or {})
        except Exception:
            return {}

    def _host_allowed(self, host: str, port: Optional[int]) -> tuple[Optional[str], float, str]:
        """``("any", since, target)`` when every program may reach host:port (an Allow grant or a saved host
        or web tool rule; *target* the grant's: the host, or ``tool:<name>``), ``("some", 0, host)`` when only
        some programs may (a page destination or an approved request), else ``(None, 0, host)``."""
        ports = {port} if port else set(HOST_PORTS)
        for g in self.grants:
            if g["kind"] != "network" or not g.get("applied_at") or host not in (g.get("hosts") or [g["host"]]):
                continue
            want = ({port} if port else set(TOOL_PORTS)) if g.get("tool") else ports
            if want <= set(g["ports"]) or (g.get("tool") and (host, port or TOOL_PORTS[0]) in self._bound_now(g["tool"])):
                return "any", g["applied_at"], g["host"]
        net = self._saved_network()
        for name, rule in (net.get("approved") or {}).items():
            hosts = _rule_hosts(rule)
            tool = name[len(TOOL_RULE_PREFIX):] if name.startswith(TOOL_RULE_PREFIX) else None
            want = ({port} if port else set(TOOL_PORTS)) if tool else ports
            if tool and (host, port or TOOL_PORTS[0]) in self._bound_now(tool):
                return "any", 0.0, tool_target(tool)  # a credential is bound there for this category
            if host in hosts and (want <= hosts[host] or None in hosts[host]):
                if ANY_BINARY in _bin_paths(rule):
                    return "any", 0.0, (tool_target(tool) if tool else host)
                return "some", 0.0, host
        for r in net.get("allow") or []:
            if str(r.get("host") or "").lower() == host:
                return "some", 0.0, host
        return None, 0.0, host

    def _web_tool(self, host: str, key: Optional[str], tool: Optional[str], port: Optional[int] = None) -> Optional[str]:
        """The tool category a refused request belongs to (its id), or None: a site card then, labelled by the
        tool if known. By the tool's name where the launcher knows the running tool (the tool the hook relayed,
        else a tool in flight in the chat) and the host is one of that category's services; by the host alone
        where it does not: a host of the Nous tool gateway belongs to one category. One of the services Hermes's
        web tools share says which tool only with a web tool's name."""
        names = [tool] if categories.of_tool(tool) is not None else []
        if not names and key:
            names = [n for s, ns in self._tool_names.items() if self._chat_of(s) == key for n in ns
                     if categories.of_tool(n) is not None]
        gateway = categories.of_gateway(host, port)
        if gateway is not None:
            for name in names:
                category = categories.of_tool(name)
                if any(at == host and (port is None or p == port) for at, p in categories.gateway_endpoints(category)):
                    return category.id
            return gateway.id
        if host not in WEB_BACKENDS:
            return None
        names = [n for n in names if n in _WEB_TOOLS]
        return _TOOL_CANON.get(names[0], names[0]) if names else None

    def _tool_services(self, tool: str) -> dict:
        """What an approval of the category *tool* opens for this profile (``Supervisor.tool_services``):
        ``plain`` hosts and ``bound`` addresses. A launcher part that cannot say leaves the hosts the
        category's tools use without a credential."""
        category = categories.by_id(_TOOL_CANON.get(tool, tool))
        ask = getattr(self._sup, "tool_services", None)
        try:
            found = ask(category.id) if callable(ask) and category is not None else None
        except Exception:
            log.warning("the services of %s could not be listed", tool, exc_info=True)
            found = None
        if not isinstance(found, dict):
            return {"plain": list(category.keyless) if category is not None else [], "bound": []}
        return {"plain": list(found.get("plain") or []), "bound": list(found.get("bound") or [])}

    def _bound_now(self, tool: str) -> set:
        """``(host, port)`` of the addresses the category *tool* has a credential bound to in the sandbox that
        runs now."""
        ask = getattr(self._sup, "bound_hosts", None)
        try:
            bound = set(ask()) if callable(ask) else set()
        except Exception:
            bound = set()
        return {(row["host"], row["port"]) for row in self._tool_services(tool)["bound"]} & bound

    def _rebinds(self, card: dict) -> bool:
        """Whether an Allow of *card* binds a credential to an address the running sandbox does not have it
        bound to: a sign-in's token or a service's key reaches a new address only in a sandbox that starts
        with it, so such an answer restarts the sandbox as a folder's does."""
        tool = card.get("tool") if card.get("kind") == "network" else None
        if not tool:
            return False
        wanted = {(row["host"], row["port"]) for row in self._tool_services(tool)["bound"]}
        return bool(wanted - self._bound_now(tool))

    async def raise_host(self, host: str, *, key: Optional[str] = None, port: Optional[int] = None,
                         proposal: Optional[dict] = None, origin: str = "proposal", tool: Optional[str] = None,
                         strength: str = "strong", refused_at: Optional[float] = None,
                         asked: Optional[list] = None) -> tuple[int, dict]:
        """One network card per host and chat (http and https, any program in the sandbox), or per Hermes web
        tool when the refused host is one of its backends (every service the tool rotates through, https)."""
        h = card_host(host)
        if not self.cards:
            return 409, {"detail": "Cards are off."}
        if h is None:
            return 422, {"detail": f"No card for {host!r}: not a public host name."}
        key = key or self._target_chat()
        if key is None:
            return 409, {"detail": "No desktop chat is attached to this sandbox."}
        web_tool = self._web_tool(h, key, tool, port)
        target = tool_target(web_tool) if web_tool else h
        if port and not web_tool:
            self._ports.setdefault(h, set()).add(int(port))
        pid = (proposal or {}).get("id")
        for card in self.open.values():
            if card["kind"] == "network" and card["host"] == target and card["chat"] == key:
                if pid and pid not in card["proposal_ids"]:
                    card["proposal_ids"].append(pid)
                if asked and card.get("tool"):  # raised from OpenShell's draft first: the hook names the site
                    card["asked"] = sorted(set(card.get("asked") or ()) | set(asked))
                return 200, {"detail": "already asking", **card}
        waiting = [b["entry"] for b in self._pending_restart if b.get("entry")]  # (a tool category's restart)
        for entry in [*self._pending_net, *self._applying_net, *waiting]:  # answered, not in force yet: no 2nd card
            if entry["card"]["host"] == target:
                if pid:
                    self._chunks.setdefault(pid, {})["decided"] = "approved"
                return 200, {"detail": "allowed; applying", **entry["card"]}
        loading = self._loading.get(target)
        if loading is not None:  # answered, its rule submitted and not loaded yet: no second card
            if pid:
                self._chunks.setdefault(pid, {})["decided"] = "approved"
            return 200, {"detail": "allowed; loading", **loading["card"]}
        allowed, since, cover = self._host_allowed(h, port)
        if allowed == "any" or (allowed == "some" and strength == "weak"):
            if pid:
                self._chunks.setdefault(pid, {})["decided"] = "covered"
            if allowed == "any" and refused_at is not None and since >= refused_at - 1.0:
                return 200, {"detail": "allowed", "host": cover}  # refused just before the rule landed: retry works
            return 204, {"detail": "already allowed" if allowed == "any" else "the site's own answer"}
        denied = self._denied_for(key, net_key(target))
        if denied is None and web_tool:
            # Hermes's web tools share one ring of services: a chat that denied one tool's card denied those hosts
            # (a Deny on Web extract also answers Web search)
            ring = [self._denied.get(f"{key}|{net_key(x)}") for x in
                    (tool_hosts(h) if categories.by_id(web_tool).keyless else self._tool_candidates(web_tool))]
            if ring and all(ring):
                denied = self._denied[f"{key}|{net_key(target)}"] = ring[0]
        if denied is not None:
            if pid:
                self._chunks.setdefault(pid, {})["decided"] = "rejected"
            return 200, {"detail": "denied earlier in this chat", "host": target, **denied}
        extra: dict = {}
        if web_tool:
            category = categories.by_id(web_tool)
            label = category.label
            services = self._tool_services(web_tool)
            # Everything the Allow opens, named on the card: the addresses a credential is bound to, then the
            # services used without one (with the refused one, when it is a keyed service's own host).
            plain = list(services["plain"])
            if h in WEB_BACKENDS and h not in plain and all(row["host"] != h for row in services["bound"]):
                plain.append(h)
            hosts = list(dict.fromkeys([*(row["host"] for row in services["bound"]), *plain]))
            shown = list(dict.fromkeys([*(categories.host_text(row["host"], row["port"]) for row in services["bound"]),
                                        *plain]))
            name = tool if categories.of_tool(tool) is category else (category.tools[0] if category.tools else "")
            extra = {"tool": web_tool, "hosts": hosts, "asked": sorted(set(asked or ())), "plain": plain,
                     "shown": shown, "name": name}
            description = f"Allow Hermes's {label} tool to reach its {'web ' if category.keyless else ''}services"
            risk = (f"Hermes's {label.lower()} tool uses "
                    f"{'one of these services, whichever it picks' if len(shown) > 1 else 'this service'}: "
                    f"{', '.join(shown)} (https).") + (f" {category.reach}" if category.reach else "")
        else:
            label = self._label(h, key, tool)
            lead = (f"Hermes's {label.split(' (')[0].lower()} tool uses this site." if label else
                    "Any program in the sandbox, http and https.")
            risk = " ".join(x for x in (lead, _risk_line(proposal)) if x)
            description = f"Allow the sandbox to reach {label or h}"
        card = await self._raise("network", key, {"host": target}, description=description, risk=risk,
                                 extra={"proposal_ids": [pid] if pid else [], "label": label,
                                        "origin": origin, "proposal": proposal, "refused": h, **extra})
        if card is None:
            return 409, {"detail": "No desktop connection for this chat."}
        if pid:
            self._chunks.setdefault(pid, {})["carded"] = card["id"]
        self.verdicts.target(net_key(target), kind="network", host=target, label=label, status="asking", chat=key,
                             card=card["request_id"], raised_at=card["raised_at"], reason=None, scope=None, **extra)
        self._bind_unbound(key, net_key(target))
        return 200, card

    async def raise_network(self, proposal: dict, key: Optional[str] = None) -> Optional[dict]:
        """A card for the first host a proposal names (one card per host)."""
        for host, port in _proposal_hosts(proposal):
            status, card = await self.raise_host(host, key=key, port=port, proposal=proposal)
            return card if status == 200 and card.get("id") else None
        return None

    async def raise_access(self, path: str, access: str, *, key: Optional[str] = None, origin: str = "refusal",
                           missing: bool = False, must_exist: bool = False) -> tuple[int, dict]:
        """A folder card for *path* (a refused file or folder). Checked on the host: the nearest existing
        folder, by Add folder's rules, not a credential path, not already granted. *missing*: the tool said "no
        such file", so there is a card only when the host has the path. *must_exist*: the call did not fail and
        only its own text says the path was refused, so there is a card only when the host has the path (for a
        refused write, the folder it goes into); a path the host lacks never asks for a folder above it."""
        from .layout import LayoutError
        from .spec import folder_from_entry

        if not self.cards:
            return 409, {"detail": "Cards are off."}
        key = key or self._target_chat()
        if key is None:
            return 409, {"detail": "No desktop chat is attached to this sandbox."}
        access = "read_write" if access in ("read_write", "rw") else "read"
        p = Path(path)
        if missing and not p.exists():
            return 204, {"detail": "not on the host"}
        if must_exist and not _on_host(p, access):
            self._record({"event": "not carded", "origin": origin, "path": str(path), "detail": "not on the host"})
            return 204, {"detail": "not on the host"}
        covered = self._covered(p, access)
        if covered:
            return 204, {"detail": covered}
        own = next((d for d in openshell_host_dirs() if _inside(p, d)), None)
        if own is not None:
            detail = f"OpenShell's own folder on the host ({own})"
            self._record({"event": "not carded", "origin": origin, "path": str(path), "detail": detail})
            return 204, {"detail": detail}
        candidate = p
        while not candidate.is_dir() and candidate.parent != candidate:
            candidate = candidate.parent
        try:
            folder = folder_from_entry({"path": str(candidate), "access": "rw" if access == "read_write" else "ro"},
                                       self._layout)
        except LayoutError as exc:
            self._record({"event": "refused", "origin": origin, "path": str(path), "detail": str(exc)})
            return 422, {"detail": str(exc)}
        fkey = dir_key(folder["path"])
        denied = self._denied.get(f"{key}|{fkey}")
        if denied is not None:
            return 200, {"detail": "denied earlier in this chat", "path": folder["path"], **denied}
        for card in self.open.values():
            if card["kind"] == "access" and card["chat"] == key and dir_key(card["path"]) == fkey:
                if access == "read_write" and card["access"] == "read":
                    continue  # ask again for more
                return 200, {"detail": "already asking", **card}
        for entry in self._pending_restart:
            card = entry.get("card")
            if card and card["kind"] == "access" and dir_key(card["path"]) == fkey:
                return 200, {"detail": "allowed; the sandbox restarts with it", **card}
        verb = "read & write" if access == "read_write" else "read"
        risk = ("The agent can change and delete files in this folder." if access == "read_write"
                else "The agent can read every file in this folder.")
        card = await self._raise("access", key, {"path": folder["path"], "access": access},
                                 description=f"Allow {verb} access to {folder['path']}", risk=risk,
                                 extra={"origin": origin, "refused": str(path)})
        if card is None:
            return 409, {"detail": "No desktop connection for this chat."}
        self.verdicts.target(fkey, kind="access", path=folder["path"], access=access, status="asking", chat=key,
                             card=card["request_id"], raised_at=card["raised_at"], reason=None, scope=None)
        return 200, card

    def _covered(self, path: Path, access: str) -> Optional[str]:
        """Why *path* needs no folder card: the running sandbox already has it at *access* or more, or is
        denied it on purpose. None when a card may ask for it."""
        grants = getattr(self._sup, "_grants", None)
        for denied in (getattr(grants, "denied", None) or []):
            if _inside(path, denied):
                return "a path the sandbox is denied on purpose"
        for granted in (getattr(grants, "readwrite", None) or []):
            if _inside(path, granted):
                return "already granted read & write"
        if access != "read_write":
            for granted in (getattr(grants, "readonly", None) or []):
                if _inside(path, granted):
                    return "already granted read"
        return None

    async def _withdraw_covered(self) -> None:
        """After a restart with new folders: withdraw open folder cards those folders now cover (the card for
        ``folders/outside`` once ``folders`` was allowed), so the user is not asked for what already works."""
        for srq, card in list(self.open.items()):
            if card["kind"] != "access":
                continue
            covered = self._covered(Path(card["path"]), card.get("access") or "read")
            if covered:
                self.open.pop(srq, None)
                await self._withdraw(card, f"covered by a folder granted since ({covered})")
                self.verdicts.target(dir_key(card["path"]), status="allowed")

    # -- the hook's relayed refusals ----------------------------------------------------------------
    async def _request_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self._request_poll)
                self._expire_unbound()
                requests = await asyncio.to_thread(read_requests, self._requests_dir)
                for request in requests:
                    if request["kind"] == "network":
                        # checking OpenShell's records can take a few seconds: other requests don't wait for it
                        task = asyncio.ensure_future(self.on_request(request))
                        self._tasks.append(task)
                        task.add_done_callback(lambda t: t in self._tasks and self._tasks.remove(t))
                    else:
                        await self.on_request(request)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("reading the sandbox's relayed refusals failed")

    async def on_request(self, request: dict) -> None:
        """One relayed refusal from the hook: raise (or find) the card(s) and tell the hook which verdicts
        to wait for, or that there is no card."""
        self._relaying.add(request["id"])
        try:
            await self._on_request(request)
        finally:
            self._relaying.discard(request["id"])

    async def _on_request(self, request: dict) -> None:
        rid = request["id"]
        key = self._chat_for_session(request.get("session_id"))
        keys, details = [], []
        asked = None  # the sites a web tool call named (kept on its card; a denial of the card does not cover them)
        self._record({"event": "relayed", "request": rid, "kind": request["kind"], "chat": key,
                      "tool": request.get("tool"), "hosts": request.get("hosts"),
                      "paths": [p["path"] for p in request.get("paths") or []],
                      **({"strength": CANDIDATE} if request.get("strength") == CANDIDATE else {}),
                      **({"zero_wait": True} if request.get("zero_wait") else {}),
                      **({"succeeded": True} if request.get("succeeded") else {})})
        if request["kind"] == "access":
            raised = 0
            for item in request["paths"]:
                if raised >= MAX_ACCESS_CARDS_PER_RESULT:
                    break
                status, payload = await self.raise_access(item["path"], item["access"], key=key, origin="hook",
                                                          missing=item["missing"],
                                                          must_exist=bool(request.get("succeeded")))
                if status == 200 and payload.get("path"):
                    keys.append(dir_key(payload["path"]))
                    raised += 1
                else:
                    details.append(str(payload.get("detail") or status))
        else:
            drv = getattr(self._sup, "driver", None)
            candidate = request["strength"] == CANDIDATE
            zero_wait = candidate and bool(request.get("zero_wait"))  # a call that succeeded: one look, no waiting
            if self.cards and drv is not None and drv.can("requests_supported") and not zero_wait:
                self._kick_proposals()
            items = request.get("hosts") or []
            tool = request.get("tool")
            if candidate:
                named = len(items)
                items = self._candidates(request)
                request = {**request, "hosts": items}
                if named and not items:
                    details.append("every program may already reach the hosts this call named")
            category = categories.of_tool(tool)
            if category is not None:
                # A Hermes tool reached one of its own services, which its error rarely names ("Keyless
                # Firecrawl extract failed: 403 Forbidden"): every service of its category is a candidate,
                # confirmed like the rest against what OpenShell refused.
                named = {i.get("host") for i in items}
                items = [*items, *({"host": h, "port": p, "source": "tool"}
                                   for h, p in self._tool_endpoints(category.id) if h not in named)]
                request = {**request, "hosts": items}
            if key:
                for i in items:
                    h = card_host(i.get("host") or "")
                    if h:
                        self._asked[h] = {"chat": key, "t": self._clock(), "wait": request.get("wait", HOOK_WAIT),
                                          "tool": tool, "rid": rid, **({"candidate": True} if candidate else {})}
            refused = [] if not items else await (self._refused_in_call(request) if zero_wait else
                                                  self._confirm_refused(request))
            own = set(self._tool_candidates(category.id)) if category is not None else set()
            asked = ([h for h in (card_host(i.get("host") or "") for i in items)
                      if h and h not in WEB_BACKENDS and h not in own] if category is not None else None)
            for item in refused:
                # (a candidate OpenShell's records confirm is a refusal like any other)
                status, payload = await self.raise_host(item["host"], key=key, port=item.get("port"), origin="hook",
                                                        tool=request.get("tool"),
                                                        strength="strong" if candidate else request["strength"],
                                                        refused_at=request.get("t") or None, asked=asked)
                if status == 200 and payload.get("host"):
                    k = net_key(payload["host"])
                    if payload.get("detail") == "allowed":
                        self.verdicts.target(k, kind="network", host=payload["host"], status="allowed",
                                             scope=(self.verdicts.get(k) or {}).get("scope") or "allow")
                    if k not in keys:
                        keys.append(k)
                else:
                    details.append(str(payload.get("detail") or status))
            if items and not refused:
                details.append("the sandbox's proxy refused none of " + ", ".join(i["host"] for i in items))
            if not refused and request["strength"] == "strong" and key:
                # Nothing named a destination OpenShell refused: a card this chat raised from OpenShell's own draft
                # for the refusal (since shortly before the call) is the one the hook waits for; or else the next.
                since = float(request.get("t") or self._clock()) - CONFIRM_LOOKBACK
                recent = [net_key(c["host"]) for c in list(self.open.values())
                          if c.get("kind") == "network" and c.get("chat") == key and c.get("host")
                          and float(c.get("raised_at") or 0) >= since]
                keys.extend(k for k in dict.fromkeys(recent) if k not in keys)
            if not refused and candidate and key:
                # None of the hosts the failed call named was refused, but OpenShell drafted a rule for a program
                # the agent ran in this chat since the call started (a redirect's target, a site its script
                # fetched): that card is this call's refusal, and the call waits for it.
                since = float(request.get("t") or self._clock())
                recent = [net_key(c["host"]) for c in list(self.open.values())
                          if c.get("kind") == "network" and c.get("chat") == key and c.get("host")
                          and self._tool_owned(c) and float(c.get("raised_at") or 0) >= since]
                keys.extend(k for k in dict.fromkeys(recent) if k not in keys)
            if not keys and not refused and request["strength"] == "strong" and key:
                # Nothing named a destination OpenShell refused (yet): the next network card in this chat, raised
                # from OpenShell's own draft for the refusal, is the one it waits for.
                self._unbound[rid] = {"chat": key, "t": self._clock(), "wait": request.get("wait", HOOK_WAIT),
                                      "tool": request.get("tool"), "since": float(request.get("t") or self._clock()),
                                      "asked": asked}
                self._bindings[rid] = {"chat": key, "keys": [], "t": self._clock(),
                                       "wait": request.get("wait", HOOK_WAIT)}
                return
        self._note_asked(key, keys, asked)
        for k in keys:
            denied = self._denied_for(key, k)
            if denied is not None:  # this chat said no before: the hook answers at once
                self.verdicts.target(k, status="denied", reason=denied.get("reason"), chat=key)
        self.verdicts.answer(rid, "card" if keys else "refused", keys, "; ".join(details) or None)
        for k in keys:
            self._hook_asked[f"{key}|{k}"] = self._clock()
        if keys:
            # A hook whose targets are all decided already returns at once: it is not waiting on anything.
            settled = all((self.verdicts.get(k) or {}).get("status") in FINAL for k in keys)
            self._bindings[rid] = {"chat": key, "keys": keys, "t": self._clock(), "wait": request.get("wait", HOOK_WAIT),
                                   **({"released": True} if settled else {})}
            self._pause_held(key, keys)

    def _tool_endpoints(self, tool: str) -> list[tuple]:
        """``(host, port)`` of every service a tool of the category *tool* may have been refused at, for this
        profile: the addresses a credential is bound to first, then the services used without one (https)."""
        services = self._tool_services(tool)
        return list(dict.fromkeys([*((row["host"], int(row["port"])) for row in services["bound"]),
                                   *((host, TOOL_PORTS[0]) for host in services["plain"])]))

    def _tool_candidates(self, tool: str) -> list[str]:
        """The hosts of ``_tool_endpoints``."""
        return list(dict.fromkeys(host for host, _port in self._tool_endpoints(tool)))

    async def _confirm_refused(self, request: dict) -> list[dict]:
        """The relayed hosts OpenShell's proxy really refused. A tool result names candidates: the refused
        connection, but also the URL the tool was asked to fetch and links in its error text (\"Set EXA_API_KEY
        (https://exa.ai)\"), none of which the sandbox connected to. A card is raised only for a host OpenShell's
        own records show it refused (``_denials``: OCSF denial events, or a draft it made for a refusal) from
        shortly before the tool call on; the records can trail the refusal by a moment, so the launcher looks
        again for up to ``CONFIRM_WAIT``. A driver that keeps no such records leaves the hosts the refusal itself
        named (``CONNECT host:port``, ``host='...'``), never ones only found in the text."""
        items = [i for i in request.get("hosts") or [] if card_host(i.get("host") or "")]
        if not items:
            return []
        # A candidate request's hosts are only what a failed call named: looked for a shorter time (its result
        # waits, and most failed commands were refused nothing), and never carded without a record.
        candidate = request.get("strength") == CANDIDATE
        limit, poll = (CANDIDATE_WAIT, CANDIDATE_POLL) if candidate else (CONFIRM_WAIT, CONFIRM_POLL)
        since = float(request.get("t") or self._clock()) - CONFIRM_LOOKBACK
        started = time.monotonic()
        while True:
            denied, kept = await asyncio.to_thread(self._denials, since)
            if not kept:
                named = [] if candidate else [i for i in items if i.get("source") not in ("text", "tool")]
                self._record({"event": "confirmed", "request": request["id"], "how": "refusal text",
                              "candidates": [i["host"] for i in items], "refused": [i["host"] for i in named]})
                return named
            got = [i for i in items if card_host(i["host"]) in denied]
            waited = time.monotonic() - started
            if got or waited >= limit:
                self._record({"event": "confirmed", "request": request["id"], "how": "openshell records",
                              "candidates": [i["host"] for i in items], "refused": [i["host"] for i in got],
                              "waited": round(waited, 2), "denied": sorted(denied)[:20]})
                return got
            await asyncio.sleep(poll)

    async def _refused_in_call(self, request: dict) -> list[dict]:
        """The hosts of a zero-wait request (a call that SUCCEEDED and named them) that OpenShell's records show
        refused inside that call: between its start (``t``) and its end (``until``; now when the hook gave none),
        give or take ``ZERO_WAIT_SKEW``. One look at the records as they are now: the driver's feed of refusals
        where it has one, else its audit events. Nothing is waited for; a refusal recorded before the call started
        is not this call's, and a request that does not say when its call started has no window to lie in."""
        items = [i for i in request.get("hosts") or [] if card_host(i.get("host") or "")]
        started = float(request.get("t") or 0.0)
        drv = getattr(self._sup, "driver", None)
        if not items or started <= 0.0 or drv is None:
            return []
        since = started - ZERO_WAIT_SKEW
        until = (float(request.get("until") or 0.0) or self._clock()) + ZERO_WAIT_SKEW
        events, how = [], None
        try:
            if callable(getattr(drv, "recent_refusals", None)):
                events, how = drv.recent_refusals(since), "record feed"
            elif drv.can("audit_events"):
                events, how = await asyncio.to_thread(drv.events, since=since, limit=400), "audit events"
        except Exception:
            log.debug("reading the sandbox's refusals failed", exc_info=True)
        times = refused_between(events, since, until)
        got = [i for i in items if card_host(i["host"]) in times]
        self._record({"event": "confirmed", "request": request["id"], "how": f"openshell records, one look ({how})",
                      "candidates": [i["host"] for i in items], "refused": [i["host"] for i in got],
                      "window": [round(since, 3), round(until, 3)], "denied": sorted(times)[:20]})
        return got

    def _feed_refusals(self) -> None:
        """A terminal / execute_code call started: where the driver hears of refusals as they happen, copy them
        to the verdict file for as long as such a call is open (``_refusal_feed``)."""
        drv = getattr(self._sup, "driver", None)
        if not self.cards or not callable(getattr(drv, "recent_refusals", None)):
            return
        if self._feed is None or self._feed.done():
            try:
                self._feed = asyncio.get_running_loop().create_task(self._refusal_feed())
            except RuntimeError:
                pass

    async def _refusal_feed(self) -> None:
        """While a terminal / execute_code call is open: what the driver's record feed shows refused since the
        oldest open call started goes into the verdict file (``Verdicts.note_refused``; written only when
        something is new). The hook reads it the moment such a call returns."""
        while True:
            opened = [c["since"] for c in self._agent_calls.values() if c["open"] > 0]
            drv = getattr(self._sup, "driver", None)
            if not opened or not callable(getattr(drv, "recent_refusals", None)):
                return
            try:
                since = min(opened) - ZERO_WAIT_SKEW
                self.verdicts.note_refused(refused_between(drv.recent_refusals(since), since, float("inf")))
            except Exception:
                log.debug("the refusal feed failed", exc_info=True)
            await asyncio.sleep(self._feed_poll)

    def _candidates(self, request: dict) -> list[dict]:
        """The hosts of a candidate request worth asking OpenShell's records about. One every program may reach
        already (an Allow grant or a saved rule from before the call) was not refused: with none left the hook
        hears at once that there is no card."""
        started = float(request.get("t") or 0.0)
        out = []
        for item in request.get("hosts") or []:
            host = card_host(item.get("host") or "")
            if host is None:
                continue
            allowed, since, _ = self._host_allowed(host, item.get("port"))
            if allowed == "any" and not (started and since >= started - 1.0):
                continue
            out.append({**item, "host": host})
        return out

    @staticmethod
    def _tool_owned(card: dict) -> bool:
        """*card* was raised from OpenShell's draft for a program the agent ran (``_draft_owner`` rule b): a
        refusal inside one of its chat's terminal / execute_code calls, which no hook request named."""
        return card.get("kind") == "network" and card.get("origin") == "proposal:tool"

    def _denials(self, since: float) -> tuple[set, bool]:
        """Hosts OpenShell's proxy refused at or after *since*, by its own records: the audit events
        (``NET``/``HTTP`` DENIED) and drafts the launcher first listed since then. Second: whether the driver
        keeps any such records. Blocking (CLI calls on Windows): run off the event loop."""
        drv = getattr(self._sup, "driver", None)
        found: set = set()
        kept = False
        if drv is None:
            return found, kept
        if drv.can("audit_events"):
            try:
                found |= set(denied_in_events(drv.events(since=since, limit=400), since=since))
                kept = True
            except Exception:
                log.debug("listing the sandbox's denials failed", exc_info=True)
        if drv.can("requests_supported"):
            try:
                proposals = drv.proposals("all")
            except Exception:
                log.debug("listing the sandbox's drafts failed", exc_info=True)
            else:
                kept = True
                now = self._clock()
                for p in proposals:
                    first = self._proposal_first.setdefault(p.get("id"), now) if p.get("id") else now
                    if p.get("status") == "pending" and first >= since:
                        found |= {h for h, _ in _proposal_hosts(p)}
        return found, kept

    def _bind_unbound(self, key: str, target_key: str) -> None:
        for rid, entry in list(self._unbound.items()):
            if entry["chat"] == key:
                self._unbound.pop(rid)
                self._bindings[rid] = {"chat": key, "keys": [target_key], "t": entry["t"], "wait": entry["wait"]}
                self._hook_asked[f"{key}|{target_key}"] = self._clock()
                self.verdicts.answer(rid, "card", [target_key])
                self._note_asked(key, [target_key], entry.get("asked"))

    def _note_asked(self, key: Optional[str], target_keys, asked) -> None:
        """The sites a web tool call named, onto the chat's open card for that tool (whichever path raised it:
        the hook's request, or OpenShell's draft first). The card log shows them; a Deny of the card is for the
        tool and its services and does not deny these sites (``_deny``)."""
        if not asked:
            return
        for card in self.open.values():
            if card.get("tool") and card["chat"] == key and net_key(card["host"]) in target_keys:
                card["asked"] = sorted(set(card.get("asked") or ()) | set(asked))

    def _expire_unbound(self) -> None:
        now = self._clock()
        for rid, b in list(self._bindings.items()):
            if now - b["t"] > max(b.get("wait", HOOK_WAIT), 0) + 60.0:
                self._bindings.pop(rid, None)
        for rid, entry in list(self._unbound.items()):
            if now - entry["t"] > 20.0:
                self._unbound.pop(rid)
                self._bindings.pop(rid, None)
                self.verdicts.answer(rid, "refused", [], "no card was raised for this refusal")

    def _denied_for(self, chat: Optional[str], target_key: str) -> Optional[dict]:
        """This chat's standing answer for *target_key*: denied in the chat."""
        return self._denied.get(f"{chat}|{target_key}")

    def _asked_by_hook(self, chat: Optional[str], target_key: str) -> bool:
        """A hook request in *chat* waited on *target_key* (now or earlier): the agent asked for it."""
        return f"{chat}|{target_key}" in self._hook_asked or any(
            target_key in (b.get("keys") or ()) and b.get("chat") == chat for b in self._bindings.values())

    def _request_waits(self, rid: Optional[str]) -> bool:
        """Whether the hook that relayed request *rid* still waits for its verdict: the launcher is still checking
        its refusal, it waits for the next card in its chat (``_unbound``), or a card target it waits for is not
        decided yet. A request answered with no card, stopped, given up on, or whose targets are all decided waits
        for nothing."""
        if rid is None:
            return False
        if rid in self._relaying or rid in self._unbound:
            return True
        b = self._bindings.get(rid)
        if b is None or b.get("stopped") or b.get("released") or self._clock() - b["t"] >= b.get("wait", HOOK_WAIT):
            return False
        return any((self.verdicts.get(k) or {}).get("status") not in FINAL for k in b["keys"])

    def _hook_waiting(self, target_key: str) -> bool:
        now = self._clock()
        return any(target_key in b["keys"] and now - b["t"] < b.get("wait", HOOK_WAIT) and not b.get("stopped")
                   and not b.get("released") for b in self._bindings.values())

    def _kick_proposals(self) -> None:
        task = asyncio.ensure_future(self._poll_proposals())
        self._tasks.append(task)
        task.add_done_callback(lambda t: t in self._tasks and self._tasks.remove(t))

    def _stop_waiting(self, key: Optional[str]) -> None:
        """The user stopped the turn: a hook waiting in it stops waiting (its card stays open)."""
        if not key:
            return
        for rid, b in self._bindings.items():
            if b["chat"] == key and not b.get("stopped") and self._clock() - b["t"] < b.get("wait", HOOK_WAIT):
                b["stopped"] = True
                self.verdicts.stop(rid)

    # -- a card no tool call is held on pauses its chat's turn ------------------------------------------
    def _spawn(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.append(task)
        task.add_done_callback(lambda t: t in self._tasks and self._tasks.remove(t))

    def _tool_in_flight(self, key: Optional[str]) -> bool:
        return any(n and self._chat_of(sid) == key for sid, n in self._tools.items())

    def _pausing(self, key: Optional[str]) -> bool:
        """The launcher interrupted chat *key*'s turn for a pause and the backend has not reported it stopped: a
        note steered now would land in a turn that is ending."""
        pause = self._pauses.get(key)
        return pause is not None and pause["state"] == "sent"

    def _pause_holds(self, key: Optional[str]) -> bool:
        """Chat *key*'s reply is paused on cards the user has not answered, or whose answer is still being put in
        force: its notes wait, so one continuation carries every outcome."""
        pause = self._pauses.get(key)
        return bool(pause is not None and pause["state"] != "pending" and (pause["keys"] or pause["settling"])
                    and self._clock() < (pause["deadline"] or 0.0))

    async def _pause_for(self, card: dict) -> None:
        """*card* was raised from OpenShell's draft for a program the agent ran, with no tool call held on it:
        its chat's running turn pauses until the user answers (``PAUSE_WAIT``). A turn that has ended is not
        paused; the answer continues the reply all the same (``_grants_applied``, ``_deny``)."""
        key, target = card["chat"], net_key(card["host"])
        pause = self._pauses.get(key)
        if pause is None:
            if not self._chat_running(key) or self._hook_waiting(target):
                return
            pause = self._pauses[key] = {"keys": {}, "settling": set(), "since": self._clock(), "state": "pending",
                                         "deadline": None}
        pause["keys"][target] = card.get("label") or card["host"]
        if pause["state"] == "pending" and not self._tool_in_flight(key):
            await self._pause_now(key)

    async def _pause_now(self, key: str) -> None:
        """Stop chat *key*'s turn for its pending pause (no tool call is in flight any more)."""
        pause = self._pauses.get(key)
        if pause is None or pause["state"] != "pending":
            return
        if not pause["keys"] or not self._chat_running(key):
            # every card was answered while the call ran (the outcome is steered into the turn), or the turn is over
            self._pause_over(key, "the turn ended first" if pause["keys"] else "answered")
            return
        pause["state"], pause["deadline"] = "sent", self._clock() + PAUSE_WAIT
        sent = await self._interrupt(key, "a card waits for the user's answer")
        if self._pauses.get(key) is not pause:
            return  # answered, or ended by the user, while the interrupt went out
        if not sent:
            # no desktop connection reaches the turn: it runs on, and an answer is steered into it
            self._pause_over(key, "no connection shows the chat")
            return
        self._record({"event": "paused", "chat": key, "hosts": sorted(pause["keys"].values()), "wait": PAUSE_WAIT})
        self._spawn(self._pause_watch(key, pause))

    async def _tool_boundary(self, key: str) -> None:
        """Chat *key*'s last tool call in flight ended: what waited for that boundary happens now. A pending
        pause stops the turn; so does a network grant given while the call ran, on a build whose reload cuts
        open connections (the rule then loads, and the reply continues)."""
        if self._tool_in_flight(key):
            return  # the next call of the same batch started already: its end is the boundary
        if (self._pauses.get(key) or {}).get("state") == "pending":
            await self._pause_now(key)
        if key in self._stop_at_boundary:
            self._stop_at_boundary.discard(key)
            if self._net_dirty and self._chat_running(key):
                await self._stop_turns_soon(key, "network grant")

    async def _pause_watch(self, key: str, pause: dict) -> None:
        """End a pause nobody answered: the reply continues with a note that says so. The cards stay open, and an
        answer given later continues the reply again."""
        while self._pauses.get(key) is pause and self._clock() < pause["deadline"]:
            await asyncio.sleep(min(0.25, max(0.01, pause["deadline"] - self._clock())))
        if self._pauses.get(key) is pause:
            self._pause_over(key, "no answer", tell=True)

    def _pause_over(self, key: Optional[str], why: str, *, tell: bool = False) -> Optional[str]:
        """Chat *key*'s pause is over (*why*). Returns the note about the cards still unanswered, if any; *tell*
        also queues it as the reply's continuation."""
        pause = self._pauses.pop(key, None)
        if pause is None:
            return None
        asked = sorted(pause["keys"].values())
        self._record({"event": "pause ended", "chat": key, "why": why, "hosts": asked,
                      "after": round(self._clock() - pause["since"], 3)})
        if not asked:
            return None
        note = (f"The sandbox blocked {', '.join(asked)} for a program you ran. A card in the chat asks the user to "
                f"allow it, and the user has not answered. {UNANSWERED_TAIL}")
        if tell:
            self._continue(key, note)
        return note

    def _pause_answered(self, card: dict) -> None:
        """The user answered *card*: its chat's pause holds the reply until the outcome is queued for the agent
        (``_pause_settled``: a denial's reason at once, a grant once its rule has loaded)."""
        pause = self._pauses.get(card.get("chat")) if card.get("kind") == "network" else None
        if pause is not None and pause["keys"].pop(net_key(card["host"]), None) is not None:
            pause["settling"].add(net_key(card["host"]))

    def _pause_settled(self, card: dict) -> None:
        """*card* is done with for its chat's pause: its outcome is queued for the agent, or there is none to tell
        (withdrawn). With no card left the pause is over and the reply continues."""
        pause = self._pauses.get(card.get("chat")) if card.get("kind") == "network" else None
        if pause is None:
            return
        pause["keys"].pop(net_key(card["host"]), None)
        pause["settling"].discard(net_key(card["host"]))
        if not pause["keys"] and not pause["settling"] and pause["state"] != "sent":
            self._pause_over(card["chat"], "answered")
        # ("sent": the turn is still stopping; the entry stays until it has, so no outcome is steered into it)

    def _pause_turn_ended(self, key: Optional[str]) -> None:
        if not self._chat_running(key):
            self._stop_at_boundary.discard(key)
        pause = self._pauses.get(key)
        if pause is None or self._chat_running(key):
            return
        if pause["state"] == "pending":
            self._pause_over(key, "the turn ended first")  # by itself, or the user stopped it
        elif pause["state"] == "sent":
            pause["state"] = "paused"
            self._record({"event": "turn paused", "chat": key, "after": round(self._clock() - pause["since"], 3)})
            if not pause["keys"] and not pause["settling"]:
                self._pause_over(key, "answered")

    def _pause_held(self, key: Optional[str], keys) -> None:
        """A hook request in chat *key* waits on *keys*: its tool call is held on those cards, so a pause that has
        not stopped the turn yet has nothing left to do for them."""
        pause = self._pauses.get(key)
        if pause is None or pause["state"] != "pending":
            return
        for k in keys:
            pause["keys"].pop(k, None)
        if not pause["keys"] and not pause["settling"]:
            self._pause_over(key, "a tool call waits on the card")

    async def _refused_again(self, srq: str, times=()) -> None:
        """OpenShell recorded another refusal for an open card (one more hit on its draft, or a second draft).
        When a program the agent runs in the card's chat was refused (a terminal / execute_code call open or just
        ended) and no tool call is held on the card, that turn pauses on it like the turn that first raised it
        would have. *times*: OpenShell's own times for that refusal (``_draft_news``), for one listed late."""
        card = self.open.get(srq)
        if card is None or not self._tool_owned(card) or card["chat"] in self._pauses:
            return
        call = self._agent_calls.get(card["chat"])
        now = self._clock()
        if call and (call["open"] > 0 or (call["ended"] and now - call["ended"] <= AGENT_TOOL_GRACE)
                     or self._refused_during(call, list(times), now)):
            await self._pause_for(card)

    # -- answers ----------------------------------------------------------------------------------
    async def _capture(self, conn: _Conn, srq: str, *, via: str, result=None, error=None) -> None:
        card = self.open.pop(srq, None)
        if card is None:
            return
        result = result if isinstance(result, dict) else {}
        scope = SCOPE_OF.get(result.get("choice"), "deny")
        reason = result.get("reason") or result.get("message")
        reason = str(reason).strip()[:MAX_REASON] if isinstance(reason, str) and reason.strip() else None
        entry = {"event": "answered", "request_id": card["request_id"], "server_request_id": srq,
                 "kind": card["kind"], "chat": card["chat"], "choice": scope, "reason": reason, "error": error,
                 "via": via, "connection": getattr(conn, "n", None), "answered_at": self._clock(),
                 "target": {k: card.get(k) for k in ("path", "access", "host", "label")
                            if card.get(k) not in (None, "")}}
        self.answers.append(entry)
        self._record(entry)
        paused = card["chat"] in self._pauses  # (asked before this answer ends the pause)
        self._pause_answered(card)
        cancel = server_text_frame({"jsonrpc": "2.0", "method": "event", "params": {
            "type": "request.cancel", "session_id": card["session_id"],
            "payload": {"id": srq, "method": "approval", "reason": "resolved"}}})
        for other in self._conns:
            if other is not conn:
                try:
                    await other.to_client(cancel)
                except (ConnectionError, OSError, AttributeError):
                    pass
        if not self.cards:
            return
        if scope == "deny":
            # off the relay's path: rejecting lists and decides through the driver (a CLI call on Windows)
            task = asyncio.ensure_future(self._deny(card, reason or DEFAULT_DENY_REASON))
            self._tasks.append(task)
            task.add_done_callback(lambda t: t in self._tasks and self._tasks.remove(t))
            return
        covered = self._covered_cards(card) if card["kind"] == "network" else []
        keys = [net_key(card["host"])] + [net_key(c["host"]) for c in covered] if card["kind"] == "network" else []
        if card["kind"] == "access" or self._rebinds(card):
            # A folder grant restarts the sandbox, and so does a tool category's that binds a credential to a
            # new address. The launcher stops the chat's running turn itself, BEFORE the waiting hook gets its
            # verdict, so the turn ends at that tool result instead of the model being asked to end it (a model
            # may ignore that and keep retrying).
            await self._restart_soon(card["chat"], "folder grant" if card["kind"] == "access" else "tool grant")
        elif self._net_between_turns() and any(self._hook_waiting(k) for k in keys):
            # The same for a network grant on a build whose policy reload would cut the turn's model stream: the
            # turn waiting on this card stops at its tool result, the rule loads, and the chat continues. While
            # another chat streams a reply (the reload would cut it), this chat's tool call keeps waiting, its row
            # still running, and stops once that reply ended (``_soon_wait``).
            if self._replies_streaming(exclude={card["chat"]}):
                self._new_soon().setdefault("held", {})[card["chat"]] = {"card": card, "scope": scope}
            else:
                await self._stop_turns_soon(card["chat"], "network grant")
        elif self._net_between_turns() and self._tool_owned(card) and (paused or self._chat_running(card["chat"])):
            # No tool call is held on this card (it came from OpenShell's draft), but its chat's turn is paused on
            # it or still runs: the rule loads as soon as that turn has stopped, not when the whole sandbox is next
            # idle, and the reply continues. The launcher stops the turn itself unless the pause already did; while
            # the card's own call still runs, it does so when that call ends (now would kill the command).
            if self._tool_in_flight(card["chat"]) and not self._pausing(card["chat"]):
                self._stop_at_boundary.add(card["chat"])
            else:
                await self._stop_turns_soon(card["chat"], "network grant")
        for other in covered:  # before the grant's verdict, so the covered cards' hooks follow it (_target_for)
            card.setdefault("covers", []).append(net_key(other["host"]))
        try:
            self._record_grant(card, scope)
        except Exception as exc:
            self._history("grant failed", card, scope=scope, error=str(exc))
            self._target_for(card, status="failed", error=str(exc), scope=scope)
            what = (f"Access to {card['path']}" if card["kind"] == "access" else
                    f"Network access to {card.get('label') or card['host']}")
            told = False
            if self._soon is not None:
                (self._soon.get("held") or {}).pop(card["chat"], None)
                if card["chat"] in self._soon["interrupted"]:
                    self._continue(card["chat"], f"{what} could not be granted: {exc}")
                    told = True
                if not self._pending_restart and not self._pending_net:
                    self._soon = None
            if not told and self._tool_owned(card) and not self._hook_waiting(net_key(card["host"])):
                # no tool call waits on this card for the verdict: its chat hears it (a paused reply continues)
                await self._deliver(card["chat"], f"{what} could not be granted: {exc}")
            self._stop_at_boundary.discard(card["chat"])
            self._pause_settled(card)
            return
        for other in covered:
            await self._withdraw_covered_card(other, card)
        self._kick()

    def _covered_cards(self, card: dict) -> list[dict]:
        """The chat's other open network cards an Allow of *card* covers: every host they ask for is one the new
        rule opens (a site card for one of a web tool's services; another web tool on the same services)."""
        granted = set(card.get("hosts") or [card["host"]])
        return [c for c in self.open.values()
                if c["kind"] == "network" and c["chat"] == card["chat"] and c is not card
                and (c["host"] == card["host"] or set(c.get("hosts") or [c["host"]]) <= granted)]

    async def _withdraw_covered_card(self, other: dict, card: dict) -> None:
        """*other* is covered by the Allow of *card* (same chat): no stale second card; its hook waits on
        *card*'s verdict (``covers``)."""
        srq = next((k for k, c in self.open.items() if c is other), None)
        if srq is None:
            return
        self.open.pop(srq, None)
        await self._withdraw(other, f"covered by the answer for {card.get('label') or card['host']}")
        for pid in other.get("proposal_ids") or []:
            self._chunks.setdefault(pid, {})["decided"] = "approved"

    def _target_for(self, card: dict, **fields) -> None:
        k = net_key(card["host"]) if card["kind"] == "network" else dir_key(card["path"])
        self.verdicts.target(k, **fields)
        for other in card.get("covers") or ():  # cards this answer covered (_covered_cards)
            self.verdicts.target(other, **fields)

    def _release_card(self, card: dict) -> None:
        for k in [net_key(card["host"]), *(card.get("covers") or ())]:
            self._release(k)

    def _record_grant(self, card: dict, scope: str) -> None:
        """An Allow / Always allow, in the state every launch and policy update is built from: Allow in the
        grants (``Supervisor.temporary``), Always allow in spec.yaml. The apply loop puts it in force."""
        from .spec import load_spec, network_policy, update_spec

        sup = self._sup
        entry = {"card": card, "scope": scope, "answered_at": self._clock()}
        if card["kind"] == "network":
            tool = card.get("tool")
            hosts = list(card.get("hosts") or [card["host"]]) if tool else [card["host"]]
            rebind = self._rebinds(card)
            if tool:  # a Hermes tool's category: every service it uses without a credential, https
                ports = set(TOOL_PORTS)
                rule = tool_rule(tool, card["plain"] if "plain" in card else hosts)
            else:
                ports = set(HOST_PORTS) | self._ports.get(card["host"], set())
                rule = host_rule(card["host"], ports)
            entry["rule"] = rule
            for pid in card.get("proposal_ids") or []:
                self._chunks.setdefault(pid, {})["decided"] = "approved"
            if scope == "always":
                spec = load_spec(self._layout)
                net = network_policy(spec)
                approved = dict(net.get("approved") or {})
                approved[rule["name"]] = _merge_rule(approved.get(rule["name"]), rule)
                sup.set_spec(update_spec(self._layout, network={**net, "approved": approved}))
            else:
                self.grants = [g for g in self.grants if not (g["kind"] == "network" and g["host"] == card["host"])]
                self.grants.append({"kind": "network", "scope": "allow", "host": card["host"], "ports": sorted(ports),
                                    "rule_name": rule["name"], "rule": rule, "label": card.get("label"),
                                    "chat": card["chat"], "applied_at": None, "answered_at": entry["answered_at"],
                                    **({"tool": tool, "hosts": hosts, "shown": card.get("shown") or hosts}
                                       if tool else {})})
                self._sync_temporary()
            if rebind:
                # A credential reaches the category's addresses only in a sandbox that starts bound to them:
                # one restart, as for a folder, and the reply continues after it. The restart carries the
                # answer; no policy update is made for it.
                entry["rebind"] = True
                self._pending_restart.append({"tool_add": card.get("label") or tool_label(tool), "chat": card["chat"],
                                              "scope": scope, "entry": entry})
                self._target_for(card, status="restarting", scope=scope, reason=None)
                return
            self._pending_net.append(entry)
            self._net_dirty = True
            held = self._soon is not None and card["chat"] in (self._soon.get("held") or {})
            self._target_for(card, status="applying" if self._net_live() or held else "allowed_later", scope=scope,
                             reason=None)
            if not self._net_live() and not held:
                # the waiting hook returns with this final answer: what comes next (the rule in place, or that it
                # failed) reaches the agent as a continuation or a steer, never through that hook
                self._release_card(card)
        else:
            folder = {"path": card["path"], "access": "rw" if card.get("access") == "read_write" else "ro"}
            if scope == "always":
                spec = load_spec(self._layout)
                same = [f for f in spec.get("folders") or [] if dir_key(f["path"]) == dir_key(folder["path"])]
                if same and str(same[0].get("access")) == "rw":
                    folder["access"] = "rw"
                entry["spec_folders_before"] = spec.get("folders") or []
                folders = [f for f in spec.get("folders") or [] if dir_key(f["path"]) != dir_key(folder["path"])]
                sup.set_spec(update_spec(self._layout, folders=folders + [folder]))
            else:
                self.grants.append({"kind": "access", "scope": "allow", "path": card["path"],
                                    "access": card.get("access"), "chat": card["chat"], "applied_at": None,
                                    "answered_at": entry["answered_at"]})
                self._sync_temporary()
            self._pending_restart.append(entry)
            self._target_for(card, status="restarting", scope=scope, reason=None)

    async def _deny(self, card: dict, reason: str) -> None:
        key = card["chat"]
        if card["kind"] == "network":
            target = net_key(card["host"])
            self._denied[f"{key}|{target}"] = {"reason": reason, "t": self._clock()}
            for host in card.get("hosts") or ():  # a web tool's card: the services it asked for are denied too
                self._denied[f"{key}|{net_key(host)}"] = self._denied[f"{key}|{target}"]
            self.verdicts.target(target, status="denied", reason=reason, chat=key)
            for pid in card.get("proposal_ids") or []:
                self._chunks.setdefault(pid, {}).update({"decided": "rejected", "chat": key})
                current = await self._fresh(pid)
                if current is not None and current.get("status") == "pending":
                    try:
                        await asyncio.to_thread(self._sup.driver.reject, pid, reason)
                    except Exception as exc:  # recorded; the agent still gets the reason
                        self._history("reject failed", card, error=str(exc), proposal_id=pid)
            self._history("rejected", card, reason=reason)
            note = f"The user denied network access to {card.get('label') or card['host']}. Reason: {reason}"
        else:
            target = dir_key(card["path"])
            self._denied[f"{key}|{target}"] = {"reason": reason, "t": self._clock()}
            self.verdicts.target(target, status="denied", reason=reason, chat=key)
            verb = "read & write" if card.get("access") == "read_write" else "read"
            note = f"The user denied {verb} access to {card['path']}. Reason: {reason}"
            self._history("denied", card, reason=reason)
        if not self._hook_waiting(target) or self._pausing(key):
            # (a hook that waits in a turn the launcher is stopping for a pause tells a turn that ends: the reply's
            # continuation carries the reason)
            await self._deliver(key, note + " " + DENIED_TAIL)
        self._pause_settled(card)

    async def _fresh(self, pid: str) -> Optional[dict]:
        try:
            for p in await asyncio.to_thread(self._sup.driver.proposals, "all"):
                if p.get("id") == pid:
                    return p
        except Exception:
            return None
        return None

    # -- telling the agent ------------------------------------------------------------------------
    async def _deliver(self, key: str, note: str) -> None:
        """An outcome for the agent when no hook waits for it: steered into the chat's running turn, else
        a continuation (a hidden prompt) so the agent resumes by itself. A turn that refused a steer gets none:
        the note waits for its end."""
        if self._chat_running(key) and key not in self._no_steer and not self._pausing(key):
            await self._tell(key, note, now=True)
        else:
            self._continue(key, note)

    async def _tell(self, key: str, note: str, *, now: bool = False) -> None:
        """A note for the agent: steered into the running turn when *now* and the chat's turn runs, else
        prefixed to the chat's next prompt. Always one ``[Sandbox] `` line (a user's deny reason may hold
        newlines; the desktop lifts only single-line notes off the prompt)."""
        text = sandbox_note(note)
        live = next((s for s in self._running if self._chat_of(s) == key), None) if now else None
        conn = next((c for c in self._conns if live in c.sessions), None) if live else None
        if conn is not None and getattr(conn, "u_writer", None) is not None:
            rid = _CALL_PREFIX + secrets.token_hex(6)
            conn.own_calls[rid] = {"method": "session.steer", "chat": key, "text": text, "live": live}
            try:
                await conn.to_upstream(client_text_frame({"jsonrpc": "2.0", "id": rid, "method": "session.steer",
                                                          "params": {"session_id": live, "text": text}}))
                self._record({"event": "steered", "chat": key, "text": text})
                return
            except (ConnectionError, OSError):
                conn.own_calls.pop(rid, None)
        self.notices.setdefault(key, []).append(text)
        self._record({"event": "noted", "chat": key, "text": text})

    def _continue(self, key: str, note: str) -> None:
        """Queue *note* for a continuation of chat *key*: once the sandbox runs, the chat is idle and a
        desktop connection shows it (after a restart: once the desktop has resumed it, or the launcher has
        on a connection that shows another page), the launcher submits it as a hidden prompt so the agent
        picks up where it stopped."""
        self._continue_text.setdefault(key, []).append(one_line(note))
        task = self._continuing.get(key)
        if task is None or task.done():
            self._continuing[key] = asyncio.ensure_future(self._continue_when_ready(key))

    def _delivered(self, key: str) -> None:
        """The backend took a note for chat *key* (a steer queued, a continuation started), or the user's prompt
        carries it: refusals start over."""
        self._note_tries.pop(key, None)
        self._no_steer.discard(key)

    def _retry_note(self, key: str, text: str, *, steer: bool) -> None:
        """The backend refused a note for chat *key* (its steer or its continuation): it goes as a continuation (or,
        *steer*, into a turn of the chat that runs by then) after a backoff that doubles with each refusal in a row,
        at most NOTE_RETRIES times; then it goes with the chat's next prompt. *steer* False: the running turn itself
        refused the steer, so the note waits for that turn to end."""
        tries = self._note_tries.get(key, 0) + 1
        if tries > NOTE_RETRIES:
            self._delivered(key)
            notes = [*self._continue_text.pop(key, []), one_line(text)]
            self.notices.setdefault(key, []).extend(sandbox_note(n) for n in notes)
            self._record({"event": "noted", "chat": key, "text": notes, "why": f"the backend refused it {tries} times"})
            return
        self._note_tries[key] = tries
        if not steer:
            self._no_steer.add(key)
        self._continue(key, text)

    async def _continue_when_ready(self, key: str) -> None:
        deadline = self._clock() + CONTINUE_WAIT
        tries = self._note_tries.get(key, 0)
        delay = min(NOTE_BACKOFF * 2 ** (tries - 1), NOTE_BACKOFF_MAX) if tries else 0.25
        resolved = False
        resume_at = 0.0
        while True:
            await asyncio.sleep(delay)
            delay = 0.25
            notes = self._continue_text.get(key) or []
            if not notes:
                return
            running = self._chat_running(key)
            if running and key not in self._no_steer and not self._pausing(key):
                # a turn started first (the user wrote): the notes go into it
                self._continue_text.pop(key, None)
                await self._tell(key, " ".join(notes), now=True)
                return
            sup = self._sup
            # (a reply paused on cards still unanswered waits for them: one continuation carries every outcome)
            ready = not running and (sup is None or (sup.running() and not self._applying)) \
                and not self._pause_holds(key)
            live = self._live_for(key)
            conn = next((c for c in reversed(self._conns) if live in c.sessions and getattr(c, "u_writer", None)
                         is not None), None) if live else None
            if conn is None and ready and tries and not resolved:
                # the backend refused the chat's live id: it may run the chat under another one
                resolved = True
                if await self._resolve_live(key) is not None:
                    delay = 0.0
                    continue
            if conn is None and ready and self._clock() >= resume_at:
                # No window shows the chat (another page is open): the reply goes on all the same.
                resumed = await self._resume_chat(key)
                if resumed:
                    delay = 0.0
                    continue
                if resumed is False:
                    resume_at = self._clock() + RESUME_RETRY
            if ready and conn is not None:
                self._continue_text.pop(key, None)
                text = "[Sandbox] " + " ".join(n.removeprefix("[Sandbox] ") for n in notes)
                if "Continue where you left off" not in text and \
                        not all(any(tail in n for tail in _NO_RETRY_TAILS) for n in notes):
                    # (denials and unanswered cards only: the notes say what to do, and nothing can be retried)
                    text += " " + CONTINUE_TAIL
                rid = _CALL_PREFIX + secrets.token_hex(6)
                conn.own_calls[rid] = {"method": "prompt.submit", "chat": key, "text": text, "live": live}
                try:
                    await conn.to_upstream(client_text_frame({"jsonrpc": "2.0", "id": rid, "method": "prompt.submit",
                                                              "params": {"session_id": live, "text": text,
                                                                         "display_kind": "hidden"}}))
                except (ConnectionError, OSError):
                    conn.own_calls.pop(rid, None)
                    self._continue_text.setdefault(key, []).extend(notes)
                    continue
                self._turn_started(live)
                self._record({"event": "continued", "chat": key, "session_id": live, "text": text})
                return
            if self._clock() > deadline and not self._pause_holds(key):
                self._continue_text.pop(key, None)
                self._delivered(key)
                self.notices.setdefault(key, []).extend(sandbox_note(n) for n in notes)
                connected = any(getattr(c, "u_writer", None) is not None for c in self._conns)
                if not running:
                    self._stopped[key] = STOPPED_LINE  # said when the chat is next opened (``_say_stopped``)
                self._record({"event": "noted", "chat": key, "text": notes,
                              "why": "its turn still ran" if running else "the chat could not be resumed"
                              if connected else "no window was connected"})
                return

    async def _resume_chat(self, key: str):
        """Chat *key* waits for its continuation and no desktop connection shows it: the window shows another
        page, so it connected again after the restart and resumed nothing. Resume the chat on the newest
        connection that has had ``RESUME_GRACE`` to do so itself, with the call the desktop makes when a chat is
        opened. The backend then holds a live session for the chat on that connection; when the user opens the
        chat, the desktop's own resume joins that session and shows the reply.

        The live session id on success. False: the backend refused or did not answer (tried again after
        ``RESUME_RETRY``). None: no connection is old enough yet, or none is there."""
        now = self._clock()
        conn = next((c for c in reversed(self._conns) if getattr(c, "u_writer", None) is not None
                     and now - getattr(c, "opened", 0.0) >= RESUME_GRACE), None)
        if conn is None:
            return None
        params = {**RESUME_PARAMS, **((self._chats.get(key) or {}).get("resume") or {}), "session_id": key}
        rid = _CALL_PREFIX + secrets.token_hex(6)
        reply = asyncio.get_running_loop().create_future()
        conn.own_calls[rid] = {"method": "session.resume", "chat": key, "reply": reply, "quiet": True}
        frame = client_text_frame({"jsonrpc": "2.0", "id": rid, "method": "session.resume", "params": params})
        try:
            await asyncio.wait_for(conn.to_upstream(frame), 1.0)
            obj = await asyncio.wait_for(reply, RESUME_WAIT)
        except (ConnectionError, OSError, asyncio.TimeoutError):
            conn.own_calls.pop(rid, None)
            self._record({"event": "resume refused", "chat": key, "connection": conn.n, "error": "no answer"})
            return False
        result = obj.get("result") if isinstance(obj.get("result"), dict) else {}
        live = result.get("session_id") or result.get("id")
        if not isinstance(live, str) or not live:
            refusal = obj.get("error") if isinstance(obj.get("error"), dict) else {}
            self._record({"event": "resume refused", "chat": key, "connection": conn.n,
                          "error": {"code": refusal.get("code"), "message": one_line(refusal.get("message") or "")[:200]}})
            return False
        if conn not in self._conns:
            return False  # the connection went away while the backend answered
        self._link(live, key)
        conn.saw(live)
        self._record({"event": "resumed", "chat": key, "session_id": live, "connection": conn.n,
                      "why": "no window showed the chat"})
        return live

    async def _say_stopped(self, conn: _Conn, key: str, live: str) -> None:
        """A desktop opened chat *key*, whose reply did not go on after a restart (no window was connected, and
        the launcher gave up): the chat says so once, in the line the desktop shows for a reply that could not
        run. Nothing is started; the note for the agent goes with the user's next message."""
        await asyncio.sleep(STOPPED_LINE_DELAY)
        line = self._stopped.pop(key, None)
        if line is None:
            return
        frame = {"jsonrpc": "2.0", "method": "event",
                 "params": {"type": "error", "session_id": live, "payload": {"message": line}}}
        try:
            await conn.to_client(server_text_frame(frame))
        except (ConnectionError, OSError, AttributeError):
            self._stopped[key] = line  # the next window that opens the chat says it
            return
        self._record({"event": "told", "chat": key, "session_id": live, "text": line})

    def _with_notices(self, params: dict) -> Optional[dict]:
        """The desktop's note format: ``[Sandbox] <note>`` lines first, ONE blank line,
        then the user's text unchanged."""
        key = self._chat_of(params.get("session_id"))
        notes = self.notices.get(key) if key else None
        text = params.get("text")
        if not notes or not isinstance(text, str) or params.get("display_kind") == "hidden" \
                or any(k.startswith("truncat") or k in ("ordinal", "edit_ordinal") for k in params):
            return None
        self.notices.pop(key, None)
        notes = [sandbox_note(n) for n in notes if one_line(n).removeprefix("[Sandbox]").strip()]
        if not notes:
            return None
        self._record({"event": "delivered", "chat": key, "notes": notes})
        return {**params, "text": "\n".join(notes) + "\n\n" + text, "_notes": notes}

    # -- relay --------------------------------------------------------------------------------------
    async def relay(self, c_reader, c_writer, u_reader, u_writer) -> None:
        head = await u_reader.readuntil(b"\r\n\r\n")
        c_writer.write(head)
        await c_writer.drain()
        if not head.startswith((b"HTTP/1.1 101", b"HTTP/1.0 101")):
            while chunk := await u_reader.read(65536):
                c_writer.write(chunk)
                await c_writer.drain()
            return
        conn = _Conn(c_writer, u_writer)
        conn.opened = self._clock()
        self._conns.append(conn)
        tasks = [asyncio.ensure_future(self._pump(self._from_client, conn, c_reader, upstream=True)),
                 asyncio.ensure_future(self._pump(self._from_sandbox, conn, u_reader, upstream=False))]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            if tasks[1] in done:
                # The sandbox's side ended (its backend stopped or died) without closing the socket itself:
                # close the desktop's side now, as a planned service restart, instead of leaving it open
                # until the desktop's heartbeat gives up.
                await conn.close_client(CLOSE_RESTART, "service restart")
        finally:
            self._conns.remove(conn)
            self._closed(conn)

    async def close_clients(self, why: str = "restarting") -> None:
        """The backend is going down on purpose (a restart, a stop) or died (``Supervisor.on_down``): close
        every relayed desktop socket with 1012 at once. The relay then ends; the desktop reconnects and
        reads the launcher's status (``restarting`` / ``stopping``) instead of timing out a heartbeat."""
        conns = list(self._conns)
        if conns:
            self._record({"event": "closed sockets", "why": why, "connections": [c.n for c in conns]})
        await asyncio.gather(*(c.close_client(CLOSE_RESTART, "service restart") for c in conns),
                             return_exceptions=True)

    def _closed(self, conn: _Conn) -> None:
        """A desktop connection went away. Its live sessions are gone with it (a reconnect resumes the
        chat under a new live id), so they leave their chats; a chat no connection shows is orphaned."""
        now = self._clock()
        held = {s for c in self._conns for s in c.sessions}
        for sid in conn.sessions:
            key = self._chat_of(sid)
            chat = self._chats.get(key)
            if sid not in held:
                if chat is not None:
                    chat["live"].discard(sid)
                if sid not in self._running:
                    self._live.pop(sid, None)
            if chat is not None and not any(self._chat_of(s) == key for s in held):
                chat.setdefault("orphaned", now)
        if self._detached_turns():
            self._watch_detached()

    async def _pump(self, handle, conn: _Conn, reader, *, upstream: bool) -> None:
        try:
            async for kind, opcode, data, raws in _messages(reader):
                keep = True
                if kind == "data" and opcode == 0x1:
                    try:
                        obj = json.loads(data)
                    except ValueError:
                        obj = None
                    if isinstance(obj, dict):
                        keep = await handle(conn, obj)
                if keep is False:
                    continue
                if upstream:
                    await conn.to_upstream(client_text_frame(keep) if isinstance(keep, dict) else b"".join(raws))
                else:
                    if kind == "control" and opcode == 0x8:
                        if conn.close_sent:
                            continue  # the launcher closed this socket already
                        conn.close_sent = True  # the sandbox's own close goes through; no second one
                    await conn.to_client(server_text_frame(keep) if isinstance(keep, dict) else b"".join(raws))
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass

    def _card_for_request_id(self, rid) -> Optional[str]:
        return next((srq for srq, c in self.open.items() if c["request_id"] == rid), None)

    async def _from_client(self, conn: _Conn, obj: dict):
        """True: forward unchanged. False: captured here, never reaches the sandbox. A dict: forward this."""
        rid = obj.get("id")
        if "method" not in obj and isinstance(rid, str) and rid in self.open and ("result" in obj or "error" in obj):
            await self._capture(conn, rid, via="response", result=obj.get("result"), error=obj.get("error"))
            return False
        method = obj.get("method")
        params = obj.get("params") if isinstance(obj.get("params"), dict) else {}
        if method in ("approval.respond", "approval.received") and (srq := self._card_for_request_id(params.get("request_id"))):
            if method == "approval.respond":
                await self._capture(conn, srq, via="approval.respond",
                                    result={"choice": params.get("choice"), "all": params.get("all"),
                                            "reason": params.get("reason")})
            reply = {"resolved": 1} if method == "approval.respond" else {"acknowledged": True}
            await conn.to_client(server_text_frame({"jsonrpc": "2.0", "id": rid, "result": reply}))
            return False
        if method == "request.answer" and params.get("id") in self.open:
            await self._capture(conn, params["id"], via="request.answer", result=params.get("result"))
            await conn.to_client(server_text_frame({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}}))
            return False
        if isinstance(rid, (str, int)) and method:
            if isinstance(conn.calls, dict):
                conn.calls[rid] = (method, params)
        if method == "approval.pending":
            conn.pending_lists[rid] = params.get("session_id")
        elif method == "prompt.submit":
            sid = params.get("session_id")
            conn.saw(sid)
            if self._applying and self._apply_done is not None:
                try:  # a change is being applied: the turn starts once it is in place
                    await asyncio.wait_for(self._apply_done.wait(), GATE_TIMEOUT)
                except asyncio.TimeoutError:
                    pass
            key = self._chat_of(sid)
            self._stopped.pop(key, None)      # ... and the line about a reply that stopped has nothing left to say
            unanswered = self._pause_over(key, "the user wrote")
            if unanswered:  # the reply was paused on a card: this prompt carries what the continuation would have
                self.notices.setdefault(key, []).append(sandbox_note(unanswered))
            if key and self._unplaced_notes:
                self.notices.setdefault(key, []).extend(sandbox_note(n) for n in self._unplaced_notes)
                self._unplaced_notes = []
            if key and self._continue_text.get(key):
                # the user writes first: the pending continuation rides on this prompt instead
                self.notices.setdefault(key, []).extend(sandbox_note(n) for n in self._continue_text.pop(key))
                self._delivered(key)
            if isinstance(sid, str) and sid:
                self._turn_started(sid)
            changed = self._with_notices(params)
            if changed is not None:
                if rid is not None:  # put the notes back if the backend refuses this submit
                    conn.notice_calls[rid] = (self._chat_of(params.get("session_id")), changed.pop("_notes"))
                else:
                    changed.pop("_notes")
                return {**obj, "params": changed}
        elif method == "session.interrupt":
            self._stop_waiting(self._chat_of(params.get("session_id")))
            self._pause_over(self._chat_of(params.get("session_id")), "the user stopped the reply")
        elif method == "session.close":
            self._chat_closed(params.get("session_id"))
        return True

    def _chat_closed(self, sid) -> None:
        key = self._chat_of(sid)
        if key is None:
            return
        chat = self._chats.get(key)
        if chat is not None:
            chat["live"].discard(sid)
            if not chat["live"]:
                self._end_chat(key)
        self._live.pop(sid, None)
        self._running.pop(sid, None)
        for conn in self._conns:
            if sid in conn.sessions:
                conn.sessions.remove(sid)

    def _end_chat(self, key: str) -> None:
        """A chat ended. Grants stay (Allow lasts until the sandbox is switched off); its pending
        continuation and its denials go."""
        self._chats.pop(key, None)
        self._notes_lost("the chat was closed", key)
        self._stopped.pop(key, None)
        self._pauses.pop(key, None)
        self._denied = {k: v for k, v in self._denied.items() if not k.startswith(f"{key}|")}

    async def _from_sandbox(self, conn: _Conn, obj: dict):
        """True: forward unchanged. False: dropped. A dict: forward this instead."""
        method, rid = obj.get("method"), obj.get("id")
        params = obj.get("params") if isinstance(obj.get("params"), dict) else {}
        if method and rid is not None and (rid in self.open or _reserved(rid) or _reserved(params.get("request_id"))):
            self._drop(conn, "forged request", obj)
            return False
        if method is None and rid is not None and rid in getattr(conn, "own_calls", {}):
            self._own_reply(conn, rid, obj)
            return False
        if method == "approval":
            # Only cards the launcher raises may carry access wording: a sandbox-sent approval keeps its
            # command text but loses any kind and access target, so it renders as a command approval.
            clean = _without_access_fields(params)
            if clean is not params:
                self.stripped += 1
                return {**obj, "params": clean}
            return True
        if method == "event":
            typ, sid, payload = params.get("type"), params.get("session_id"), params.get("payload")
            payload = payload if isinstance(payload, dict) else {}
            if typ == "request.cancel" and (payload.get("id") in self.open or _reserved(payload.get("id"))):
                self._drop(conn, "forged cancel", obj)
                return False
            if isinstance(sid, str) and sid:
                if typ in ("tool.start", "tool.complete"):
                    n = self._tools.get(sid, 0) + (1 if typ == "tool.start" else -1)
                    self._tools[sid] = max(0, n)
                    self._tool_seen = self._clock()
                    names = self._tool_names.setdefault(sid, [])
                    name = str(payload.get("name") or "")
                    if typ == "tool.start":
                        names.append(name)
                    elif name in names:
                        names.remove(name)
                    if name in AGENT_TOOLS:
                        self._agent_call(sid, started=typ == "tool.start")
                    if typ == "tool.complete" and (self._pauses or self._stop_at_boundary) and not self._tools.get(sid):
                        chat = self._chat_of(sid)
                        if not self._tool_in_flight(chat) and (
                                chat in self._stop_at_boundary or (self._pauses.get(chat) or {}).get("state") == "pending"):
                            self._spawn(self._tool_boundary(chat))
                if typ in _TURN_EVENTS:
                    conn.saw(sid)
                    conn.running.add(sid)
                    if self.cards:
                        self._turn_started(sid)
                elif typ == "message.complete":
                    conn.running.discard(sid)
                    self._tools.pop(sid, None)
                    self._tool_names.pop(sid, None)
                    if self.cards:
                        self._turn_ended(sid)
                elif typ == "session.info":
                    if self.cards:
                        self._link(sid, payload.get("stored_session_id"))
                        if payload.get("running") is True:
                            self._turn_started(sid)
                        elif payload.get("running") is False:
                            self._drop_detached_turns(sid)
                            if sid in self._running:
                                self._turn_ended(sid)
            if typ == "tool.complete":
                self._maybe_card_for_denial(sid, payload)
            return True
        if method is None and rid is not None:
            call = conn.calls.pop(rid, None) if isinstance(getattr(conn, "calls", None), dict) else None
            carried = conn.notice_calls.pop(rid, None) if isinstance(getattr(conn, "notice_calls", None), dict) else None
            if carried and obj.get("error") is not None:
                # The backend refused that submit (the desktop retries it, e.g. without fields an older
                # backend rejects): the notes go with the retry instead of being lost.
                key, notes = carried
                if key:
                    self.notices[key] = [*notes, *self.notices.get(key, [])]
                    refusal = obj["error"] if isinstance(obj["error"], dict) else {}
                    self._record({"event": "kept", "chat": key, "notes": notes, "why": "submit refused",
                                  "error": {"code": refusal.get("code"),
                                            "message": one_line(refusal.get("message") or "")[:200]}})
            if call and self.cards and self._unknown_session(obj):
                # the backend does not hold the id the desktop used (e.g. the host backend's id of a chat the desktop
                # has not resumed here yet): a submit under it started no turn, and nothing more goes to it
                self._forget_session((call[1] or {}).get("session_id"), call[0])
            result = obj.get("result") if isinstance(obj.get("result"), dict) else None
            if call and result is not None and call[0] in ("session.create", "session.resume") and self.cards:
                live = result.get("session_id") or result.get("id")
                if isinstance(live, str):
                    conn.saw(live)
                    stored = result.get("stored_session_id")
                    if not stored and call[0] == "session.resume":
                        stored = (call[1] or {}).get("session_id")  # resume names the stored id
                    self._link(live, stored)
                    key = self._chat_of(live)
                    named = {k: (call[1] or {})[k] for k in _RESUME_KEPT if (call[1] or {}).get(k) is not None}
                    if named and key in self._chats:
                        self._chats[key]["resume"] = named
                    if call[0] == "session.resume" and key in self._stopped:
                        self._spawn(self._say_stopped(conn, key, live))
            if rid in conn.pending_lists and result is not None:
                sid = conn.pending_lists.pop(rid)
                result = dict(result)
                listed = result.get("approvals") if isinstance(result.get("approvals"), list) else []
                own = [_without_access_fields(a) if isinstance(a, dict) else a for a in listed]
                changed = any(a is not b for a, b in zip(own, listed))
                key = self._chat_of(sid)
                extra = [self._pending_entry(c) for c in self.open.values()
                         if c["chat"] == key or c["session_id"] == sid]
                if extra or changed:
                    self.stripped += int(changed)
                    result["approvals"] = [*own, *extra]
                    return {**obj, "result": result}
        return True

    def _own_reply(self, conn: _Conn, rid, obj: dict) -> None:
        what = conn.own_calls.pop(rid, {})
        error = obj.get("error") if isinstance(obj.get("error"), dict) else {}
        if what.get("resume") and error.get("code") == 4000:
            # A core without session.interrupt ``resume`` refuses the parameter: stop the turn plainly (the reply
            # then reads as stopped until its continuation starts). The caller's ack waits for that reply.
            self._record({"event": "own reply", "method": "session.interrupt", "result": error,
                          "then": "plain interrupt"})
            asyncio.ensure_future(self._send_interrupt(conn, what["chat"], what["live"], what.get("acked"),
                                                       resume=False))
            return
        if what.get("acked") is not None and not what["acked"].done():
            what["acked"].set_result(True)
        unknown = self._unknown_session(obj)
        if unknown and what.get("live"):
            self._forget_session(what["live"], what.get("method") or "?")  # nothing more goes to that id
        if what.get("reply") is not None and not what["reply"].done():
            what["reply"].set_result(obj)
        if what.get("quiet"):
            return  # a status poll: its answer (chat titles and previews) stays out of the card log
        result = obj.get("result") if isinstance(obj.get("result"), dict) else {}
        if what.get("method") == "process.list":  # commands stay out of the card log
            result = {"processes": len(result.get("processes") or [])}
        self._record({"event": "own reply", "method": what.get("method"), "result": result or obj.get("error")})
        if what.get("method") == "session.steer":
            rejected = result.get("status") == "rejected"
            if obj.get("error") or rejected:
                if rejected and what.get("live") in self._running:
                    self._turn_ended(what["live"])  # the backend runs no turn there: its end was never relayed
                # the turn ended first, or its id is gone: the note goes as a continuation (or into a turn of the
                # chat that runs by then); refused by the running turn itself, it waits for that turn to end
                self._retry_note(what["chat"], what["text"], steer=rejected or unknown)
            else:
                self._delivered(what["chat"])
        elif what.get("method") == "prompt.submit" and obj.get("error") and unknown:
            # the session is gone: the chat may run under another id by now (resumed, or listed by the backend)
            self._retry_note(what["chat"], what["text"], steer=True)
        elif what.get("method") == "prompt.submit" and obj.get("error"):
            # the backend refused the continuation for another reason (busy, say): with the next prompt
            self.notices.setdefault(what["chat"], []).append(what["text"])
            for sid in [s for s in self._running if self._chat_of(s) == what["chat"]]:
                self._running.pop(sid, None)
        elif what.get("method") == "prompt.submit":
            self._delivered(what["chat"])

    def _drop(self, conn: _Conn, why: str, obj: dict) -> None:
        entry = {"event": "dropped", "why": why, "connection": getattr(conn, "n", None), "frame": json.dumps(obj)[:400]}
        self.dropped.append(entry)
        self._record(entry)

    def _maybe_card_for_denial(self, sid, payload: dict) -> None:
        if not self.cards:
            return
        args = payload.get("args") if isinstance(payload.get("args"), dict) else {}
        result = payload.get("result")
        if result is None:
            result = payload.get("result_text") or payload.get("summary") or ""
        # A failed call names refused paths (``refusals.failed_result``): a successful read's text is the file's
        # data. A frame that says whether the call failed (``is_error``) adds that to the result's own shape. A
        # terminal or execute_code call that did not fail names only denied paths its command or code named, and
        # is asked only for one the host has (``raise_access``).
        status = "error" if payload.get("is_error") is True else None
        name = str(payload.get("name") or "")
        found = refused_paths(name, args, result, status=status)
        if not found:
            return
        must_exist = not failed_result(name, result, status)
        key = self._chat_of(sid) if isinstance(sid, str) and sid else None

        async def raise_all():
            raised = 0
            for path, access, missing in found:
                if raised >= MAX_ACCESS_CARDS_PER_RESULT:
                    break
                status, _ = await self.raise_access(str(path), access, key=key, origin="tool.complete",
                                                    missing=missing, must_exist=must_exist)
                raised += status == 200

        try:
            asyncio.get_running_loop().create_task(raise_all())
        except RuntimeError:
            pass

    # -- the built-in usage data destination ----------------------------------------------------
    def _watch_usage_data(self) -> None:
        """The profile started or stopped sharing its usage data while the sandbox runs (the desktop's question
        saves the answer through the sandboxed backend): one policy update adds or removes the launcher's built-in
        destination (usage_data.py). It goes through the loop that applies card answers, so on a build whose
        reload closes connections it waits for the running turns to end. The changed answer must stand for
        USAGE_DATA_HOLD first, so a config flipped back and forth loads no revision per flip."""
        from . import usage_data

        sup = self._sup
        driver = getattr(sup, "driver", None)
        home = getattr(self._layout, "home", None)
        applied = getattr(driver, "usage_data_open", None)
        if applied is None or home is None or self._net_dirty or not sup.running() \
                or not driver.capabilities().get("network_live") or usage_data.shared(home) == applied:
            self._usage_data_since = None  # nothing to do, or the update already waiting carries it
            return
        now = self._clock()
        if self._usage_data_since is None:
            self._usage_data_since = now
        elif now - self._usage_data_since >= USAGE_DATA_HOLD:
            self._usage_data_since = None
            self._record({"event": "usage data", "shared": not applied})
            self._net_dirty = True
            self._kick()

    # -- watching proposals ---------------------------------------------------------------------
    async def _watch_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self._poll_interval)
                self._expire_orphans()
                self._watch_usage_data()
                sup = self._sup
                if not (sup.running() and sup.driver.can("requests_supported")):
                    continue
                if self._idle() and self._clock() - self._last_turn_end > POLL_GRACE and not self.open:
                    continue
                proposals = await asyncio.to_thread(sup.driver.proposals, "all")
                await self._on_proposals(proposals)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.debug("proposal watch failed", exc_info=True)

    def _expire_orphans(self) -> None:
        now = self._clock()
        for key, chat in list(self._chats.items()):
            if chat.get("orphaned") and now - chat["orphaned"] > CHAT_GRACE:
                self._end_chat(key)

    def _tool_recent(self) -> bool:
        """A tool call is running, or one ran within TOOL_WINDOW: a request blocked now is the agent's."""
        return any(self._tools.values()) or (self._tool_seen > 0 and self._clock() - self._tool_seen <= TOOL_WINDOW)

    async def _on_proposals(self, proposals: list[dict]) -> None:
        by_id = {p.get("id"): p for p in proposals if p.get("id")}
        now = self._clock()
        for pid in by_id:
            self._proposal_first.setdefault(pid, now)
            if pid not in self._proposal_order:
                self._proposal_order[pid] = self._tick()
        news = self._draft_news(by_id)
        # cards whose proposals someone else decided (the Sandbox page, the CLI): withdraw them
        for srq, card in list(self.open.items()):
            pids = card.get("proposal_ids") or []
            if card["kind"] != "network" or not pids:
                continue
            states = [by_id.get(pid, {}).get("status") for pid in pids]
            if all(s not in (None, "pending") for s in states) and \
                    not any(self._chunks.get(pid, {}).get("decided") for pid in pids):
                self.open.pop(srq, None)
                approved = states[0] == "approved"
                if self._tool_owned(card) and not self._asked_by_hook(card["chat"], net_key(card["host"])):
                    # no tool call waits on this card for the verdict: its chat hears the outcome (a paused reply
                    # continues with it; queued before the withdrawal ends the pause)
                    what = card.get("label") or card["host"]
                    await self._deliver(card["chat"], f"Network access to {what} was allowed on the Sandbox page."
                                        if approved else
                                        f"Network access to {what} was denied on the Sandbox page. {DENIED_TAIL}")
                await self._withdraw(card, f"decided elsewhere ({states[0]})")
                self.verdicts.target(net_key(card["host"]), status="allowed" if approved else "denied",
                                     reason=None if approved else "Decided on the Sandbox page.")
        for pid, p in by_id.items():
            info = self._chunks.setdefault(pid, {})
            hits = int(p.get("hit_count") or 1)
            fresh, times = news[pid]
            if info.get("carded") or info.get("decided") or p.get("status") != "pending":
                if info.get("carded") and p.get("status") == "pending" and hits > int(info.get("hits") or hits):
                    info["hits"] = hits
                    await self._refused_again(info["carded"], times)
                info.setdefault("hits", hits)
                continue
            hosts = _proposal_hosts(p)
            if not hosts:
                continue
            if self._sign_in_renewal(p, hosts):
                # The backend's own try to renew a sign-in the launcher keeps current on this computer (it tries
                # once after a refused request). It stays blocked: no card, no follow-up message, and the draft
                # is turned down so the Sandbox page does not ask about it either.
                if pid not in self._quiet:
                    self._quiet.add(pid)
                    self._record({"event": "draft not carded", "draft": pid, "hosts": [h for h, _ in hosts],
                                  "why": "sign-in renewal"})
                    try:
                        await asyncio.to_thread(self._sup.driver.reject, pid,
                                                "Sign-ins are renewed on this computer, not in the sandbox.")
                    except Exception:
                        log.debug("a sign-in renewal draft could not be turned down", exc_info=True)
                continue
            owner = self._draft_owner(p, hosts, info, hits, fresh, times)
            if owner is None:
                # Nothing asked about this host: Hermes's own background fetch (or a program nobody can tell from
                # one). It stays blocked and on the Activity page; no card, no follow-up message.
                if pid not in self._quiet:
                    self._quiet.add(pid)
                    self._record({"event": "draft not carded", "draft": pid, "hosts": [h for h, _ in hosts],
                                  "program": _leaf(str(p.get("binary") or "")) or None})
                continue
            why, key, tool = owner
            for host, port in hosts:
                status, card = await self.raise_host(host, key=key, port=port, proposal=p, tool=tool,
                                                     origin=f"proposal:{why}")
                if status == 200 and card.get("id"):
                    info.update({"carded": card["id"], "hits": hits})
                    if why == "tool" and not card.get("detail"):
                        # a new card no tool call is held on: its chat's turn pauses until the user answers
                        await self._pause_for(card)
                    elif why == "open card" and fresh:
                        await self._refused_again(card["id"], times)  # another draft for a card left open
                break
            if not (info.get("carded") or info.get("decided")):
                # its chat could not be shown the card at this listing (no desktop connection): the next listing
                # takes the draft as listed for the first time and asks again
                self._draft_seen.pop(pid, None)

    def _draft_news(self, by_id: dict) -> dict:
        """What this listing tells of new refusals, by draft id: ``(fresh, times)``. *fresh*: the draft is listed
        for the first time, or with a higher hit count than in the listing before. *times*: OpenShell's own time
        for that new refusal, as epoch seconds: ``first_seen`` of a draft listed first (whatever its ``last_seen``
        reads by then), ``last_seen`` of one hit again unless this listing shows it to be a policy change's stamp;
        empty where the driver gives no usable time. A draft listed again with the same hit count is not fresh:
        every policy change stores a pending draft again and moves its ``last_seen``, and that is no refusal."""
        read, moved = {}, []
        for pid, p in by_id.items():
            hits = int(p.get("hit_count") or 1)
            first, last = _stamp(p.get("first_seen")), _stamp(p.get("last_seen"))
            before = self._draft_seen.get(pid)
            grew = before is not None and hits > before[0]
            if not grew and before is not None and last is not None and before[1] is not None and last != before[1]:
                moved.append(last)  # stored again with no new hit
            read[pid] = (before, hits, first, last, grew)
        news = {}
        for pid, (before, hits, first, last, grew) in read.items():
            if before is not None and hits < before[0]:
                news[pid] = (False, [])  # an older listing that arrived late
                continue
            self._draft_seen[pid] = (hits, last)
            if before is not None and not grew:
                news[pid] = (False, [])
                continue
            times = [first] if before is None and first is not None else []
            if grew and last is not None and not any(abs(last - m) <= AGENT_RESTAMP_NEAR for m in moved):
                times.append(last)
            news[pid] = (True, times)
        return news

    def _agent_call(self, sid: str, *, started: bool) -> None:
        """A terminal/execute_code call in *sid*'s chat started or ended (``AGENT_TOOLS``)."""
        key = self._chat_of(sid) or sid
        now = self._clock()
        entry = self._agent_calls.setdefault(key, {"open": 0, "since": now, "ended": 0.0, "order": 0})
        if started:
            if entry["open"] == 0:
                entry["since"], entry["order"] = now, self._tick()
            entry["open"] += 1
            self._feed_refusals()
        else:
            entry["open"] = max(0, entry["open"] - 1)
            entry["ended"] = now
            if entry["open"] == 0:
                spans = entry.setdefault("spans", [])
                spans.append((entry["since"], now))
                del spans[:-AGENT_CALL_SPANS]

    @staticmethod
    def _refused_during(call: dict, seen: list, now: float) -> bool:
        """Whether one of a draft's own refusal times (*seen*, epoch seconds) lies inside one of this chat's
        terminal / execute_code calls: the one still open, or one that ended at most AGENT_DRAFT_LATE ago."""
        spans = list(call.get("spans") or ([(call["since"], call["ended"])] if call.get("ended") else []))
        if call.get("open"):
            spans.append((call["since"], now))
        return any(now - end <= AGENT_DRAFT_LATE and start - AGENT_DRAFT_SKEW <= t <= end + AGENT_DRAFT_SKEW
                   for start, end in spans for t in seen)

    def _tick(self) -> int:
        self._seq += 1
        return self._seq

    def _sign_in_renewal(self, p: dict, hosts: list) -> bool:
        """Whether the draft *p* is the backend's own request to an address where a sign-in of this profile is
        renewed: every host it names is such an address, and the program is the backend's interpreter (or is
        not named)."""
        known = getattr(self._sup, "sign_in_token_hosts", None)
        try:
            renewed_at = known() if callable(known) else set()
        except Exception:
            renewed_at = set()
        if not renewed_at or not all(str(host).lower() in renewed_at for host, _port in hosts):
            return False
        return self._backend_binary(str(p.get("binary") or "")) is not False

    async def note(self, text: str) -> None:
        """A note from the launcher itself, not an answer to a card: steered into the chat whose turn runs,
        else put before the next prompt of the chat a desktop shows; kept for the first chat that writes when
        none is known yet."""
        key = self._target_chat()
        if key is None:
            self._unplaced_notes.append(one_line(text))
            self._record({"event": "noted", "chat": None, "text": sandbox_note(text),
                          "why": "no chat is open: it goes with the first message"})
            return
        if not self._chat_running(key):
            # Nothing is sent to a model that is idle. The card log says why the note waits.
            self.notices.setdefault(key, []).append(sandbox_note(text))
            self._record({"event": "noted", "chat": key, "text": sandbox_note(text),
                          "why": "no reply runs in the chat: it goes with its next message"})
            return
        await self._tell(key, text, now=True)

    def _backend_binary(self, binary: str) -> Optional[bool]:
        """Whether *binary* is the backend's own interpreter: True/False, None when unknown (no binary named,
        or a driver that does not say which interpreter the backend runs as)."""
        drv = getattr(self._sup, "driver", None)
        try:
            own = drv.backend_binaries() if drv is not None and hasattr(drv, "backend_binaries") else []
        except Exception:
            own = []
        if not binary or not own:
            return None

        def norm(b) -> str:
            return str(b).replace("\\", "/").rstrip("/").lower()

        mine = norm(binary)
        return any(mine == norm(b) or fnmatch.fnmatchcase(mine, norm(b)) for b in own)  # a rule may name a glob

    def _draft_owner(self, p: dict, hosts: list, info: dict, hits: int, fresh: bool = True,
                     times=()) -> Optional[tuple]:
        """Who a pending draft belongs to: ``(why, chat, tool)``, or None when nothing asked about it. *fresh*
        and *times*: what this listing tells of a new refusal for it (``_draft_news``)."""
        now = self._clock()
        names = {h for h, _ in hosts}
        # a card already open for the host (raised from the hook's request): the draft joins it
        for card in self.open.values():
            if card["kind"] == "network" and (card.get("host") in names or names & set(card.get("hosts") or ())):
                return "open card", card["chat"], card.get("tool")
        # (a) a waiting hook request named the host. Only while it waits: once it has its verdict, a later draft for
        # the host is a new refusal, often another chat's whose own relay is a moment behind OpenShell's draft.
        for h in names:
            asked = self._asked.get(h)
            if not asked:
                continue
            if now - asked["t"] > max(asked.get("wait", HOOK_WAIT), CONFIRM_WAIT) or \
                    not self._request_waits(asked.get("rid")):
                self._asked.pop(h, None)
                continue
            if asked.get("candidate") and not fresh:
                # the call only named this host and printed no refusal: a draft that was there before is no record
                # of one in it (``_confirm_refused`` still raises the card when OpenShell's records show one)
                continue
            return "hook", asked["chat"], asked.get("tool")
        first = self._proposal_first.get(p.get("id"), now)
        # (a') a hook request of the agent's (terminal / execute_code) whose refusal named no host waits for the
        # next card in its chat: a draft OpenShell first listed after that call started is its refusal, whatever
        # program made it (pip's "Tunnel connection failed: 403" names no host, and runs as the backend's python)
        for entry in self._unbound.values():
            if entry.get("tool") in AGENT_TOOLS and first >= entry.get("since", entry["t"]):
                return "unbound", entry["chat"], None
        binary = p.get("binary") or ""
        if not binary:
            first_bin = (p.get("binaries") or [None])[0]
            binary = (first_bin.get("path") if isinstance(first_bin, dict) else first_bin) or ""
        binary = str(binary)
        if not binary or self._backend_binary(binary) is True:
            # the backend's own interpreter (Hermes internals, or one of its in-process tools), or a program
            # OpenShell did not name: nothing tells it apart from Hermes's own fetches
            return None
        # (b) a program the agent ran (terminal / execute_code), refused while that call was open. Only a new
        # refusal is given to a call: a draft listed before with this hit count has not been refused again since
        # (the hit count it had when it was first left alone stays in ``outside_tools``).
        best = timed = None
        for key, call in self._agent_calls.items() if fresh else ():
            if self._refused_during(call, list(times), now):
                # OpenShell's own time for the refusal lies inside a call of this chat, however late it is listed:
                # that says more than which call happens to run now
                if timed is None or call["since"] > timed[1]["since"]:
                    timed = (key, call)
            elif call["open"] > 0 or (call["ended"] and now - call["ended"] <= AGENT_TOOL_GRACE):
                # no usable time, or none inside a call: the call that runs, or just ended, as the draft is listed
                if best is None or call["since"] > best[1]["since"]:
                    best = (key, call)
        best = timed or best
        if best is not None:
            # a hook request in that chat that named no host waits for this card
            return ("unbound" if any(e["chat"] == best[0] for e in self._unbound.values()) else "tool"), best[0], None
        if info.get("outside_tools") is None:
            info["outside_tools"] = hits
        return None

    async def _withdraw(self, card: dict, why: str) -> None:
        cancel = server_text_frame({"jsonrpc": "2.0", "method": "event", "params": {
            "type": "request.cancel", "session_id": card["session_id"],
            "payload": {"id": card["id"], "method": "approval", "reason": "resolved"}}})
        for conn in self._conns:
            try:
                await conn.to_client(cancel)
            except (ConnectionError, OSError, AttributeError):
                pass
        for pid in card.get("proposal_ids") or []:
            self._chunks.setdefault(pid, {}).update({"carded": None, "decided": "elsewhere"})
        self._pause_settled(card)
        self._record({"event": "withdrawn", "request_id": card["request_id"], "why": why})

    async def _poll_proposals(self) -> None:
        sup = self._sup
        if not (sup.running() and sup.driver.can("requests_supported")):
            return
        try:
            await self._on_proposals(await asyncio.to_thread(sup.driver.proposals, "all"))
        except Exception:
            log.debug("proposal listing failed", exc_info=True)

    # -- applying answers ---------------------------------------------------------------------------
    async def _restart_soon(self, key: str, why: str = "folder grant") -> None:
        """A folder answer in chat *key* (or a tool category's that needs a restart): its restart goes ahead as
        soon as the turns it would cut have stopped (``_soon_wait``), not when the model chooses to end its
        reply. The chat's running turn is interrupted now; any refused call that still slips in gets the same
        ``restarting`` answer, no new card."""
        await self._stop_turns_soon(key, why)

    async def _stop_turns_soon(self, key: str, why: str) -> None:
        """An answer in chat *key* that goes into force once the turns it would cut have stopped (a folder
        answer's restart; a network answer's policy update on a build whose reload cuts open connections): the
        chat's running turn is interrupted now; other chats' turns are handled by ``_soon_wait``."""
        now = self._clock()
        self._new_soon()
        if self._chat_running(key) and key not in self._soon["chats"]:
            self._soon["chats"][key] = now + INTERRUPT_STOP_WAIT
            if self._pausing(key):
                self._soon["interrupted"].add(key)  # the pause for this card has interrupted it already
            else:
                await self._interrupt(key, why)

    def _new_soon(self) -> dict:
        if self._soon is None:
            self._soon = {"since": self._clock(), "quiet_from": self._tool_seen, "chats": {}, "interrupted": set(),
                          "cut": set()}
        return self._soon

    def _replies_streaming(self, exclude=()) -> list:
        """Chats (other than *exclude*) whose running turn streams a model reply: no tool call in flight."""
        return sorted({self._chat_of(s) for s in self._running if not self._tools.get(s)} - set(exclude) - {None})

    def _hold_until(self, soon: dict) -> float:
        """How long a held chat's tool call may keep waiting: ``OTHER_REPLIES_WAIT`` after the answer, and
        ``HOLD_MARGIN`` before the first of its hooks would give up."""
        until = soon["since"] + OTHER_REPLIES_WAIT
        keys = {net_key(h["card"]["host"]) for h in (soon.get("held") or {}).values()}
        for b in self._bindings.values():
            if keys & set(b["keys"]) and not b.get("stopped") and not b.get("released"):
                until = min(until, b["t"] + b.get("wait", HOOK_WAIT) - HOLD_MARGIN)
        return until

    async def _interrupt(self, key: str, why: str) -> bool:
        """Stop chat *key*'s running turn in the backend: ``session.interrupt`` (what the desktop's Stop sends)
        on a relayed desktop connection that shows the chat; the backend's reply is swallowed. The backend
        ends the turn at the next tool boundary (before another model call) and retires its crash marker,
        so the desktop's resume after the restart does not replay it. Returns once the backend confirmed it
        (at most ``INTERRUPT_ACK_WAIT``), so a verdict sent next reaches a turn that already stops. Returns
        whether it was sent.

        Every turn stopped here gets a continuation, so the interrupt asks for a pause (``resume``): core then
        reports the turn ``paused``, and the desktop shows the reply as continuing rather than stopped and holds
        the user's next message until the continuation ran. A core without ``resume`` refuses the parameter
        (4000); ``_own_reply`` then sends the plain interrupt."""
        sent, acks = [], []
        for live in [s for s in list(self._running) if self._chat_of(s) == key]:
            conn = next((c for c in reversed(self._conns)
                         if live in c.sessions and getattr(c, "u_writer", None) is not None), None)
            if conn is None:
                continue
            acked = asyncio.get_running_loop().create_future()
            if not await self._send_interrupt(conn, key, live, acked, resume=True):
                continue
            sent.append(live)
            acks.append(acked)
        if sent and self._soon is not None:
            self._soon["interrupted"].add(key)
        self._record({"event": "interrupted", "chat": key, "why": why, "sessions": sent})
        if acks and self._interrupt_ack > 0:  # the caller's verdict follows: let the backend take the interrupt first
            await asyncio.wait([*acks], timeout=self._interrupt_ack)
        return bool(sent)

    async def _send_interrupt(self, conn: _Conn, key: str, live: str, acked, *, resume: bool) -> bool:
        rid = _CALL_PREFIX + secrets.token_hex(6)
        conn.own_calls[rid] = {"method": "session.interrupt", "chat": key, "acked": acked, "live": live,
                               "resume": resume}
        params = {"session_id": live, **({"resume": True} if resume else {})}
        frame = client_text_frame({"jsonrpc": "2.0", "id": rid, "method": "session.interrupt", "params": params})
        try:
            await asyncio.wait_for(conn.to_upstream(frame), 2.0)
        except (ConnectionError, OSError, asyncio.TimeoutError):
            conn.own_calls.pop(rid, None)
            return False
        return True

    async def _soon_wait(self, *, restart: bool = True) -> float:
        """Seconds until a folder answer's restart (or, *restart* False, a network answer's policy update on a
        build whose reload cuts open connections) may begin (0: now). It waits for the turns it interrupted
        to stop (each at most ``INTERRUPT_STOP_WAIT``). Before a restart, other chats' turns get at most
        ``OTHER_TURNS_WAIT`` after the answer, then are stopped too (they continue afterwards); before a policy
        update they are left running: an answering chat held while one of them streams a model reply is stopped
        once none does (``_hold_until``), and the update waits for such replies (at most ``OTHER_REPLIES_WAIT``).
        Then ``SOON_SETTLE`` after the last turn ended (its history is written) and,
        before a restart, ``SOON_QUIET`` after the last tool call seen before the answer (OpenShell's denial
        flush; a restart drops the old sandbox's drafts). Tool events after the answer are the interrupted turn's
        own aftermath (the waiting hook's result), not new requests, so they don't restart the quiet period."""
        soon, now = self._soon, self._clock()
        self._idle()  # drops turns no event has shown for RUNNING_STALE
        held = soon.get("held") or {}
        if held and not restart:
            if self._replies_streaming(exclude=set(held)) and now < self._hold_until(soon):
                return 0.25
            soon["held"] = {}
            for key, h in sorted(held.items()):  # interrupt first, then the hook's final answer (as in _capture)
                await self._stop_turns_soon(key, "network grant")
                self._target_for(h["card"], status="allowed_later", scope=h["scope"], reason=None)
                self._release_card(h["card"])
            return 0.1
        if any(self._chat_running(k) and now < deadline for k, deadline in soon["chats"].items()):
            return 0.1
        others = {self._chat_of(s) for s in self._running} - set(soon["chats"]) - set(held) - {None}
        if others and not restart:
            # A policy update cuts only the connections open at that moment, so other chats' turns are not stopped
            # (an interrupted reply shows "Response stopped" and its continuation starts the reply over). The update
            # waits while one of them streams a model reply (runs with no tool call in flight), at most
            # OTHER_REPLIES_WAIT after the answer.
            streaming = [k for k in self._replies_streaming() if k in others]
            if streaming and now < soon["since"] + OTHER_REPLIES_WAIT:
                return 0.25
            if streaming and not soon.get("waited_out"):
                soon["waited_out"] = streaming
                self._record({"event": "reload while replies stream", "chats": streaming})
        elif others:
            if now < soon["since"] + OTHER_TURNS_WAIT:
                return 0.25
            for k in sorted(others):  # the restart would cut them: stop them cleanly instead
                soon["chats"][k] = now + INTERRUPT_STOP_WAIT
                soon["cut"].add(k)
                await self._interrupt(k, "another chat's folder grant restarts the sandbox")
            return 0.1
        wait = 0.0
        if soon["interrupted"] and self._last_turn_end:
            wait = min(self._settle, SOON_SETTLE) - (now - self._last_turn_end)
        if restart and soon["quiet_from"]:
            wait = max(wait, min(self._restart_quiet, SOON_QUIET) - (now - soon["quiet_from"]))
        return max(0.0, min(wait, 1.0))

    async def _proposals_before_restart(self) -> None:
        """List proposals once more (bounded) so requests the old sandbox blocked become cards first."""
        try:
            await asyncio.wait_for(self._poll_proposals(), PROPOSALS_BEFORE_RESTART)
        except asyncio.TimeoutError:
            log.debug("proposal listing before the restart took too long; restarting anyway")

    async def _apply_loop(self) -> None:
        while True:
            try:
                await self._wake.wait()
                self._wake.clear()
                while self._net_dirty or self._pending_restart:
                    if self._net_dirty and self._net_live() and self._sup.running():
                        await asyncio.sleep(self._batch_window)  # answers clicked together: one update
                        await self.apply_network_now()
                        continue
                    if not self._pending_restart and not self._sup.running():
                        break  # the next launch carries the rules; a later kick retries
                    if self._pending_restart and self._soon is not None:
                        # a folder answer: restart as soon as the turns it would cut have stopped
                        wait = await self._soon_wait()
                        if wait > 0:
                            await asyncio.sleep(wait)
                            continue
                        await self._proposals_before_restart()
                        await self.restart_now()
                        continue
                    if self._net_dirty and self._soon is not None:
                        # a network answer on a build whose reload cuts open connections: load the rule as soon as
                        # the turns it would cut have stopped
                        wait = await self._soon_wait(restart=False)
                        if wait > 0:
                            await asyncio.sleep(wait)
                            continue
                        await self._apply_network_soon()
                        continue
                    if not self._idle():
                        break  # the next turn end kicks again
                    if self._idle_since is None:
                        self._idle_since = self._clock()
                    wait = self._settle - (self._clock() - self._idle_since)
                    if self._pending_restart and self._tool_seen:
                        # OpenShell drafts a blocked request a moment after it happened, and a restart drops
                        # the old sandbox's drafts: let them arrive and become cards first
                        wait = max(wait, self._restart_quiet - (self._clock() - self._tool_seen))
                    if wait > 0:
                        await asyncio.sleep(min(wait, 1.0))  # recheck: a turn may start meanwhile
                        continue
                    if self._pending_restart:
                        await self._poll_proposals()
                        await self.restart_now()
                    else:
                        await self.apply_network_now()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("applying card answers failed")
                await asyncio.sleep(1.0)

    async def apply_now(self) -> dict:
        """Apply everything waiting (the caller has checked the sandbox is idle): one restart when folders
        changed (it carries the network too), else one policy update."""
        if self._pending_restart:
            return await self.restart_now()
        return await self.apply_network_now()

    async def _apply_network_soon(self) -> dict:
        """The policy update a network answer waited for (builds whose reload cuts open connections), once the
        answering turn stopped: the chat continues with the grant's note (``_grants_applied``)."""
        soon, self._soon = self._soon, None
        self._record({"event": "applying", "answered": (soon or {}).get("since"),
                      "interrupted": sorted((soon or {}).get("interrupted") or ()),
                      "replies_streaming": (soon or {}).get("waited_out") or []})
        return await self.apply_network_now()

    async def apply_network_now(self) -> dict:
        """ONE policy update with every network answer and removal waiting: saved rules plus Allow grants.
        An answer counts as in place (``allowed``: the hook tells the agent to retry now) only once the
        driver reports the new revision loaded; one it could not confirm within its bounded wait is
        ``unconfirmed`` and is checked on in the background (``_confirm_loading``)."""
        from .spec import network_policy

        sup = self._sup
        batch, self._pending_net = self._pending_net, []
        self._net_dirty = False
        done = {"network": len(batch), "restarted": False, "errors": []}
        if not sup.running():
            # a restart is under way or the sandbox is down: the next launch carries the rules
            self._pending_net, self._net_dirty = batch + self._pending_net, True
            return done
        live = not self._idle()
        bg = await self._background_chats() if self._net_between_turns() else set()
        self._applying = True
        self._applying_net = batch  # OpenShell may list the refused request's draft while this update loads
        self._apply_done.clear()
        try:
            result = await sup.apply_network(network_policy(sup.spec))
        except Exception as exc:
            done["errors"].append(str(exc))
            await self._grants_failed(batch, str(exc))
        else:
            result = result if isinstance(result, dict) else {}
            done.update({k: result[k] for k in ("policy_version", "loaded", "waited") if k in result})
            if result.get("skipped"):  # the sandbox went down meanwhile: the next launch carries the rules
                self._pending_net, self._net_dirty = batch + self._pending_net, True
            elif result.get("loaded") is False:
                await self._grants_unconfirmed(batch, result)
                await self._note_background(bg, {})
            else:
                # this revision carries every earlier answer still loading too (built from the same state)
                earlier = list(self._loading.values())
                self._loading.clear()
                await self._grants_applied(batch, live=live, bg=bg)
                if earlier:
                    await self._grants_applied(earlier, live=False)
        finally:
            self._applying = False
            self._applying_net = []
            self._apply_done.set()
        self._record({"event": "applied", **done})
        return done

    async def _grants_unconfirmed(self, batch: list[dict], result: dict) -> None:
        """The rules were submitted but the sandbox had not loaded them when the driver's bounded wait
        ended: the hook says so (end the reply; the chat continues once they are in place), no second card
        is raised meanwhile, and the launcher keeps checking."""
        waited = result.get("waited")
        for entry in batch:
            card = entry.get("card")
            if not card:
                continue
            self._loading[card["host"]] = entry
            self._history("grant not confirmed", card, scope=entry["scope"], waited=waited,
                          policy_version=result.get("policy_version"))
            self._target_for(card, status="unconfirmed", scope=entry["scope"], waited=waited)
            self._release_card(card)
            self._pause_settled(card)  # (its note follows once the rule is confirmed; a paused reply does not wait on)
        version = result.get("policy_version")
        if self._loading and isinstance(version, int):
            if self._confirming is not None and not self._confirming.done():
                self._confirming.cancel()  # the newer revision carries the earlier rules too
            self._confirming = asyncio.ensure_future(self._confirm_loading(version))

    def _release(self, target_key: str) -> None:
        """The hooks waiting on *target_key* got a final answer that is not \"in place\": whatever happens
        next reaches the agent as a steer or a continuation."""
        for b in self._bindings.values():
            if target_key in b["keys"]:
                b["released"] = True

    async def _confirm_loading(self, version: int) -> None:
        """Keep checking an unconfirmed revision (bounded): once it loads, the agent hears it is in place
        (steered into its turn, else a continuation); if it fails or never loads, the grant is withdrawn and
        the agent is told."""
        deadline = time.monotonic() + LOAD_CONFIRM_MORE
        drv = getattr(self._sup, "driver", None)
        state = None
        while self._loading:
            await asyncio.sleep(self._confirm_poll)
            try:
                state = await asyncio.to_thread(drv.loaded, version)
            except Exception:
                log.debug("checking policy revision %s failed", version, exc_info=True)
                state = None
            if state is not None or time.monotonic() >= deadline:
                break
        entries = list(self._loading.values())
        self._loading.clear()
        if not entries:
            return
        if state is True:
            await self._grants_applied(entries, live=False)
            self._record({"event": "applied", "network": len(entries), "late": True, "policy_version": version})
            return
        error = (f"the sandbox rejected policy revision {version}" if state is False else
                 f"the sandbox had not loaded the new rule {int(LOAD_CONFIRM_MORE)} seconds later")
        await self._grants_failed(entries, error)
        self._net_dirty = True  # the next update leaves the withdrawn rules out
        self._kick()

    async def hide_new(self, names: list) -> None:
        """Credential-named entries appeared at the top of the profile folder while the sandbox is on
        (``Supervisor.hide_new_private``): one restart, whose start lists them, as soon as the turns it would cut
        have stopped. Every running turn is paused now, as a folder answer pauses its chat's, and continues after
        the restart. The copy is readable until the old sandbox is gone, so this restart does not wait for late
        proposals as a folder answer's does."""
        fresh = self._soon is None
        soon, now = self._new_soon(), self._clock()
        if fresh:
            soon["quiet_from"] = 0.0
        paused = sorted({self._chat_of(s) for s in self._running} - set(soon["chats"]) - {None})
        self._pending_restart.append({"hide": list(names)})
        self._record({"event": "hiding", "names": list(names), "paused": paused})
        for key in paused:
            soon["chats"][key] = now + INTERRUPT_STOP_WAIT
            soon["cut"].add(key)
            await self._interrupt(key, "a credential file appeared in the profile folder: the sandbox restarts")
        self._kick()

    async def restart_now(self) -> dict:
        """One restart for every folder answer and removal waiting (and any network change with it)."""
        sup = self._sup
        batch, self._pending_restart = self._pending_restart, []
        net, self._pending_net = [*self._pending_net, *(b["entry"] for b in batch if b.get("entry"))], []
        self._net_dirty = False
        done = {"folders": len([b for b in batch if b.get("card")]), "network": len(net), "restarted": False,
                "errors": []}
        adds = [b["card"]["path"] for b in batch if b.get("card")]
        removes = [b["path"] for b in batch if b.get("remove")]
        # tool categories whose approval, or its removal, binds a credential anew (their labels)
        tool_adds = list(dict.fromkeys(b["tool_add"] for b in batch if b.get("tool_add")))
        tool_removes = list(dict.fromkeys(b["tool_remove"] for b in batch if b.get("tool_remove")))
        names = lambda paths: ", ".join(Path(p).name or str(p) for p in paths)  # noqa: E731
        added = ", ".join(x for x in (names(adds), ", ".join(tool_adds)) if x)
        removed = ", ".join(x for x in (names(removes), ", ".join(tool_removes)) if x)
        label = "Restarting the sandbox" + (f" to add {added}" if added else f" to remove {removed}" if removed else "")
        # Why, for the launcher's status (``restart``) and the held /api/status
        # (``openshell_sandbox``); the supervisor sets it with the ``restarting`` state, before the backend stops.
        note = {"why": "folders" if adds or removes or not (tool_adds or tool_removes) else "tools",
                "reason": "folder" if adds else "remove" if removes else None,
                "folder": (adds or removes or [None])[0], "add": adds, "remove": removes, "label": label,
                "since": self._clock()}
        hides = [name for b in batch for name in b.get("hide") or ()]
        if hides and not (adds or removes or tool_adds or tool_removes):
            # a restart only to hide credential-named entries that appeared in the profile folder (``hide_new``)
            from .layout import hide_note

            note = hide_note(list(dict.fromkeys(hides)), self._clock())
            label = note["label"]
        # The restart ends every turn still running (a folder answer's restart only gets here once the turns it
        # interrupted stopped or their bound passed): they are over for the relay too, and a chat the restart
        # cut that has no grant of its own to hear about continues after it.
        soon, self._soon = self._soon, None
        granted = {b["card"]["chat"] for b in batch if b.get("card")} | {b["chat"] for b in batch if b.get("tool_add")}
        cut = ({self._chat_of(s) for s in self._running} | set((soon or {}).get("cut") or ())) - granted - {None}
        self._running.clear()
        self._tools.clear()
        self._tool_names.clear()
        self._agent_calls.clear()
        self._stop_at_boundary.clear()
        for key, pause in list(self._pauses.items()):  # the restart ends every turn, one being paused too
            if pause["state"] == "pending":
                self._pause_over(key, "the sandbox restarted")
            else:
                pause["state"] = "paused"
        # No tool call runs in the new sandbox yet: what it blocks before the next one is Hermes's own (the model
        # catalog at the continuation's start), not a tool's. Without this, a restart that follows the last tool
        # call within TOOL_WINDOW would raise a "models.dev" card after every folder grant.
        self._tool_seen = 0.0
        self._idle_since = self._clock()
        self._record({"event": "restarting", "label": label, "answered": (soon or {}).get("since"),
                      "interrupted": sorted((soon or {}).get("interrupted") or ()), "cut": sorted(cut)})
        self._applying = True
        self._apply_done.clear()
        try:
            try:
                try:
                    await sup.restart(note=note)
                except Exception as first:
                    # one more try before giving up: a restart reuses the sandbox name, and a gateway can
                    # trip over the old record for a moment
                    done["errors"].append(f"restart with the new folders failed once ({first}); retrying")
                    await asyncio.sleep(2)
                    await sup.restart(note=note)
                done["restarted"] = True
            except Exception as exc:
                done["errors"].append(f"restart with the new folders failed: {exc}")
                # A tool category's approval that needed this restart is taken back with it: the sandbox that
                # starts again is the one from before the answer.
                await self._grants_failed([e for e in net if e.get("rebind")], str(exc))
                net = [e for e in net if not e.get("rebind")]
                await self._restart_failed(batch, net, str(exc), done)
            else:
                # a restart launches with every rule, the ones still loading in the old sandbox too
                loading = list(self._loading.values())
                self._loading.clear()
                await self._grants_applied([b for b in batch if b.get("card")] + net + loading, live=False)
                for b in batch:
                    if b.get("remove"):
                        self._history("removed", {"kind": "access", "path": b["path"], "scope": b.get("scope")})
                await self._withdraw_covered()
        finally:
            self._applying = False
            self._apply_done.set()
        why = (f" to add {added} (allowed in another chat)" if added else
               f" to remove {removed}" if removed else "")
        for key in sorted(cut):
            self._continue(key, f"The sandbox restarted{why}, which stopped your reply. Continue where you left off.")
        self._record({"event": "applied", **done})
        return done

    async def _background_chats(self) -> set:
        """Chats whose background processes still run, from the backend's process registry: ``process.list`` (the
        desktop's own session-scoped view) for each chat a desktop connection shows, at most ``BG_LIST_WAIT``. A
        chat whose backend does not answer in time counts as having none."""
        if self._bg_wait <= 0:
            return set()
        asks: dict[str, asyncio.Future] = {}
        for key in list(self._chats):
            live = self._live_for(key)
            conn = next((c for c in reversed(self._conns)
                         if live in c.sessions and getattr(c, "u_writer", None) is not None), None) if live else None
            if conn is None:
                continue
            rid = _CALL_PREFIX + secrets.token_hex(6)
            reply = asyncio.get_running_loop().create_future()
            conn.own_calls[rid] = {"method": "process.list", "chat": key, "reply": reply}
            frame = client_text_frame({"jsonrpc": "2.0", "id": rid, "method": "process.list",
                                       "params": {"session_id": live}})
            try:
                await asyncio.wait_for(conn.to_upstream(frame), 1.0)
            except (ConnectionError, OSError, asyncio.TimeoutError):
                conn.own_calls.pop(rid, None)
                continue
            asks[key] = reply
        if not asks:
            return set()
        await asyncio.wait(list(asks.values()), timeout=self._bg_wait)
        found = set()
        for key, reply in asks.items():
            result = reply.result().get("result") if reply.done() else None
            procs = result.get("processes") if isinstance(result, dict) else None
            if any(isinstance(p, dict) and p.get("status") == "running" for p in procs or ()):
                found.add(key)
        self._record({"event": "background processes", "chats": sorted(found), "asked": len(asks),
                      "answered": sum(r.done() for r in asks.values())})
        return found

    async def _note_background(self, chats: set, continuing: dict) -> None:
        """``BG_CUT_NOTE`` once for each chat in *chats*: with the grant's own note when that chat continues
        (*continuing*: chat -> texts), else steered into its running turn or put before its next prompt (no turn
        is started for it)."""
        for key in sorted(chats):
            if key in continuing:
                continuing[key].append(BG_CUT_NOTE)
            else:
                await self._tell(key, BG_CUT_NOTE, now=self._chat_running(key))

    async def _grants_applied(self, batch: list[dict], *, live: bool, bg: frozenset = frozenset()) -> None:
        now = self._clock()
        for g in self.grants:
            if g.get("applied_at") is None:
                g["applied_at"] = now
        by_chat: dict[str, list[str]] = {}
        for entry in batch:
            card = entry.get("card")
            if not card:
                continue
            scope = entry["scope"]
            self._history("granted", card, scope=scope, rule=(entry.get("rule") or {}).get("name"))
            self._target_for(card, status="allowed", scope=scope)
            k = net_key(card["host"]) if card["kind"] == "network" else dir_key(card["path"])
            ks = [k, *(card.get("covers") or ())]
            if card["kind"] == "network" and card.get("tool"):
                text = (f"Hermes's {card.get('label') or card['tool']} tool can reach its web services now, "
                        f"{SCOPE_LABEL[scope]}.")
            elif card["kind"] == "network":
                text = (f"Network access to {card.get('label') or card['host']} (http and https, any program) is in "
                        f"place now, {SCOPE_LABEL[scope]}.")
                if self._tool_owned(card) and not any(self._asked_by_hook(card["chat"], x) for x in ks):
                    # no tool result told the agent of this refusal (the card came from OpenShell's draft)
                    text = (f"The sandbox blocked {card.get('label') or card['host']} for a program you ran, and the "
                            f"user has now allowed it. {text}")
            else:
                verb = "read & write" if card.get("access") == "read_write" else "read"
                text = f"The sandbox restarted with {verb} access to {card['path']}, {SCOPE_LABEL[scope]}."
            # A hook waiting in a running turn tells the agent to retry now; anything applied while the chat
            # is idle (after a restart, or a build that applies network changes between turns) continues it.
            if live and any(self._hook_waiting(x) for x in ks) and self._chat_running(card["chat"]) \
                    and not self._pausing(card["chat"]):
                continue  # (not in a turn the launcher is stopping for a pause: its continuation says it)
            if card["kind"] == "network" and not any(self._asked_by_hook(card["chat"], x) for x in ks) \
                    and not self._tool_owned(card):
                # neither a hook request nor a program the agent ran asked for this card: nothing in the
                # conversation did, so no follow-up message steers the agent elsewhere. (A card from OpenShell's
                # draft for a program the agent ran always reaches the agent: its reply continues, or the note is
                # steered into its running turn.)
                self._record({"event": "granted quietly", "host": card["host"], "chat": card["chat"]})
                continue
            by_chat.setdefault(card["chat"], []).append(text)
            self._grant_notes.setdefault(k, []).append((card["chat"], text))
        await self._note_background(set(bg), by_chat)
        for key, texts in by_chat.items():
            await self._deliver(key, " ".join(texts))
        for entry in batch:  # (after the notes are queued: a paused reply continues with them)
            if entry.get("card"):
                self._pause_settled(entry["card"])

    async def _grants_failed(self, batch: list[dict], error: str) -> None:
        from .spec import load_spec, network_policy, update_spec

        for entry in batch:
            card = entry.get("card")
            if not card:
                continue
            if entry["scope"] == "allow":
                self.grants = [g for g in self.grants if not (g["kind"] == "network" and g["host"] == card["host"])]
            else:
                spec = load_spec(self._layout)
                net = network_policy(spec)
                approved = {k: v for k, v in (net.get("approved") or {}).items() if k != entry["rule"]["name"]}
                new = {**net, "approved": approved} if approved else {k: v for k, v in net.items() if k != "approved"}
                self._sup.set_spec(update_spec(self._layout, network=new))
            self._history("grant failed", card, scope=entry["scope"], error=error)
            self._target_for(card, status="failed", error=error)
            if (not self._hook_waiting(net_key(card["host"])) or self._pausing(card["chat"])) and (
                    self._asked_by_hook(card["chat"], net_key(card["host"])) or self._tool_owned(card)):
                await self._deliver(card["chat"], f"Network access to {card.get('label') or card['host']} could not be "
                                                  f"granted: {error}")
            self._pause_settled(card)
        self._sync_temporary()

    async def _restart_failed(self, batch: list[dict], net: list[dict], error: str, done: dict) -> None:
        """The new grants kept the sandbox from starting: put everything back and start as before."""
        from .spec import update_spec

        for entry in batch:
            card = entry.get("card")
            if not card:
                continue
            if entry["scope"] == "allow":
                self.grants = [g for g in self.grants if not (g["kind"] == "access" and g["path"] == card["path"]
                                                              and g.get("applied_at") is None)]
            elif "spec_folders_before" in entry:
                self._sup.set_spec(await asyncio.to_thread(update_spec, self._layout,
                                                           folders=entry["spec_folders_before"]))
            self._history("grant failed", card, scope=entry["scope"], error=error)
            self._target_for(card, status="failed", error=error)
            await self._deliver(card["chat"], f"Access to {card['path']} could not be granted: {error}")
        self._sync_temporary()
        self._pending_net, self._net_dirty = net + self._pending_net, bool(net) or self._net_dirty
        try:
            await self._sup.restart()
        except Exception as exc2:
            done["errors"].append(f"restart without them failed too: {exc2}")

    def _sync_temporary(self) -> None:
        """Supervisor.temporary mirrors the Allow grants: every launch includes them, nothing saves them."""
        approved: dict = {}
        folders: list = []
        for g in self.grants:
            if g["kind"] == "network":
                approved[g["rule_name"]] = _merge_rule(approved.get(g["rule_name"]), g["rule"])
            else:
                folders.append({"path": g["path"], "access": "rw" if g.get("access") == "read_write" else "ro"})
        temporary = getattr(self._sup, "temporary", None)
        if isinstance(temporary, dict):
            temporary["approved"], temporary["folders"] = approved, folders

    # -- the Sandbox page's list of grants ------------------------------------------------------------
    def grants_view(self) -> dict:
        """Everything granted from cards that is in force or on its way: Allow grants (until the sandbox is
        switched off) and hosts saved with Always allow. Folders saved with Always allow are in the
        stored policy's folder list (the page's Folders section)."""
        rows = []
        for g in self.grants:
            target = g["host"] if g["kind"] == "network" else g["path"]
            rows.append({"id": _grant_id(g["kind"], "allow", target),
                         "kind": "network" if g["kind"] == "network" else "folder",
                         # a tool category's row names its services (the id names the category)
                         "target": ", ".join(g.get("shown") or g["hosts"]) if g.get("tool") else target,
                         "label": g.get("label"), "ports": g.get("ports"), "access": g.get("access"),
                         "scope": "allow", "status": "active" if g.get("applied_at") else "pending",
                         "since": g.get("applied_at") or g.get("answered_at"),
                         **(self._tool_row(g["tool"], pending=not g.get("applied_at")) if g.get("tool") else {})})
        waiting = {e["rule"]["name"] for e in [*self._pending_net, *(b["entry"] for b in self._pending_restart
                                                                    if b.get("entry"))]
                   if e.get("rule") and e["scope"] == "always"}
        for name, rule in (self._saved_network().get("approved") or {}).items():
            if name.startswith(TOOL_RULE_PREFIX):
                tool = name[len(TOOL_RULE_PREFIX):]
                # every service the approval opens for this profile: the addresses a credential is bound to
                # for it, then the rule's own hosts
                bound = [categories.host_text(row["host"], row["port"]) for row in self._tool_services(tool)["bound"]]
                rows.append({**saved_tool_row(name, rule, bound, pending=name in waiting),
                             **self._tool_row(tool, pending=name in waiting)})
                continue
            if not name.startswith(HOST_RULE_PREFIX):
                continue
            for host, ports in _rule_hosts(rule).items():
                rows.append({"id": _grant_id("network", "always", host), "kind": "network", "target": host,
                             "label": self._label(host, None, None), "ports": sorted(p for p in ports if p),
                             "scope": "always", "status": "pending" if name in waiting else "active",
                             "rule_name": name})
        return {"grants": rows, "network_apply": "live" if self._net_live() else "turn_end",
                "restarting": getattr(self._sup, "restart_note", None)}

    def _tool_row(self, tool: str, *, pending: bool) -> dict:
        """What a tool category's row says beside its hosts: ``note`` where its services let the agent reach
        more than the hosts listed, ``bound`` where a credential of the profile is used at one of them (the
        row then does not say "any program"), and ``restart`` while the approval waits for the restart that
        binds it."""
        out: dict = {}
        if self._tool_services(tool)["bound"]:
            out["bound"] = True
        note = _GRANT_NOTES.get(_TOOL_CANON.get(tool, tool))
        if note:
            out["note"] = note
        if pending and self._rebinds({"kind": "network", "tool": tool}):
            out["restart"] = True
        return out

    async def _route_grants(self, req, body: bytes):
        return 200, self.grants_view(), {}

    async def _route_remove(self, req, body: bytes):
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            return 422, {"detail": "Body is not JSON."}, {}
        gid = data.get("id") if isinstance(data, dict) else None
        status, detail = await self.remove_grant(gid if isinstance(gid, str) else "")
        if status != 200:
            return status, {"detail": detail}, {}
        return 200, self.grants_view(), {}

    async def remove_grant(self, gid: str) -> tuple[int, str]:
        """Remove one grant the page lists. Network: one policy update (at once where the reload keeps
        streams, else when the sandbox is idle). Folders: one restart when the sandbox is idle."""
        from .spec import load_spec, network_policy, update_spec

        kind, scope, target = (gid.split(":", 2) + ["", "", ""])[:3]
        # A tool category that has a credential bound for it in the running sandbox: taking the approval away
        # takes the binding away, which a sandbox gets only at a start.
        tool = target[len(TOOL_TARGET_PREFIX):] if kind == "network" and target.startswith(TOOL_TARGET_PREFIX) else None
        unbind = bool(tool and self._bound_now(tool))
        if kind == "network" and scope == "allow":
            before = len(self.grants)
            self.grants = [g for g in self.grants if not (g["kind"] == "network" and g["host"] == target)]
            if len(self.grants) == before:
                return 404, "No such grant."
            self._pending_net = [e for e in self._pending_net if e["card"]["host"] != target or e["scope"] != "allow"]
            self._sync_temporary()
            self._net_dirty = True
        elif kind == "network" and scope == "always":
            spec = load_spec(self._layout)
            net = network_policy(spec)
            approved = without_grant(net.get("approved") or {}, target)
            if approved is None:
                return 404, "No such grant."
            new = {**net, "approved": approved} if approved else {k: v for k, v in net.items() if k != "approved"}
            self._sup.set_spec(await asyncio.to_thread(update_spec, self._layout, network=new))
            self._net_dirty = True
        elif kind == "folder" and scope == "allow":
            match = [g for g in self.grants if g["kind"] == "access" and dir_key(g["path"]) == dir_key(target)]
            if not match:
                return 404, "No such grant."
            self.grants = [g for g in self.grants if g not in match]
            self._sync_temporary()
            if any(g.get("applied_at") for g in match):
                self._pending_restart.append({"remove": True, "path": match[0]["path"], "scope": "allow"})
            else:
                self._pending_restart = [e for e in self._pending_restart
                                         if not (e.get("card") and dir_key(e["card"]["path"]) == dir_key(target))]
        else:
            return 404, "No such grant."
        if unbind:
            self._pending_restart.append({"tool_remove": tool_label(tool), "scope": scope})
        if kind == "network":
            self._loading.pop(target, None)  # removed while its rule was still loading: nothing to announce
        self._drop_grant_notes(net_key(target) if kind == "network" else dir_key(target))
        self.verdicts.drop(net_key(target) if kind == "network" else dir_key(target))
        self._history("removed", {"kind": "network" if kind == "network" else "access",
                                  ("host" if kind == "network" else "path"): target, "scope": scope,
                                  # a tool category is named as its card and its row name it
                                  "label": tool_label(target[len(TOOL_TARGET_PREFIX):])
                                  if kind == "network" and target.startswith(TOOL_TARGET_PREFIX) else None})
        self._kick()
        return 200, "removed"

    def _drop_grant_notes(self, target_key: str) -> None:
        """The grant *target_key* stands for was removed: what still waits to tell the agent it is in place
        (a continuation no window took, a note kept for the chat's next message) is not said any more."""
        for chat, text in self._grant_notes.pop(target_key, []):
            lost = []
            for store, shape in ((self._continue_text, one_line), (self.notices, sandbox_note)):
                kept = []
                for note in store.get(chat) or []:
                    if one_line(text) not in note:
                        kept.append(note)
                        continue
                    lost.append(sandbox_note(text))
                    rest = " ".join(note.replace(one_line(text), " ").split())
                    if rest.removeprefix("[Sandbox]").strip():
                        kept.append(shape(rest))
                if kept:
                    store[chat] = kept
                else:
                    store.pop(chat, None)
            if lost:
                self._record({"event": "notes lost", "chat": chat, "notes": list(dict.fromkeys(lost)),
                              "why": "the approval was removed"})

    # -- records --------------------------------------------------------------------------------
    def _history(self, what: str, item: dict, **extra) -> None:
        entry = {"event": what, "t": self._clock(), "kind": item.get("kind"), "chat": item.get("chat"),
                 **{k: item.get(k) for k in ("request_id", "host", "label", "path", "access", "scope", "rule_name")
                    if item.get(k) is not None}, **extra}
        self.history.append(entry)
        self._record(entry)

    def _record(self, entry: dict) -> None:
        log.info("card: %s", {k: v for k, v in entry.items() if k != "proposal"})
        self._records.append({k: v for k, v in entry.items() if k != "proposal"})
        del self._records[:-500]
        if self._log_path is not None:
            try:
                with open(self._log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"t": time.time(), **entry}, default=str) + "\n")
            except OSError:
                log.debug("card log write failed", exc_info=True)
