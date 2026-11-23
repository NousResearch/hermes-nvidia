"""What a sandbox refusal looks like in a tool result: refused paths and refused network destinations.

Shared by the launcher (folder cards from relayed tool results, cards.py) and the in-sandbox hook that
waits for the user's answer (sandbox_hook.py). Pure functions, standard library only: the hook imports
this inside the sandbox on every refused tool result.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Optional

WRITE_TOOLS = frozenset({"write_file", "patch", "edit_file", "apply_patch", "str_replace", "create_file"})
# File tools: a successful call's output is a file's data (or a listing of files), never a refusal of any kind.
FILE_TOOLS = WRITE_TOOLS | frozenset({"read_file", "search_files"})
# ... nor is what a program printed when it succeeded (terminal, execute_code): a refused program fails, and
# OpenShell's draft for its refused connection raises the card in any case.
PROGRAM_TOOLS = frozenset({"terminal", "execute_code"})
DATA_TOOLS = FILE_TOOLS | PROGRAM_TOOLS
_FAILED_STATUSES = frozenset({"error", "failed", "failure"})
DENIED_RE = re.compile(r"permission denied|access is denied|operation not permitted|read-only file system|"
                       r"errno 13|eacces|erofs", re.I)
# "file not found": Hermes's own read_file. On Windows an MXC sandbox sees an ungranted file as absent, so
# the agent's first read of it says "File not found: <path>" (a card only if the host has the path).
MISSING_RE = re.compile(r"no such file or directory|errno 2\b|enoent|cannot find the path|file not found", re.I)
_WRITE_HINT_RE = re.compile(r"can't create|cannot create|read-only file system|can't write|cannot write|"
                            r"for writing|can't remove|cannot remove|can't move|cannot move|can't make|"
                            r"cannot make|mkdir|erofs", re.I)
_WRITE_CMD_RE = re.compile(r"(?:^|[\s;&|])(?:>>?|tee|touch|mkdir|cp|mv|rm|rmdir|install|sed\s+-i)(?:\s|$)")
_QUOTED_PATH_RE = re.compile(r"""['"`]((?:[A-Za-z]:[\\/]|/)[^'"`\n]{0,400})['"`]""")
_PLAIN_PATH_RE = re.compile(r"(?:^|(?<=[\s=(]))((?:[A-Za-z]:[\\/]|/)[^\s'\"`:;,)]{0,400})")
_MSYS_RE = re.compile(r"^/([A-Za-z])(/.*)?$")
# The arguments a file tool names its path in.
_PATH_ARGS = ("path", "file_path", "filename", "target", "directory")

# OpenShell's proxy refuses a destination with a 403 whose JSON body says ``policy_denied`` (CONNECT and
# forward proxying alike); clients mostly print only the status line of a refused CONNECT.
NET_STRONG_RE = re.compile(r"policy_denied|not permitted by policy|tunnel connection failed:\s*403|"
                           r"connect tunnel failed,\s*response 403|proxyerror\b[^\n]{0,200}\b403\b|"
                           r"unable to connect to proxy[^\n]{0,200}\b403\b|proxy[^\n]{0,40}\b403 forbidden", re.I)
# OpenShell's Linux (Docker driver) sandboxes have no proxy variables: the supervisor resolves an unapproved name
# to a synthetic address and refuses the connection (OCSF ``transparent_tcp_policy_denied``), so clients report a
# refused connection, not a 403: curl "(7) Failed to connect to <host> port <p> ... Could not connect to server",
# urllib3/requests "[Errno 111] Connection refused", wget "failed: Connection refused", node ECONNREFUSED. Only a
# candidate, like every refusal here: the launcher raises a card once OpenShell's own records show the refusal.
NET_REFUSED_RE = re.compile(r"could not connect to server|couldn'?t connect to server|connection refused|"
                            r"errno 111\b|econnrefused|failed to establish a new connection", re.I)
_CURL_CONNECT_RE = re.compile(r"Failed to connect to \[?([A-Za-z0-9._-]+)\]? port (\d{1,5})", re.I)
# On v0.1.6 a Python connect() to a refused destination fails with EACCES (the supervisor's answer to the
# workload's connect), so urllib and Hermes's own keyless web tools say only "[Errno 13] Permission denied"
# ("<urlopen error [Errno 13] Permission denied>", "Keyless Firecrawl extract failed: [Errno 13] Permission
# denied."): no host, no "connection refused". The same words with a path after them are a file refusal.
NET_EACCES_RE = re.compile(r"\[errno 13\] permission denied(?!:\s*['\"]?[/~.\\A-Za-z])", re.I)
_WGET_CONNECT_RE = re.compile(r"Connecting to ([A-Za-z0-9._-]+) \([^)]*\)\|[^|]*\|:(\d{1,5})\.\.\. failed", re.I)
# A bare 403 is usually the site's own answer; it counts only when a card for the destination appears.
NET_WEAK_RE = re.compile(r"\b403\b[^\n]{0,20}forbidden|http error 403|status(?: code)?[ =:]+403\b", re.I)
_CONNECT_RE = re.compile(r"CONNECT\s+\[?([A-Za-z0-9._-]+)\]?:(\d{1,5})", re.I)
_HOSTKW_RE = re.compile(r"""host\s*=\s*['"]([A-Za-z0-9._-]+)['"](?:\s*,\s*port\s*=\s*(\d{1,5}))?""", re.I)
_URL_RE = re.compile(r"""\b(https?|wss?)://(?:[^@/\s'"\\]+@)?([A-Za-z0-9._-]+|\[[0-9a-fA-F:]+\])(?::(\d{1,5}))?""", re.I)
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})+$")
# Names that never get a card: the sandbox's own gateway alias and loopback names.
_NO_CARD_HOSTS = frozenset({"localhost", "host.openshell.internal", "host.docker.internal"})
# Hermes's web tool backends, by the vendor names their errors carry (keyless ring and keyed providers).
WEB_VENDOR_HOSTS = {"keenable": "api.keenable.ai", "firecrawl": "api.firecrawl.dev", "exa": "mcp.exa.ai",
                    "parallel": "search.parallel.ai", "tavily": "api.tavily.com"}
# Hermes's own web tools and the services they use without a key: core's keyless ring
# (``plugins/web/keyless_mcp.py``: ``_KEYLESS_RING`` = exa, parallel, firecrawl, keenable; web_search and
# web_extract both rotate through it, one vendor per call). A card for one of these tools covers all of them,
# so one Allow makes the tool work whichever service it picks next (tests compare this with core).
WEB_TOOLS = frozenset({"web_search", "web_extract", "web_crawl"})
KEYLESS_WEB_HOSTS = ("mcp.exa.ai", "search.parallel.ai", "api.firecrawl.dev", "api.keenable.ai")
# Where a refused host came from: named by the refusal itself (``CONNECT host:port``, urllib3's
# ``host='...'``) or only found in the result's or the arguments' text (a URL, a docs link, a vendor name).
SOURCE_REFUSAL, SOURCE_TEXT = "refusal", "text"
# A failed program call that printed no refusal at all (``curl -s`` exits 7 with "HTTP 000"; a script swallows its
# error) still names where it went: URLs in its command or code and in its output, and the bare host arguments of
# a network client (``curl example.com``). Those are relayed as *candidates* (``CANDIDATE`` strength): the launcher
# raises a card only for one OpenShell's own records show refused, and never from the name alone.
CANDIDATE = "candidate"
MAX_CANDIDATES = 4
# A program call that SUCCEEDED relays the hosts it named only when OpenShell's records already show one refused
# inside the call (cards.py, ``ZERO_WAIT_FEED``). "Inside": from the call's start to its end, give or take
# ZERO_WAIT_SKEW seconds (the tool's own timing against the record's). Of a successful call's output, which can be
# long, only the first NAMED_SCAN characters are read for names.
ZERO_WAIT_SKEW = 0.25
NAMED_SCAN = 65536
# Whether such a call was refused is read from OpenShell's records, never from what it printed (``curl ...; echo
# done`` exits 0 with curl's refusal line in its output, or with nothing at all). A record can reach the verdict file
# a moment after the call returned, so the hook looks for a short time, and only for a call that named a host (one
# that named none waits for nothing). How long is the driver's to say, since it knows how far its feed trails a
# refusal: the seconds it puts in ``HERMES_SANDBOX_REFUSALS`` (at most RECORD_SETTLE_MAX). A network refusal's own
# words in the output of a call whose command named a host (``shows_network_refusal``) lengthen the look to
# RECORD_SETTLE_SHOWN; they never stand in for the record.
RECORD_SETTLE_MAX = 5.0
RECORD_SETTLE_SHOWN = 2.0
RECORD_POLL = 0.02
_NET_CLIENTS = frozenset({"curl", "wget", "http", "https", "xh", "nc", "ncat", "netcat", "telnet", "ssh", "scp",
                          "sftp", "ftp", "lftp", "aria2c"})
# Options of those clients whose next argument is a value (a file, a header, a format), not a destination.
_VALUE_OPTIONS = frozenset({"-o", "-O", "--output", "--output-document", "-w", "--write-out", "-H", "--header", "-A",
                            "--user-agent", "-d", "--data", "--data-raw", "--data-binary", "-u", "--user", "-e",
                            "--referer", "-K", "--config", "-T", "--upload-file", "-b", "--cookie", "-c",
                            "--cookie-jar", "--cacert", "--cert", "--key", "-F", "--form", "-i", "-l", "-p", "-P",
                            "-x", "--proxy", "-X", "--request", "-m", "--max-time", "--connect-timeout", "--retry"})
_SHELL_BREAKS = frozenset({";", "&&", "||", "|", "&", "(", ")"})
_BARE_HOST_RE = re.compile(r"^(?:[^@/\s]+@)?((?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*)(?::(\d{1,5}))?(?:[/?#:].*)?$", re.I)
_TOKEN_RE = re.compile(r"""\|\||&&|[;|&()]|"[^"]*"|'[^']*'|[^\s;|&()]+""")
_ANY_RE = re.compile(DENIED_RE.pattern + "|" + MISSING_RE.pattern + r"|403|policy_denied|not permitted by policy|"
                     + NET_REFUSED_RE.pattern, re.I)


def _text(result) -> str:
    text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
    return text.replace("\\\\", "\\")


def _strings(value, out: list) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _strings(v, out)


def result_lines(result) -> list[str]:
    """A tool result's text as the lines the tool printed: a JSON result's strings, each split at its own line
    breaks (core escapes them, so the encoded result is one line however many a file or traceback has); text that
    is not JSON as it is."""
    data = result
    if isinstance(result, (str, bytes)):
        try:
            data = json.loads(result)
        except ValueError:
            return _text(result).splitlines()
    out: list[str] = []
    _strings(data, out)
    return [line for s in out for line in s.splitlines()]


def maybe_refused(result) -> bool:
    """Cheap first look: could *result* hold a refusal at all? (Most tool results stop here.)"""
    try:
        return bool(_ANY_RE.search(result if isinstance(result, str) else json.dumps(result, default=str)))
    except (TypeError, ValueError):
        return False


def failed_result(name: str, result, status: Optional[str] = None) -> bool:
    """Whether a tool call failed, so its result can report a sandbox refusal. A successful call's output is data
    (the file the agent read, a listing, a page): words in it are not a refusal, however much they look like one
    (a plan document saying "permission denied" and quoting a host folder raised a folder card for that folder).
    *status* is core's own verdict where the caller has it (``transform_tool_result`` passes ``status="error"``);
    otherwise the result's top-level shape decides, as core's does: a JSON object failed when it says so
    (``success: false``, an ``error``, a ``status`` of error/failed, a non-zero ``exit_code``), and text that is not
    JSON may be an error message. An error nested in a successful-shaped result (a web tool's per-URL
    ``results[].error``) does not make the call failed; ``refused_destinations`` still reads those."""
    if str(status or "").strip().lower() == "error":
        return True
    data = result
    if isinstance(result, (str, bytes)):
        try:
            data = json.loads(result)
        except ValueError:
            return True
    if not isinstance(data, dict):
        return isinstance(data, str)
    if data.get("success") is False or data.get("error"):
        return True
    if str(data.get("status") or "").strip().lower() in _FAILED_STATUSES:
        return True
    if name in PROGRAM_TOOLS and "exit_code" not in data and "status" not in data:
        return True  # a program's printout counts as successful only where the result says it succeeded
    code = data.get("exit_code")
    return isinstance(code, int) and not isinstance(code, bool) and code != 0


def clearly_failed(result, status: Optional[str] = None) -> bool:
    """Whether a program tool's result itself says the call failed: core's verdict (``status="error"``), or a JSON
    object with a non-zero ``exit_code``, ``success: false``, an ``error`` or a failed ``status``. Stricter than
    ``failed_result``: text that is not JSON, and an object that says nothing either way, do not count (they may
    be an error, which is enough to read a refusal's own words, but not to go looking for one nothing printed)."""
    verdict = str(status or "").strip().lower()
    if verdict == "error":
        return True
    if verdict == "ok":
        return False  # core derives it from the same shape
    data = result
    if isinstance(result, (str, bytes)):
        try:
            data = json.loads(result)
        except ValueError:
            return False
    if not isinstance(data, dict):
        return False
    if data.get("success") is False or data.get("error"):
        return True
    if str(data.get("status") or "").strip().lower() in _FAILED_STATUSES:
        return True
    code = data.get("exit_code")
    return isinstance(code, int) and not isinstance(code, bool) and code != 0


def host_path(raw: str) -> Optional[Path]:
    """A path a tool reported, as the host names it (MSYS ``/c/x`` -> ``C:/x`` on Windows); None when it is
    not absolute."""
    text = (raw or "").strip().strip("'\"`").rstrip(".,;:")
    if not text:
        return None
    if os.name == "nt":
        m = _MSYS_RE.match(text)
        if m:
            text = f"{m.group(1).upper()}:{m.group(2) or '/'}"
        if not re.match(r"^[A-Za-z]:[\\/]", text):
            return None
    elif not text.startswith("/"):
        return None
    return Path(text)


def refused_paths(name: str, args: dict, result, *, status: Optional[str] = None) -> list[tuple[Path, str, bool]]:
    """Paths a tool result says were refused: ``(path, access, missing)``. *access* is ``read`` or
    ``read_write``; *missing* is True when the tool said "no such file" rather than "denied". Only a failed
    call names any (``failed_result``; *status* is core's verdict when the caller has it)."""
    if not failed_result(name, result, status):
        return []
    # A refusal line names only the paths on it, line by line as the tool printed them (``result_lines``): read as
    # one encoded line, a JSON result put every path a call printed beside its refusal. A connect() the sandbox
    # refused ("[Errno 13] Permission denied" with no path after it) is a network refusal and names no path, even
    # when paths share its line (a traceback's line naming the sandbox CA bundle under /run became a card for /run).
    lines = [ln for ln in result_lines(result)
             if DENIED_RE.search(NET_EACCES_RE.sub("", ln)) or MISSING_RE.search(ln)]
    if not lines:
        return []
    command = str(args.get("command") or "") if isinstance(args, dict) else ""
    write = name in WRITE_TOOLS or bool(_WRITE_CMD_RE.search(command))
    found: dict[str, tuple[Path, str, bool]] = {}

    def add(raw: str, line: str) -> None:
        path = host_path(raw)
        if path is None:
            return
        missing = not DENIED_RE.search(line) and bool(MISSING_RE.search(line))
        access = "read_write" if write or _WRITE_HINT_RE.search(line) else "read"
        key = os.path.normcase(str(path))
        if key not in found or (access == "read_write" and found[key][1] == "read"):
            found[key] = (path, access, missing)

    # A file tool names its path in args; the message may not repeat it (or quote it differently). That path is the
    # only one its refusal can be about: other paths in its error are data (patch's "Did you mean" snippet of the
    # file), so a tool that named its path is never asked for another folder, nor held on a card for one.
    named = [v for v in (args.get(k) for k in _PATH_ARGS) if isinstance(v, str) and host_path(v) is not None] \
        if isinstance(args, dict) else []
    if named:
        for value in named:
            add(value, "\n".join(lines))
        return list(found.values())
    for line in lines:
        for raw in _QUOTED_PATH_RE.findall(line):
            add(raw, line)
        for raw in _PLAIN_PATH_RE.findall(line):
            add(raw, line)
    if command:  # quoted paths in the command a refusal line also names
        for raw in _QUOTED_PATH_RE.findall(command) + _PLAIN_PATH_RE.findall(command):
            p = host_path(raw)
            if p is not None and any(Path(raw).name and Path(raw).name in ln for ln in lines):
                add(raw, lines[0])
    # an unquoted match cut at a space inside a longer path found too ("D:\Jane" of "D:\Jane Doe\x")
    return [v for k, v in found.items() if not any(o != k and o.startswith(k + " ") for o in found)]


def card_host(host: str) -> Optional[str]:
    """*host* as a network card names it (lowercase DNS name), or None when it never gets one: IP
    literals, single-label and loopback names, the sandbox's own gateway alias."""
    h = str(host or "").strip().strip("[]").rstrip(".").lower()
    if not h or h in _NO_CARD_HOSTS or h.endswith(".localhost") or h.endswith(".internal"):
        return None
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    return h if _HOSTNAME_RE.match(h) else None


def _arg_text(args) -> str:
    if not isinstance(args, dict):
        return ""
    parts = []
    for value in args.values():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, (list, tuple)):
            parts.extend(v for v in value if isinstance(v, str))
    return "\n".join(parts)


def refused_hosts(name: str, args: dict, result, *,
                  status: Optional[str] = None) -> tuple[list[tuple[str, Optional[int]]], Optional[str]]:
    """Destinations a tool result says the sandbox's proxy refused: ``([(host, port)], strength)``
    (``refused_destinations`` without where each host came from)."""
    found, strength = refused_destinations(name, args, result, status=status)
    return [(h, p) for h, p, _ in found], strength


def refused_destinations(name: str, args: dict, result, *,
                         status: Optional[str] = None) -> tuple[list[tuple[str, Optional[int], str]], Optional[str]]:
    """Candidate destinations of a network refusal in a tool result: ``([(host, port, source)], strength)``.
    *strength* is ``strong`` (OpenShell's own refusal), ``weak`` (a bare 403 that may be the site's) or
    None (no network refusal). Hosts come from the refusal itself (``CONNECT host:port``, urllib3's
    ``host='...'``: *source* ``refusal``), then from URLs in the result and the tool's arguments, then
    from the web tool vendor a web tool's error names (*source* ``text``). Only candidates: the launcher
    raises a card for a host only once OpenShell's own records show the proxy refused it (a URL the tool
    was asked to fetch, or a docs link in its error, is not a refused connection). The successful result of a
    file tool, terminal or execute_code names none: it is a file's data or a program's printout (a web tool's
    refused service, by contrast, comes back inside a successful-shaped result, so other tools' results are read
    whatever their shape)."""
    if name in DATA_TOOLS and not failed_result(name, result, status):
        return [], None
    text = _text(result)
    strength = "strong" if _strong(text) else "weak" if NET_WEAK_RE.search(text) else None
    if strength is None:
        return [], None
    found: dict[str, list] = {}

    def add(host: str, port, source: str) -> None:
        h = card_host(host)
        if h is None:
            return
        p = int(port) if port and str(port).isdigit() and 0 < int(port) < 65536 else None
        if h not in found:
            found[h] = [p, source]
        elif found[h][0] is None and p is not None:
            found[h][0] = p

    for host, port in _CONNECT_RE.findall(text):
        add(host, port, SOURCE_REFUSAL)
    for regex in (_CURL_CONNECT_RE, _WGET_CONNECT_RE):
        for host, port in regex.findall(text):
            add(host, port, SOURCE_REFUSAL)
    for host, port in _HOSTKW_RE.findall(text):
        add(host, port, SOURCE_REFUSAL)
    for scheme, host, port in _URL_RE.findall(text):
        add(host, port or (443 if scheme.lower() in ("https", "wss") else 80), SOURCE_TEXT)
    for scheme, host, port in _URL_RE.findall(_arg_text(args)):
        add(host, port or (443 if scheme.lower() in ("https", "wss") else 80), SOURCE_TEXT)
    if not found and name in WEB_TOOLS:
        low = text.lower()
        for vendor, host in WEB_VENDOR_HOSTS.items():
            if re.search(rf"\b{vendor}\b", low):
                add(host, 443, SOURCE_TEXT)
    return [(h, p, s) for h, (p, s) in found.items()][:4], strength


def _strong(text: str) -> bool:
    return bool(NET_STRONG_RE.search(text) or NET_REFUSED_RE.search(text) or NET_EACCES_RE.search(text))


def shows_network_refusal(result) -> bool:
    """Whether *result* carries a network refusal's own words, whatever the call's outcome: the proxy's 403 body
    (``policy_denied``), a client's line for a refused CONNECT, or (a sandbox without proxy variables) a refused
    connection. Words only: OpenShell's records say whether anything was refused."""
    return _strong(_text(result))


def _client_hosts(command: str) -> list[tuple[str, Optional[int]]]:
    """Bare host arguments of the network clients a shell command runs: ``curl -s example.com/x``,
    ``ssh git@example.org``. Not the value of an option that takes one (``-o page.html``)."""
    out: list[tuple[str, Optional[int]]] = []
    client, skip = False, False
    for token in _TOKEN_RE.findall(command or ""):
        if token in _SHELL_BREAKS:
            client, skip = False, False
            continue
        word = token.strip("'\"")
        if not client:
            name = re.split(r"[\\/]", word)[-1].lower()
            client = (name[:-4] if name.endswith(".exe") else name) in _NET_CLIENTS
            continue
        if skip:
            skip = False
            continue
        if word.startswith("-"):
            skip = word in _VALUE_OPTIONS
            continue
        m = _BARE_HOST_RE.match(word)
        if m:
            out.append((m.group(1), int(m.group(2)) if m.group(2) else None))
    return out


def named_destinations(name: str, args: dict, result, *,
                       scan: Optional[int] = None) -> list[tuple[str, Optional[int], str]]:
    """The hosts a terminal / execute_code call named, whatever its outcome: ``[(host, port, source)]``, at most
    ``MAX_CANDIDATES``. URLs in its command or code, else the bare host arguments of a network client in the
    command, then URLs in its output (only its first *scan* characters when given). Names only: none of them says
    the call connected anywhere."""
    if name not in PROGRAM_TOOLS:
        return []
    found: dict[str, Optional[int]] = {}

    def add(host: str, port) -> None:
        h = card_host(host)
        if h is None or len(found) >= MAX_CANDIDATES:
            return
        p = int(port) if port and str(port).isdigit() and 0 < int(port) < 65536 else None
        if found.get(h) is None:
            found[h] = p

    asked = _arg_text(args)
    urls = _URL_RE.findall(asked) if "://" in asked else []
    for scheme, host, port in urls:
        add(host, port or (443 if scheme.lower() in ("https", "wss") else 80))
    if not urls and name == "terminal" and isinstance(args, dict):
        # no URL in the command: a client's bare arguments name the site (with URLs there, they are its files)
        for host, port in _client_hosts(str(args.get("command") or "")):
            add(host, port)
    shown = _text(result[:scan] if isinstance(result, str) else result)[:scan]
    for scheme, host, port in _URL_RE.findall(shown) if "://" in shown else ():
        add(host, port or (443 if scheme.lower() in ("https", "wss") else 80))
    return [(h, p, SOURCE_TEXT) for h, p in found.items()]


def candidate_destinations(name: str, args: dict, result, *,
                           status: Optional[str] = None) -> list[tuple[str, Optional[int], str]]:
    """Where a failed terminal / execute_code call may have been refused, when its result says nothing about a
    refusal: ``[(host, port, source)]``, at most ``MAX_CANDIDATES``. The hosts the call named
    (``named_destinations``). Empty unless the result itself says the call failed (``clearly_failed``). Only
    candidates, like every host here: the launcher asks OpenShell's records whether one was refused before any
    card."""
    if name not in PROGRAM_TOOLS or not clearly_failed(result, status):
        return []
    return named_destinations(name, args, result)


# -- OpenShell's own records of what its proxy refused ------------------------------------------------

# The destination of a refused connection in OpenShell's OCSF shorthand detail: ``<binary>(<pid>) ->
# host:port`` (NET:OPEN DENIED, a refused CONNECT) or ``<binary>(<pid>) -> GET http://host[:port]/path``
# (HTTP DENIED, a refused forward request).
_DENIED_DST_RE = re.compile(r"->\s*(?:[A-Z]+\s+)?(?:[a-z][a-z0-9+.-]*://)?\[?([A-Za-z0-9._-]+)\]?(?::(\d{1,5}))?",
                            re.I)
_DENIED_ACTIONS = frozenset({"DENIED", "BLOCKED"})


def denied_in_events(events, since: Optional[float] = None) -> dict[str, set]:
    """Hosts OpenShell's proxy refused, from its audit events (``parse_event`` dicts: NET or HTTP class,
    action DENIED/BLOCKED) at or after *since*: ``{host: {ports}}`` (a port None when the record names
    none). Destinations the proxy allowed, and anything else, are not refusals."""
    out: dict[str, set] = {}
    for event in events or []:
        if not isinstance(event, dict) or event.get("class") not in ("NET", "HTTP"):
            continue
        if str(event.get("action") or "").upper() not in _DENIED_ACTIONS:
            continue
        t = event.get("time")
        if since is not None and isinstance(t, (int, float)) and _secs(t) < since:
            continue
        m = _DENIED_DST_RE.search(str(event.get("detail") or event.get("message") or ""))
        if not m:
            continue
        host = card_host(m.group(1))
        if host is None:
            continue
        port = int(m.group(2)) if m.group(2) and 0 < int(m.group(2)) < 65536 else None
        out.setdefault(host, set()).add(port)
    return out


def _secs(t: float) -> float:
    """Event times are seconds, or milliseconds in OCSF records."""
    return t / 1000.0 if t > 1e11 else float(t)


def refused_between(events, since: float, until: float) -> dict[str, float]:
    """Hosts OpenShell's proxy refused between *since* and *until*, by its own records: ``{host: time of the
    latest such refusal}``. *events*: audit events as ``denied_in_events`` reads them, or the driver's own rows of
    recent refusals (``host`` and ``time``). A record that carries no time is in no interval and never counts."""
    out: dict[str, float] = {}
    for event in events or []:
        if not isinstance(event, dict):
            continue
        t = event.get("time")
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not since <= _secs(t) <= until:
            continue
        hosts = [card_host(str(event.get("host") or ""))] if "host" in event else list(denied_in_events([event]))
        for host in hosts:
            if host and _secs(t) > out.get(host, 0.0):
                out[host] = _secs(t)
    return out
