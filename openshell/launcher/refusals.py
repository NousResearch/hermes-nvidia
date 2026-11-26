"""What a sandbox refusal looks like in a tool result: refused paths and refused network destinations.

Shared by the launcher (folder cards from relayed tool results, cards.py) and the in-sandbox hook that
waits for the user's answer (sandbox_hook.py). Pure functions, standard library only: the hook imports
this inside the sandbox on every refused tool result.
"""
from __future__ import annotations

import ipaddress
import itertools
import json
import os
import re
from pathlib import Path
from typing import Optional

WRITE_TOOLS = frozenset({"write_file", "patch", "edit_file", "apply_patch", "str_replace", "create_file"})
# File tools: a successful call's output is a file's data (or a listing of files), never a refusal of any kind.
FILE_TOOLS = WRITE_TOOLS | frozenset({"read_file", "search_files"})
# ... nor is what a program printed when it succeeded (terminal, execute_code): a refused program fails, and
# OpenShell's draft for its refused connection raises the card in any case. One thing is read from such a printout:
# a line that says access was denied to a path the call's own command or code named (``named_refusals``).
PROGRAM_TOOLS = frozenset({"terminal", "execute_code"})
DATA_TOOLS = FILE_TOOLS | PROGRAM_TOOLS
_FAILED_STATUSES = frozenset({"error", "failed", "failure"})
DENIED_RE = re.compile(r"permission denied|access is denied|operation not permitted|read-only file system|"
                       r"errno 13|eacces|erofs", re.I)
# "file not found": Hermes's own read_file. On Windows an MXC sandbox sees an ungranted file as absent, so
# the agent's first read of it says "File not found: <path>" (a card only if the host has the path).
MISSING_RE = re.compile(r"no such file or directory|errno 2\b|enoent|cannot find the path|file not found", re.I)
# What a refusal line says of the paths it names, read from the line without those paths (``_said``). A refused
# write: the words coreutils and busybox print for one, or a line led by the name of a program that only writes
# the files it is given (``touch: /x: Permission denied``). A refused read: the words for a file or folder that
# could not be opened to read or looked at.
_WRITE_HINT_RE = re.compile(r"can't create|cannot create|read-only file system|can't write|cannot write|"
                            r"for writing|can't remove|cannot remove|can't move|cannot move|can't make|"
                            r"cannot make|mkdir|erofs|can't touch|cannot touch|setting times|can't overwrite|"
                            r"cannot overwrite|can't set|cannot set|can't rename|cannot rename|can't unlink|"
                            r"cannot unlink|can't delete|cannot delete|failed to create|unable to create|"
                            r"temporary file|^[ \t]*(?:touch|tee|rm|rmdir)(?:\.exe)?:", re.I | re.M)
_READ_HINT_RE = re.compile(r"for reading|can't access|cannot access|can't stat|cannot stat|can't read|cannot read|"
                           r"can't open directory|cannot open directory", re.I)
# What a shell command does to the paths it names, program by program. Programs that write every path they are
# given, programs that write the last one and read the others, and programs that only read. ``sed`` writes its
# files with ``-i`` and reads them without. A program in none of these sets does not show what it does.
# ``_WRITES_BELOW``: the writers that also change what lies below a folder they are given (``mkdir -p D`` and
# ``touch D`` leave the files in ``D`` alone).
_WRITES_ALL = frozenset({"touch", "mkdir", "rm", "rmdir", "tee", "mv"})
_WRITES_LAST = frozenset({"cp", "install"})
_WRITES_BELOW = frozenset({"rm", "mv", "cp", "install"})
_READS = frozenset({"cat", "cd", "cmp", "diff", "dir", "du", "file", "grep", "head", "less", "ls", "md5sum", "more",
                    "sha256sum", "stat", "tac", "tail", "wc"})
# Words in front of the program a command runs.
_COMMAND_PREFIXES = frozenset({"sudo", "env", "command", "exec", "nohup", "time", "if", "then", "elif", "else",
                               "while", "until", "do", "!", "{"})
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_REDIRECT_RE = re.compile(r"&>>?|\d*>[>|&]?|\d*<[<&]?<?")
# A shell command's tokens: a line break, an operator that ends a command, a redirection, or a word with its
# quoted and escaped parts. A part is told by its first character and read in one pass, so a command is read
# in time that grows in step with its length whatever it holds. A quote that is never closed runs to the end of
# the command as the last part of its word (the groups ``open`` and ``bare``), and so does a backslash that
# ends the command.
_WORD_PART = r"""[^\s;|&()<>"'\\]+|\\.|"[^"\\]*(?:\\.[^"\\]*)*"|'[^']*'"""
_OPEN_PART = r"""\\|"[^"\\]*(?:\\.[^"\\]*)*|'[^']*"""
_SHELL_TOKEN_RE = re.compile(r"\n|\|\||&&|;|" + _REDIRECT_RE.pattern + r"|[|&()]|(?:" + _WORD_PART + r")+(?P<open>"
                             + _OPEN_PART + r")?|(?P<bare>" + _OPEN_PART + r")", re.S)
_COMMAND_ENDS = frozenset({"\n", ";", "&&", "||", "|", "&", "(", ")"})
# How much of a command is read for what it does to the paths it names. The launcher reads commands the
# sandboxed side sends, so the work one of them can ask for has a limit. 32,768 characters is more than a Windows
# command line holds. Of a longer command, a write found within them counts, and no path is shown as only read:
# the rest is not read and can write it (``_command_uses``).
COMMAND_READ_CHARS = 32768
# The longest word of a command, and the longest path argument of a tool, that is taken for a path. The launcher
# asks for none that is longer (``verdicts.parse_request``).
MAX_PATH_CHARS = 1024
# The paths a call names itself (``_asked_paths``) are collected from the first ``ASKED_READ_CHARS`` characters
# of its arguments, ``ASKED_PATHS`` different ones at most. The launcher reads arguments the sandboxed side sends,
# megabytes of them in one frame, and every path it collects costs it some work. 262,144 characters hold a script
# of several thousand lines, and a call that lists files names hundreds of paths. A path named beyond either
# limit is not the call's own: a failed call's refusal of it is still read from the refusal line, and a call that
# did not fail raises no card for it.
ASKED_READ_CHARS = 262144
ASKED_PATHS = 4096
# How much of a result's refusal lines is read for the paths they name, for the same reason: whole lines, in
# the order the tool printed them, while they fit. A recursive listing can print thousands, and a card is raised
# for two paths of one result at most.
REFUSAL_READ_CHARS = 32768
# A path of the call's own with a space in it, or another character an unquoted path ends at, is also looked
# for where a line prints it without quotes (``_Spaced``): up to its first ``SPACED_PARTS`` such characters, and
# with ``SPACED_STEPS`` steps of that work for one call at most.
SPACED_PARTS = 8
SPACED_STEPS = 4096
_QUOTED_PATH_RE = re.compile(r"""['"`]((?:[A-Za-z]:[\\/]|/)[^'"`\n]{0,400})['"`]""")
_PLAIN_PATH_RE = re.compile(r"(?:^|(?<=[\s=(]))((?:[A-Za-z]:[\\/]|/)[^\s'\"`:;,)]{0,400})")
# A path in a line whose separators are folded to ``/``, after any character that is no part of a longer name: a
# bracket or a typographic quote as well as a space. It ends where an unquoted path ends.
_PATH_END = r"\s'\"`\u2018\u2019:;,)"
_LOOSE_PATH_RE = re.compile(rf"(?<![\w./~-])((?:[A-Za-z]:/|/)[^{_PATH_END}]{{0,400}})")
_PATH_END_RE = re.compile(rf"[{_PATH_END}]")
# How a path goes on after a character an unquoted path ends at.
_MORE_PATH_RE = re.compile(rf"[{_PATH_END}]+[^{_PATH_END}]{{1,400}}")
_SLASHES_RE = re.compile(r"[\\/]+")
_MSYS_RE = re.compile(r"^/([A-Za-z])(/.*)?$")
# How many denial lines that name a path of the call's own are read from a call that did not fail (a recursive
# listing can print thousands). Lines that name none of its paths do not count.
NAMED_REFUSAL_LINES = 64
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
    ``results[].error``) does not make the call failed; ``refused_destinations`` still reads those. A terminal or
    execute_code call that did not fail can still name a refused path, by a narrower rule (``named_refusals``)."""
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
    ``read_write``; *missing* is True when the tool said "no such file" rather than "denied". A failed call
    names them (``failed_result``; *status* is core's verdict when the caller has it). A call that did not fail
    names only the denied paths its own command or code named (``named_refusals``: terminal and execute_code).

    *access* is what the refused path itself needs. ``read_write``: a tool that writes was refused its path, the
    refusal line says a write was refused, or the command writes the path (a redirection into it, the files of
    ``touch``, ``mkdir``, ``rm``, ``rmdir``, ``tee``, ``mv`` and ``sed -i``, the target of ``cp`` and ``install``).
    ``read`` in every other case: a write to another path in the same command changes nothing.

    The caller can be the launcher, reading what the sandboxed side sent. What a command does to its paths is
    read from its first ``COMMAND_READ_CHARS`` characters, and a result's refusal lines up to
    ``REFUSAL_READ_CHARS``. The paths a call names itself are the first ``ASKED_PATHS`` in the first
    ``ASKED_READ_CHARS`` characters of its arguments."""
    found = refused_accesses(name, args, result, status=status)
    return [(path, access, missing) for path, access, missing, _ in found]


def refused_accesses(name: str, args: dict, result, *,
                     status: Optional[str] = None) -> list[tuple[Path, str, bool, bool]]:
    """``refused_paths`` with a fourth value: ``(path, access, missing, assumed)``. *assumed* is True when a failed
    call was denied the path and neither the refusal line nor the command shows what was done to it (a script, a
    variable, code): ``read`` is then the least the path needs, and the launcher asks for more when the sandbox
    can already read it (cards.py). A path reported missing, and a path of a call that did not fail, never
    have it."""
    return _refusals(name, args, result, failed_result(name, result, status))


def _refusals(name: str, args: dict, result, failed: bool) -> list[tuple[Path, str, bool, bool]]:
    """The refused paths of a call that failed, or of one that did not (``named_refusals``). The work grows in
    step with the length of the call's arguments and of its result: a refusal line is read once,
    ``REFUSAL_READ_CHARS`` of them at most, and a path it names is looked up, never compared with every path of
    the call."""
    if not failed and name not in PROGRAM_TOOLS:
        return []
    lines = _refusal_lines(result, failed)
    if not lines:
        return []
    args = args if isinstance(args, dict) else {}
    found: dict[str, tuple[Path, str, bool, bool]] = {}

    def told(text: str, said: str) -> tuple[bool, bool, bool]:
        """What one refusal says of every path on it: that the path is missing, that a write was refused, that
        a read was. *text* is the refusal as printed and *said* its words without the paths (``_said``)."""
        missing = failed and not DENIED_RE.search(text) and bool(MISSING_RE.search(text))
        return missing, bool(_WRITE_HINT_RE.search(said)), bool(_READ_HINT_RE.search(said))

    def add(key: str, path: Path, facts: tuple[bool, bool, bool], uses: Optional[_Uses]) -> None:
        missing, wrote, read = facts
        access, shown = _access(name, key, wrote, read, uses)
        if key not in found or (access == "read_write" and found[key][1] == "read"):
            found[key] = (path, access, missing, failed and not missing and access == "read" and not shown)

    # A file tool names its path in args; the message may not repeat it (or quote it differently). That path is the
    # only one its refusal can be about: other paths in its error are data (patch's "Did you mean" snippet of the
    # file), so a tool that named its path is never asked for another folder, nor held on a card for one. Where
    # lines of the error name the path, they say what happened to it; else the whole error does.
    named = [path for path in (host_path(v) for v in (args.get(k) for k in _PATH_ARGS)
                               if isinstance(v, str) and len(v) <= MAX_PATH_CHARS)
             if path is not None] if failed else []
    if named:
        for path in named:
            own = {_path_key(path): path}
            spaced = _Spaced(own)
            each = [(line, *_named_on(line, own, spaced)) for line in lines]
            mine = [(line, _said(folded, spans)) for line, shown, folded, spans in each
                    if any(_within(key, own) for key, _ in shown)]
            mine = mine or [(line, _said(folded, spans)) for line, _, folded, spans in each]
            facts = told("\n".join(line for line, _ in mine), "\n".join(said for _, said in mine))
            add(_path_key(path), path, facts, None)
        return list(found.values())
    # The call's own paths: a failed call is refused every path a refusal line names, a call that did not fail
    # only those of its own paths (or paths below one) a denial line names.
    asked = _asked_paths(args)
    if not failed and not asked:
        return []
    spaced = _Spaced(asked)
    uses = _command_uses(str(args.get("command") or ""))
    read = 0
    for line in lines:
        shown, folded, spans = _named_on(line, asked, spaced)
        facts = None
        for key, path in shown:
            if not failed and not _within(key, asked):
                continue
            facts = told(line, _said(folded, spans)) if facts is None else facts
            add(key, path, facts, uses)
        read += facts is not None
        if not failed and read >= NAMED_REFUSAL_LINES:
            break
    # An unquoted match cut at a space is dropped when the longer path it was cut from was found too ("D:\Jane" of
    # "D:\Jane Doe\x").
    cut = {key[:at] for key in found if " " in key for at, char in enumerate(key) if char == " "}
    return [value for key, value in found.items() if key not in cut]


def _refusal_lines(result, failed: bool) -> list[str]:
    """The lines of a result that say a path was refused, in the order the tool printed them, while they fit in
    ``REFUSAL_READ_CHARS``: the first line that does not fit ends the reading, so no path is read cut short.

    A refusal line names only the paths on it, line by line as the tool printed them (``result_lines``): read as
    one encoded line, a JSON result put every path a call printed beside its refusal. A connect() the sandbox
    refused ("[Errno 13] Permission denied" with no path after it) is a network refusal and names no path, even
    when paths share its line (a traceback's line naming the sandbox CA bundle under /run became a card for /run).
    "No such file" counts for a failed call only."""
    lines: list[str] = []
    left = REFUSAL_READ_CHARS
    for line in result_lines(result):
        if DENIED_RE.search(NET_EACCES_RE.sub("", line)) or (failed and MISSING_RE.search(line)):
            left -= len(line)
            if left < 0:
                break
            lines.append(line)
    return lines


def _path_key(path: Path) -> str:
    """*path* as two spellings of one host path compare equal: the kind of slash, a trailing separator and, on
    Windows, the case make no difference."""
    return os.path.normcase(os.path.normpath(str(path)))


def _above(key: str):
    """The keys of the folders above the path *key*, nearest first."""
    cut = key.rfind(os.sep)
    while cut > 0:
        key = key[:cut]
        yield key
        cut = key.rfind(os.sep)


def _within(key: str, keys) -> bool:
    """Whether the path *key* is one of *keys* or lies below one."""
    return key in keys or any(folder in keys for folder in _above(key))


def _asked_paths(args) -> dict[str, Path]:
    """The absolute paths a call's own arguments name (its command or code), by ``_path_key``. A drive or
    filesystem root is left out: it is above every path, so naming it names none of them. A path written straight
    after a redirection (``>/x``) is named like one that follows a space. They are taken from the first
    ``ASKED_READ_CHARS`` characters of the arguments, the quoted ones and then the unquoted ones in the order
    they are written, ``ASKED_PATHS`` different ones at most."""
    text = re.sub(r"(?<=[<>])(?=[A-Za-z]:[\\/]|/)", " ", _asked_text(args))
    out: dict[str, Path] = {}
    seen: set[str] = set()
    for match in itertools.chain(_QUOTED_PATH_RE.finditer(text), _PLAIN_PATH_RE.finditer(text)):
        raw = match.group(1)
        if raw in seen:
            continue
        if len(seen) >= ASKED_PATHS:
            break
        seen.add(raw)
        path = host_path(raw)
        if path is not None and path.parent != path:
            out.setdefault(_path_key(path), path)
    return out


def _asked_text(args) -> str:
    """The first ``ASKED_READ_CHARS`` characters of a call's arguments, read like ``_arg_text``: its string
    values and the strings in its list values, one per line. Every value counts for one character, so a list of
    numbers has an end too. The word the limit cuts in two is left out: a path cut short is another path."""
    parts: list[str] = []
    left = ASKED_READ_CHARS
    for value in args.values() if isinstance(args, dict) else ():
        for item in value if isinstance(value, (list, tuple)) else (value,):
            left -= 1
            if left < 0:
                break
            if not isinstance(item, str):
                continue
            if len(item) > left:
                kept = item[:left]
                parts.append(kept[:max(kept.rfind(" "), kept.rfind("\n"), kept.rfind("\t"), 0)])
                left = -1
                break
            parts.append(item)
            left -= len(item)
        if left < 0:
            break
    return "\n".join(parts)


class _Spaced:
    """Those of a call's paths that no pattern for an unquoted path takes whole, because they hold a character
    such a path ends at (a space, say). A line that prints one without quotes shows its start, up to that
    character, as a path of its own; ``follow`` goes on from there. Kept as keys (``_path_key``): the paths
    themselves (``whole``) and what a line shows of one before each such character (``starts``), up to its first
    ``SPACED_PARTS`` of them. ``SPACED_STEPS`` is the most that is worked out for one call, here and in
    ``follow``."""

    def __init__(self, asked: dict[str, Path]):
        self.whole: set[str] = set()
        self.starts: set[str] = set()
        self.steps = SPACED_STEPS
        known: dict[str, Optional[str]] = {}  # the text of a start -> its key
        for key, path in asked.items():
            text = str(path)
            if not _PATH_END_RE.search(text, 2 if text[1:2] == ":" else 0):
                continue
            self.whole.add(key)
            posix = path.as_posix().rstrip("/")
            part = _LOOSE_PATH_RE.match(posix)
            end = part.end() if part is not None else len(posix)
            for _ in range(SPACED_PARTS):
                shown = posix[:end]
                if end >= len(posix) or (shown not in known and len(known) >= SPACED_STEPS):
                    break
                if shown not in known:
                    start = host_path(shown)
                    known[shown] = _path_key(start) if start is not None else None
                if known[shown] is not None:
                    self.starts.add(known[shown])
                more = _MORE_PATH_RE.match(posix, end)
                end = more.end() if more is not None else len(posix)

    def follow(self, folded: str, start: int, end: int, key: str):
        """*folded* shows a path from *start* to *end*, with the key *key*. Where that is the start of one of
        these paths, the longer paths the line goes on with that are one of them or lie below one, as
        ``(key, path, end)``."""
        for _ in range(SPACED_PARTS):
            if key not in self.starts or self.steps <= 0:
                return
            more = _MORE_PATH_RE.match(folded, end)
            path = host_path(folded[start:more.end()]) if more is not None else None
            if path is None:
                return
            self.steps -= 1
            key, end = _path_key(path), more.end()
            if _within(key, self.whole):
                yield key, path, end


def _named_on(line: str, asked: dict, spaced: _Spaced) -> tuple[list[tuple[str, Path]], str, list]:
    """The paths a line of output names, each with its key: the quoted and the unquoted ones, and those of the
    call's own paths (*asked*, and paths below them) it spells in another way: after a bracket or a typographic
    quote, or without quotes with a space inside (*spaced*). Also what ``_said`` reads: the line with its
    separators folded to ``/``, and where in it the paths with a space lie."""
    shown = []
    for raw in _QUOTED_PATH_RE.findall(line) + _PLAIN_PATH_RE.findall(line):
        path = host_path(raw)
        if path is not None:
            shown.append((_path_key(path), path))
    folded = _SLASHES_RE.sub("/", line)
    spans = []
    for part in _LOOSE_PATH_RE.finditer(folded) if asked else ():
        path = host_path(part.group(1))
        if path is None:
            continue
        key = _path_key(path)
        if _within(key, asked):
            shown.append((key, path))
        last = None
        for longer, path, last in spaced.follow(folded, part.start(1), part.end(1), key):
            shown.append((longer, path))
        if last is not None:
            spans.append((part.start(1), last))
    return shown, folded, spans


def _said(folded: str, spans: list[tuple[int, int]]) -> str:
    """A refusal line without the paths it names: the words that say what was refused. A file or folder name is
    no part of them (``mkdir-notes/a.txt`` was not refused a ``mkdir``). *folded* and *spans* are ``_named_on``'s."""
    parts, at = [], 0
    for start, end in spans:
        if end > at:
            parts += [folded[at:max(start, at)], " "]
            at = end
    parts.append(folded[at:])
    return _LOOSE_PATH_RE.sub(" ", _QUOTED_PATH_RE.sub(" ", "".join(parts)))


class _Uses:
    """What a shell command does to the absolute paths it names (``_command_uses``), kept by path so that a
    refused path is answered from the operands that concern it, not from every operand of the command."""

    def __init__(self, whole: bool):
        self.whole = whole  # False when a part of the command was not read
        self.named: dict[str, set] = {}  # a path -> the uses of the operands that are that path or lie below it
        self.reach: dict[str, set] = {}  # a path -> those uses of its own operands that reach what lies below it

    def add(self, key: str, use: Optional[str], below: bool) -> None:
        self.named.setdefault(key, set()).add(use)
        for folder in _above(key):
            self.named.setdefault(folder, set()).add(use)
        if below:
            self.reach.setdefault(key, set()).add(use)

    def of(self, key: str) -> Optional[str]:
        """What the command does to the path *key*, from the operands that name it, a path below it (the program
        was refused on its way there) or, where the program's use reaches below its operand, a folder above it:
        ``write`` when one of them is written, ``read`` when all of them are read and the whole command was read,
        None when the command does not show it (no operand names the path, a program whose operands are not
        known does, or a part that was not read can write it)."""
        seen = set(self.named.get(key, ()))
        for folder in _above(key):
            seen |= self.reach.get(folder, set())
        if "write" in seen:
            return "write"
        return "read" if seen == {"read"} and self.whole else None


def _access(name: str, key: str, wrote: bool, read: bool, uses: Optional[_Uses]) -> tuple[str, bool]:
    """What the refused path *key* needs, and whether that is shown: ``(access, shown)``. ``read_write`` when the
    tool writes, the refusal line's words say a write was refused (*wrote*), or the command writes the path
    (*uses*). Else ``read``, shown when the line says a read was refused (*read*), the command only reads the
    path, or the tool is one that reads."""
    if name in WRITE_TOOLS or wrote:
        return "read_write", True
    use = uses.of(key) if uses is not None else None
    if use == "write":
        return "read_write", True
    return "read", use == "read" or name in FILE_TOOLS or read


def _command_uses(command: str) -> _Uses:
    """What a shell command does to each absolute path it names: ``write``, ``read`` or None where the program
    does not show it, and whether the use reaches what lies below the path. The command is read one simple
    command at a time (split at ``;``, ``&&``, ``||``, ``|``, ``&``, parentheses and line breaks, outside quotes),
    so a write in one of them says nothing of a path another one names. It is read up to ``COMMAND_READ_CHARS``
    and up to a quote that is never closed. Where that leaves a part unread, the simple command it stops in is
    left out, because its last word there is not its last word."""
    uses = _Uses(len(command) <= COMMAND_READ_CHARS)
    tokens: list[str] = []

    def note() -> None:
        for word, use, below in _simple_command_uses(tokens):
            path = host_path(re.sub(r"""["']""", "", word)) if len(word) <= MAX_PATH_CHARS else None
            if path is not None and path.parent != path:
                uses.add(_path_key(path), use, below)

    for token in _SHELL_TOKEN_RE.finditer(command[:COMMAND_READ_CHARS]):
        if token.lastgroup:
            uses.whole = False
        if token.group() in _COMMAND_ENDS:
            note()
            tokens = []
        else:
            tokens.append(token.group())
    if uses.whole:
        note()
    return uses


def _simple_command_uses(tokens: list[str]) -> list[tuple[str, Optional[str], bool]]:
    """``(word, use, below)`` for the words of one simple command: the target of an output redirection is written
    and the source of an input redirection read; the operands follow the program (``_WRITES_ALL``,
    ``_WRITES_LAST``, ``_READS``, ``sed``); the words of any other program get None."""
    uses: list[tuple[str, Optional[str], bool]] = []
    words: list[str] = []
    skip = False
    for i, token in enumerate(tokens):
        if skip:
            skip = False
        elif not _REDIRECT_RE.fullmatch(token):
            words.append(token)
        else:
            skip = True
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            # A here-document's delimiter and a duplicated descriptor (``2>&1``) are no paths.
            if "<<" not in token and not (token.endswith("&") and re.fullmatch(r"\d+|-", target)):
                uses.append((target, "read" if "<" in token else "write", False))
    first = 0
    while first < len(words) and (_ASSIGNMENT_RE.match(words[first]) or words[first] in _COMMAND_PREFIXES):
        first += 1
    words = words[first:]
    if not words:
        return uses
    program = re.split(r"[\\/]", words[0].strip("'\""))[-1].lower()
    program = program[:-4] if program.endswith(".exe") else program
    options = [w for w in words[1:] if w.startswith("-")]
    operands = [w for w in words[1:] if not w.startswith("-")]
    below = program in _WRITES_BELOW
    if program == "sed":
        in_place = any(re.match(r"-[A-Za-z]*i|--in-place", option) for option in options)
        return uses + [(w, "write", False) if in_place else (w, "read", True) for w in operands]
    if program in _WRITES_ALL or (program == "install" and {"-d", "--directory"} & set(options)):
        return uses + [(w, "write", below and program != "install") for w in operands]
    if program in _WRITES_LAST:
        # ``-t DIR`` and ``--target-directory=DIR`` name the target in front of the sources.
        target = next((w.partition("=")[2] for w in options if w.startswith("--target-directory=")), None)
        if target is None and {"-t", "--target-directory"} & set(options):
            target = next((words[i + 1] for i, w in enumerate(words[:-1]) if w in ("-t", "--target-directory")), None)
        if target is None and len(operands) > 1:
            target = operands[-1]
        return uses + [(w, "read", True) for w in operands if w != target] \
            + ([(target, "write", True)] if target else [])
    if program in _READS:
        return uses + [(w, "read", True) for w in operands]
    # Any other program: every path in its words, an option's value included (``--out=/x``).
    return uses + [(raw, None, True) for w in words for raw in _QUOTED_PATH_RE.findall(w) + _PLAIN_PATH_RE.findall(w)]


def named_refusals(name: str, args: dict, result) -> list[tuple[Path, str, bool]]:
    """Refused paths of a terminal / execute_code call that did not fail: ``(path, access, False)``. ``ls A; ls B``
    exits 0 when only A was refused, and code that catches its error ends normally. Such a call's output is data, so
    a path counts only when both hold: a line of the output says access was denied and names the path, and the
    call's own command or code named that path or a folder above it. "No such file" is not enough here, and a path
    that only the output names never counts (a printed document or log that quotes a refusal), nor does one the
    call names beyond ``ASKED_READ_CHARS`` or ``ASKED_PATHS``. The path returned is the one the refusal line names,
    which is the least that was refused; *access* follows the rule for failed calls (``refused_paths``). Only
    candidates: the launcher asks for one once the host has it outside the sandbox's grants (cards.py)."""
    return [(path, access, missing) for path, access, missing, _ in _refusals(name, args, result, False)]


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
