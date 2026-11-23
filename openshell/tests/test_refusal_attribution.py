"""Which refusals a tool result can report (launcher/refusals.py), shared by the in-sandbox hook and the launcher.

A sandbox refusal is only ever the outcome of a failed call: a successful call's output is data (the file the agent
read, a listing, a page) and words in it are not a refusal. The replay below is a successful read_file of a plan
document that mentions a denial on one line and quotes a host folder on another: one JSON line once core encodes
it, so every path in the document used to count as refused (a folder card for the host folder, held the read).
"""
import json
import os
from pathlib import Path

from openshell.launcher import refusals as R

NT = os.name == "nt"
# A folder the host has outside every grant (the OpenShell host supervisor's log folder on Windows), and the
# document the agent read, as this OS spells them.
HOST_FOLDER = "C:\\var\\log" if NT else "/var/log"
DOC = "C:\\work\\docs\\PLAN.md" if NT else "/work/docs/PLAN.md"


def plan_lines(folder: str = HOST_FOLDER) -> list[str]:
    """A plan document: a denial phrase and a Windows switch on one line, the host folder quoted on another."""
    return ["# Sandbox support: delivery plan", "",
            "| A4 | Optional: tree kill when `taskkill /T` is refused; `read_file` says permission denied instead of "
            "not found | Ready |", "",
            "Upstream asks:",
            f"6. Stop writing to `{folder}`.",
            "7. A refused site answers 403 with policy_denied (CONNECT example.com:443), see https://example.com/docs."]


def read_result(lines: list[str]) -> str:
    """core's read_file result for a successful read (tools/file_tools.py): one JSON object, numbered lines."""
    content = "".join(f"{i}|{line}\n" for i, line in enumerate(lines, 1))
    return json.dumps({"content": content, "total_lines": len(lines), "file_size": len(content), "truncated": False,
                       "is_binary": False, "is_image": False}, ensure_ascii=False)


def test_a_successful_read_names_no_refused_path():
    result = read_result(plan_lines())
    assert R.maybe_refused(result)  # the cheap first look still matches: the words are there
    assert R.refused_paths("read_file", {"path": DOC}, result) == []
    # the launcher's copy: the desktop's tool.complete carries the result as parsed JSON
    assert R.refused_paths("read_file", {"path": DOC}, json.loads(result)) == []


def test_a_file_tools_success_names_no_refused_host():
    result = read_result(plan_lines())
    assert R.refused_destinations("read_file", {"path": DOC}, result) == ([], None)
    assert R.refused_destinations("search_files", {"path": DOC, "pattern": "403"},
                                  json.dumps({"matches": [{"path": DOC, "line": 7, "content": plan_lines()[6]}]})) \
        == ([], None)


def test_a_programs_successful_printout_names_no_refused_host(monkeypatch):
    """terminal and execute_code return what a program printed: a log read with exit code 0 that says "Connection
    refused" and quotes a proxy answer is not a refusal. The hook relayed it, and the launcher held the call while it
    looked for OpenShell's record of it and then for the chat's next card. A refused program fails (and OpenShell's
    draft for its connection raises the card)."""
    from openshell import sandbox_hook as H

    log = ("12:00:01 worker: upstream https://api.example.com/v1: Connection refused, retrying\n"
           "12:00:02 worker: proxy said {\"error\":\"policy_denied\"}")
    for name, result in (("terminal", {"output": log, "exit_code": 0}),
                         ("execute_code", {"status": "success", "output": log})):
        assert R.refused_destinations(name, {}, json.dumps(result)) == ([], None), name
    sent = []
    monkeypatch.setattr(H, "_send", lambda request: sent.append(request) or None)
    assert H.resolve("terminal", {"command": "cat app.log"}, {"output": log, "exit_code": 0}, status="ok") is None
    assert sent == []
    # the same printout from a failed call is a candidate (confirmed against OpenShell's records by the launcher)
    hosts, strength = R.refused_destinations("terminal", {}, json.dumps({"output": log, "exit_code": 7}))
    assert strength == "strong" and hosts[0][0] == "api.example.com"


def test_failed_calls_still_name_their_refusals():
    found = R.refused_paths("read_file", {"path": DOC},
                            json.dumps({"content": "", "error": f"File not found: {DOC}", "not_found": True}))
    assert [(str(p), missing) for p, _, missing in found] == [(str(Path(DOC)), True)]
    secret = "C:/data/secret.txt" if NT else "/data/secret.txt"
    for name, result in (("terminal", {"output": f"cat: can't open '{secret}': Permission denied", "exit_code": 1}),
                         ("execute_code", {"status": "error",
                                           "output": f"PermissionError: [Errno 13] Permission denied: '{secret}'"}),
                         ("terminal", f"cat: can't open '{secret}': Permission denied")):  # plain text: may be an error
        assert [p for p, _, _ in R.refused_paths(name, {}, result)] == [Path(secret)], name
    # a web tool reports a refused service inside a successful-shaped result: still a network candidate
    extract = json.dumps({"results": [{"url": "https://example.org/", "content": "", "error": (
        "Keyless Keenable extract failed: HTTPSConnectionPool(host='api.keenable.ai', port=443): Max retries exceeded "
        "(Caused by ProxyError('Unable to connect to proxy', OSError('Tunnel connection failed: 403 Forbidden')))")}]})
    hosts, strength = R.refused_destinations("web_extract", {"urls": ["https://example.org/"]}, extract)
    assert strength == "strong" and hosts[0][0] == "api.keenable.ai"


def test_a_refusal_names_only_the_paths_on_its_own_line():
    """A terminal call printed one path, then was refused another: core's JSON result holds the output as one string
    (newlines escaped), which used to put every path the call printed on the refusal's line."""
    listed = "C:\\data\\public\\a.txt" if NT else "/data/public/a.txt"
    secret = "C:/data/private/b.txt" if NT else "/data/private/b.txt"
    result = json.dumps({"output": f"{listed}\ncat: can't open '{secret}': Permission denied", "exit_code": 1})
    command = f"ls {listed}; cat {secret}"
    assert [p for p, _, _ in R.refused_paths("terminal", {"command": command}, result)] == [Path(secret)]


def test_a_tool_that_named_its_path_is_asked_for_that_path_only():
    """A file tool's refusal is about the path it was given. Other paths in its error are data: here patch's "Did you
    mean" snippet of the document, which quotes an old refusal of another folder."""
    other = "C:\\srv\\state" if NT else "/srv/state"
    result = json.dumps({"success": False, "error": (
        f"Could not find match for old_string in {DOC}\n\nDid you mean one of these sections?\n"
        f"  41| - the old build printed \"cat: can't open '{other}/x.log': Permission denied\"\n  42| - fixed since")})
    found = R.refused_paths("patch", {"path": DOC, "old_string": "a", "new_string": "b"}, result)
    assert [(p, a) for p, a, _ in found] == [(Path(DOC), "read_write")]


def test_a_failed_call_is_told_by_its_shape_or_by_core():
    failed = R.failed_result
    assert not failed("read_file", read_result(plan_lines()))
    assert not failed("terminal", {"output": "permission denied: see notes", "exit_code": 0})
    assert failed("terminal", {"output": "Access is denied.", "exit_code": 1})
    assert failed("terminal", {"output": "Access is denied."})  # no exit code: nothing says the program succeeded
    assert not failed("execute_code", {"status": "success", "output": "Access is denied."})
    assert failed("write_file", {"error": "Permission denied"}) and failed("patch", {"success": False, "error": "x"})
    assert failed("execute_code", json.dumps({"status": "error", "output": "Traceback"}))
    assert not failed("web_extract", {"results": [{"url": "https://example.org/", "error": "403 Forbidden"}]})
    assert failed("terminal", "cat: x: Permission denied")  # not JSON: plain text may be an error message
    assert failed("plugin_tool", json.dumps("Permission denied")) and not failed("plugin_tool", "[1, 2]")
    assert failed("read_file", read_result(plan_lines()), status="error")  # core's own verdict, when it gives one
    assert not failed("read_file", read_result(plan_lines()), status="ok")
