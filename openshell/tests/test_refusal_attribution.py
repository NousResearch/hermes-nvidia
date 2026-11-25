"""Which refusals a tool result can report (launcher/refusals.py), shared by the in-sandbox hook and the launcher.

A sandbox refusal is the outcome of a failed call: a successful call's output is data (the file the agent read, a
listing, a page) and words in it are not a refusal. One exception, for terminal and execute_code: a call that did not
fail names a refused path when a line of its output says access was denied and names a path the call's own command or
code named (several folders listed in one command, one of them refused). The replay below is a successful read_file of a plan
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


# -- a program call that did not fail, refused a path its own command or code named --------------------------------

HOME = "C:/Users/you" if NT else "/home/you"
DESKTOP, NOTES = f"{HOME}/Desktop", f"{HOME}/Documents/notes"
PROFILE = f"{HOME}/AppData/Local/hermes/profiles/work" if NT else f"{HOME}/.hermes/profiles/work"
OS_DENIAL = "[WinError 5] Access is denied" if NT else "[Errno 13] Permission denied"


def listing(refused: str = DESKTOP, said: str = "Permission denied") -> tuple[dict, dict]:
    """A terminal call that lists three folders in one command. The second is refused and the third lists, so the
    command exits 0."""
    args = {"command": f'ls "{NOTES}"; ls "{refused}"; ls "{PROFILE}"'}
    return args, {"output": f"a.txt\nls: {refused}: {said}\nconfig.yaml\n", "exit_code": 0, "error": None}


def relayed(monkeypatch, name: str, args: dict, result) -> list[dict]:
    """What the in-sandbox hook asks the launcher after one call core reports as successful (nothing answers here,
    so the result returns as it came)."""
    from openshell import sandbox_hook as H

    sent = []
    monkeypatch.setattr(H, "_send", lambda request: sent.append(request) or None)
    assert H.resolve(name, args, json.dumps(result), session_id="chatA", status="ok") is None
    return sent


def asked_for(request: dict) -> list[tuple[str, str]]:
    return [(item["path"], item["access"]) for item in request["paths"]]


def test_a_command_that_succeeded_names_the_folder_it_was_refused(monkeypatch):
    """Several folders listed in one command: one is refused and a later listing succeeds, so the command exits 0.
    The refusal line names a folder the command itself named, so that folder is asked for, to read."""
    args, result = listing()
    assert not R.failed_result("terminal", result, "ok")
    for shape in (result, json.dumps(result)):  # Parsed (the launcher's copy) and as core encodes it (the hook's)
        assert R.refused_paths("terminal", args, shape, status="ok") == [(Path(DESKTOP), "read", False)]
    [request] = relayed(monkeypatch, "terminal", args, result)
    assert request["kind"] == "access" and request["tool"] == "terminal"
    assert asked_for(request) == [(str(Path(DESKTOP)), "read")]


def test_the_command_and_the_refusal_line_may_spell_the_folder_differently():
    """The two are compared as the host names paths: quotes and a trailing separator do not count, nor on Windows
    do the kind of slash, the case, or the shell's /c/ spelling of a drive."""
    spaced = f"{HOME}/My Files"
    pairs = [(f'ls "{DESKTOP}/"', f"ls: {DESKTOP}: Permission denied", DESKTOP),
             (f"ls '{DESKTOP}'", f"ls: cannot open directory '{DESKTOP}/': Permission denied", DESKTOP),
             (f"ls {DESKTOP}", f'ls: cannot access "{DESKTOP}": Operation not permitted', DESKTOP),
             (f'ls "{spaced}"', f"ls: {spaced}: Permission denied", spaced),  # Printed unquoted, with its space
             (f'find "{DESKTOP}" -name "*.md" | head', f"find: \u2018{DESKTOP}\u2019: Permission denied", DESKTOP)]
    if NT:
        pairs += [("ls /c/Users/you/Desktop", "ls: C:/Users/you/Desktop: Permission denied", DESKTOP),
                  ('ls "C:\\Users\\you\\Desktop"', "ls: c:/users/you/desktop: Permission denied", DESKTOP),
                  ("dir C:\\Users\\you\\Desktop", "Access is denied: 'C:\\\\Users\\\\you\\\\Desktop'", DESKTOP),
                  ('ls "C:/Users/you/Desktop"', "ls: /c/Users/you/Desktop: Permission denied", DESKTOP)]
    for command, line, folder in pairs:
        result = {"output": f"{line}\ndone\n", "exit_code": 0}
        found = R.refused_paths("terminal", {"command": f"{command}; echo done"}, result)
        assert [(os.path.normcase(str(p)), a) for p, a, _ in found] \
            == [(os.path.normcase(str(Path(folder))), "read")], command


def test_a_refused_write_in_a_command_that_succeeded_asks_to_read_and_write(monkeypatch):
    """A write into the refused folder, then a listing that succeeds: the command exits 0 and the folder is asked for
    with read and write, as for a failed write."""
    new = f"{DESKTOP}/new.txt"
    args = {"command": f'echo hi > "{new}"; ls "{PROFILE}"'}
    result = {"output": f"sh: can't create {new}: Permission denied\nconfig.yaml\n", "exit_code": 0, "error": None}
    assert R.refused_paths("terminal", args, result, status="ok") == [(Path(new), "read_write", False)]
    [request] = relayed(monkeypatch, "terminal", args, result)
    assert request["kind"] == "access" and asked_for(request) == [(str(Path(new)), "read_write")]


def test_code_that_caught_its_refusal_names_the_folder_it_was_refused(monkeypatch):
    """execute_code catches the error, prints it and ends normally: the printed refusal names a folder the code
    itself named."""
    code = (f"import os\ntry:\n    print(os.listdir({DESKTOP!r}))\nexcept OSError as exc:\n"
            "    print('skipped:', exc)\nprint('done')\n")
    result = {"status": "success", "output": f"skipped: {OS_DENIAL}: {DESKTOP!r}\ndone\n", "tool_calls_made": 0,
              "duration_seconds": 0.21}
    assert not R.failed_result("execute_code", result, "ok")
    assert R.refused_paths("execute_code", {"code": code}, result, status="ok") == [(Path(DESKTOP), "read", False)]
    [request] = relayed(monkeypatch, "execute_code", {"code": code}, result)
    assert request["kind"] == "access" and asked_for(request) == [(str(Path(DESKTOP)), "read")]


def test_a_refusal_below_the_named_folder_asks_for_the_path_it_names():
    """A recursive listing of a folder is refused one folder inside it: the path asked for is the one the refusal
    line names, the least that was refused, not the folder above it that the command named."""
    inner = f"{NOTES}/private"
    result = {"output": f"{NOTES}:\na.txt\nprivate\nls: {inner}: Permission denied\n", "exit_code": 0}
    assert R.refused_paths("terminal", {"command": f'ls -R "{NOTES}" | head -50'}, result) \
        == [(Path(inner), "read", False)]
    # A drive or filesystem root is above every path, so naming it names none of them
    root = "C:/" if NT else "/"
    assert R.refused_paths("terminal", {"command": f"ls -R {root} | head -50"}, result) == []


def test_a_successful_calls_output_stays_data_for_paths_its_command_did_not_name(monkeypatch):
    """What a call that succeeded printed is data wherever it names a path the call's own command or code did not,
    and a successful file tool's result is data whatever it names."""
    cases = [
        # The plan document printed by cat: a denial phrase on one line, a host folder quoted on another
        ("terminal", {"command": f'cat "{DOC}"'}, {"output": "\n".join(plan_lines()), "exit_code": 0}),
        # A log line that says denied and names a folder the command did not name
        ("terminal", {"command": f'cat "{DOC}"; ls "{NOTES}"'},
         {"output": f"12:00:01 worker: open('{HOST_FOLDER}/app.log'): Permission denied\na.txt\n", "exit_code": 0}),
        # "no such file" alone does not make a call that succeeded a refused one
        ("terminal", *listing(said="No such file or directory")),
        # A folder beside the named one whose name starts the same
        ("terminal", {"command": f'ls "{DESKTOP}"; echo done'},
         {"output": f"ls: {DESKTOP}-old: Permission denied\nls: {DESKTOP}2/a: Permission denied\ndone\n",
          "exit_code": 0}),
        # A refused connect() says "[Errno 13] Permission denied" with no path after it: a network refusal
        ("execute_code", {"code": f"print(open({DOC!r}).read())"},
         {"status": "success", "output": f"fetching for {DOC}: [Errno 13] Permission denied\n"}),
        # File tools: the file's own text, even where it names the path the tool was given
        ("read_file", {"path": DOC}, json.loads(read_result([f"cat: can't open '{DOC}': Permission denied"]))),
        ("search_files", {"path": HOST_FOLDER, "pattern": "denied"},
         {"total_count": 1, "matches": [{"path": f"{HOST_FOLDER}/a.log", "line": 3,
                                         "content": f"open('{HOST_FOLDER}/b'): Permission denied"}]}),
    ]
    for name, args, result in cases:
        assert R.refused_paths(name, args, result, status="ok") == [], (name, args)
        assert relayed(monkeypatch, name, args, result) == [], (name, args)


def test_a_command_that_succeeded_is_asked_for_two_folders_at_most(monkeypatch):
    folders = [f"{HOME}/{name}" for name in ("Desktop", "Downloads", "Pictures")]
    args = {"command": "; ".join(f'ls "{folder}"' for folder in folders) + f'; ls "{PROFILE}"'}
    result = {"output": "".join(f"ls: {folder}: Permission denied\n" for folder in folders) + "config.yaml\n",
              "exit_code": 0}
    [request] = relayed(monkeypatch, "terminal", args, result)
    assert asked_for(request) == [(str(Path(folder)), "read") for folder in folders[:2]]
