"""What a folder card asks for (launcher/refusals.py, sandbox_hook.py, launcher/cards.py, launcher/activity.py).

A refused path is asked for with the access that path needs: read and write when its refusal line says a write was
refused or the command writes that path, read otherwise. A write to another path in the same command changes
nothing. Where neither the line nor the command shows what was done to the path (a script, a variable, code the
agent runs), the card asks to read; when such a path is refused while the sandbox can already read it and the
host's user can read it too, the card asks to read and write.

The launcher reads commands and results the sandboxed side sends. The time that takes grows in step with a
command's length, whatever it holds. What a command does to its paths is read from its first
``COMMAND_READ_CHARS`` characters, and a result's refusal lines are read up to ``REFUSAL_READ_CHARS``. The paths
a call names itself are the first ``ASKED_PATHS`` in the first ``ASKED_READ_CHARS`` characters of its arguments.
"""
import asyncio
import json
import os
import time
from pathlib import Path

from openshell import sandbox_hook as H
from openshell.launcher import activity as A
from openshell.launcher import cards as C
from openshell.launcher import layout as L
from openshell.launcher import refusals as R
from openshell.launcher import verdicts as V
from test_activity import T0, call, make_db, work_profile  # noqa: F401
from test_cards import _answer, _cards, _settle, _setup, _turn_end, _turn_start, channel, harness  # noqa: F401

NT = os.name == "nt"
ROOT = "C:/fixture" if NT else "/fixture"
# A folder outside the sandbox's folders and one inside them, as this OS spells them.
P, E = f"{ROOT}/Desktop", f"{ROOT}/work"
NOTE = f"{P}/note.txt"
FAILED_OR_NOT = (1, 0)  # The command's exit code: a refused program can be followed by one that ends well
READ_WITHIN = 5.0  # Seconds for one reading of a long call. Reading in step with its length takes a fraction.


def said(path: str, by: str = "cat", what: str = "Permission denied") -> str:
    """A refusal line that names the program and the path and says nothing of what was being done."""
    return f"{by}: {path}: {what}\n"


def terminal(command: str, output: str, exit_code: int = 1) -> tuple[str, dict, dict]:
    return "terminal", {"command": command}, {"output": output, "exit_code": exit_code, "error": None}


def code(source: str, output: str, status: str = "error") -> tuple[str, dict, dict]:
    return "execute_code", {"code": source}, {"status": status, "output": output, "tool_calls_made": 0}


def asked(name: str, args: dict, result: dict) -> list[tuple[str, str]]:
    """Each refused path with its access. The parsed result (the launcher's copy) and the result as core encodes it
    (the hook's) read the same."""
    found = R.refused_paths(name, args, result)
    assert R.refused_paths(name, args, json.dumps(result)) == found
    return [(path.as_posix(), access) for path, access, _ in found]


def marked(name: str, args: dict, result: dict) -> list[tuple[str, str, bool]]:
    """Each refused path with its access and whether that access is assumed."""
    return [(path.as_posix(), access, assumed) for path, access, _, assumed in R.refused_accesses(name, args, result)]


def relayed(monkeypatch, name: str, args: dict, result: dict, status: str) -> list[dict]:
    """The paths the in-sandbox hook asks the launcher for after one call (nothing answers here)."""
    sent = []
    monkeypatch.setattr(H, "_send", lambda request: sent.append(request) or None)
    assert H.resolve(name, args, json.dumps(result), session_id="chatA", status=status) is None
    return [item for request in sent for item in request.get("paths") or []]


# -- the reader ------------------------------------------------------------------------------------------------

def test_a_write_to_another_path_leaves_a_refused_read_a_read():
    """The refused file is read. The same command writes somewhere else, before or after, joined in any way."""
    commands = [f"cat {NOTE}",
                f"touch {E}/stamp.txt; cat {NOTE}",
                f"cat {NOTE}; touch {E}/stamp.txt",
                f"mkdir -p {E}/out\ncat {NOTE}",
                f"touch {E}/stamp.txt && cat {NOTE}",
                f"cat {NOTE} || touch {E}/stamp.txt",
                f"touch {E}/stamp.txt & cat {NOTE}",
                f"cat {NOTE} | tee {E}/copy.txt",
                f"cat {NOTE} > {E}/copy.txt",
                f"cat {NOTE} | grep x >> {E}/out.txt",
                f"cat {NOTE} 2>&1 | tee -a {E}/log.txt",
                f"sed -i s/a/b/ {E}/f.txt; cat {NOTE}",
                f"rm -f {E}/old.txt; cp {E}/a.txt {E}/b.txt; mv {E}/b.txt {E}/c.txt; cat {NOTE}",
                f"mkdir -p {P}; cat {NOTE}",  # Making or touching the folder leaves the files in it alone
                f"touch {P} && cat {NOTE}",
                f'cat {NOTE} | grep -c "a; rm b"']  # A separator inside quotes starts no new command
    for command in commands:
        for exit_code in FAILED_OR_NOT:
            assert asked(*terminal(command, said(NOTE), exit_code)) == [(NOTE, "read")], (command, exit_code)


def test_a_refused_write_asks_to_read_and_write():
    new = f"{P}/new.txt"
    # The refusal line says a write was refused, whatever ran it.
    for line in (f"touch: cannot touch '{new}': Permission denied\n",
                 f"touch: setting times of '{new}': Permission denied\n",
                 f"cp: cannot create regular file '{new}': Permission denied\n",
                 f"sh: 1: cannot create {new}: Permission denied\n",
                 said(new, by="touch"), said(new, by="tee")):
        assert asked(*terminal(f"bash {E}/job.sh", line)) == [(new, "read_write")], line
    # The command writes the path, and the refusal line names it and no more.
    for command, by in ((f"echo x > {new}", "bash"), (f"echo x >> {new}", "bash"), (f"cat {E}/a.txt >{new}", "bash"),
                        (f"echo x | tee -a {new}", "tee"), (f"cp {E}/a.txt {new}", "cp"),
                        (f"mv {new} {E}/", "mv"), (f"sed -i s/a/b/ {new}", "sed"), (f"touch {new}", "touch"),
                        (f"cat {E}/a.txt; rm {new}", "rm")):
        for exit_code in FAILED_OR_NOT:
            assert asked(*terminal(command, said(new, by=by), exit_code)) == [(new, "read_write")], (command, exit_code)


def test_a_copy_names_the_side_that_was_refused():
    """The source of a copy is read and its target written. A path the command names is refused only when a
    refusal line names it too: a file name shared with the refused path is not enough."""
    assert asked(*terminal(f"cp {NOTE} {E}/", f"cp: cannot open '{NOTE}' for reading: Permission denied\n")) \
        == [(NOTE, "read")]
    assert asked(*terminal(f"cp {NOTE} {E}/", said(NOTE, by="cp"))) == [(NOTE, "read")]
    assert asked(*terminal(f"cp {E}/a.txt {P}/", f"cp: cannot create regular file '{P}/a.txt': Permission denied\n")) \
        == [(f"{P}/a.txt", "read_write")]
    inner = f"{P}/src/a.txt"
    assert asked(*terminal(f"cp -r {E}/src {P}/", said(inner, by="cp"))) == [(inner, "read_write")]
    assert asked(*terminal(f"cp -t {P} {E}/a.txt", said(f"{P}/a.txt", by="cp"))) == [(f"{P}/a.txt", "read_write")]
    assert asked(*terminal(f"cp -r {P} {E}/", said(NOTE, by="cp"))) == [(NOTE, "read")]
    assert asked(*terminal(f"cat {E}/list.txt; rm -r {P}", said(NOTE, by="sh"))) == [(NOTE, "read_write")]
    assert asked(*terminal(f"D={P}; touch {E}/s; cat $D/note.txt", said(NOTE))) == [(NOTE, "read")]


def test_two_refused_paths_each_get_their_own_access():
    new = f"{P}2/new.txt"
    output = said(NOTE) + f"touch: cannot touch '{new}': Permission denied\n"
    for exit_code in FAILED_OR_NOT:
        assert asked(*terminal(f"cat {NOTE}; touch {new}", output, exit_code)) == [(NOTE, "read"), (new, "read_write")]
    gone = f"{E}/gone.txt"
    found = R.refused_paths(*terminal(f"cat {NOTE} {gone}", said(NOTE) + said(gone, what="No such file or directory")))
    assert [(path.as_posix(), missing) for path, _, missing in found] == [(NOTE, False), (gone, True)]


def test_a_path_with_a_space_and_the_windows_spellings_are_matched_to_the_command():
    spaced, copy = f"{P}/my note.txt", f"{P}/my copy.txt"
    assert asked(*terminal(f'touch "{E}/my stamp.txt"; cat "{spaced}"', said(spaced))) == [(spaced, "read")]
    assert asked(*terminal(f'cat "{E}/a b.txt" > "{copy}"', said(copy, by="bash"))) == [(copy, "read_write")]
    if NT:
        new = f"{P}/new.txt"
        for command, line, expected in (
                ("touch /c/fixture/work/s; cat /c/fixture/Desktop/note.txt",
                 "cat: C:\\fixture\\Desktop\\note.txt: Permission denied\n", (NOTE, "read")),
                ('touch "C:\\fixture\\work\\s"; cat "C:\\fixture\\Desktop\\note.txt"',
                 "cat: /c/fixture/Desktop/note.txt: Permission denied\n", (NOTE, "read")),
                ("cat /c/fixture/work/a.txt > /c/fixture/Desktop/new.txt",
                 "bash: c:/fixture/desktop/new.txt: Permission denied\n", (new, "read_write"))):
            found = asked(*terminal(command, line))
            assert [(os.path.normcase(path), access) for path, access in found] \
                == [(os.path.normcase(expected[0]), expected[1])], command


def test_many_paths_with_spaces_are_each_matched_to_their_own_line():
    """A folder with a space in its name holds 200 files the command names. Each refusal line prints its path
    without quotes, and each path comes out whole, one with three spaces in it too."""
    files = [f"{P}/my files/f{n}.txt" for n in range(200)] + [f"{P}/my files/old ones/a b.txt"]
    command = "cat " + " ".join(f'"{path}"' for path in files)
    assert asked(*terminal(command, "".join(said(path) for path in files))) == [(path, "read") for path in files]
    two = [files[150], files[-1]]  # A call that did not fail: the refused ones among the paths it named
    assert asked(*terminal(command, "".join(said(path) for path in two), 0)) == [(path, "read") for path in two]


def test_a_word_in_a_path_is_not_what_its_refusal_line_says():
    """A file or folder whose name holds a word a refused write is told by was read all the same."""
    for folder in ("mkdir-notes", "for writing"):
        path = f"{P}/{folder}/a.txt"
        for line in (said(path), said(f"'{path}'")):
            assert asked(*terminal(f'cat "{path}"', line)) == [(path, "read")], line


def test_where_nothing_shows_what_was_done_the_card_asks_to_read(monkeypatch):
    """A script, a variable and code do not show what they did to the refused path. It is asked for to read, and
    the request says the access is assumed, so the launcher can ask for more when reading was not the trouble. A
    path the line or the command shows as read carries no such mark, and neither does a call that did not fail."""
    python_line = f"PermissionError: [Errno 13] Permission denied: '{NOTE}'\n"
    note = {"path": str(Path(NOTE)), "access": "read", "missing": False}
    for call_ in (terminal(f"bash {E}/job.sh", said(NOTE)),
                  terminal(f"D={P}; touch {E}/s; cat $D/note.txt", said(NOTE)),
                  terminal(f"python {E}/tool.py {NOTE}", python_line),
                  code(f"print(open('{NOTE}').read())", python_line),
                  code(f"open('{NOTE}', 'w').write('x')", python_line),
                  code(f"open('{E}/stamp.txt', 'w').write('x')\nprint(open('{NOTE}').read())", python_line)):
        assert asked(*call_) == [(NOTE, "read")], call_[1]
        assert relayed(monkeypatch, *call_, "error") == [{**note, "assumed": True}], call_[1]
    for call_ in (terminal(f"touch {E}/stamp.txt; cat {NOTE}", said(NOTE)),
                  terminal(f"bash {E}/job.sh", f"cp: cannot open '{NOTE}' for reading: Permission denied\n"),
                  ("read_file", {"path": NOTE}, {"error": f"Permission denied: {NOTE}"})):
        assert relayed(monkeypatch, *call_, "error") == [note], call_[1]
    caught = code(f"try:\n    open('{NOTE}').read()\nexcept OSError as exc:\n    print(exc)\n"
                  f"open('{E}/stamp.txt', 'w').write('x')", f"[Errno 13] Permission denied: '{NOTE}'\n", "success")
    assert asked(*caught) == [(NOTE, "read")]
    assert relayed(monkeypatch, *caught, "ok") == [note]


def test_a_file_tool_asks_by_what_it_does_and_each_path_by_its_own_lines():
    assert asked("write_file", {"path": NOTE, "content": "x"}, {"error": f"Permission denied: {NOTE}"}) \
        == [(NOTE, "read_write")]
    assert asked("read_file", {"path": NOTE}, {"error": f"Permission denied: {NOTE}"}) == [(NOTE, "read")]
    # A tool that names two paths: the one that is absent stays absent beside one that was denied.
    gone = f"{E}/gone/copy.txt"
    found = R.refused_paths("plugin_tool", {"path": NOTE, "target": gone},
                            {"error": f"{NOTE}: Permission denied\n{gone}: No such file or directory"})
    assert [(path.as_posix(), access, missing) for path, access, missing in found] \
        == [(NOTE, "read", False), (gone, "read", True)]


def test_other_refusal_lines_do_not_hide_the_one_that_names_the_commands_path():
    """A command that did not fail is read for the lines that name its own paths, however many other lines that
    say "denied" its output holds first."""
    noise = "".join(f"sshd: user{n}: Permission denied (publickey)\n" for n in range(R.NAMED_REFUSAL_LINES + 6))
    assert asked(*terminal(f"cat {E}/auth.log; ls {P}; echo done", noise + said(P, by="ls"), 0)) == [(P, "read")]


# -- how much is read ------------------------------------------------------------------------------------------

def test_a_long_command_with_quotes_that_never_close_is_read_in_bounded_time():
    """A command can hold a file's worth of escaped quotes (a here-document that writes JSON). 200,000 characters
    of quotes that never close are read in the time their length takes, and the paths the command names at its
    start come out with their access."""
    new = f"{P}/new.txt"
    output = said(NOTE) + said(new, by="sh")
    for tail in ('\\"', '"a\\'):
        command = f"cat {NOTE}; touch {new}; " + tail * (200_000 // len(tail))
        began = time.perf_counter()
        found = R.refused_paths(*terminal(command, output))
        took = time.perf_counter() - began
        assert [(path.as_posix(), access) for path, access, _ in found] == [(NOTE, "read"), (new, "read_write")], tail
        assert took < READ_WITHIN, (tail, took)


def test_refusal_lines_are_read_up_to_a_bound_and_in_bounded_time():
    """A recursive listing can print thousands of refusals. The lines are read whole, in the order they were
    printed, while they fit in ``REFUSAL_READ_CHARS``: each of their paths comes out with its access, and the
    work does not multiply with the paths the command names. A line longer than the bound is not read."""
    folders = [f"{ROOT}/data/d{n}" for n in range(3000)]
    lines = [said(folder, by="ls") for folder in folders]
    fit = total = 0
    while total + len(lines[fit]) - 1 <= R.REFUSAL_READ_CHARS:  # A line counts without its line break
        total += len(lines[fit]) - 1
        fit += 1
    assert 100 < fit < len(folders)
    began = time.perf_counter()
    found = R.refused_paths(*terminal("ls " + " ".join(folders), "".join(lines)))
    took = time.perf_counter() - began
    assert [(path.as_posix(), access) for path, access, _ in found] == [(folder, "read") for folder in folders[:fit]]
    assert took < READ_WITHIN, took
    assert asked(*terminal(f"cat {NOTE}", "x" * R.REFUSAL_READ_CHARS + " " + said(NOTE))) == []
    assert asked(*terminal(f"cat {NOTE}", "x" * 1000 + " " + said(NOTE))) == [(NOTE, "read")]


def test_a_command_is_read_for_what_it_does_up_to_a_bound(monkeypatch):
    """What a command does to its paths is read from its first ``COMMAND_READ_CHARS`` characters. A write found
    there counts. A path the command names only beyond them is not shown, and neither is one that is only seen
    read within them, because the rest can write it: such a path is asked for to read, with the mark. The command
    the bound cuts in two is not read: its last word there is not its last word."""
    new = f"{P}/new.txt"
    quiet = said(new, by="sh")  # Names the path and says nothing of what was done to it
    pad = "echo word; " * (R.COMMAND_READ_CHARS // 11 + 1)
    assert len(pad) > R.COMMAND_READ_CHARS
    # A command the bound holds.
    assert marked(*terminal(f"cat {NOTE}; echo word", said(NOTE))) == [(NOTE, "read", False)]
    assert marked(*terminal(f"echo word; touch {new}", quiet)) == [(new, "read_write", False)]
    # A longer one.
    assert marked(*terminal(f"touch {new}; {pad}", quiet)) == [(new, "read_write", False)]
    assert marked(*terminal(f"{pad}touch {new}", quiet)) == [(new, "read", True)]
    assert marked(*terminal(f"cat {NOTE}; {pad}", said(NOTE))) == [(NOTE, "read", True)]
    assert marked(*terminal(f"cat {NOTE}; {pad}", said(NOTE), 0)) == [(NOTE, "read", False)]  # It did not fail
    copy = f"cp {E}/a.txt {new}"
    filled = ("echo word; " * ((R.COMMAND_READ_CHARS - len(copy)) // 11)).ljust(R.COMMAND_READ_CHARS - len(copy))
    assert marked(*terminal(f"{filled}{copy} {E}/dir/", quiet)) == [(new, "read", True)]
    items = relayed(monkeypatch, *terminal(f"{pad}touch {new}", quiet), "error")
    assert items == [{"path": str(Path(new)), "access": "read", "missing": False, "assumed": True}]


def test_what_follows_a_quote_that_never_closes_is_not_read_as_commands():
    """A quote that is never closed runs to the end of the command as one word (a here-document's text with an
    apostrophe in it). Nothing after it is read as a command. A write seen before it counts; a read seen before
    it is not shown, and the path is asked for to read, with the mark."""
    new = f"{P}/new.txt"
    for quote in ('"', "'"):
        rest = f"echo {quote}it is; rm {NOTE}; touch {NOTE}"
        assert marked(*terminal(f"cat {NOTE}; {rest}", said(NOTE))) == [(NOTE, "read", True)], quote
        assert marked(*terminal(f"touch {new}; {rest}", said(new, by="sh"))) == [(new, "read_write", False)], quote
    # A quote that closes holds its text and hides nothing after it, and an escaped quote opens none.
    assert marked(*terminal(f'cat {NOTE}; echo "it is; rm it"', said(NOTE))) == [(NOTE, "read", False)]
    assert marked(*terminal(f'cat {NOTE}; echo "it is"; rm {NOTE}', said(NOTE))) == [(NOTE, "read_write", False)]
    assert marked(*terminal(f'cat {NOTE}; echo \\"it is; rm {NOTE}', said(NOTE))) == [(NOTE, "read_write", False)]


def test_a_call_that_names_300000_paths_is_read_in_bounded_time():
    """A call's arguments can be megabytes of nothing but paths. The first of them are the call's own, and a
    refusal of the first comes out with its access in the time that part takes. A path the call names after its
    limits is not its own: a failed call's refusal of it is still read from the refusal line, and in a call that
    did not fail its line is text."""
    paths = [f"{ROOT}/data/d{n}" for n in range(300_000)]
    command = "ls " + " ".join(paths)
    first, last = paths[0], paths[-1]
    began = time.perf_counter()
    found = R.refused_paths(*terminal(command, said(first, by="ls")))
    took = time.perf_counter() - began
    assert [(path.as_posix(), access) for path, access, _ in found] == [(first, "read")]
    assert took < READ_WITHIN, took
    both = said(first, by="ls") + said(last, by="ls")
    assert marked(*terminal(command, both, 0)) == [(first, "read", False)]
    assert marked(*terminal(command, both, 1)) == [(first, "read", True), (last, "read", True)]


def test_arguments_as_long_as_the_largest_frame_are_read_in_bounded_time():
    """The sandboxed side can fill the launcher's largest frame with one command. Of one path written again and
    again to that length, the first characters are read, and its refusal comes out with its access."""
    command = (f"ls {NOTE} " * (C.MAX_MESSAGE // len(f"ls {NOTE} ") + 1))[:C.MAX_MESSAGE]
    began = time.perf_counter()
    found = R.refused_paths(*terminal(command, said(NOTE, by="ls")))
    took = time.perf_counter() - began
    assert [(path.as_posix(), access) for path, access, _ in found] == [(NOTE, "read")]
    assert took < READ_WITHIN, took


def test_a_calls_own_paths_are_its_first_ones_up_to_two_limits():
    """The paths a call names itself are collected from the first ``ASKED_READ_CHARS`` characters of its
    arguments, ``ASKED_PATHS`` different ones at most. A path named again counts once. A path beyond either limit
    is refused like a path only the output names: read from the line when the call failed, text when it did not.
    The word the first limit cuts in two is not taken for the shorter path it leaves."""
    folders = [f"{ROOT}/data/d{n}" for n in range(R.ASKED_PATHS + 1)]
    command = "ls " + " ".join([folders[0]] * 500 + folders)
    assert len(command) < R.ASKED_READ_CHARS
    three = [folders[0], folders[-2], folders[-1]]  # The first, the last within the limit, the one after it
    lines = "".join(said(folder, by="ls") for folder in three)
    assert asked(*terminal(command, lines, 0)) == [(folder, "read") for folder in three[:2]]
    assert asked(*terminal(command, lines, 1)) == [(folder, "read") for folder in three]
    pad = "echo word; " * (R.ASKED_READ_CHARS // 11 + 1)
    assert asked(*terminal(f"echo word; ls {P}", said(P, by="ls"), 0)) == [(P, "read")]
    assert asked(*terminal(f"{pad}ls {P}", said(P, by="ls"), 0)) == []
    assert asked(*terminal(f"{pad}ls {P}", said(P, by="ls"), 1)) == [(P, "read")]
    assert asked(*code(f"# {pad}\nprint(open('{NOTE}').read())", said(NOTE), "success")) == []
    cut = [f"{P}/n", f"{P}/no", f"{P}/not"]  # What the limit leaves of the path, give or take a character
    filled = "echo word; " * ((R.ASKED_READ_CHARS - len(f"ls {cut[1]}")) // 11)
    command = filled.ljust(R.ASKED_READ_CHARS - len(f"ls {cut[1]}")) + f"ls {NOTE}"
    assert asked(*terminal(command, "".join(said(path, by="ls") for path in cut), 0)) == []


def test_a_path_argument_longer_than_a_path_can_be_is_not_read_as_one():
    """A file tool names its path in an argument. A text longer than ``MAX_PATH_CHARS`` is no path: nothing is
    asked for it, and nothing walks it."""
    long = ROOT + "/a" * (R.MAX_PATH_CHARS // 2)
    assert len(long) > R.MAX_PATH_CHARS
    assert asked("read_file", {"path": long}, {"error": "Permission denied"}) == []
    short = ROOT + "/a" * 100
    assert asked("read_file", {"path": short}, {"error": "Permission denied"}) == [(short, "read")]


# -- the hook's relay ------------------------------------------------------------------------------------------

def test_a_path_the_hook_leaves_out_does_not_take_the_place_of_a_refused_one(monkeypatch, tmp_path):
    """ "No such file" in a folder the sandbox can list is a real miss, which the hook does not relay. Two of them
    in front of a refused path leave that path asked for."""
    seen = tmp_path / "seen"
    seen.mkdir()
    gone = [(seen / name).as_posix() for name in ("a.txt", "b.txt")]
    output = "".join(f"ls: cannot access '{path}': No such file or directory\n" for path in gone) \
        + f"ls: cannot open directory '{P}': Permission denied\n"
    items = relayed(monkeypatch, *terminal(f'ls "{gone[0]}" "{gone[1]}" "{P}"', output), "error")
    assert [(item["path"], item["access"]) for item in items] == [(str(Path(P)), "read")]


def test_the_hook_relays_as_many_refused_paths_as_the_launcher_reads(monkeypatch):
    folders = [f"{ROOT}/{name}" for name in ("a", "b", "c", "d", "e")]
    result = terminal("ls " + " ".join(folders), "".join(said(folder, by="ls") for folder in folders))
    items = relayed(monkeypatch, *result, "error")
    assert [item["path"] for item in items] == [str(Path(folder)) for folder in folders[:4]]
    request = V.parse_request("0-abcd", json.dumps({"kind": "access", "paths": items}).encode("utf-8"))
    assert [item["path"] for item in request["paths"]] == [item["path"] for item in items]  # The launcher reads all


# -- the launcher ----------------------------------------------------------------------------------------------

def _shown(harness, tmp_path) -> Path:
    """A folder the sandbox has to read only, with one file in it."""
    shown = tmp_path / "shown"
    shown.mkdir()
    (shown / "note.txt").write_text("x", encoding="utf-8")
    grants = harness["sup"]._grants
    harness["sup"]._grants = L.Grants(readonly=[shown], readwrite=list(grants.readwrite), denied=list(grants.denied))
    return shown


def _hook(name: str, args: dict, result: dict, status: str = "error"):
    """The hook on a worker thread, called the way core calls it."""
    return asyncio.ensure_future(asyncio.to_thread(
        H.on_tool_result, tool_name=name, args=args, result=json.dumps(result), session_id="chatA",
        tool_call_id="call_1", duration_ms=300, status=status))


async def _relay(cards, conn, hook, rounds: int = 200) -> None:
    """The launcher reads the hook's requests, as it does every REQUEST_POLL, until a card is up or the hook has
    returned."""
    for _ in range(rounds):
        for request in V.read_requests(cards._requests_dir):
            await cards.on_request(request)
        if _cards(conn) or hook.done():
            return
        await asyncio.sleep(0.02)


def _asks(conn) -> list[tuple[Path, str]]:
    return [(Path(card["params"]["path"]), card["params"]["access"]) for card in _cards(conn)]


def _complete(name: str, args: dict, result: dict) -> dict:
    """The desktop's relayed tool.complete for one call."""
    return {"jsonrpc": "2.0", "method": "event", "params": {"type": "tool.complete", "session_id": "live1", "payload": {
        "name": name, "args": args, "result": result}}}


def test_a_write_refused_where_the_sandbox_can_read_asks_to_read_and_write(harness, channel, tmp_path):  # noqa: F811
    """Code the agent runs writes into a folder the sandbox has to read only. The refusal names the file and says no
    more, and code does not show what it did there, so the path is asked for to read. The sandbox can read it
    already: what was refused was a write, the card asks to read and write, and the call is held on it."""
    sup, shown = harness["sup"], _shown(harness, tmp_path)
    note = (shown / "note.txt").as_posix()
    write = code(f"open('{note}', 'w').write('x')", f"PermissionError: [Errno 13] Permission denied: '{note}'\n")

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn, tool_name="execute_code")
        hook = _hook(*write)
        await _relay(cards, conn, hook)
        assert _asks(conn) == [(shown.resolve(), "read_write")]
        assert not hook.done()  # The call waits for the answer
        [card] = _cards(conn)
        await cards._from_client(conn, _answer(card, "once"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert "read & write access" in out["sandbox"] and H.STOP_NOW in out["sandbox"]
        await _turn_end(cards, conn)
        assert [r["folders"] for r in sup.restarts] == [[{"path": str(shown.resolve()), "access": "rw"}]]
        await cards.stop()

    asyncio.run(main())


def test_a_read_refused_where_the_sandbox_can_read_asks_for_nothing(harness, channel, tmp_path):  # noqa: F811
    """Only a path whose access is assumed is asked for with more. A command that shows it read the path, a call
    that did not fail, and a file the folder does not hold raise no card: the result returns as it came."""
    shown = _shown(harness, tmp_path)
    note, gone = (shown / "note.txt").as_posix(), (shown / "gone.txt").as_posix()
    python_line = f"PermissionError: [Errno 13] Permission denied: '{note}'\n"
    calls = [(*terminal(f'cat "{note}"', said(note)), "error"),
             (*code(f"try:\n    open('{note}', 'w')\nexcept OSError as exc:\n    print(exc)\n",
                    f"[Errno 13] Permission denied: '{note}'\n", "success"), "ok"),
             (*code(f"open('{gone}')", f"FileNotFoundError: [Errno 2] No such file or directory: '{gone}'\n"), "error")]

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        for name, args, result, status in calls:
            hook = _hook(name, args, result, status)
            await _relay(cards, conn, hook)
            assert _cards(conn) == [] and await asyncio.wait_for(hook, 10) is None, args
            await cards._from_sandbox(conn, _complete(name, args, result))
            await _settle()
            assert _cards(conn) == [], args
        # The launcher's own reading of the relayed tool.complete asks for more by the same rule.
        await cards._from_sandbox(conn, _complete(*code(f"open('{note}', 'w').write('x')", python_line)))
        await _settle()
        assert _asks(conn) == [(shown.resolve(), "read_write")]
        await cards.stop()

    asyncio.run(main())


def _host_reads(monkeypatch, folder: Path, verdict: bool) -> list[Path]:
    """Makes the host's answer to "can this user read the path" *verdict* for every path in *folder*. Returns
    the list of the paths it is asked about."""
    looked: list[Path] = []
    real = os.access

    def access(path, mode, *args, **kwargs):
        if mode != os.R_OK or folder not in (Path(path), *Path(path).parents):
            return real(path, mode, *args, **kwargs)
        looked.append(Path(path))
        return verdict

    monkeypatch.setattr(C.os, "access", access)
    return looked


def test_the_card_asks_for_more_when_the_host_can_read_the_path(harness, channel, tmp_path, monkeypatch):  # noqa: F811
    """The path is asked for with more only when the host's user can read it: the sandbox reads the folder, the
    host reads the path, so the refusal was of a write. For a file that does not exist yet the host is asked
    about the nearest folder above it that does."""
    shown = _shown(harness, tmp_path)
    looked = _host_reads(monkeypatch, shown, True)
    new = (shown / "out" / "new.txt").as_posix()
    write = code(f"open('{new}', 'w').write('x')", f"PermissionError: [Errno 13] Permission denied: '{new}'\n")

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn, tool_name="execute_code")
        hook = _hook(*write)
        await _relay(cards, conn, hook)
        assert _asks(conn) == [(shown.resolve(), "read_write")]
        assert looked == [shown]
        cards._stop_waiting("chatA")
        await asyncio.wait_for(hook, 10)
        await cards.stop()

    asyncio.run(main())


def test_no_card_asks_for_more_when_the_host_cannot_read_it(harness, channel, tmp_path, monkeypatch):  # noqa: F811
    """A script is refused a file in a folder the sandbox reads, and the host's user cannot read that file
    either (its owner closed it). More access to the folder would not help: no card, and the result returns as
    it came, on both of the launcher's routes."""
    shown = _shown(harness, tmp_path)
    looked = _host_reads(monkeypatch, shown, False)
    note = shown / "note.txt"
    refused = terminal(f"python {E}/job.py", f"PermissionError: [Errno 13] Permission denied: '{note.as_posix()}'\n")

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        hook = _hook(*refused)
        await _relay(cards, conn, hook)
        assert _cards(conn) == [] and await asyncio.wait_for(hook, 10) is None
        assert looked == [note]
        await cards._from_sandbox(conn, _complete(*refused))
        await _settle()
        assert _cards(conn) == [] and looked == [note, note]
        await cards.stop()

    asyncio.run(main())


def test_paths_the_sandbox_has_do_not_take_the_place_of_a_refused_one(harness, channel):  # noqa: F811
    """One command is refused three files. The first two lie in a folder the sandbox has, so no card is due for
    them; the third is outside its folders and gets the card."""
    work, outside = harness["work"], harness["outside"]
    paths = [(work / "a.txt").as_posix(), (work / "b.txt").as_posix(), (outside / "secret.txt").as_posix()]

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        command = "cat " + " ".join(f'"{path}"' for path in paths)
        hook = _hook(*terminal(command, "".join(said(path) for path in paths)))
        await _relay(cards, conn, hook)
        assert _asks(conn) == [(outside.resolve(), "read")]
        cards._stop_waiting("chatA")  # The user stops the turn: the held call returns
        await asyncio.wait_for(hook, 10)
        await cards.stop()

    asyncio.run(main())


def test_one_result_raises_two_folder_cards_at_most(harness, channel, tmp_path):  # noqa: F811
    folders = [tmp_path / name for name in ("one", "two", "three")]
    for folder in folders:
        folder.mkdir()

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        command = "ls " + " ".join(f'"{folder.as_posix()}"' for folder in folders)
        hook = _hook(*terminal(command, "".join(said(folder.as_posix(), by="ls") for folder in folders)))
        await _relay(cards, conn, hook)
        assert _asks(conn) == [(folder.resolve(), "read") for folder in folders[:2]]
        cards._stop_waiting("chatA")
        await asyncio.wait_for(hook, 10)
        await cards.stop()

    asyncio.run(main())


# -- the Activity log ------------------------------------------------------------------------------------------

def test_the_activity_log_lists_each_refused_file_with_its_own_access(work_profile):  # noqa: F811
    """A refused read beside a write to another path is listed as a read, and a refused copy lists the file that
    could not be written, not the one it was copied from."""
    read = terminal(f"touch {E}/stamp.txt; cat {NOTE}", said(NOTE))
    copy = terminal(f"cp {E}/a.txt {P}/", f"cp: cannot create regular file '{P}/a.txt': Permission denied\n")
    make_db(work_profile.home, [
        ("chat-a", "user", T0 + 10, "go", None, None, None),
        ("chat-a", "assistant", T0 + 11, "", None, None,
         json.dumps([call("c1", "terminal", read[1]), call("c2", "terminal", copy[1])])),
        ("chat-a", "tool", T0 + 12, json.dumps(read[2]), "c1", "terminal", None),
        ("chat-a", "tool", T0 + 13, json.dumps(copy[2]), "c2", "terminal", None),
    ])
    rows, _ = A.file_rows(work_profile.home, [(T0, T0 + 100)], None, None)
    assert [(row["outcome"], Path(row["path"]), row["access"]) for row in rows] \
        == [("denied", Path(NOTE), "read"), ("denied", Path(f"{P}/a.txt"), "write")]
