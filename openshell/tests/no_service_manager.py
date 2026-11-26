"""Keeps a test run from reaching the computer's service manager.

The Sandbox switch registers a login service with the system's own service manager (``launcher/login_service.py``:
Task Scheduler through ``schtasks``, systemd through ``systemctl``, launchd through ``launchctl``), and the service's
bootstrap starts a hidden console helper (``cmd.exe /d /q /k``). Every manager takes a runner whose default is
``subprocess.run``, so a test that leaves the default in place asks, registers or removes services on the computer
that runs the tests.

So an audit hook refuses these programs for the whole run (``tests/conftest.py``), whoever is about to start them:
the call is recorded and stops the test at once, before any program runs, and the test fails at its end as well when
the code under test swallowed that stop. A test of a manager gives it a recording runner, and a test of the switch
gives it a manager of its own; neither starts a program, so neither is stopped.

The hook sees what this process starts. A program that a test runs in an interpreter of its own is outside it.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

PROGRAMS = ("schtasks", "systemctl", "loginctl", "launchctl")
CONSOLE_HELPER = ("cmd", ("/d", "/q", "/k"))  # the bootstrap's hidden console helper (login_service.BOOTSTRAP)
STARTS = frozenset({"subprocess.Popen", "os.posix_spawn", "os.exec", "os.spawn", "os.system"})
WORDS = 12  # words of a command that are looked at and quoted
READ = 4096  # characters of a command line that are split into words
SHOWN = 200  # characters of a command a message quotes
ADVICE = "give the test a runner or a manager of its own"


class ReachedServiceManager(BaseException):
    """A test reached the computer's service manager. Not an ``Exception``: the code that runs a manager catches
    those around its calls, and the test has to stop either way."""


def _text(value) -> str:
    return os.fsdecode(value) if isinstance(value, (bytes, os.PathLike)) else str(value)


def split(line) -> list:
    """The first words of a command line: split at blanks outside double quotes, in one pass."""
    out, word, quoted = [], [], False
    for char in _text(line)[:READ]:
        if char == '"':
            quoted = not quoted
        elif char.isspace() and not quoted:
            if word:
                out.append("".join(word))
                word = []
                if len(out) == WORDS:
                    return out
        else:
            word.append(char)
    return out + (["".join(word)] if word else [])


def command_of(event: str, args: tuple) -> list:
    """The command an audit event is about to start, as words with the program first. ``subprocess.Popen`` names
    it as a list, or on Windows as one command line; the ``os`` calls name a path and a list, ``os.system`` a line."""
    if event == "os.system":
        return split(args[0])
    path, argv = (args[1], args[2]) if event == "os.spawn" else (args[0], args[1])
    found = split(argv) if isinstance(argv, (str, bytes)) else [_text(word) for word in list(argv or [])[:WORDS]]
    return [_text(path), *found[1:]] if path else found


def service_manager_command(command: list) -> Optional[str]:
    """*command* as a message names it when it is the service manager's (or the console helper), else None."""
    if not command:
        return None
    name = os.path.basename(command[0].replace("\\", "/")).lower()
    name = name[:-4] if name.endswith(".exe") else name
    helper = name == CONSOLE_HELPER[0] and tuple(word.lower() for word in command[1:]) == CONSOLE_HELPER[1]
    return " ".join([name, *command[1:]])[:SHOWN] if name in PROGRAMS or helper else None


class Guard:
    """The calls one test made that were about to run the service manager."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def report(self) -> str:
        return f"the test reached the computer's service manager ({'; '.join(self.calls)}): {ADVICE}"


RUNNING: list[Guard] = []  # the guard of the test that runs now, when one does
_hooked = False


def refuse_event(event: str, args: tuple) -> None:
    """The audit hook: whatever starts a program announces it with one of these events first."""
    if event not in STARTS:
        return
    try:
        command = service_manager_command(command_of(event, tuple(args)))
    except (IndexError, TypeError, ValueError):  # a call of another shape is not a service manager's
        return
    if command is None:
        return
    for guard in RUNNING[-1:]:
        guard.calls.append(command)
    raise ReachedServiceManager(f"a test reached the computer's service manager: `{command}` was about to run; {ADVICE}")


def install() -> None:
    """Refuse the service manager's programs for this whole process. An audit hook cannot be removed, so it is
    added once."""
    global _hooked
    if not _hooked:
        sys.addaudithook(refuse_event)
        _hooked = True


def hooked() -> bool:
    return _hooked
