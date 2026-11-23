"""Keeps a test run from starting the user's browser or any other program of theirs.

Hermes's sign-in code opens the default browser itself (``webbrowser.open``), and ``os.startfile`` hands a file or an
address to whichever program the system has registered for it. A test often points HOME or USERPROFILE at a temporary
folder first, and a browser started from such a process runs against that folder instead of the user's own profile.

So these entry points are replaced for the whole run (``tests/conftest.py``): a call is recorded and stops the test
at once, and the test fails at its end as well when the code under test swallowed that stop. An audit hook refuses the
real openers too, so a test that puts the real function back still starts nothing. A test of a flow that opens a
browser replaces the entry point with its own recorder, as it would for any other outside effect.

A helper script that a test starts in a Python of its own calls ``install()`` first: the fixture does not reach it.
"""
from __future__ import annotations

import os
import sys
import urllib.parse

BROWSER_ENTRIES = ("open", "open_new", "open_new_tab", "get")
AUDITED = ("webbrowser.open", "os.startfile")


class StartedRealApp(BaseException):
    """A test reached the user's browser or another program of theirs. Not an ``Exception``: the sign-in code catches
    those around its own browser call, and the test has to stop either way."""


def target_of(args: tuple, kwargs: dict) -> str:
    """What was to be opened, without anything a sign-in address carries: the host of an address, the name of a file."""
    value = args[0] if args else next(iter(kwargs.values()), None)
    if value is None:
        return "no target"
    text = os.fsdecode(value) if isinstance(value, (bytes, os.PathLike)) else str(value)
    host = urllib.parse.urlsplit(text).hostname if "://" in text else None
    return f"host {host}" if host else f"name {os.path.basename(text.rstrip('/' + os.sep)) or text[:40]}"


class Guard:
    """The replaced entry points and the calls they took."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def refuse(self, name: str):
        def refused(*args, **kwargs):
            self.calls.append((name, target_of(args, kwargs)))
            raise StartedRealApp(f"{name} was called ({self.calls[-1][1]}): a test must not start the user's browser "
                                 "or another program; replace the entry point in the test if the flow needs one")

        refused.refuses_real_apps = True
        return refused

    def install(self, replace=setattr) -> "Guard":
        """Replace every entry point through *replace* (``setattr``, or a ``monkeypatch.setattr`` for one test)."""
        import webbrowser

        for entry in BROWSER_ENTRIES:
            replace(webbrowser, entry, self.refuse(f"webbrowser.{entry}"))
        if hasattr(os, "startfile"):  # Windows
            replace(os, "startfile", self.refuse("os.startfile"))
        return self

    def report(self) -> str:
        made = ", ".join(f"{name} ({target})" for name, target in self.calls)
        return f"the test called {made}: a test must not start the user's browser or another program"


PROCESS = Guard()
_hooked = False


def refuse_event(event: str, args: tuple) -> None:
    """The audit hook: the real openers announce themselves with these events before they start anything."""
    if event in AUDITED:
        raise StartedRealApp(f"{event} reached the real opener ({target_of(tuple(args), {})}): refused")


def refuse_real_openers() -> None:
    """Refuse the real openers themselves, whoever calls them and whatever a test put back. An audit hook cannot be
    removed, so it is added once for the process."""
    global _hooked
    if not _hooked:
        sys.addaudithook(refuse_event)
        _hooked = True


def hooked() -> bool:
    return _hooked


def install() -> Guard:
    """Replace the entry points for this whole process, and refuse the real openers."""
    refuse_real_openers()
    return PROCESS.install()
