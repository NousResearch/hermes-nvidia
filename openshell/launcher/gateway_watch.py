"""Whether a sandbox's gateway is still there.

The OpenShell drivers ask their gateway about the sandbox every couple of seconds (``exit_code``). A question
that gets no answer is one of two things. A gateway that is busy, or that its service manager is starting again,
answers by itself a moment later: Linux's service manager starts a gateway that died again after a few seconds,
and the sandbox's container is still there. A gateway whose process ended and that nothing starts again never
answers: on Windows nothing does before the next logon, and OpenShell ends every sandbox process with its gateway
(the gateway holds each in a job). And a gateway that came back by itself has ended the sandbox it had: the
sandbox then reads as exited, a moment after the gateway answered again.

The two are told apart here with one loopback connect and, for the gateway the plugin runs itself, one question
to the login service manager. Nothing is asked of the gateway and no OpenShell program is started for it.
``Supervisor.gateway_gone`` acts on the answer: the gateway and the sandbox are started again once, and a gateway
that is gone again within ``RETRY_WINDOW`` seconds leaves the sandbox ``failed`` with ``STOPPED`` as the reason.
"""
from __future__ import annotations

import contextlib
import json
import socket
import time
import urllib.parse
from typing import Callable, Optional

# What the status, the page and `hermes sandbox status` say once the gateway is gone and is not started again.
STOPPED = "The sandbox's gateway stopped. Turn the sandbox off, then on again."
# The page's header while the launcher starts the gateway and the sandbox again (the page adds the ellipsis).
RESTARTING = "Restarting the sandbox after its gateway stopped"
RETRY_WINDOW = 600.0  # seconds after a gateway was gone in which a gateway that is gone again is not started again
LOOKS = 2  # looks in a row that find nothing listening and the gateway's service not running: it is gone
GRACE = 30.0  # seconds a gateway may stay away while its service manager is starting it again
AFTERMATH = 60.0  # seconds after a gateway answered again in which a sandbox that ended has ended with it


def address(cfg) -> Optional[tuple]:
    """``(host, port)`` of the gateway *cfg* names, from its CLI registration; None when that cannot be read."""
    try:
        meta = json.loads((cfg.gateway_dir / "metadata.json").read_text(encoding="utf-8"))
        parts = urllib.parse.urlsplit(str(meta.get("gateway_endpoint") or ""))
        return (parts.hostname, int(parts.port or 443)) if parts.hostname else None
    except (OSError, ValueError, AttributeError, TypeError):
        return None


def registered(cfg) -> Optional[bool]:
    """Whether the gateway *cfg* names is registered with the CLI. False: it has no registration file. True:
    the file gives the gateway's address. None: the file is there and cannot be read, or gives no address, so
    nothing is known of the gateway."""
    try:
        with open(cfg.gateway_dir / "metadata.json", "rb"):
            pass
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return True if address(cfg) is not None else None


def listens(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _service_of(cfg) -> Optional[Callable[[], str]]:
    """The question to the login service manager, for the gateway the plugin runs itself; None for a gateway
    the profile's spec names (the plugin does not run that one)."""
    root = getattr(cfg, "managed_root", None)
    if root is None:
        return None

    def state() -> str:
        from .gateway_service import service_state

        return service_state(root)

    return state


class GatewayWatch:
    """What one driver knows about its gateway between two looks at its sandbox.

    The driver wraps its question to the gateway in ``ask()``. ``lost`` turns True when ``LOOKS`` questions in
    a row got no answer while nothing listened at the gateway's address and its login service was not running,
    or when nothing has listened there for ``GRACE`` seconds whatever the service manager says. Any answer, and
    any look that finds the address listening, starts the count anew. ``silent`` is True from the first such
    question on: the driver's stop then asks the gateway nothing. ``back()`` is True for ``AFTERMATH`` seconds
    after a gateway that had been away answered again. ``asking`` is True while a question is out: a second
    caller then takes the driver's last answer instead of asking too."""

    def __init__(self, cfg, *, service: Optional[Callable[[], str]] = None, probe: Optional[Callable] = None,
                 clock: Callable[[], float] = time.monotonic):
        self.cfg = cfg
        self._service = service if service is not None else _service_of(cfg)
        self._probe, self._clock = probe, clock
        self.asking = False
        self.lost = False
        self.silent = False
        self._looks = 0
        self._since: Optional[float] = None
        self._back: Optional[float] = None

    def down(self) -> Optional[str]:
        """One look. None: something listens at the gateway's address, or the address is not known.
        ``stopped``: nothing listens there and the gateway's login service is not running. ``starting``:
        nothing listens there, and the service manager says the service runs (it is starting the gateway) or
        cannot be asked."""
        if self._probe is not None:
            return self._probe()
        where = address(self.cfg)
        if where is None or listens(*where):
            return None
        if self._service is None:
            return "starting"
        try:
            return "starting" if self._service() == "running" else "stopped"
        except Exception:
            return "starting"

    def reset(self) -> None:
        """A sandbox starts: nothing is known of the gateway yet."""
        self.lost, self.silent, self._looks, self._since, self._back = False, False, 0, None, None

    def answered(self) -> None:
        """The gateway answered a question. When it had been away, the moment is kept (``back``)."""
        if self.silent:
            self._back = self._clock()
        self.lost, self.silent, self._looks, self._since = False, False, 0, None

    def back(self) -> bool:
        """True for ``AFTERMATH`` seconds after a gateway that had been away answered again."""
        return self._back is not None and self._clock() - self._back < AFTERMATH

    def unanswered(self) -> bool:
        """A question to the gateway got no answer: look why, and say whether the gateway is gone."""
        down = self.down()
        if down is None:  # it listens (again) and is not ready to answer: not gone
            self.lost, self._looks, self._since = False, 0, None
            return False
        now = self._clock()
        self.silent = True
        if self._since is None:
            self._since = now
        self._looks = self._looks + 1 if down == "stopped" else 0
        self.lost = self._looks >= LOOKS or now - self._since >= GRACE
        return self.lost

    @contextlib.contextmanager
    def ask(self):
        """Around one question to the gateway: an answer starts the count anew, an error is looked into."""
        self.asking = True
        try:
            try:
                yield
            except Exception:
                self.unanswered()
                raise
            self.answered()
        finally:
            self.asking = False
