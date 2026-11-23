"""Sandbox drivers: the one seam between the launcher and the thing that enforces the sandbox.

``openshell_driver.OpenShellDriver`` runs the backend as an OpenShell sandbox through a private OpenShell
gateway (Docker on Linux); on Windows ``openshell_windows.OpenShellWindowsDriver`` does the same through
OpenShell's MXC driver. Both sit behind the same five lifecycle methods; the optional network-request,
revision and audit methods below are answered only by drivers whose enforcer has them
(``capabilities_info`` says which), and the host routes check before calling.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from .layout import Grants


class DriverUnavailable(RuntimeError):
    """The driver cannot enforce the sandbox on this host; the message says why."""


class NotSupported(RuntimeError):
    """This driver's enforcer has no such feature (network requests, revisions, audit events)."""


class ProposalChanged(RuntimeError):
    """The enforcer rechecked a network request since it was listed; review it again."""

    def __init__(self, message: str, proposal: dict | None = None):
        super().__init__(message)
        self.proposal = proposal


@dataclass
class LaunchRequest:
    sandbox_id: str
    argv: list[str]
    cwd: Path
    env: dict[str, str]
    grants: Grants
    network: dict
    log_path: Path
    config_dir: Path  # host-only; the driver may stage launch material there
    # Host-only facts a driver that does not run the host's interpreter needs. ``secrets`` is the
    # profile's .env: never part of ``env``; each driver decides how (or whether) values reach the
    # sandbox.
    profile: str = ""
    home: Path | None = None
    inner_port: int = 0
    inner_token: str = ""
    folders: list = field(default_factory=list)
    secrets: dict = field(default_factory=dict)
    # ``pins.route_pin``: the model entries as they were when the sandbox was switched on and the pairs the user
    # allowed since. A driver binds a key to an endpoint only against it (``openshell_driver.route_decisions``).
    pins: dict = field(default_factory=dict)
    # Sign-in files at the top of the home whose name holds a stand-in the sandbox writes at its start
    # (``standins.py``): the launcher took the real file out beforehand, and a driver neither hides nor holds
    # these names. ``step`` is what goes in front of the command a driver builds by itself: the interpreter,
    # the start-up step's path and ``--`` (``argv`` already carries it).
    standin: tuple = ()
    step: tuple = ()


class SandboxDriver(ABC):
    name: str
    # What the settings page may claim about this driver. ``credentials``: how keys reach the
    # sandbox ("environment": real values in its environment at start; "placeholders": the sandbox
    # sees stand-ins and the enforcer swaps them). ``host_loopback``: "open" when every host
    # loopback port is reachable from inside whatever the egress policy says. Optional keys, read
    # with .get() and these defaults: ``network_rules`` (["cidr"]; "host" when websites can be
    # named), ``network_live`` (False: network edits wait for a restart), ``network_live_interrupts``
    # (True: a live change drops open connections, a streaming model reply included), ``egress_allow_all``
    # (True: "all internet" exists), ``policy_revisions`` and ``audit_events`` (False).
    capabilities_info: dict = {"label": "", "requests_supported": False, "credentials": "environment",
                               "host_loopback": "unknown"}
    # Whether the sandbox runs the host's own interpreter and shell (the busybox pin applies).
    uses_host_shell: bool = True
    # Whether the network rules this driver last built hold the launcher's built-in usage data destination
    # (usage_data.py); None before it built any, or for a driver that adds none.
    usage_data_open: bool | None = None
    # Set by the launcher: a callable that is True while no chat turn runs (cards.py). A driver that replaces
    # credential values under a running sandbox asks it first.
    turns_idle = None
    # True for a driver whose ``exit_code`` asks a gateway: a call that can take seconds, so the supervisor's
    # watch makes it from a worker thread and the event loop keeps answering meanwhile.
    asks_gateway: bool = False

    @classmethod
    def capabilities(cls) -> dict:
        return {"driver": cls.name, **cls.capabilities_info}

    @classmethod
    def can(cls, feature: str) -> bool:
        return bool(cls.capabilities_info.get(feature, False))

    def backend_binaries(self) -> list[str]:
        """The executables the in-sandbox Hermes backend itself runs as (its resolved interpreter), as the
        proxy names them in drafts and denials; empty when the driver does not know. A draft from one of
        these is Hermes's own traffic or one of its in-process tools, never by itself a program the agent
        ran: the terminal's ``python`` is often the very same executable, so it cannot be told apart."""
        return [str(b) for b in (getattr(self, "_binaries", None) or ()) if b]

    @abstractmethod
    def preflight(self) -> dict:
        """Capability facts; raise DriverUnavailable when the host cannot enforce the policy."""

    def drop_leftover(self, profile: str) -> bool:
        """Delete a sandbox that still runs under *profile*'s name although no launcher owns it (its launcher
        was killed). True when there was one. A switch-on calls this after ``preflight`` and before it reviews,
        pins and records the profile's home: nothing may still write that home meanwhile. ``start`` replaces
        such a sandbox too, but only once the new launcher runs."""
        return False

    @abstractmethod
    def start(self, request: LaunchRequest) -> None:
        """Start the backend; returns once the sandbox process exists (not when it is ready)."""

    @abstractmethod
    def exit_code(self) -> int | None:
        """None while the sandbox runs; its exit code after it ends (or -1 if never started)."""

    def gateway_lost(self) -> bool:
        """True when the sandbox's state cannot be read because its gateway's process is gone (nothing listens
        at its address and nothing is starting it again), or because the gateway came back by itself and the
        sandbox ended with the one before: not a sandbox that exited on its own, and not a gateway that is busy
        for a moment. A driver without a gateway never says so."""
        return False

    @abstractmethod
    def stop(self, timeout: float = 20.0) -> None:
        """End the sandbox and everything in it. Idempotent."""

    @abstractmethod
    def policy(self) -> dict:
        """The policy as handed to the enforcer, secrets redacted (shown to the user verbatim)."""

    def endpoint_changed(self) -> list[dict]:
        """Keys withheld at the last start because a model entry names an endpoint the user did not set up:
        ``[{label, host, port, env}]``."""
        return []

    def guard(self) -> list:
        """Called about once a second while the sandbox runs. A driver that keeps credential files out of the
        sandbox's reach by where they are (``held.py``) checks that here and returns the names it had to put
        right; [] otherwise."""
        return []

    def sandbox_gone(self) -> bool:
        """After ``stop``: whether the sandbox is known to be gone (False when its removal failed)."""
        return True

    def launch_settled(self) -> None:
        """The backend is up: drop any launch material that carried secrets."""

    # -- optional: answered by drivers whose capabilities say so (blocking; call off the loop) ----
    def apply_network(self, network: dict) -> dict:
        """Apply *network* to the running sandbox without a restart (``network_live``). Returns at least
        ``loaded``: True once the enforcer runs the new rules, False when it had not confirmed them within
        the driver's bounded wait (submitted; they may still land, see ``loaded``)."""
        raise NotSupported(f"{self.name} applies network changes on restart only")

    def loaded(self, version: int) -> bool | None:
        """Whether policy revision *version* (from ``apply_network``) is in force: True, False (rejected),
        None (not yet)."""
        raise NotSupported(f"{self.name} keeps no policy revisions")

    def proposals(self, status: str = "pending") -> list[dict]:
        """Network requests the enforcer blocked and drafted rules for (``requests_supported``)."""
        raise NotSupported(f"{self.name} reports no network requests")

    def approve(self, proposal_id: str) -> dict:
        raise NotSupported(f"{self.name} reports no network requests")

    def reject(self, proposal_id: str, reason: str) -> dict:
        raise NotSupported(f"{self.name} reports no network requests")

    def revisions(self) -> dict:
        """The enforcer's policy history (``policy_revisions``)."""
        raise NotSupported(f"{self.name} keeps no policy revisions")

    def revision(self, version: int) -> dict:
        raise NotSupported(f"{self.name} keeps no policy revisions")

    def rollback(self, version: int) -> dict:
        raise NotSupported(f"{self.name} keeps no policy revisions")

    def events(self, *, since: float | None = None, until: float | None = None, limit: int = 200,
               classes: tuple[str, ...] = ()) -> list[dict]:
        """Recent audit events from the enforcer (``audit_events``)."""
        raise NotSupported(f"{self.name} reports no audit events")

    def current_network(self) -> dict | None:
        """The network the running sandbox enforces, in spec form, when it can differ from what
        the launcher last applied (approvals, rollbacks); None otherwise."""
        return None
