"""Runs one profile's sandbox: the driver, the proxy in front of it, and the host-only state file."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from . import categories, handback
from . import pins as key_pins
from . import provider_rows, settings_view, standins
from . import usage_data
from .driver import LaunchRequest, SandboxDriver
from .layout import (ProfileLayout, Runtime, box_dirs, fresh_install_state_dir, fresh_shared_sign_in_dir, hide_note,
                     listed_names, new_private_entries, profile_grants)
from .managed import write_managed_scope
from .proxy import Upstream
from .settings_view import saved_policy
from .spec import checked_folders, free_loopback_port, network_policy

log = logging.getLogger("openshell.supervisor")

READY_TIMEOUT = 180.0
# The driver's every-second check of the credential files it keeps from the sandbox (``SandboxDriver.guard``):
# this many repairs within the window stop the sandbox. One repair is a program on this computer that replaced a
# file by rename; a sandbox that keeps putting something under such a name gets no fourth try.
GUARD_LIMIT, GUARD_WINDOW = 3, 60.0
WATCH_INTERVAL = 0.25  # seconds between two looks of ``Supervisor.watch`` (the sandbox's exit, the guard)
PRIVATE_LOOK = 1.0  # seconds between two looks at the top of the profile folder for a new credential-named entry
PRIVATE_LIMIT = 3  # restarts for such entries within GUARD_WINDOW seconds; one more stops the sandbox
RUN_ELSEWHERE_DIRNAME = "profiles_run_elsewhere"  # hermes_cli.profiles_run_elsewhere.RUN_ELSEWHERE_DIRNAME
_PASSTHROUGH_ENV = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SystemDrive", "NUMBER_OF_PROCESSORS",
                    "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "OS")


class SandboxStartError(RuntimeError):
    pass


class Supervisor:
    def __init__(self, layout: ProfileLayout, runtime: Runtime, spec: dict, driver: SandboxDriver, outer_port: int):
        self.layout, self.runtime, self.spec, self.driver = layout, runtime, spec, driver
        self.outer_port = outer_port
        self.state = "stopped"
        self.keys_changed = False  # a credential write since the sandbox started
        # A sign-in the running sandbox started without has a value that lasts again, as of the sign-in engine's
        # last look (``SignIns.returned``): the page asks for the restart that hands it in, while that holds.
        self._sign_ins_back = False
        self.applied: Optional[dict] = None  # the folders and network the running sandbox got
        self._inner_port: Optional[int] = None
        self._inner_token: Optional[str] = None  # memory only: handed to the sandbox, never persisted
        self._started_at: Optional[float] = None
        self._last_error: Optional[str] = None
        self._grants = None
        self._lock = asyncio.Lock()
        # Card grants answered Allow (cards.py; until the sandbox is switched off): part of every launch, never saved,
        # never pending. {"folders": [{"path", "access": ro|rw}], "approved": {rule name: OpenShell rule}}
        self.temporary: dict = {"folders": [], "approved": {}}
        self._saved_network: Optional[dict] = None
        self.switching_off = False  # the switch is turning off: the launcher stops and exits for good
        self._gateway_gone_at: Optional[float] = None  # when the gateway was last found gone (``gateway_gone``)
        self._watching = False  # ``watch`` runs: it looks at the sandbox, off this loop where that takes time
        # Why the sandbox is restarting, while it does (cards.py passes it for folder grants and removals):
        # {"why": "folders", "reason": "folder" | "remove", "folder": path, "add": [paths], "remove": [paths],
        #  "label": "Restarting the sandbox to add outside", "since": t}
        self.restart_note: Optional[dict] = None
        # True while the launcher has a restart of its own to make (a removal that waits for the turn to end):
        # the page then asks the user for none. The cards set it (cards.py ``restart_queued``).
        self.restart_queued = lambda: False
        self._opened_for: dict = {}  # (host, port) -> what the page last said the address is for
        # Called (sync or async) when the backend is about to go down on purpose or has exited: "restarting",
        # "stopping" or "exited", with the state already set. The launcher closes relayed chat sockets here
        # (close code 1012) so the desktop asks the status route at once instead of waiting on a dead socket.
        self.on_down: list[Callable[[str], object]] = []
        self._down_tasks: set = set()
        self._in_restart = False  # a restart runs: its start phase still reports "restarting" (one state)
        self._pinned = True  # False: this sandbox was switched on without a pin (pins.py)
        self._endpoints_allowed: list[tuple] = []  # pairs allowed since the last start (registered at the next)
        self._guard_repairs: list[float] = []  # when the driver's guard had to put a credential name right
        # The names at the top of the home that the current start listed to hide (``layout.listed_names``); None
        # before a start listed the home. ``hide_new_private`` restarts the sandbox for a name that is not here.
        self._listed_private: Optional[frozenset] = None
        self._private_looked = float("-inf")  # never: the first look is due at once
        self._private_restarts: list[float] = []
        # Called (async) with the new names instead of a plain restart: the cards' restart pauses the replies
        # in flight and continues them afterwards (cards.py ``hide_new``; set by the launcher).
        self.on_private: Optional[Callable[[list], object]] = None
        # The profile's sign-ins, kept current on this computer while the sandbox is on (signins.py). The engine
        # is made at the first start that finds a pin and a driver that takes credentials; it then lives as long
        # as the launcher, in a thread of its own (a renewal waits on the network).
        self.signins = None
        self._declared: Optional[list] = None  # what the engine handed to the driver; None before it was asked
        self._standin: standins.Plan = standins.Plan()  # the stand-in sign-in store of the current start
        self._signin_thread: Optional[threading.Thread] = None
        self._signin_stop = threading.Event()
        self._signin_rows: list = []  # the engine's rows as its thread last published them
        self._key_rows: list = []  # the key rows of the current start, as the driver's discovery found them
        self._secret_names: set = set()  # the names of the profile's keys at the current start (no values)
        self._route_rows: list = []  # the sign-in report of the current start: what each model route uses
        # Called from the engine's thread with each note for the user (a sign-in that expired for good, a
        # token that could not be renewed in time). The launcher puts it into the chat (launcher_cli).
        self.on_signin_note: Optional[Callable[[str], object]] = None

    # -- proxy callbacks -----------------------------------------------------------------------
    def upstream(self) -> Optional[Upstream]:
        if self.state != "running" or self._exit_code() is not None:
            return None
        return Upstream("127.0.0.1", self._inner_port, self._inner_token)

    def reported_state(self) -> str:
        """The state the status routes report: a restart says ``restarting`` until the backend is back,
        including while the new sandbox starts, so the desktop shows one planned state, not two."""
        return "restarting" if self._in_restart and self.state == "starting" else self.state

    def unavailable(self) -> dict:
        out = {"state": self.reported_state(), "error": self._last_error}
        if self.restarting_view():
            out["restarting"] = self.restarting_view()
            out["restart"] = self.restart_view()
        return out

    def restarting_view(self) -> Optional[dict]:
        """Why the sandbox is down while a card's folder grant or a grant removal restarts it, else None. The
        one source for both the plugin status (``restarting``, ``restart``) and the held ``/api/status``
        (``openshell_sandbox``)."""
        if self.restart_note and self.state in ("restarting", "starting"):
            return {"state": "restarting", "reason": None, "folder": None, **self.restart_note}
        return None

    def restart_view(self) -> Optional[dict]:
        """The desktop's planned-restart field: ``{"reason": "folder" | "remove",
        "folder": path}`` while such a restart runs, else None."""
        view = self.restarting_view()
        if view is None or view.get("reason") not in ("folder", "remove"):
            return None
        return {"reason": view["reason"], "folder": view.get("folder")}

    def status_on_hold(self) -> bool:
        """The sandbox is down on purpose (a restart, a stop, the switch turning off), not failed: the
        proxy keeps answering the desktop's status probe from the last good answer meanwhile."""
        return self.switching_off or self.state in ("starting", "restarting", "stopping")

    def owns_profile(self, name: str) -> bool:
        from hermes_cli.profiles import normalize_profile_name

        value = (name or "").strip()
        if not value or value.lower() == "current":
            return True
        try:
            return normalize_profile_name(value) == self.layout.name
        except ValueError:
            return False

    # -- lifecycle -----------------------------------------------------------------------------
    def _launch_request(self, profile_secrets: Optional[dict] = None,
                        plan: Optional[standins.Plan] = None) -> tuple[LaunchRequest, list[dict]]:
        folders = checked_folders(self.spec, self.layout)
        self._saved_network = network = network_policy(self.spec)
        launched, network = _with_temporary(folders, network, self.temporary, self.layout)
        self._grants = profile_grants(self.layout, self.runtime, launched)
        self._listed_private = listed_names(self.layout.home, self._grants.denied)
        plan = plan if plan is not None else standins.Plan()
        if plan.names:
            # A sign-in file the sandbox writes a stand-in for: exactly its name leaves the hidden files (the
            # real file is in the launcher's copy by now, ``pins.vacate``). Every other credential file stays
            # hidden as it is.
            stand_ins = {os.path.normcase(str(self.layout.home / name)) for name in plan.names}
            self._grants.denied = [p for p in self._grants.denied if os.path.normcase(str(p)) not in stand_ins]
        # Core's run-elsewhere markers: the sandbox must never clear (or forge) its own. Created so the
        # deny names a real folder; a backend that cannot list it knows it is the one running elsewhere.
        marker_dir = self.layout.root / RUN_ELSEWHERE_DIRNAME
        marker_dir.mkdir(parents=True, exist_ok=True)
        self._grants.denied.append(marker_dir)
        box = box_dirs(self.layout)
        try:
            # The Nous Portal sign-in that every profile of this computer shares lives below the Hermes root, which
            # no sandbox may open. The sandbox gets a folder of its own for it, empty at every start, so Hermes
            # inside says that it is not signed in instead of failing on a folder it cannot open.
            shared_sign_in = fresh_shared_sign_in_dir(self.layout)
        except OSError as exc:
            raise SandboxStartError("the sandbox's sign-in folder of its own could not be emptied "
                                    f"({exc.strerror or exc}: {exc.filename})") from exc
        self._grants.readwrite.append(shared_sign_in)
        install_state = None
        if self.driver.uses_host_shell:
            # The host's own interpreter runs inside, so the install's state folder is an ancestor of the
            # environment the sandbox reads: Hermes inside sees it, can neither read nor lock it, and ends at
            # start. It is named a folder of its own, empty at every start (a driver that builds the sandbox's
            # file system itself puts an empty folder over the state there).
            try:
                install_state = fresh_install_state_dir(self.layout)
            except OSError as exc:
                raise SandboxStartError("the sandbox's install-state folder of its own could not be emptied "
                                        f"({exc.strerror or exc}: {exc.filename})") from exc
            self._grants.readwrite.append(install_state)
        self._inner_port, self._inner_token = free_loopback_port(), secrets.token_urlsafe(32)
        # The profile's keys travel beside the environment, never in it: the driver decides how
        # they reach the sandbox (OpenShell: providers, placeholders inside). Keys and the endpoints they may be
        # used at come from the pins taken when the sandbox was switched on, never from the home as it is now.
        if profile_secrets is None:
            profile_secrets = _profile_secrets(self.layout)
        route_pin = self._route_pin()
        self._pinned = bool(route_pin["present"])
        env = {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}
        system_root = env.get("SYSTEMROOT", r"C:\Windows")
        env.update({
            "PATH": os.pathsep.join([str(self.runtime.python.parent), os.path.join(system_root, "System32"), system_root]),
            "LOCALAPPDATA": str(box["localappdata"]), "APPDATA": str(box["appdata"]),
            "USERPROFILE": str(box["userprofile"]), "HOME": str(box["userprofile"]),
            "TEMP": str(box["tmp"]), "TMP": str(box["tmp"]),
            "HERMES_HOME": str(self.layout.home),
            "HERMES_SHARED_AUTH_DIR": str(shared_sign_in),
            "HERMES_DASHBOARD_SESSION_TOKEN": self._inner_token,
            # Installed launchers put the source tree first on sys.path; PM finds its store here.
            "PYTHONPATH": str(self.runtime.code_dir),
            "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1",
            # Nothing installs from inside: no network, read-only code. Skips the boot-time source
            # update tail, which would take the install's write locks.
            "HERMES_DISABLE_LAZY_INSTALLS": "1",
        })
        if self.runtime.store is not None:
            env["HERMES_RUNTIME_DIR"] = str(self.runtime.store)
        if install_state is not None:
            env["HERMES_INSTALL_STATE_DIR"] = str(install_state)
        # The card hook inside (sandbox_hook.py): it relays refusals into the box's requests folder
        # (read & write, a box dir) and waits for verdicts the launcher writes into a folder the
        # sandbox may read but never write.
        from ..sandbox_hook import DEFAULT_WAIT, HOOK_TIMEOUT_PIN, REQUESTS_ENV, VERDICTS_ENV, WAIT_ENV

        verdicts = self.layout.state_dir / "verdicts"
        verdicts.mkdir(parents=True, exist_ok=True)
        self._grants.readonly.append(verdicts)
        env.update({VERDICTS_ENV: str(verdicts), REQUESTS_ENV: str(box["requests"]),
                    WAIT_ENV: str(int(DEFAULT_WAIT))})
        busybox = self._busybox() if self.driver.uses_host_shell else None
        # Managed scope, on every driver: the hook timeout is raised so the card hook's wait fits under it (a
        # callback that outlives core's default 30 s is abandoned and suppressed, and the agent never learns the
        # answer); the busybox pin below; the driver may add the model's sandbox-side URL (host loopback).
        pins: dict = {"plugins": {"hook_callback_timeout": self._hook_timeout(HOOK_TIMEOUT_PIN)}}
        if busybox is not None:
            # Git Bash cannot start in the container; the plugin's busybox backend is the shell there.
            from ..busybox_env import BACKEND_NAME, BUSYBOX_ENV

            self._grants.readonly.append(busybox)
            env.update({BUSYBOX_ENV: str(busybox), "TERMINAL_ENV": BACKEND_NAME})
            # TERMINAL_ENV loses to a backend named in the profile's config.yaml; managed scope wins.
            pins["terminal"] = {"backend": BACKEND_NAME}
        managed = write_managed_scope(self.layout.state_dir / "managed", pins)
        self._grants.readonly.append(managed)
        env["HERMES_MANAGED_DIR"] = str(managed)
        if plan.folder is not None:
            # The stand-in sign-in store's template and the step that fills it: read-only inside, no secret.
            self._grants.readonly.append(plan.folder)
            env.update(standins.environment(plan))
        rw_folders = [f["path"] for f in launched if f["access"] == "rw"]
        # --isolated: a server scoped to this one profile. Without it a named profile's serve routes
        # to the machine-level server rooted at the default home, which the sandbox cannot reach.
        serve = [str(self.runtime.python), "-m", "hermes_cli.main", "serve", "--isolated", "--host", "127.0.0.1",
                 "--port", str(self._inner_port), "--skip-build"]
        # With a sign-in, the start-up step runs first, started by its path: it writes the stand-in sign-in
        # store and then runs the command (as the same process where the system allows it). Without one the
        # command is the one above, unchanged.
        argv = standins.command(plan, serve)
        request = LaunchRequest(
            sandbox_id=f"hermes-{self.layout.name}-{self._inner_port}", argv=argv,
            cwd=rw_folders[0] if rw_folders else box["userprofile"], env=env, grants=self._grants,
            network=network, log_path=self.layout.log_path, config_dir=self.layout.state_dir,
            profile=self.layout.name, home=self.layout.home, inner_port=self._inner_port,
            inner_token=self._inner_token, folders=launched, secrets=profile_secrets, pins=route_pin,
            standin=tuple(plan.names), step=tuple(argv[:len(argv) - len(serve)]))
        return request, folders

    async def start(self) -> None:
        async with self._lock:
            await self._start_locked()

    def _hook_timeout(self, minimum: int) -> int:
        """The profile's own ``plugins.hook_callback_timeout`` when it is longer, else *minimum*."""
        from .openshell_driver import _read_yaml

        try:
            own = float(((_read_yaml(self.layout.home / "config.yaml").get("plugins") or {})
                         .get("hook_callback_timeout")) or 0)
        except (TypeError, ValueError, AttributeError):
            own = 0
        return int(max(minimum, min(own, 600)))

    def _busybox(self) -> Optional[Path]:
        if self.spec.get("busybox"):
            path = Path(self.spec["busybox"])
            if not path.is_file():
                raise SandboxStartError(f"busybox not found at {path}")
            return path.resolve()
        from . import windows_programs
        from .driver import DriverUnavailable

        # The person's own copy (OPENSHELL_BUSYBOX), else the plugin's pinned one: installed when it is missing,
        # and compared with its pinned sha256 again at every sandbox start.
        try:
            found = windows_programs.use("busybox", self.spec, self.layout.root)["file"]
        except DriverUnavailable as exc:
            raise SandboxStartError(str(exc)) from exc
        if found is None:
            # Without busybox there is no backend pin, and a backend that can't read its withheld .env
            # refuses to start without one; fail here with the reason instead of a dead sandbox.
            raise SandboxStartError("busybox-w32 was not found. The sandbox runs terminal commands with it: "
                                    "set OPENSHELL_BUSYBOX to busybox64u.exe (busybox64a.exe on an Arm PC) or put it "
                                    "on PATH.")
        return Path(found).resolve()

    async def _start_locked(self) -> None:
        self.state, self._last_error, self.applied = "starting", None, None
        try:
            _rotate_log(self.layout.log_path)
            # Off the event loop: the user's own secret sources (a helper command, a vault) may take seconds,
            # and so may the first look at the profile's sign-ins (Hermes renews a token that is about to expire).
            profile_secrets = await asyncio.to_thread(_profile_secrets, self.layout)
            self._standin = await asyncio.to_thread(self._prepare_sign_ins, profile_secrets)
            request, folders = self._launch_request(profile_secrets, self._standin)
            await asyncio.to_thread(self.driver.start, request)
            await self._wait_ready()
            self._keep_sign_ins_current()
        except Exception as exc:
            self.state, self._last_error = "failed", str(exc)
            await asyncio.to_thread(self.driver.stop)
            raise
        finally:
            self.driver.launch_settled()
        self.state, self._started_at, self.keys_changed, self._sign_ins_back = "running", time.time(), False, False
        self._endpoints_allowed = []
        self.applied = {"folders": folders, "network": self._saved_network or request.network}

    async def _wait_ready(self) -> None:
        deadline = time.monotonic() + READY_TIMEOUT
        while time.monotonic() < deadline:
            code = self.driver.exit_code()
            if code is not None:
                raise SandboxStartError(f"sandbox exited with {code} before the backend was ready; "
                                        f"see {self.layout.log_path}\n{_log_tail(self.layout.log_path)}")
            if await _health(self._inner_port):
                return
            await asyncio.sleep(0.5)
        raise SandboxStartError(f"backend not ready after {READY_TIMEOUT:.0f}s; see {self.layout.log_path}")

    async def stop(self) -> None:
        async with self._lock:
            self.state = "stopping"
            await self._down("stopping")
            await self._stop_driver()
            self.state, self._inner_port, self._inner_token, self.applied = "stopped", None, None, None
            if self.switching_off:
                # Before the sign-in files go back into the profile: no renewal may start from here on.
                await asyncio.to_thread(self.close_sign_ins)

    # -- sign-ins ------------------------------------------------------------------------------
    def _prepare_sign_ins(self, profile_secrets: dict) -> standins.Plan:
        """Before a sandbox is created (blocking: called off the event loop). The first time: ask Hermes for the
        profile's sign-ins and hand each current token to the driver. Every later time: bring the driver's
        values up to date with the copy, so a sandbox that starts again starts with the current tokens. Every
        time: build the stand-in sign-in store from the copy as it is now, put it where the sandbox reads it,
        and take the real sign-in files it stands in for out of the home. A profile without a pin, a driver
        that takes no credentials, and a profile with no sign-in get no stand-in, and nothing about their start
        changes."""
        from . import signins

        self._secret_names = {name for name, value in (profile_secrets or {}).items() if value}
        routes, on_approval = self._discovered(profile_secrets)
        try:
            self._key_rows = settings_view.key_rows_of(routes, profile_secrets, facts=True,
                                                       on_approval=on_approval)[0]
        except Exception as exc:
            log.warning("profile %s: the key rows could not be made: %s", self.layout.name, exc)
            self._key_rows = []
        if not key_pins.present(self.layout) or not callable(getattr(self.driver, "declare", None)):
            self._route_rows = []
            return standins.write(self.layout, None)
        if self.signins is None:
            self.signins = signins.SignIns(key_pins.pin_dir(self.layout), self.driver, sleep=self._signin_stop.wait,
                                           on_change=lambda names: key_pins.follow_copy(self.layout),
                                           approved=self.approved_tools)
        if self._declared is None:
            try:
                self._declared = self.signins.declare()
            except Exception as exc:  # the sandbox starts without the sign-ins; their rows say so
                log.warning("profile %s: the sign-ins could not be handed to the sandbox: %s", self.layout.name, exc)
                self._declared = []
        else:
            # The sandbox starts again in this launcher (a folder grant restarts it, and so does a tool
            # category's approval): the sign-ins were declared once, and may have been renewed since. A sign-in
            # Hermes's tools use is declared again when the approved categories changed, so the sandbox that
            # starts now is bound to their hosts and to no others.
            try:
                changed = self.signins.rebind()
                if changed:
                    log.info("profile %s: sign-ins bound to other addresses from this start on: %s",
                             self.layout.name, ", ".join(changed))
            except Exception as exc:  # the sandbox starts bound as the one before it was
                log.warning("profile %s: the sign-ins could not be bound anew: %s", self.layout.name, exc)
            try:
                self.signins.catch_up()
            except Exception as exc:
                log.warning("profile %s: the sign-ins could not be brought up to date: %s", self.layout.name, exc)
        try:
            # A sign-in that has ended, or whose token ran out with nothing newer at hand, is not handed to
            # this sandbox: it starts without it, and that sign-in's row says why its model does not answer.
            left = self.signins.for_start()
            if left:
                log.warning("profile %s: the sandbox starts without the sign-ins that ended or ran out: %s",
                            self.layout.name, ", ".join(left))
        except Exception as exc:
            log.warning("profile %s: the sign-ins could not be settled for this start: %s", self.layout.name, exc)
        try:
            self._route_rows = signins.report(key_pins.pin_dir(self.layout), self.approved_tools())
        except Exception as exc:  # the rows then say less: no provider is marked as the model's
            log.warning("profile %s: the model routes could not be read: %s", self.layout.name, exc)
            self._route_rows = []
        self._publish_sign_ins()
        tokens = {str(r["env"]): "anthropic" for r in routes if r.get("token") and r.get("env")}
        template, names, left_out = standins.build(self.signins, tokens)
        plan = standins.write(self.layout, template, names, left_out)
        if left_out:
            log.info("profile %s: sign-in rows the sandbox does not get: %s", self.layout.name, ", ".join(left_out))
        key_pins.vacate(self.layout, plan.names)
        return plan

    def _discovered(self, profile_secrets: dict) -> tuple[list, list]:
        """The profile's keys and where each travels, as the driver's own discovery finds them at this start,
        and the keys of web services that wait for a tool category's approval. A route whose key is a sign-in
        token kept in the env file is marked ``token``: inside, such a variable gets a token-shaped alias of
        its placeholder."""
        try:
            from .openshell_driver import discover_routes

            found = discover_routes(self.layout.home, profile_secrets, self._route_pin())
            return list(found.routes), list(found.on_approval)
        except Exception as exc:
            log.warning("profile %s: the keys could not be listed: %s", self.layout.name, exc)
            return [], []

    # -- tool categories -------------------------------------------------------------------------
    def approved_tools(self) -> set:
        """The ids of the tool categories the user approved in a chat (categories.py): the saved ones and the
        ones that last until the sandbox is switched off."""
        try:
            saved = network_policy(self.spec).get("approved")
        except Exception:
            saved = None
        return categories.granted(saved, (self.temporary or {}).get("approved"))

    def _route_pin(self) -> dict:
        """The pin the driver's key discovery reads, with the approved tool categories."""
        return {**key_pins.route_pin(self.layout), "tools": sorted(self.approved_tools())}

    def tool_services(self, category_id: str) -> dict:
        """What an approval of a tool category opens for this profile. ``plain``: the hosts its tools use
        without a credential. ``bound``: the addresses a credential of the profile is bound to with it
        (``{host, port, label}``): the Nous tool gateway's for a sign-in to Nous Portal, a vendor's own for a
        key of that vendor."""
        category = categories.by_id(category_id)
        if category is None:
            return {"plain": [], "bound": []}
        bound = list(self.signins.tool_hosts(category.id)) if self.signins is not None else []
        from .openshell_driver import WEB_BACKENDS

        for env, uses in categories.KEY_CATEGORIES.items():
            if category.id in uses and env in self._secret_names and env in WEB_BACKENDS:
                label, host, port = WEB_BACKENDS[env][:3]
                bound.append({"host": host, "port": int(port), "label": label})
        taken = {(row["host"], row["port"]) for row in bound}
        return {"plain": [host for host in category.keyless if (host, 443) not in taken], "bound": bound}

    def bound_hosts(self) -> set:
        """``(host, port)`` of every address a credential is bound to in the sandbox that runs now."""
        registered = getattr(self.driver, "registered_providers", None)
        out: set = set()
        if self.applied is None or not callable(registered):
            return out
        for row in registered():
            for text in row.get("endpoints") or []:
                host, _, port = str(text).rpartition(":")
                if host and port.isdigit():
                    out.add((host.lower(), int(port)))
        return out

    def opened_hosts(self) -> list:
        """Every address a sign-in or a key keeps open in the sandbox that runs now, as the Sandbox page lists
        it among the allowed destinations: the host, its port and what it is for (the model, or the tool
        category whose approval opened it) with the provider's name."""
        registered = getattr(self.driver, "registered_providers", None)
        out: list = []
        if self.applied is None or not callable(registered):
            return out
        approved = self.approved_tools()
        for row in registered():
            label = str(row.get("label") or "").split(" (")[0]
            for text in row.get("endpoints") or []:
                host, _, port = str(text).rpartition(":")
                if not host or not port.isdigit():
                    continue
                use = categories.use_label(host, int(port), row.get("env"), approved,
                                           was=self._opened_for.get((host, int(port))))
                if use:
                    self._opened_for[(host, int(port))] = use
                use = use or "Model"
                shown = "localhost" if host in settings_view._THIS_COMPUTER else host
                entry = {"host": shown, "port": int(port),
                         "reason": f"{use} \u00b7 {label}" if label and label != use else use,
                         "rule": f"_provider_{row.get('name')}"}
                if entry not in out:
                    out.append(entry)
        return out

    def _keep_sign_ins_current(self) -> None:
        """Once the first sandbox is ready: the engine's schedule runs in one thread of its own for the life
        of the launcher (a renewal waits on the network; nothing of it runs on the event loop or on a worker
        thread borrowed for one call)."""
        if self.signins is None or self._signin_thread is not None \
                or not any(row.get("id") for row in self._signin_rows):
            return
        self._signin_thread = threading.Thread(target=self._sign_in_loop, name="sign-ins", daemon=True)
        self._signin_thread.start()

    def _sign_in_loop(self) -> None:
        engine = self.signins
        while not self._signin_stop.is_set():
            try:
                wait = engine.step()
            except Exception as exc:
                log.warning("profile %s: the sign-ins could not be looked at: %s", self.layout.name, exc)
                wait = 60.0
            self._publish_sign_ins()
            self._signin_stop.wait(wait)

    def _publish_sign_ins(self) -> None:
        """From the thread that just ran the engine: its rows for the status, its notes for the chat. The
        status then never waits on a renewal."""
        engine = self.signins
        if engine is None:
            return
        try:
            self._signin_rows = engine.status()
            notes = engine.notes()
        except Exception as exc:
            log.warning("profile %s: the state of the sign-ins could not be read: %s", self.layout.name, exc)
            return
        try:
            # A sign-in this sandbox started without was renewed and its value lasts: it is used after a restart,
            # which the page asks for as it does for a saved key (``pending``). Read anew at every look: a token
            # that did not last, or has run out again, asks for nothing.
            self._sign_ins_back = bool(engine.returned())
        except Exception:
            log.debug("the sign-ins renewed since the start could not be read", exc_info=True)
        for note in notes:
            log.warning("profile %s: %s", self.layout.name, note)
            if self.on_signin_note is not None:
                try:
                    self.on_signin_note(note)
                except Exception:
                    log.debug("a sign-in note could not be passed on", exc_info=True)

    def close_sign_ins(self) -> None:
        """Stop the schedule and wait for a renewal that is under way (blocking). The copy is then ready to go
        back into the profile."""
        self._signin_stop.set()
        engine, thread = self.signins, self._signin_thread
        if engine is not None:
            engine.close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=60.0)

    def sign_in_token_hosts(self) -> set:
        """Where the declared sign-ins are renewed: a request there from the backend inside is its own refresh
        attempt, never a website to ask the user about (cards.py)."""
        return standins.token_hosts(getattr(row, "provider", "") for row in self._declared or [])

    def provider_rows(self) -> list:
        """The profile's providers as the Sandbox page lists them (provider_rows.py): the sign-ins as their
        schedule stands, and, while a sandbox runs, the keys the driver registered for it."""
        registered = getattr(self.driver, "registered_providers", None)
        try:
            keys = self._key_rows if self.applied is not None else []
            if keys and callable(registered):
                handed = {env for row in registered() for env in row.get("envs") or [row.get("env")]}
                # (a web service's key that waits for its tool category's approval keeps its row: it says so)
                keys = [row for row in keys if row.get("env") in handed or row.get("reason") == "key_on_approval"]
            return provider_rows.live_rows(self.layout, self._signin_rows, keys, self.endpoint_changed(),
                                           self._route_rows)
        except Exception as exc:
            log.warning("profile %s: the provider rows could not be made: %s", self.layout.name, exc)
            return []

    async def restart(self, note: Optional[dict] = None) -> None:
        """Stop and start again. *note* says why (a card's folder grant or a removal); it is set together
        with the ``restarting`` state, before anything goes down, and cleared once the restart is over."""
        async with self._lock:
            self.restart_note = dict(note) if note else None
            self.state, self._in_restart = "restarting", True
            try:
                await self._down("restarting")
                await self._stop_driver()
                await self._start_locked()
            finally:
                self.restart_note, self._in_restart = None, False

    async def _down(self, why: str) -> None:
        """Tell ``on_down`` listeners (bounded: a listener never holds up a stop)."""
        waits = []
        for listener in list(self.on_down):
            try:
                result = listener(why)
            except Exception:
                log.debug("on_down listener failed", exc_info=True)
                continue
            if asyncio.iscoroutine(result) or isinstance(result, asyncio.Future):
                waits.append(asyncio.ensure_future(result))
        if waits:
            done, pending = await asyncio.wait(waits, timeout=2.0)
            for task in pending:  # finishes on its own; keep a reference until then
                self._down_tasks.add(task)
                task.add_done_callback(self._down_tasks.discard)

    def set_spec(self, spec: dict) -> None:
        """The saved spec changed on disk (settings page): the next start uses it."""
        self.spec = spec

    # -- live changes (drivers whose enforcer updates a running sandbox) -------------------------
    def running(self) -> bool:
        return self.state == "running" and self._exit_code() is None

    def _exit_code(self) -> Optional[int]:
        """The sandbox's exit code for callers on the event loop (a request the proxy forwards, the cards'
        loops). While ``watch`` does the looking for a driver that asks a gateway, this is what the driver last
        saw: no request waits for a look of its own."""
        last = getattr(self.driver, "last_exit_code", None)
        return last() if self._watching and callable(last) else self.driver.exit_code()

    async def apply_network(self, network: dict) -> dict:
        """Apply a saved network edit to the running sandbox now (``network_live`` drivers). Returns the
        driver's answer (``loaded``: whether the enforcer confirmed the new rules within its bounded wait);
        ``skipped`` when no sandbox runs (the next start carries the rules)."""
        async with self._lock:
            if not self.running():
                return {"loaded": False, "skipped": "not running"}
            result = await asyncio.to_thread(self.driver.apply_network, _with_temporary([], network, {
                "approved": self.temporary.get("approved")}, self.layout)[1])
            if self.applied is not None:
                self.applied = {**self.applied, "network": network}
            return result if isinstance(result, dict) else {"loaded": True}

    def adopt_network(self, spec: dict) -> None:
        """The enforcer changed the running sandbox's network itself (an approved request, a
        rollback) and the saved spec now matches it: both views move together, nothing pends.
        Card grants answered Allow (until the sandbox is switched off) are live but never saved: a spec adopted from the
        live policy has them taken out again."""
        temp = self.temporary.get("approved") or {}
        if temp:
            from .spec import update_spec

            saved = network_policy(spec)
            before = network_policy(self.spec).get("approved") or {}
            cleaned = dict(saved.get("approved") or {})
            for name, rule in temp.items():
                if name not in cleaned:
                    continue
                keep = [b for b in cleaned[name].get("binaries") or []
                        if b not in (rule.get("binaries") or []) or b in ((before.get(name) or {}).get("binaries") or [])]
                if keep:
                    cleaned[name] = {**cleaned[name], "binaries": keep}
                else:
                    cleaned.pop(name)
            if cleaned != (saved.get("approved") or {}):
                net = {k: v for k, v in saved.items() if k != "approved"}
                spec = update_spec(self.layout, network={**net, **({"approved": cleaned} if cleaned else {})})
        self.spec = spec
        if self.applied is not None:
            self.applied = {**self.applied, "network": saved_policy(spec)["network"]}

    async def _stop_driver(self) -> None:
        """Stop the sandbox and wait until its backend stops answering: the container can outlive the
        stop call for a moment, and a restart must not race the old backend for the log or the home."""
        await asyncio.to_thread(self.driver.stop)
        deadline = time.monotonic() + 15.0
        while self._inner_port and time.monotonic() < deadline and await _health(self._inner_port):
            await asyncio.sleep(0.5)

    async def _look(self) -> Optional[int]:
        """``watch``'s look at the sandbox. A driver that asks a gateway is asked from a worker thread: the
        answer takes seconds when the gateway's process is gone, and the status route, the switch and the chat
        sockets are answered on this loop meanwhile."""
        if not getattr(self.driver, "asks_gateway", False):
            return self.driver.exit_code()
        try:
            return await asyncio.to_thread(self.driver.exit_code)
        except Exception:
            log.debug("the look at the sandbox failed", exc_info=True)
            return None

    async def gateway_gone(self) -> bool:
        """One step of ``watch``: True when the running sandbox's gateway is gone (``SandboxDriver.gateway_lost``)
        and this dealt with it. The sandbox cannot be reached without its gateway and ends with it (on Linux
        when the service manager has started the gateway again), so a reply in flight ends as it does when the
        sandbox ends on its own: the state says ``exited``
        with the reason and the chat sockets are closed (``on_down``). Then, once, the sandbox is started again
        the way a restart does it; the driver's start brings the gateway back first, by the path a switch-on
        uses. A gateway that is gone again within ``gateway_watch.RETRY_WINDOW`` seconds, or a start that
        fails, leaves the sandbox stopped and ``failed`` with one sentence (``gateway_watch.STOPPED``): nothing
        is started in a loop, and the status goes on answering. Turning the switch off and on starts anew."""
        if self.state != "running" or self._lock.locked() or not self.driver.gateway_lost():
            return False
        from . import gateway_watch

        now = time.monotonic()
        again = self._gateway_gone_at is not None and now - self._gateway_gone_at < gateway_watch.RETRY_WINDOW
        self._gateway_gone_at = now
        self.state, self._last_error = "exited", gateway_watch.STOPPED
        log.warning("profile %s: the sandbox's gateway is gone%s", self.layout.name,
                    " again: it is not started a second time" if again else ": starting it and the sandbox again")
        await self._down("exited")
        try:
            if not again:
                await self.restart({"why": "gateway", "label": gateway_watch.RESTARTING, "since": time.time()})
                return True
            await self.stop()  # the forward ends; a gateway that is not listening is asked nothing
        except Exception as exc:
            log.error("profile %s: the sandbox did not start again after its gateway stopped: %s",
                      self.layout.name, exc)
        self.state, self._last_error = "failed", gateway_watch.STOPPED
        return True

    async def watch(self) -> None:
        """Notice a sandbox that ends on its own; the proxy then answers 503 with the reason, and relayed
        chat sockets are closed (``on_down``). Notice a gateway that is gone too (``gateway_gone``)."""
        self._watching = bool(getattr(self.driver, "asks_gateway", False))
        while True:
            await asyncio.sleep(WATCH_INTERVAL)
            code = await self._look()
            if await self.gateway_gone():
                continue
            if self.state == "running" and code is not None:
                self.state, self._last_error = "exited", f"sandbox exited with {code}"
                log.warning("sandbox for profile %s exited with %s", self.layout.name, code)
                await self._down("exited")
            elif self.state == "running" and not self._lock.locked():
                await self.guard()
                await self.hide_new_private()

    async def guard(self) -> list:
        """One look at the credential files the driver keeps from the running sandbox (``SandboxDriver.guard``).
        A name it had to put right is logged; ``GUARD_LIMIT`` of them within ``GUARD_WINDOW`` seconds stop the
        sandbox with the reason as its error (the switch stays on: turning it off and on starts it again).
        A driver without a guard of its own (the base class's does nothing) is not asked: no worker thread is
        woken for it several times a second."""
        if getattr(type(self.driver), "guard", None) is SandboxDriver.guard:
            return []
        try:
            repaired = await asyncio.to_thread(self.driver.guard)
        except Exception:
            log.debug("the driver's guard failed", exc_info=True)
            return []
        if not repaired:
            return []
        names = ", ".join(sorted(set(repaired)))
        log.warning("profile %s: %s was replaced in the home while the sandbox ran; what stood there is in the "
                    "quarantine folder and the file kept from the sandbox is in place", self.layout.name, names)
        now = time.monotonic()
        self._guard_repairs = [t for t in self._guard_repairs if now - t < GUARD_WINDOW] + [now]
        if len(self._guard_repairs) >= GUARD_LIMIT and self.state == "running":
            self._guard_repairs = []
            await self.stop()
            self.state, self._last_error = "failed", (
                f"The sandbox was stopped: a credential file ({names}) kept being replaced while it ran. "
                "Turn the sandbox off, then on again.")
            log.error("profile %s: %s", self.layout.name, self._last_error)
        return list(repaired)

    async def hide_new_private(self) -> list:
        """One look, at most every ``PRIVATE_LOOK`` seconds, at the top of the profile folder for an entry that
        Hermes calls a credential store or a copy of one and that this sandbox's start did not list
        (``layout.new_private_entries``): a copy of the keys file made while the sandbox is on, by Hermes's own
        config migration (``.env.bak-<stamp>``), by a person or by a tool on this computer. What a sandbox may
        not read is fixed when it starts, so the sandbox is restarted: the new start lists the entry. With the
        cards wired (``on_private``) the restart is theirs and replies in flight continue after it; else a plain
        restart. More than ``PRIVATE_LIMIT`` such restarts within ``GUARD_WINDOW`` seconds stop the sandbox
        with the reason (the sandbox writes this folder too). Returns the names found. Never raises."""
        now = time.monotonic()
        if (self._listed_private is None or self.state != "running" or self._lock.locked()
                or now - self._private_looked < PRIVATE_LOOK):
            return []
        self._private_looked = now
        try:
            new = await asyncio.to_thread(new_private_entries, self.layout.home, self._listed_private)
        except Exception:
            log.debug("the look for new credential files failed", exc_info=True)
            return []
        if not new or self.state != "running":
            return []
        names = ", ".join(new)
        self._listed_private = self._listed_private | {name.casefold() for name in new}  # asked for once
        self._private_restarts = [t for t in self._private_restarts if now - t < GUARD_WINDOW] + [now]
        try:
            if len(self._private_restarts) > PRIVATE_LIMIT:
                self._private_restarts = []
                await self.stop()
                self.state, self._last_error = "failed", (
                    f"The sandbox was stopped: credential files ({names}) kept appearing in the profile folder "
                    "while it ran. Turn the sandbox off, then on again.")
                log.error("profile %s: %s", self.layout.name, self._last_error)
                return new
            log.warning("profile %s: %s appeared in the profile folder while the sandbox was on; the sandbox "
                        "restarts so that it cannot read it", self.layout.name, names)
            if self.on_private is not None:
                await self.on_private(list(new))
            else:
                await self.restart(note=hide_note(new, time.time()))
        except Exception as exc:
            log.warning("profile %s: the restart that hides %s failed: %s", self.layout.name, names, exc)
        return new

    # -- reporting ---------------------------------------------------------------------------
    def pending(self) -> dict:
        """What the running sandbox lacks against the saved spec (nothing is pending while stopped)."""
        if self.applied is None:
            return {"folders": False, "network": False, "keys": False}
        saved = saved_policy(self.spec)
        return {"folders": _folder_keys(saved["folders"]) != _folder_keys(self.applied["folders"]),
                "network": saved["network"] != self.applied["network"],
                "keys": self.keys_changed or self._sign_ins_back}

    @property
    def restart_required(self) -> bool:
        return any(self.pending().values())

    def endpoint_changed(self) -> list[dict]:
        """Keys the running sandbox did not get because a model entry names an endpoint that is not the pinned
        one: ``[{label, host, port, env}]``, without the pairs the user has allowed since (those are bound at
        the next start)."""
        if self.applied is None:
            return []
        return [c for c in self.driver.endpoint_changed()
                if (c.get("env"), c.get("host"), c.get("port")) not in self._endpoints_allowed]

    def endpoint_allowed(self, row: dict) -> None:
        """The user allowed *row* (host route): no longer reported, and the sandbox needs a restart to get it."""
        self._endpoints_allowed.append((row.get("env"), row.get("host"), row.get("port")))
        self.keys_changed = True

    def keys_saved(self) -> bool:
        """A key was saved through the launcher while the sandbox runs. True when the driver put what was saved
        to use in the running sandbox (the value behind a placeholder was replaced): nothing about the
        profile's keys waits for a restart then. False when the restart is still needed."""
        apply = getattr(self.driver, "keys_saved", None)
        if self.state != "running" or apply is None:
            return False
        try:
            live = bool(apply(_profile_secrets(self.layout), self._route_pin()))
        except Exception as exc:  # the restart the page asks for then does what this could not
            log.warning("a saved key could not be put to use in the running sandbox: %s", exc)
            return False
        if live:
            self.keys_changed = False
        return live

    def key_use(self, name: str, restart: bool) -> str:
        """What a key saved while the sandbox is on means for it, for the Keys page's one line: ``after_restart``
        (*restart*: the sandbox uses it once it has restarted), ``in_use`` (the running sandbox uses the saved
        value now) or ``not_used`` (no model of the profile names the key, so it is not handed in)."""
        if restart:
            return "after_restart"
        registered = getattr(self.driver, "registered_providers", None)
        rows = registered() if callable(registered) else []
        handed = {env for row in rows for env in row.get("envs") or [row.get("env")]}
        return "in_use" if name in handed else "not_used"

    def status(self) -> dict:
        """``applied`` is what the running sandbox got (None when none runs); ``saved`` is the spec on
        disk, which the next start uses. ``builtin`` is what the launcher keeps open by itself while a sandbox
        runs, the rows the page lists from ``config_payload``: the page's header counts them with the user's own.
        ``opened`` is every address a sign-in or a key is used at in that sandbox (``opened_hosts``), which the
        page lists and counts in the same way.
        ``restart_queued``: the launcher restarts the sandbox by itself for what is pending (a grant removed on
        the page), so the page asks the user for no restart.
        ``endpoint_changed``: keys withheld because the sandbox's model entry names another endpoint than the
        pinned one; ``pinned`` is False for a sandbox switched on before pins existed (turn it off and on).
        ``handback.open``: a baseline of the home was recorded at switch-on, so the switch-off can list what
        changed (the list itself is ``GET handback``: this status is polled). ``handback.stamp`` changes when
        that list may have (a few ``stat`` calls; the page reads the list again when it differs) and
        ``handback.kept`` counts what the user kept from a sandbox and is still in the profile."""
        return {
            "profile": self.layout.name, "sandboxed": True, "state": self.reported_state(), "driver": self.driver.name,
            "capabilities": self.driver.capabilities(),
            "url": f"http://127.0.0.1:{self.outer_port}", "started_at": self._started_at,
            "restart_required": self.restart_required, "pending": self.pending(), "error": self._last_error,
            "restart_queued": bool(self.restart_queued()),
            "applied": self.applied, "saved": saved_policy(self.spec), "temporary": self.temporary,
            "builtin": usage_data.destinations(self.layout.home) if self.applied is not None else [],
            "opened": self.opened_hosts(),
            "endpoint_changed": self.endpoint_changed(), "pinned": self._pinned,
            "handback": handback.status_view(self.layout.home, self.layout.state_dir),
            "restarting": self.restarting_view(), "restart": self.restart_view(),
            "switching_off": self.switching_off,
            "providers": self.provider_rows(),
        }

    def policy(self) -> dict:
        return {"driver": self.driver.name, "grants": self._grants.as_dict() if self._grants else None,
                "enforced": self.driver.policy()}

    def write_state(self) -> None:
        from .login_service import process_start_ticks

        data = {"pid": os.getpid(), "profile": self.layout.name, "port": self.outer_port,
                "url": f"http://127.0.0.1:{self.outer_port}", "driver": self.driver.name, "since": time.time(),
                # Linux: the kernel's start stamp of this process, which decides whether a PID is still this
                # launcher (launcher_state_alive); null elsewhere.
                "start_ticks": process_start_ticks(os.getpid())}
        tmp = self.layout.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        os.replace(tmp, self.layout.state_path)

    def clear_state(self) -> None:
        self.layout.state_path.unlink(missing_ok=True)


def _folder_keys(folders: list[dict]) -> list[tuple[str, str]]:
    return [(os.path.normcase(str(f["path"])), str(f.get("access", "rw")).lower()) for f in folders]


def _with_temporary(folders: list[dict], network: dict, temporary: dict, layout) -> tuple[list[dict], dict]:
    """The saved folders and network plus the card grants in force (``Supervisor.temporary``): a
    temporary folder is checked like a saved one and widens a saved read-only entry; a temporary rule
    adds its binaries to a saved rule of the same name."""
    from .cards import _merge_rule

    out = [dict(f) for f in folders]
    extra = checked_folders({"folders": (temporary or {}).get("folders") or []}, layout)
    for f in extra:
        same = next((g for g in out if os.path.normcase(g["path"]) == os.path.normcase(f["path"])), None)
        if same is None:
            out.append(f)
        elif f["access"] == "rw":
            same["access"] = "rw"
    approved = (temporary or {}).get("approved") or {}
    if approved:
        merged = dict(network.get("approved") or {})
        for name, rule in approved.items():
            merged[name] = _merge_rule(merged.get(name), rule)
        network = {**network, "approved": merged}
    return out, network


def _profile_secrets(layout) -> dict[str, str]:
    """The profile's keys, from the host-only pins taken when the sandbox was switched on (pins.py): the pinned
    .env plus what the user's own secret sources resolve. The OpenShell drivers register the keys the profile's
    models use as providers and hand the sandbox placeholders; the other keys stay on the host.

    Called before every sandbox start, so this is also where an env file or a sign-in store the last sandbox
    created or replaced is put back from the pin: the next sandbox never starts over them (a ``.op.env`` made
    inside would be in its deny list as a file that exists), and Hermes on this computer stops reading them
    one restart later, not only at switch-off."""
    key_pins.restore_env(layout)
    key_pins.restore_stores(layout)
    return key_pins.secrets(layout)


async def _health(port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 2.0)
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        writer.write(f"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), 5.0)
        return line.split(b" ")[1:2] == [b"200"]
    except (OSError, asyncio.TimeoutError, ConnectionError):
        return False
    finally:
        writer.close()


def _rotate_log(path) -> None:
    """Keep the previous run's log as serve.log.1; if a dying container still holds it, append."""
    if path.exists():
        try:
            os.replace(path, path.with_suffix(".log.1"))
        except OSError:
            pass


def _log_tail(path, lines: int = 20) -> str:
    try:
        return "\n".join(path.read_bytes().decode("utf-8", "replace").splitlines()[-lines:])
    except OSError:
        return ""
