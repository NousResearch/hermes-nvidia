"""``hermes sandbox``: run this profile's backend inside a sandbox, fronted by an authenticating proxy.

    hermes [-p NAME] sandbox serve [--port N] [--folder PATH[:ro|rw]]... [--wxc-exec PATH] [--busybox PATH]
                                   [--openshell-gateway NAME] [--openshell-image REF] [--egress deny|allow]
                                   [--rotate-token] [--service] [--revert | --keep]
    hermes [-p NAME] sandbox on [--revert | --keep] | off [--revert | --keep] | handback [--json]
    hermes [-p NAME] sandbox status | policy | stop
    hermes [-p NAME] sandbox requests [--status pending|approved|rejected|all]
    hermes [-p NAME] sandbox approve ID | reject ID --reason TEXT
    hermes [-p NAME] sandbox revisions | rollback VERSION | events [--since UNIX] [--class NET,HTTP]
    hermes sandbox gateway status | ensure | remove [--force]
    hermes sandbox runtime status | install [--build-dir DIR] | remove

``serve`` stays in the foreground and prints ``HERMES_SANDBOX_READY port=N profile=NAME`` once the
sandboxed backend answers. Point a client at ``http://127.0.0.1:N`` with the token stored in the file
``serve`` names (never printed). Flags given to ``serve`` are saved to the profile's host-only spec,
once the driver passes preflight.
``on`` / ``off`` flip the Sandbox switch from a terminal (the desktop's Sandbox page does the same and
also points the desktop at the launcher): ``on`` runs ``serve --service`` as a per-user login service
and marks the profile as run elsewhere; ``off`` undoes both, the marker last (see launcher/switch.py).
``off`` first compares the profile's folder with what it held when the sandbox was switched on
(launcher/handback.py). When the sandbox changed settings or files that run on this computer, ``off``
prints them, changes nothing and exits 3; run it again with ``--revert`` (put them back; the sandbox's
versions are kept in the launcher's state folder) or ``--keep``. ``handback`` prints the same list.
What was kept runs on this computer from then on like the profile's own settings: ``status`` says how many
kept changes are still in the profile, and ``handback`` lists them.
A sandbox session that ended without that step (the launcher was killed, the review could not run) is
reviewed by the next ``on``, and by the next foreground ``serve``, before anything is pinned from the
profile's folder: the same list, exit 3, and the same two flags. A foreground ``serve`` records the folder
when it starts and compares when it stops; changes that need an answer are printed then, and ``off
--revert`` or ``off --keep`` answers them.
The request, revision and event commands need a driver whose enforcer has them (OpenShell).
Without ``--openshell-gateway`` the OpenShell driver uses this Hermes root's own private gateway: the
plugin installs the pinned OpenShell (Linux: the release, checksum-verified; Windows: NVIDIA's signed
package from the pinned release, checksum- and signature-verified), runs the gateway with generated
mTLS certificates as a login service shared by every sandboxed profile, and removes it when the last
profile is switched off (``gateway``/``runtime`` show and manage it; see launcher/gateway_service.py).
On Windows ``runtime install`` and the switch-on also install the two other programs a sandbox needs, MXC's
``wxc-exec.exe`` and the sandbox's shell (launcher/windows_programs.py). ``check`` and ``runtime status`` say
for each of the two which file is used and where it comes from: the plugin's pinned install, or a copy named
with ``--wxc-exec`` / ``--busybox`` or with ``OPENSHELL_WXC_EXEC_PATH`` / ``OPENSHELL_BUSYBOX``.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_DESCRIPTION = ("Run this profile's Hermes backend inside an OpenShell sandbox (Windows: MXC process containers "
                "through OpenShell's MXC driver; Linux: Docker), through a private mTLS gateway, behind an "
                "authenticating loopback proxy. Credential files stay on the host.")


def register(ctx) -> None:
    ctx.register_cli_command(name="sandbox", help="Run this profile's backend in a sandbox",
                             setup_fn=_setup, handler_fn=_dispatch, description=_DESCRIPTION)


def _setup(parser) -> None:
    sub = parser.add_subparsers(dest="sandbox_command", metavar="{serve,on,off,handback,status,check,policy,stop,"
                                                               "requests,approve,reject,revisions,rollback,events,"
                                                               "gateway,runtime}")
    serve = sub.add_parser("serve", help="Start the sandboxed backend and its proxy (foreground)")
    serve.add_argument("--port", type=int, help="Fixed outer loopback port (saved)")
    serve.add_argument("--folder", action="append", metavar="PATH[:ro|rw]",
                       help="Folder the sandbox may use, read-only or read & write (repeat; replaces the saved list)")
    serve.add_argument("--wxc-exec", dest="wxc_exec", metavar="PATH",
                       help="Windows: your own wxc-exec.exe (MXC 1.0 or newer) instead of the one the plugin "
                            "installs (saved)")
    serve.add_argument("--busybox", metavar="PATH",
                       help="Windows: your own busybox-w32 for the sandbox's shell instead of the one the plugin "
                            "installs (saved)")
    serve.add_argument("--openshell-gateway", dest="openshell_gateway", metavar="NAME",
                       help="Registered OpenShell gateway (mTLS) to run the sandbox on (saved)")
    serve.add_argument("--openshell-image", dest="openshell_image", metavar="REF",
                       help="Hermes image for the OpenShell sandbox (saved)")
    serve.add_argument("--egress", choices=("deny", "allow"), help="Internet access from the sandbox (saved)")
    serve.add_argument("--rotate-token", action="store_true", help="Mint a new outer token")
    serve.add_argument("--service", action="store_true",
                       help="Run as the profile's login service (started by `sandbox on`; exits if the switch is off)")
    on = sub.add_parser("on", help="Turn the sandbox on: start the launcher as a login service and mark the profile")
    off = sub.add_parser("off", help="Turn the sandbox off: stop the launcher, remove its login service, unmark the profile")
    last = "the last sandbox session"
    for command, whose in ((serve, last), (on, last), (off, "the sandbox")):
        answer = command.add_mutually_exclusive_group()
        answer.add_argument("--revert", dest="handback_answer", action="store_const", const="revert",
                            help=f"Put back what {whose} changed among the settings and files that run on this computer")
        answer.add_argument("--keep", dest="handback_answer", action="store_const", const="keep", help="Keep those changes")
    for command in (serve, on):
        command.add_argument("--move-keys", dest="move_keys", action="store_true",
                             help="First move keys written in config.yaml to .env (the sandbox can read config.yaml)")
    handback = sub.add_parser("handback", help="List what the sandbox changed among the settings and files that run "
                                               "on this computer")
    handback.add_argument("--json", action="store_true", help="Print the list as JSON")
    sub.add_parser("status", help="Show the running sandbox's state")
    sub.add_parser("check", help="Check whether this computer can run the sandbox (exit 1 when it can't)")
    sub.add_parser("policy", help="Print the policy handed to the sandbox driver")
    sub.add_parser("stop", help="Stop the sandbox and its proxy")
    requests = sub.add_parser("requests", help="List network requests the sandbox blocked")
    requests.add_argument("--status", default="pending", choices=("pending", "approved", "rejected", "all"))
    approve = sub.add_parser("approve", help="Allow a blocked request (applies live)")
    approve.add_argument("id")
    reject = sub.add_parser("reject", help="Refuse a blocked request; the agent sees the reason")
    reject.add_argument("id")
    reject.add_argument("--reason", required=True)
    sub.add_parser("revisions", help="List the enforcer's policy revisions")
    rollback = sub.add_parser("rollback", help="Restore an earlier policy revision (as a new revision)")
    rollback.add_argument("version", type=int)
    events = sub.add_parser("events", help="Recent audit events (OCSF) from the enforcer")
    events.add_argument("--since", type=float, help="Unix seconds")
    events.add_argument("--class", dest="classes", help="Comma list: NET,HTTP,CONFIG,...")
    events.add_argument("--limit", type=int, default=100)
    gateway = sub.add_parser("gateway", help="This Hermes root's private OpenShell gateway")
    gateway.add_argument("action", choices=("status", "ensure", "remove"))
    gateway.add_argument("--force", action="store_true", help="remove even while profiles are switched on")
    runtime = sub.add_parser("runtime", help="The installed OpenShell binaries (Windows: and MXC's wxc-exec and "
                                             "the sandbox's shell)")
    runtime.add_argument("action", choices=("status", "install", "remove"))
    runtime.add_argument("--build-dir", dest="build_dir", metavar="DIR",
                         help="Windows: a folder that already holds the pinned OpenShell files (default: "
                              "download the pinned package)")


_RESERVED_PROFILES = ("runtime",)  # <root>/openshell/runtime holds the installed OpenShell and its gateway


def _check_profile_name(layout) -> None:
    from .launcher.layout import LayoutError

    if layout.name in _RESERVED_PROFILES:
        raise LayoutError(f"a profile named '{layout.name}' can't be sandboxed: <hermes root>/openshell/{layout.name} "
                          f"holds the installed OpenShell runtime")


def _dispatch(args) -> int:
    handlers = {"serve": _cmd_serve, "on": _cmd_on, "off": _cmd_off, "handback": _cmd_handback,
                "status": _cmd_status, "check": _cmd_check, "policy": _cmd_policy,
                "stop": _cmd_stop, "requests": _cmd_requests, "approve": _cmd_approve, "reject": _cmd_reject,
                "revisions": _cmd_revisions, "rollback": _cmd_rollback, "events": _cmd_events,
                "gateway": _cmd_gateway, "runtime": _cmd_runtime}
    handler = handlers.get(getattr(args, "sandbox_command", None))
    if handler is None:
        print("usage: hermes sandbox {serve,on,off,handback,status,check,policy,stop,requests,approve,reject,revisions,"
              "rollback,events,gateway,runtime}", file=sys.stderr)
        return 2
    return handler(args)


def _fail(message: str) -> int:
    print(f"hermes sandbox: {message}", file=sys.stderr)
    return 1


def _cmd_serve(args) -> int:
    import asyncio

    from .launcher.driver import DriverUnavailable
    from .launcher.layout import LayoutError, current_profile
    from .launcher.spec import (NO_ALL_INTERNET, ensure_token, free_loopback_port, load_spec, network_policy,
                                parse_folder_arg, save_spec)

    try:
        layout = current_profile()
        _check_profile_name(layout)
        if getattr(args, "service", False):
            from .launcher.login_service import switched_on

            if not switched_on(layout):
                # A registration a crash left behind: the switch is off, so it starts nothing.
                print(f"hermes sandbox: the sandbox switch is off for profile '{layout.name}'; not starting.",
                      flush=True)
                return 0
        first_run = not layout.spec_path.exists()
        spec = load_spec(layout)
        if args.folder is not None:
            spec["folders"] = [parse_folder_arg(raw, layout) for raw in args.folder]
        elif first_run:
            default = Path.home() / "Hermes"
            default.mkdir(exist_ok=True)
            spec["folders"] = [parse_folder_arg(f"{default}:rw", layout)]
        if args.port:
            spec["port"] = args.port
        spec["port"] = spec["port"] or free_loopback_port()
        if args.wxc_exec:
            spec["wxc_exec"] = str(Path(args.wxc_exec).resolve())
        if args.busybox:
            spec["busybox"] = str(Path(args.busybox).resolve())
        if getattr(args, "openshell_gateway", None):
            spec["openshell"] = {**(spec.get("openshell") or {}), "gateway": args.openshell_gateway}
        if getattr(args, "openshell_image", None):
            spec["openshell"] = {**(spec.get("openshell") or {}), "image": args.openshell_image}
        if args.egress:
            spec["network"] = {**(spec.get("network") or {}), "egress": args.egress}
        network_policy(spec)
        driver = make_driver(spec)
        if args.egress == "allow" and not driver.capabilities().get("egress_allow_all", True):
            raise LayoutError(NO_ALL_INTERNET)  # as the settings routes refuse it: nothing is saved
        driver.preflight()
        save_spec(layout, spec)  # only once the driver passed preflight: a refused path is never saved
        token = ensure_token(layout, rotate=args.rotate_token)
    except (LayoutError, DriverUnavailable) as exc:
        return _fail(str(exc))
    service = bool(getattr(args, "service", False))
    # The keys and model endpoints the launcher uses are pinned on the host when the sandbox is switched on
    # (launcher/pins.py). A login service never pins: it restarts over a home the sandbox has had. A foreground
    # serve started by hand is its own switch-on, unless the switch is on or a launcher already runs.
    own_pin = not service and _pins_are_ours(layout)
    if own_pin and getattr(args, "move_keys", False):
        try:
            _move_keys(layout)
        except Exception as exc:
            return _fail(f"The keys could not be moved: {exc}")
    if own_pin:
        # As a switch-on does (launcher/switch.py): the last session's changes are answered before anything is
        # pinned from the home, then the home is recorded, and compared again when this serve stops (_serve).
        # This path never marks the profile, so Hermes on this computer reads the home the whole time: the list
        # shows what the sandbox changed, it does not keep those changes from running meanwhile.
        code = _own_switch_on(layout, getattr(args, "handback_answer", None), driver)
        if code:
            return code
    try:
        return asyncio.run(_serve(layout, spec, driver, token, service=service, own_pin=own_pin))
    except KeyboardInterrupt:
        return 130
    finally:
        if own_pin:  # the sandbox and the proxy are down by now
            _own_switch_off(layout)


def _own_switch_on(layout, answer, driver=None) -> int:
    """A foreground serve's own switch-on: stop a sandbox the last launcher left running, review the last
    session, pin, record the home. 0 to go on."""
    from .launcher import handback, pins
    from .launcher.layout import remove_legacy_secret_copies
    from .launcher.switch import HandbackNeeded, SwitchError, drop_leftover, previous_session, refuse_unready

    try:
        refuse_unready(layout)
        drop_leftover(layout, driver)
        previous_session(layout, answer)
    except HandbackNeeded as exc:
        print(_handback_list(layout.name, exc.view))
        print(f"hermes sandbox: {exc} Run again with --revert or --keep.", file=sys.stderr)
        return 3
    except SwitchError as exc:
        return _fail(_with_move_hint(layout, _with_keep_hint(str(exc), "start"), exc, "serve"))
    try:
        pins.take(layout)
    except OSError as exc:
        return _fail(f"Couldn't keep a copy of this profile's keys: {exc}")
    try:
        remove_legacy_secret_copies(layout.home)  # the launcher's own cleanup is never listed as the sandbox's
        handback.take_baseline(layout.home, layout.state_dir, replace=True)
    except Exception as exc:
        pins.release(layout)
        return _fail(f"Couldn't save a copy of this profile's settings: {exc}")
    return 0


def _move_keys(layout) -> None:
    """``--move-keys``: the keys written in the profile's config.yaml go to its .env before the switch looks."""
    from .launcher import config_keys

    moved = config_keys.move_to_env(layout.home)
    if moved:
        print(f"Moved to .env: {', '.join(moved)}.", file=sys.stderr)


def _with_move_hint(layout, message: str, exc, verb: str) -> str:
    """A switch refused for keys in config.yaml names the flag that moves them."""
    if getattr(exc, "code", None) != "key_in_config":
        return message
    profile = "" if layout.name == "default" else f" -p {layout.name}"
    what = "it" if len(getattr(exc, "keys", None) or []) == 1 else "them"
    return f"{message} Run `hermes{profile} sandbox {verb} --move-keys` to move {what} and go on."


def _with_keep_hint(message: str, verb: str) -> str:
    """A review that could not run names its way past: the flag that takes the profile's folder as it is."""
    return f"{message} Run again with --keep to {verb} without a review." if message.startswith("Couldn't review") else message


def _own_switch_off(layout) -> None:
    """A foreground serve stopping: the files its pin holds go back, then the home is compared with the record
    taken at the start. Nothing that needs an answer: the record ends. Otherwise the list is printed and the
    record stays open: `sandbox off --revert | --keep` answers it, and so does the next `on` or `serve`."""
    from .launcher import handback, pins
    from .launcher.switch import hand_back, needs_an_answer, needs_answer, review

    if not handback.is_open(layout.state_dir):
        pins.release(layout)
        return
    view = review(layout)
    if view.get("error") or needs_an_answer(view, None):
        pins.release(layout)  # the env files go back either way; the record stays open for the answer
        if view.get("error"):
            print(f"hermes sandbox: Couldn't review the sandbox's changes ({view['error']}).", file=sys.stderr)
            return
        profile = "" if layout.name == "default" else f" -p {layout.name}"
        print(_handback_list(layout.name, view))
        print(f"hermes sandbox: {needs_answer(view['unanswered'])} Run `hermes{profile} sandbox off --revert` "
              f"or `hermes{profile} sandbox off --keep`.", file=sys.stderr)
        return
    done = hand_back(layout, view, None)  # the pin's files go back, what is always reverted too; the record ends
    if done["blocked"]:
        print(f"hermes sandbox: {done['blocked']}", file=sys.stderr)


def _pins_are_ours(layout) -> bool:
    from .launcher.login_service import switched_on
    from .launcher.switch import running_launcher

    return not switched_on(layout) and running_launcher(layout) is None


def make_driver(spec: dict):
    """The OpenShell driver for this OS (Windows: OpenShell's MXC driver; Linux: Docker)."""
    from .launcher.driver import DriverUnavailable
    from .launcher.spec import default_driver

    name = spec.get("driver") or default_driver()
    if name == "openshell":
        from .launcher.openshell_driver import OpenShellDriver

        return OpenShellDriver.from_spec(spec)
    raise DriverUnavailable(f"unknown sandbox driver {name!r} in the profile's sandbox spec (only openshell)")


async def _serve(layout, spec, driver, token: str, service: bool = False, own_pin: bool = False) -> int:
    """*own_pin*: this serve is its own switch-on. Nothing here depends on it: ``_cmd_serve`` pins and records
    the home before this runs, and hands the home back after it returns."""
    import asyncio

    from hermes_cli.dashboard_auth.public_paths import PUBLIC_API_PATHS

    from .launcher.host_routes import HostRoutes
    from .launcher.layout import current_runtime
    from .launcher.proxy import MAX_HEAD, Proxy
    from .launcher.supervisor import Supervisor

    port = int(spec["port"])
    sup = Supervisor(layout, current_runtime(), spec, driver, outer_port=port)
    stop = asyncio.Event()
    # The chat socket always goes through the frame relay (strips access wording from sandbox-sent
    # approvals); in-chat cards for blocked requests and folder refusals ride on it (cards.py).
    from .launcher import cards as cards_mod
    cards = cards_mod.Cards(sup, layout, layout.state_dir / "cards.jsonl", cards=cards_mod.enabled())
    # The driver asks this before it replaces a credential's value under a running sandbox. The sign-ins are
    # kept current from a thread of their own, so the question is answered on this loop whoever asks.
    loop = asyncio.get_running_loop()
    driver.turns_idle = _asked_on_loop(loop, cards.quiet)
    note_tasks: set = set()  # held until done: a task nothing refers to may be collected while it waits

    def say(text: str) -> None:
        def start() -> None:
            task = asyncio.ensure_future(cards.note(text))
            note_tasks.add(task)
            task.add_done_callback(note_tasks.discard)
        loop.call_soon_threadsafe(start)

    # A sign-in that expired for good, or could not be renewed in time: one note in the chat.
    sup.on_signin_note = say
    # A credential-named file that appears in the profile folder while the sandbox is on: the cards restart the
    # sandbox so that replies in flight are paused and continue (cards.py ``hide_new``).
    sup.on_private = cards.hide_new
    # The Activity tab's timeline; on Windows it also keeps the audit the gateway does not (activity.py).
    from .launcher.activity import AuditCollector
    activity = AuditCollector(sup, layout)
    routes = HostRoutes(sup, stop.set, extra_routes={**cards.routes(), **activity.routes()})
    proxy = Proxy(outer_token=token, upstream=sup.upstream, unavailable=sup.unavailable,
                  own_profile=sup.owns_profile, host_route=routes.match, public_paths=frozenset(PUBLIC_API_PATHS),
                  ws_relay=cards.relay, hold_status=sup.status_on_hold,
                  hold_note=sup.restarting_view)
    # A restart, a stop or a dead sandbox closes the desktop's sockets at once (1012 on the chat socket), with
    # the state already set, so the desktop reads "restarting" / "stopping" instead of timing out a heartbeat.
    sup.on_down += [cards.close_clients, proxy.close_upgrades]
    try:
        server = await asyncio.start_server(proxy.handle, "127.0.0.1", port, limit=MAX_HEAD)
    except OSError as exc:
        return _fail(f"cannot listen on 127.0.0.1:{port} ({exc}); is this profile's sandbox already running?")
    sup.write_state()
    watcher = asyncio.create_task(sup.watch())
    orphan_watch = asyncio.create_task(_stop_when_redirector_exits(stop))
    cards.start()
    activity.start()
    try:
        try:
            await sup.start()
        except Exception as exc:
            if not service:
                return _fail(str(exc))
            # A login service keeps answering with the reason (status: failed), so the switch and the
            # page can show it; the sandbox stays stopped until a restart or the switch turns it off.
            print(f"hermes sandbox: {exc}", file=sys.stderr, flush=True)
        else:
            print(f"HERMES_SANDBOX_READY port={port} profile={layout.name}", flush=True)
            print(f"Sandboxed backend for profile '{layout.name}' at http://127.0.0.1:{port} "
                  f"(driver {driver.name}); token file: {layout.token_path}", flush=True)
        await stop.wait()
        return 0
    finally:
        watcher.cancel()
        orphan_watch.cancel()
        await cards.stop()
        server.close()
        await sup.stop()
        await asyncio.to_thread(sup.close_sign_ins)  # a renewal under way ends before this process does
        await activity.stop()
        sup.clear_state()


def _asked_on_loop(loop, question):
    """*question* (it reads what the event loop's own tasks change) as a callable any thread may use: on the
    loop's thread it is asked directly, from another thread it is asked on the loop and waited for."""
    import concurrent.futures
    import threading

    owner = threading.get_ident()

    def ask():
        if threading.get_ident() == owner:
            return question()
        answer: concurrent.futures.Future = concurrent.futures.Future()

        def run() -> None:
            try:
                answer.set_result(question())
            except BaseException as exc:
                answer.set_exception(exc)

        loop.call_soon_threadsafe(run)
        return answer.result(timeout=5.0)

    return ask


def _redirector_parent():
    """This process's parent when it is the venv's ``python.exe``/``pythonw.exe`` redirector running this
    interpreter for us (Windows venvs do that), else None.

    The launcher follows only that parent: a hard kill of the launcher's visible process must not leave
    this one and its sandbox running. It never follows whoever started it otherwise. A host gateway that
    started a launcher exits after idle, and a login service's parent is the service manager; the
    launcher stops through its own stop route, the switch, or its service manager."""
    import psutil

    try:
        me = psutil.Process()
        parent = me.parent()
        if parent is None:
            return None
        venv_exe = os.path.normcase(os.path.abspath(sys.executable))
        if (os.path.normcase(parent.exe()) == venv_exe and os.path.normcase(me.exe()) != venv_exe):
            return parent
    except (psutil.Error, OSError):
        return None
    return None


async def _stop_when_redirector_exits(stop) -> None:
    import asyncio

    parent = _redirector_parent()
    if parent is None:
        return
    while parent.is_running():
        await asyncio.sleep(1.0)
    stop.set()


def _call_running(method: str, route: str, body=None):
    import urllib.error
    import urllib.request

    from .launcher.layout import current_profile

    layout = current_profile()
    if not layout.state_path.is_file():
        return None, f"no sandbox running for profile '{layout.name}'"
    state = json.loads(layout.state_path.read_text(encoding="utf-8"))
    token = layout.token_path.read_text(encoding="utf-8").strip()
    data = None if body is None else json.dumps(body).encode()
    headers = {"X-Hermes-Session-Token": token, **({"Content-Type": "application/json"} if data else {})}
    req = urllib.request.Request(f"http://127.0.0.1:{state['port']}/api/plugins/openshell/{route}", method=method,
                                 headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read() or b"null"), None
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read() or b"{}").get("detail")
        except ValueError:
            detail = None
        return None, f"{exc.code}: {detail or exc.reason}"
    except (urllib.error.URLError, OSError) as exc:
        return None, f"sandbox for profile '{layout.name}' did not answer on port {state['port']}: {exc}"


def _print_or_fail(method: str, route: str, body=None) -> int:
    payload, error = _call_running(method, route, body)
    if error:
        return _fail(error)
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_status(args) -> int:
    """The running launcher's status as JSON. On stderr, while changes kept from a sandbox are still in the
    profile: one line that says how many (also when no sandbox runs; ``sandbox handback`` lists them)."""
    from .launcher import handback
    from .launcher.layout import LayoutError, current_profile

    payload, error = _call_running("GET", "status")
    try:
        layout = current_profile()
        count = (int(((payload or {}).get("handback") or {}).get("kept") or 0) if not error
                 else len(handback.kept(layout.home, layout.state_dir)))
    except (LayoutError, OSError, ValueError, TypeError):
        layout, count = None, 0
    if not error:
        print(json.dumps(payload, indent=2))
    if count and layout is not None:
        profile = "" if layout.name == "default" else f" -p {layout.name}"
        print(f"{_kept_line(count)}. Run `hermes{profile} sandbox handback` to list them.", file=sys.stderr)
    return _fail(error) if error else 0


def _kept_line(count: int) -> str:
    return f"Kept from the sandbox: {'1 item' if count == 1 else f'{count} items'}"


def _cmd_check(args) -> int:
    """The host compatibility check the Sandbox page shows (compat.py), run fresh, and whether this profile's
    switch would turn on.

    ``ok`` is about this computer: it can run the sandbox. ``ready`` is about this profile on this computer: its
    switch would turn on now (always true while its sandbox is on). When the switch is refused, ``switch_refused``
    is the reason and it is also said on stderr; ``note`` is what to know about a switch-on that goes ahead (a
    model without a key). Exit status: 0 ready, 1 this computer cannot run the sandbox, 2 it can but the switch
    is refused for this profile."""
    from .launcher.layout import LayoutError, current_profile
    from .launcher.switch import availability, host_check

    try:
        layout = current_profile()
        result = host_check(layout, refresh=True)
    except LayoutError as exc:
        return _fail(str(exc))
    # The profile's providers, and whether each works in the sandbox: from the running launcher when there is
    # one, else from the profile as it is.
    refused = note = None
    payload, error = _call_running("GET", "status")
    if not error and isinstance(payload, dict) and isinstance(payload.get("providers"), list):
        extra = {"providers": payload["providers"]}
    else:
        from .launcher import provider_rows, settings_view

        try:
            rows: list = []
            refusal = provider_rows.refusal(layout, seen=rows)
            refused = refusal["detail"] if refusal else None
            found = settings_view.switch_note(rows)
            note = found["reason"] if found else None
            extra = {"providers": rows}
        except Exception as exc:
            extra = {"providers": [], "providers_error": str(exc)}
        # What the page says before it looks at the providers: a Hermes that is too old, the default profile.
        switch = availability(layout, check_host=False)
        if not switch["available"]:
            refused = switch["reason"]
    result = {"ok": result["ok"], "ready": bool(result["ok"]) and refused is None,
              **{name: value for name, value in result.items() if name != "ok"}, **extra,
              **_windows_programs(layout.root, layout),
              **({"switch_refused": refused} if refused else {}), **({"note": note} if note else {})}
    print(json.dumps(result, indent=2))
    for line in (refused, note):
        if line:
            print(f"hermes sandbox: {line}", file=sys.stderr)
    return 1 if not result["ok"] else 2 if refused else 0


def _cmd_on(args) -> int:
    from .launcher.layout import LayoutError, current_profile
    from .launcher.switch import HandbackNeeded, SwitchError, turn_on

    answer = getattr(args, "handback_answer", None)
    try:
        layout = current_profile()
        _check_profile_name(layout)
        if getattr(args, "move_keys", False):
            _move_keys(layout)
        result = turn_on(layout, handback_answer=answer)
    except HandbackNeeded as exc:  # exit 3 means only: an answer is needed, nothing was changed
        print(_handback_list(layout.name, exc.view))
        print(f"hermes sandbox: {exc} Run again with --revert or --keep.", file=sys.stderr)
        return 3
    except (LayoutError, SwitchError) as exc:
        return _fail(_with_move_hint(layout, _with_keep_hint(str(exc), "turn on"), exc, "on"))
    except Exception as exc:
        if type(exc).__name__ != "MoveError":
            raise
        return _fail(f"The keys could not be moved: {exc}")
    print(json.dumps({"profile": result["profile"], "url": result["url"], "service": result["service"],
                      "token_file": str(layout.token_path), "state": result["status"].get("state"),
                      **({"handback": result["handback"]} if result.get("handback") else {})}, indent=2))
    _say_handed_back(layout, result.get("handback") or {}, answer)
    if result.get("note"):  # the sandbox is on; this is what its first message would run into
        print(f"hermes sandbox: {result['note']}", file=sys.stderr)
    return 0


def _cmd_off(args) -> int:
    """Exit 3 means only: an answer is needed (``--revert`` or ``--keep``), nothing was changed."""
    from .launcher.layout import LayoutError, current_profile
    from .launcher.switch import HandbackNeeded, SwitchError, turn_off_here

    answer = getattr(args, "handback_answer", None)
    try:
        layout = current_profile()
        result = turn_off_here(layout, handback_answer=answer)
    except HandbackNeeded as exc:
        print(_handback_list(layout.name, exc.view))
        print(f"hermes sandbox: {exc} Run again with --revert or --keep.", file=sys.stderr)
        return 3
    except (LayoutError, SwitchError) as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    done = result.get("handback") or {}
    if done.get("error"):
        print(f"hermes sandbox: Couldn't review the sandbox's changes ({done['error']}). The sandbox is off.",
              file=sys.stderr)
    _say_handed_back(layout, done, answer)
    return 0


def _say_handed_back(layout, done: dict, answer) -> None:
    """What a hand-back did, on stderr: how many changes were kept or reverted and where the sandbox's versions
    are (after a switch-off, and after the review a switch-on runs for a session that ended without one)."""
    from .launcher import handback

    kept, reverted = done.get("kept") or [], done.get("reverted") or []
    if answer == "keep" and kept:
        print(f"Kept {_changes(len(kept))}.", file=sys.stderr)
    if reverted:
        where = ""
        if done.get("held"):
            folder = layout.state_dir / handback.STATE_DIRNAME / "held" / str(done["held"])
            where = f" The sandbox's {'version is' if len(reverted) == 1 else 'versions are'} in {folder}."
        print(f"Reverted {_changes(len(reverted))}.{where}", file=sys.stderr)
    if done.get("problem"):
        print(f"hermes sandbox: {done['problem']}", file=sys.stderr)


def _cmd_handback(args) -> int:
    """List what the sandbox changed among the settings and files that run on this computer since it was
    switched on: from the running launcher, else from the profile's folder and the baseline here."""
    from .launcher.layout import LayoutError, current_profile
    from .launcher.switch import review, running_launcher

    try:
        layout = current_profile()
    except LayoutError as exc:
        return _fail(str(exc))
    if running_launcher(layout) is not None:
        view, error = _call_running("GET", "handback?full=1")
        if error:
            return _fail(error)
    else:
        from .launcher.host_routes import _kept

        view = {**review(layout), "kept": _kept(layout)}
    view = view if isinstance(view, dict) else {}
    if getattr(args, "json", False):
        print(json.dumps(view, indent=2))
        return 0
    if view.get("error"):
        return _fail(f"Couldn't review the sandbox's changes ({view['error']}).")
    print(_handback_list(layout.name, view))
    return 0


def _changes(count: int) -> str:
    return "1 change" if count == 1 else f"{count} changes"


def _handback_list(profile: str, view: dict) -> str:
    """The hand-back list as text: the rows as the launcher gives them (label, name, detail), the rows that are
    always reverted last under their own heading, then one line for what else changed."""
    rows = [row for row in view.get("rows") or [] if isinstance(row, dict)]
    lines = []
    if rows:
        wide = [max(len(str(row.get(key, ""))) for row in rows) for key in ("label", "name")]
        digits = len(str(len(rows)))
        lines.append(f"Changed in the sandbox (profile {profile})")
        number = 0
        for fixed in (False, True):
            group = [row for row in rows if bool(row.get("fixed")) is fixed]
            if fixed and group:
                lines.append("Always reverted")
            for row in group:
                number += 1
                lines.append(f"  {number:>{digits}}  {str(row.get('label', '')):<{wide[0]}}  "
                             f"{str(row.get('name', '')):<{wide[1]}}  {row.get('detail', '')}".rstrip())
    else:
        lines.append(f"No sandbox changes to review for profile '{profile}'.")
    counts = (view.get("tier2") or {}).get("counts") or {}
    other = int((view.get("other_settings") or {}).get("count") or 0)
    parts = [f"{n} {one if n == 1 else many}" for n, one, many in (
        (int(counts.get("skills") or 0), "skill", "skills"), (int(counts.get("memories") or 0), "memory", "memories")) if n]
    parts += ["SOUL.md"] if counts.get("context") else []
    parts += [f"{other} other setting{'' if other == 1 else 's'}"] if other else []
    if parts:
        lines.append(f"Also changed: {', '.join(parts)}.")
    if view.get("incomplete"):
        lines.append(f"Not fully checked: {', '.join(map(str, view['incomplete']))}.")
    kept = [item for item in view.get("kept") or [] if isinstance(item, dict)]
    if kept:
        # Kept at an earlier hand-back and still in the profile: these run on this computer as the user's own.
        wide = [max(len(str(item.get(key, ""))) for item in kept) for key in ("label", "name")]
        lines.append(f"{_kept_line(len(kept))}")
        lines += [f"  {str(item.get('label', '')):<{wide[0]}}  {str(item.get('name', '')):<{wide[1]}}  "
                  f"{item.get('detail', '')}".rstrip() for item in kept]
    return "\n".join(lines)


def _cmd_policy(args) -> int:
    return _print_or_fail("GET", "policy")


def _cmd_stop(args) -> int:
    return _print_or_fail("POST", "stop")


def _cmd_requests(args) -> int:
    return _print_or_fail("GET", f"proposals?status={args.status}")


def _cmd_approve(args) -> int:
    return _print_or_fail("POST", f"proposals/{args.id}/approve", {})


def _cmd_reject(args) -> int:
    return _print_or_fail("POST", f"proposals/{args.id}/reject", {"reason": args.reason})


def _cmd_revisions(args) -> int:
    return _print_or_fail("GET", "policy/revisions")


def _cmd_rollback(args) -> int:
    return _print_or_fail("POST", "policy/rollback", {"version": args.version})


def _cmd_events(args) -> int:
    import urllib.parse

    query = {"limit": str(args.limit)}
    if args.since:
        query["since"] = str(args.since)
    if args.classes:
        query["class"] = args.classes
    return _print_or_fail("GET", "events?" + urllib.parse.urlencode(query))


def _jsonable(value):
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return str(value) if isinstance(value, Path) else value


def _hermes_root() -> Path:
    from hermes_constants import get_default_hermes_root

    return get_default_hermes_root().resolve()


def _profile_spec(layout=None) -> dict:
    """This profile's saved sandbox spec (its ``--wxc-exec`` / ``--busybox``), or nothing when it has none."""
    from .launcher.layout import LayoutError, current_profile
    from .launcher.spec import load_spec

    try:
        return load_spec(layout if layout is not None else current_profile())
    except (LayoutError, OSError, ValueError):
        return {}


def _windows_programs(root: Path, layout=None, *, install: bool = False) -> dict:
    """On Windows, ``{"programs": ...}``: for MXC's wxc-exec and the sandbox's shell, the file the launcher uses
    and where it comes from (launcher/windows_programs.py ``status``). *install* first installs each one the
    person named no copy of. Nothing on another system."""
    from .launcher import openshell_install as inst
    from .launcher import windows_programs

    if inst.platform_key() != "windows":
        return {}
    spec = _profile_spec(layout)
    if install:
        for name in windows_programs.PROGRAMS:
            windows_programs.use(name, spec, root)
    return {"programs": windows_programs.status(root, spec)}


def _cmd_gateway(args) -> int:
    """This root's private OpenShell gateway: ``status``, ``ensure`` (through the profile's driver
    preflight, so the MXC gate runs first on Windows) or ``remove``."""
    from .launcher import gateway_service
    from .launcher.driver import DriverUnavailable
    from .launcher.layout import LayoutError, current_profile
    from .launcher.spec import load_spec

    root = _hermes_root()
    try:
        if args.action == "status":
            result = gateway_service.gateway_status(root)
        elif args.action == "ensure":
            layout = current_profile()
            spec = load_spec(layout)
            if (spec.get("openshell") or {}).get("gateway"):
                return _fail("this profile's spec names its own gateway; the managed one is not used")
            result = make_driver(spec).preflight()
        else:
            result = gateway_service.remove_gateway(root, force=args.force)
    except (DriverUnavailable, LayoutError) as exc:
        return _fail(str(exc))
    print(json.dumps(_jsonable(result), indent=2))
    return 0


def _cmd_runtime(args) -> int:
    import shutil

    from .launcher import gateway_service
    from .launcher import openshell_install as inst
    from .launcher.driver import DriverUnavailable

    root = _hermes_root()
    try:
        if args.action == "status":
            pin = None
            try:
                pin = inst.pinned()
            except DriverUnavailable as exc:
                pin = {"error": str(exc)}
            result = {"installed": inst.installed(root), "pinned": {k: pin.get(k) for k in ("id", "version", "arch",
                                                                                           "source", "signer", "error")
                                                                    if pin.get(k)},
                      "dir": str(inst.runtime_dir(root)), **_windows_programs(root)}
        elif args.action == "install":
            ident = inst.ensure_installed(root, build_dir=Path(args.build_dir) if args.build_dir else None,
                                          container_cli=shutil.which("docker") or shutil.which("podman"))
            result = {"installed": ident, "dir": str(inst.identity_dir(root, ident)),
                      **_windows_programs(root, install=True)}
        else:
            if gateway_service.gateway_dir(root).exists():
                return _fail("the OpenShell gateway is still installed; `hermes sandbox gateway remove` first")
            result = {"removed": inst.remove_runtime(root)}
    except DriverUnavailable as exc:
        return _fail(str(exc))
    print(json.dumps(_jsonable(result), indent=2))
    return 0
