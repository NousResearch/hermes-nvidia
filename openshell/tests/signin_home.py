"""A throwaway Hermes root with one named profile, for the sign-in engine's tests.

``world`` builds the folders the launcher sees: ``<root>/profiles/work`` is the profile's home and
``<root>/openshell/work/pins`` the launcher's host-only copy. Nothing of the computer's own Hermes, Codex or Claude
sign-ins is in reach: the home folders the test process names are throwaway ones, every key and token of its
environment is taken out, and every connection goes to the loopback issuers (``signin_issuers``).

Sign-ins are made the way Hermes makes them on the host with the sandbox off, through its own device-code steps
against those issuers, so every store in a test has the shape Hermes writes.

Run as a program it is the second Hermes of the two-process tests: ``python signin_home.py <role> <port> ...``.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

import signin_issuers

_SECRET_NAMES = re.compile(r"(API_KEY|_TOKEN|_SECRET|ACCESS_KEY|CREDENTIALS|_BASE_URL|^AWS_|^CODEX_|^CLAUDE_)")


def hermes_importable() -> bool:
    try:
        import agent.runtime_scope  # noqa: F401
        import hermes_cli.auth  # noqa: F401
    except ImportError:
        return False
    return True


def files_under(folder: Path) -> dict[str, str]:
    """Every file below *folder* with a digest of its bytes."""
    import hashlib

    out = {}
    for path in sorted(Path(folder).rglob("*")):
        if path.is_file():
            try:
                out[path.relative_to(folder).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
            except OSError:  # a lock file another process holds
                out[path.relative_to(folder).as_posix()] = "held"
    return out


def sign_in(provider: str, issuers=None) -> None:
    """Sign in to *provider* in the current Hermes home, as Hermes does on the host."""
    from hermes_cli import auth

    with mock.patch("time.sleep", lambda seconds: None), contextlib.redirect_stdout(open(os.devnull, "w")):
        if provider == "nous":
            auth.persist_nous_credentials(auth._nous_device_code_login(open_browser=False))
        elif provider == "openai-codex":
            creds = auth._codex_device_code_login()
            auth._save_codex_tokens(creds["tokens"], creds.get("last_refresh"))
        elif provider == "xai-oauth":
            creds = auth._xai_oauth_device_code_login(open_browser=False)
            auth._save_xai_oauth_tokens(creds["tokens"], discovery=creds["discovery"], last_refresh=creds["last_refresh"])
        elif provider == "minimax-oauth":
            auth._minimax_oauth_login(open_browser=False)
        elif provider == "anthropic":
            # Hermes's own Anthropic sign-in asks for a pasted code; its result is written with Hermes's writer.
            from agent import anthropic_credentials

            pair = issuers.open("anthropic")
            anthropic_credentials._write_hermes_oauth_credentials(
                pair["access_token"], pair["refresh_token"], int((issuers.clock() + pair["expires_in"]) * 1000))
        else:
            raise ValueError(provider)


def import_shared_sign_in() -> None:
    """Sign in to Nous Portal in the current Hermes home the way ``hermes auth add nous`` does when another
    profile of this computer is signed in already: Hermes finds that sign-in in its shared store, offers to
    import it, renews it once and saves the renewed pair as this home's own."""
    from hermes_cli import auth

    with contextlib.redirect_stdout(open(os.devnull, "w")):
        state = auth._try_import_shared_nous_state()
        if state is None:
            raise RuntimeError("the shared store holds no sign-in that could be imported")
        auth.persist_nous_credentials(state)


def refresh_token_in(home: Path, provider: str) -> str:
    """The refresh token *home*'s stores hold for *provider* ('' when none)."""
    if provider == "anthropic":
        try:
            kept = json.loads((Path(home) / ".anthropic_oauth.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ""
        return str(kept.get("refreshToken") or "")
    try:
        state = json.loads((Path(home) / "auth.json").read_text(encoding="utf-8")).get("providers", {}).get(provider, {})
    except (OSError, ValueError):
        return ""
    return str(state.get("refresh_token") or (state.get("tokens") or {}).get("refresh_token") or "")


def renew_in_home(provider: str) -> str:
    """One renewal at the issuer by the Hermes of the current home, as its own request path does it. Returns
    the new token; raises what Hermes raises when the sign-in no longer works."""
    from hermes_cli import auth

    if provider == "nous":
        return auth.resolve_nous_runtime_credentials(force_refresh=True)["api_key"]
    if provider == "openai-codex":
        return auth.resolve_codex_runtime_credentials(force_refresh=True)["api_key"]
    if provider == "xai-oauth":
        return auth.resolve_xai_oauth_runtime_credentials(force_refresh=True)["api_key"]
    if provider == "minimax-oauth":
        with auth._auth_store_lock():
            return auth._refresh_minimax_oauth_state(auth.get_provider_auth_state(provider), force=True)["access_token"]
    from agent.credential_pool import load_pool

    pool = load_pool("anthropic")
    entry = next(e for e in pool.entries() if e.source == "hermes_pkce")
    renewed = pool.try_refresh_matching(credential_id=entry.id)
    if renewed is None:
        raise RuntimeError("the Anthropic sign-in was not renewed")
    return renewed.access_token


class World:
    """The folders, the issuers, the clock and the sink of one test."""

    def __init__(self, tmp_path: Path, monkeypatch):
        self.monkeypatch = monkeypatch
        self.root = tmp_path / "root"
        self.home = self.root / "profiles" / "work"
        self.copy = self.root / "openshell" / "work" / "pins"
        self.user = tmp_path / "user"
        for folder in (self.home, self.copy, self.user):
            folder.mkdir(parents=True)
        for name in list(os.environ):
            if _SECRET_NAMES.search(name) or (name.startswith("HERMES_") and name != "HERMES_HOME"):
                monkeypatch.delenv(name)
        for name, value in self.environment(self.home).items():
            monkeypatch.setenv(name, value)
        self.stays_inside()
        self.clock = signin_issuers.Clock()
        self.issuers = signin_issuers.Issuers(self.clock)
        signin_issuers.redirect(self.issuers.port, self.issuers, monkeypatch.setattr)
        signin_issuers.arrivals_on(self.clock, monkeypatch.setattr)
        self.refused = signin_issuers.loopback_only(monkeypatch.setattr)
        self.sink = signin_issuers.Sink(self.clock)

    def environment(self, home: Path) -> dict[str, str]:
        """The variables that keep a Hermes of this world inside it."""
        return {"HERMES_HOME": str(home), "HOME": str(self.user), "USERPROFILE": str(self.user),
                "CODEX_HOME": str(self.user / "codex"), "CLAUDE_CONFIG_DIR": str(self.user / "claude"),
                # Hermes keeps a test process away from the shared Nous store's usual place: name another one.
                "HERMES_SHARED_AUTH_DIR": str(self.root / "shared-store")}

    def stays_inside(self) -> None:
        """Hermes takes a home below this computer's own Hermes folder for a part of it, whatever the folders
        above the home are called. A test would then renew the sign-ins of that folder: refuse before any does."""
        from hermes_constants import get_default_hermes_root

        found = Path(get_default_hermes_root()).resolve()
        if found != self.root.resolve():
            raise RuntimeError(f"the Hermes root resolves to {found}, outside the test folder {self.root}; refusing "
                               "to run (keep pytest's temp folder out of the Hermes folder, see --basetemp)")

    def close(self) -> None:
        self.issuers.close()

    @contextlib.contextmanager
    def at(self, home: Path):
        """Run a body as the Hermes whose own home is *home* (the profile's, or the root for the default one)."""
        with self.monkeypatch.context() as patch:
            patch.setenv("HERMES_HOME", str(home))
            yield

    def config(self, doc: dict, home: Path | None = None) -> None:
        import hermes_yaml

        text = hermes_yaml.safe_dump(doc, sort_keys=False)
        (home or self.home).joinpath("config.yaml").write_text(text, encoding="utf-8")

    def sign_in(self, provider: str, home: Path | None = None) -> None:
        with self.at(home or self.home):
            sign_in(provider, self.issuers)

    def short_token(self, provider: str, seconds: int = 60, home: Path | None = None) -> None:
        """Leave *home*'s store with a token that has *seconds* left: one renewal while the issuer hands out
        short tokens. Hermes stores the pair before it looks at the token, and may then refuse the token."""
        usual, self.issuers.ttl[provider] = self.issuers.ttl[provider], seconds
        try:
            self.renew_in_home(provider, home)
        except Exception:
            pass
        finally:
            self.issuers.ttl[provider] = usual

    def take_copy(self) -> None:
        """What the switch-on does: the profile's stores and env file go into the launcher's copy, and the copy
        gets its config.yaml."""
        from openshell.launcher import signins

        for name in (*signins.SIGN_IN_FILES, ".env"):
            if (self.home / name).is_file():
                shutil.copyfile(self.home / name, self.copy / name)
        signins.write_copy_config(self.home, self.copy)

    def engine(self, **kwargs):
        from openshell.launcher import signins

        return signins.SignIns(self.copy, self.sink, clock=self.clock, sleep=self.clock.sleep, **kwargs)

    def renew_in_home(self, provider: str, home: Path | None = None) -> str:
        with self.at(home or self.home):
            return renew_in_home(provider)

    def child(self, role: str, *args: str, home: Path | None = None, production: bool = True):
        """Start a second Hermes process of this world (``main`` below). *production*: without the marks of a
        test run, so Hermes uses the paths it uses for a user."""
        import subprocess

        env = {k: v for k, v in os.environ.items() if not (production and k == "PYTEST_CURRENT_TEST")}
        env.update(self.environment(home or self.home))
        if production:
            env.pop("HERMES_SHARED_AUTH_DIR", None)
        paths = [str(Path(__file__).resolve().parent), *[p for p in sys.path if p]]
        env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(paths))
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), role, str(self.issuers.port),
                                 *map(str, args)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A profile, its launcher copy, the issuers and a sink. Skipped when no Hermes checkout is importable. At
    the end, no connection may have been tried to anything but loopback."""
    if not hermes_importable():
        pytest.skip("no Hermes checkout is importable")
    built = World(tmp_path, monkeypatch)
    yield built
    built.close()
    assert built.refused == [], "a test reached for an address that is not loopback"


# -- the second process --------------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    """``sign-in <port> <provider>``: the Hermes of the current home signs in.
    ``import <port>``: the Hermes of the current home signs in to Nous Portal by taking over the sign-in it finds
    in the shared store, as ``hermes auth add nous`` offers when another profile is signed in.
    ``host <port> <provider> <rounds>``: the Hermes of the current home renews its sign-in *rounds* times.
    ``engine <port> <copy> <rounds>``: a sign-in engine over *copy* declares and renews *rounds* times.
    ``killed <port> <copy>``: an engine renews once and the process ends, without any cleanup, the moment the
    issuer's answer is in the copy."""
    import no_real_apps

    no_real_apps.install()  # this process runs Hermes's sign-in code outside the test run's own guard
    role, port = argv[0], int(argv[1])
    signin_issuers.redirect(port)
    signin_issuers.loopback_only()
    out = {"role": role, "ok": 0, "errors": []}
    if role == "sign-in":
        sign_in(argv[2])
        out["ok"] = 1
    elif role == "import":
        import_shared_sign_in()
        out["ok"] = 1
    elif role == "host":
        for _ in range(int(argv[3])):
            try:
                renew_in_home(argv[2])
                out["ok"] += 1
            except Exception as exc:
                out["errors"].append(f"{type(exc).__name__}: {str(exc).splitlines()[0][:120]}")
            time.sleep(0.01)
    else:
        from openshell.launcher import signins

        clock = signin_issuers.Clock()
        sink = signin_issuers.Sink(clock)

        def end_now(names):
            os._exit(9)

        engine = signins.SignIns(Path(argv[2]), sink, clock=clock, sleep=clock.sleep,
                                 on_change=end_now if role == "killed" else None)
        declared = engine.declare()
        out["declared"] = [d.id for d in declared]
        for _ in range(int(argv[3]) if role == "engine" else 1):
            for entry in engine._entries.values():
                engine._renew(entry)
                if entry.pending is not None and engine._push(entry):
                    out["ok"] += 1
                else:
                    out["errors"].append(entry.error or "not renewed")
            time.sleep(0.01)
        out["states"] = [row["state"] for row in engine.status()]
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
