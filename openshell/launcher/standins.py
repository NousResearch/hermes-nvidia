"""The stand-in sign-in store a sandbox starts with, prepared on this computer before every sandbox start.

A profile that is signed in to a provider keeps its tokens in sign-in files in its home. The sandbox never gets
them. The launcher keeps the real files in its host-only copy (pins.py), keeps the sign-ins current there
(signins.py) and hands each current token to the sandbox driver, which gives the sandbox a placeholder. This
module makes what the sandbox needs to find itself signed in:

* ``build`` reads the copy's sign-in files, takes every secret out (``inside/standin.py``, ``build_template``),
  records for each credential the variable that holds its placeholder inside, and leaves out every credential
  the launcher did not hand to the driver, with the row that needs it.
* ``write`` puts the template and a copy of the start-up step into a folder of the launcher's state that the
  sandbox reads and cannot change. Neither holds a secret.
* ``command`` puts the start-up step in front of the command the sandbox runs. The step is started by its path:
  it fills the template from the placeholders in its environment, writes the stand-in files under the real
  names in the profile home, and then runs the command.

A sign-in file gets a stand-in only when at least one credential in it was handed to the driver. Every other
credential file stays hidden exactly as it is without this module, and a profile with no sign-in gets no
template, no start-up step and the command as it was.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from ..inside import standin

log = logging.getLogger("openshell.standins")

DIRNAME = "standin"
TEMPLATE_FILE = "template.json"
STEP_FILE = "standin.py"

# Sign-ins whose stand-in row carries no refresh grant at all, instead of the fixed word a stand-in holds in
# its place: every sign-in the launcher carries. After a refused request Hermes tries a refresh with whatever
# the row holds. Where the address that renews the sign-in is one the sandbox may reach (Nous Portal, MiniMax:
# the token itself is used there), or becomes one because the user allows it, the issuer answers that the grant
# is not valid and Hermes signs the row out until the sandbox restarts (seen for Nous Portal, OpenAI Codex and
# xAI). Without a grant Hermes has nothing to try with: no request leaves, and the row stays signed in, for each
# of the five.
WITHOUT_GRANTS = ("nous", "openai-codex", "xai-oauth", "minimax-oauth", "anthropic")

# Where each sign-in is renewed. A request there from the backend inside the sandbox could only be a refresh
# attempt (a stand-in written by an earlier version still holds the fixed word): it is refused, and it is not a
# website the user is asked about (``token_hosts``).
_TOKEN_HOSTS = {
    "nous": ("portal.nousresearch.com",),
    "openai-codex": ("auth.openai.com",),
    "xai-oauth": ("auth.x.ai",),
    "minimax-oauth": ("api.minimax.io", "api.minimaxi.com"),
    "anthropic": ("platform.claude.com", "console.anthropic.com"),
}


@dataclass(frozen=True)
class Plan:
    """What one sandbox start gets. ``names``: the sign-in files whose name in the home holds a stand-in while
    the sandbox runs (the launcher takes the real file out first, and the driver neither hides nor holds that
    name). ``template`` and ``step``: the files the sandbox reads, None when the profile has nothing to stand in
    for. ``left_out``: credentials of the copy that were not handed to the driver, by id."""
    names: tuple = ()
    template: Optional[Path] = None
    step: Optional[Path] = None
    credentials: tuple = ()
    left_out: tuple = ()

    @property
    def folder(self) -> Optional[Path]:
        return self.template.parent if self.template is not None else None


def folder(layout) -> Path:
    return layout.state_dir / DIRNAME


def build(engine, env_tokens: Optional[dict] = None) -> tuple[Optional[dict], tuple, tuple]:
    """``(template, names, left out)`` for the sign-ins *engine* declared (``signins.SignIns``) and the token
    variables *env_tokens* (``{variable: provider}``: sign-in tokens the profile keeps in its env file, which the
    driver hands in as keys). The template is None when there is nothing to stand in for."""
    stores = engine.stores() if engine is not None else {}
    present = {name: doc for name, doc in stores.items() if doc is not None and name in standin.STORE_FILES}
    env_tokens = dict(env_tokens or {})
    if not present and not env_tokens:
        return None, (), ()
    template, credentials = standin.build_template(present, env_tokens, without_grants=WITHOUT_GRANTS)
    left_out = []
    for credential in credentials:
        ident = credential["id"]
        if ident.startswith("env:"):
            variable = credential["field"]  # the driver hands a key in under its own variable
        else:
            variable = engine.variable_of(standin.credential_value(present, credential))
        if variable:
            template["credentials"][ident]["env"] = variable
        else:
            left_out.append(ident)
    template = standin.without(template, left_out)
    names = []
    for name in sorted(template["files"]):
        doc = template["files"][name]
        # A file none of whose credentials was handed in gets no stand-in: it stays hidden, as it is today.
        if doc is None or "@@alias:" not in json.dumps(doc) and "@@placeholder:" not in json.dumps(doc):
            del template["files"][name]
        else:
            names.append(name)
    if not names and not template["env"]:
        return None, (), tuple(left_out)
    return template, tuple(names), tuple(left_out)


def write(layout, template: Optional[dict], names: Iterable[str] = (), left_out: Iterable[str] = ()) -> Plan:
    """Put *template* and the start-up step where the sandbox reads them, or take both away (*template* None).
    Each file is written whole to a temp file and renamed into place."""
    target = folder(layout)
    if template is None:
        shutil.rmtree(target, ignore_errors=True)
        return Plan(left_out=tuple(left_out))
    target.mkdir(parents=True, exist_ok=True)
    _readable(target, 0o755)
    step = Path(standin.__file__).resolve()
    _write_whole(target / TEMPLATE_FILE, json.dumps(template, indent=1, sort_keys=True).encode("utf-8"))
    _write_whole(target / STEP_FILE, step.read_bytes())
    return Plan(names=tuple(names), template=target / TEMPLATE_FILE, step=target / STEP_FILE,
                credentials=tuple(sorted(template.get("credentials") or {})), left_out=tuple(left_out))


def command(plan: Optional[Plan], argv: list) -> list:
    """*argv* with the start-up step in front, started by its path with the interpreter the command itself
    starts with; *argv* unchanged without a template."""
    if plan is None or plan.template is None or plan.step is None or not argv:
        return list(argv)
    return [str(argv[0]), str(plan.step), "--", *[str(arg) for arg in argv]]


def environment(plan: Optional[Plan]) -> dict:
    """The variable that names the template for the start-up step; nothing without a template."""
    if plan is None or plan.template is None:
        return {}
    return {standin.TEMPLATE_ENV: str(plan.template)}


def token_hosts(providers: Iterable[str]) -> set:
    """The hosts at which the sign-ins *providers* are renewed, lower case."""
    return {host for provider in providers for host in _TOKEN_HOSTS.get(provider, ())}


def _readable(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _write_whole(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".standin-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _readable(Path(tmp), 0o644)  # no secret in it, and the sandbox may run as another user
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
