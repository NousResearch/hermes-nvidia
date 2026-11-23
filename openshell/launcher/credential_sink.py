"""Credentials the launcher hands to the sandbox driver.

The sign-in engine and the key discovery describe each credential once; the driver turns it into an OpenShell
provider with the declared placement. Nothing here talks to OpenShell or holds a secret at rest.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

PLACEMENTS = ("bearer", "header", "query", "path", "basic", "sigv4")
PROTOCOLS = ("rest", "websocket")


@dataclass(frozen=True)
class Endpoint:
    """One address a credential may be used at. ``path_prefix`` None means every path."""
    host: str
    port: int
    path_prefix: Optional[str] = None
    protocol: str = "rest"


@dataclass(frozen=True)
class CredentialDecl:
    """One credential as the sandbox may use it.

    ``id`` stays the same for the life of the sandbox (for example ``nous:agent_key``); ``label`` is what the
    Sandbox page shows. ``placement`` says where the credential travels on the wire and ``name`` the header or
    query parameter name, or the path template, that placement needs. ``expires`` marks a credential whose value
    the launcher replaces while the sandbox runs: the driver declares it with a stable placeholder and expiry
    metadata.
    """
    id: str
    label: str
    endpoints: tuple[Endpoint, ...]
    placement: str = "bearer"
    name: Optional[str] = None
    expires: bool = False


class CredentialSink(Protocol):
    """What a sandbox driver offers for credentials."""

    def declare(self, decl: CredentialDecl, value: str, expires_at: Optional[float]) -> str:
        """Register *decl* before the sandbox starts. Returns the name of the environment variable that holds
        the credential's placeholder inside the sandbox."""

    def update(self, cred_id: str, value: str, expires_at: Optional[float]) -> None:
        """Replace the value of a declared credential while the sandbox runs. The placeholder inside does not
        change."""

    def withdraw(self, cred_id: str) -> None:
        """Take a declared credential out of every sandbox start that follows, until it is declared again. A
        sandbox that runs keeps what it started with."""

    def quiet(self) -> bool:
        """True while no reply is streaming in this sandbox: the moment a value may be replaced without cutting
        a stream."""
