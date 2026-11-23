"""Inside a Windows sandbox: programs that follow the proxy variables reach this computer's own services directly.

MXC lets a sandbox connect to every port on the computer's own addresses, loopback included, whatever the network
policy says; the Sandbox page says so. OpenShell starts the backend with ``HTTP_PROXY`` and ``HTTPS_PROXY`` set to
its proxy and ``NO_PROXY`` empty, in place of whatever the sandbox's environment asked for, and that proxy refuses
every loopback address. A program that opens its own socket therefore reached a service on this computer, while one
that follows the proxy variables (curl, Python's urllib and requests, Node) was refused for the same address.

The launcher's Windows driver names the case in the sandbox's environment (``LOOPBACK_ENV``). The plugin, loaded by
the backend inside, then lists ``LOOPBACK_HOSTS`` in ``NO_PROXY`` and ``no_proxy`` of the backend's own process,
and what the backend starts (the terminal's programs) inherits them. Those three names are all it adds: every
other destination still goes through OpenShell's proxy and the sandbox's network policy, the model's endpoint
(``host.openshell.internal``) included. Nothing becomes reachable that a direct connection from inside did not
already reach.

The Linux driver does not set the variable: a Linux sandbox has its own loopback and no proxy variables.
"""
from __future__ import annotations

import os
import re

LOOPBACK_ENV = "HERMES_SANDBOX_LOOPBACK"
DIRECT = "direct"
# The names Hermes itself never sends through a proxy (its own LOOPBACK_HOSTS), in the form curl, Python and Node read.
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
_NO_PROXY_KEYS = ("NO_PROXY", "no_proxy")


def _entries(value) -> list[str]:
    return [part for part in re.split(r"[\s,]+", str(value or "").strip()) if part]


def apply(environ=None) -> bool:
    """List the loopback names in ``NO_PROXY`` / ``no_proxy`` of *environ* (this process's environment by default)
    when the launcher asked for it; True when it did. Entries already there stay, and a ``*`` (nothing goes through
    a proxy) is left alone."""
    env = os.environ if environ is None else environ
    if env.get(LOOPBACK_ENV) != DIRECT:
        return False
    for key in _NO_PROXY_KEYS:
        entries = _entries(env.get(key))
        if "*" in entries:
            continue
        missing = [host for host in LOOPBACK_HOSTS if host not in entries]
        if missing:
            env[key] = ",".join(entries + missing)
    return True
