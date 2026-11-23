"""Tool categories: what Hermes's tools may use outside the sandbox, one approval each.

At switch-on a sandbox opens what the profile's model needs and nothing a tool needs. A tool's services open
the first time a tool of its category is used, with one card in the chat (cards.py); the approval covers the
category, whichever service the profile's settings send the tool to:

* the services a tool uses without a key (Hermes's web tools rotate through four of them),
* the Nous tool gateway's host for it, where the profile is signed in to Nous Portal: the sign-in's token is
  bound to that host only once the category is approved (signins.py), and
* a vendor's own host, where the profile holds that vendor's key (the key discovery binds it then).

The table is read from Hermes's tools, not from host names: ``tools`` are the tool names, ``gateways`` the vendor
names those tools ask Hermes's ``build_vendor_gateway_url`` for. A gateway vendor no tool here names stays
closed, and no category opens another's hosts.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urlsplit

from .refusals import KEYLESS_WEB_HOSTS

RULE_PREFIX = "allowed_tool_"  # the saved approval of a category: the rule ``allowed_tool_<id>``
GATEWAY_DOMAIN = "nousresearch.com"


@dataclass(frozen=True)
class Category:
    """``id`` names the saved approval; ``label`` is what the card and the Sandbox page call it. ``prefixes``
    match tool names that are made at run time. ``reach`` is what an approval opens beyond the listed services,
    in the card's words."""
    id: str
    label: str
    tools: tuple = ()
    prefixes: tuple = ()
    gateways: tuple = ()
    keyless: tuple = ()
    reach: str = ""


CATEGORIES = (
    # Hermes's managed web route searches through the perplexity vendor and falls back to firecrawl. Every
    # service a search uses also fetches pages, and nothing separates the two uses of one host: the card says so.
    Category("web_search", "Web search", tools=("web_search",), gateways=("perplexity", "firecrawl"),
             keyless=KEYLESS_WEB_HOSTS,
             reach="They also fetch pages, so the agent can read any public page."),
    Category("web_extract", "Web extract", tools=("web_extract", "web_crawl"), gateways=("firecrawl",),
             keyless=KEYLESS_WEB_HOSTS,
             reach="They fetch pages for it, so it can read any public page."),
    Category("browser", "Browser", tools=("browser_exec", "browser_cdp", "browser_dialog", "browser_vault"),
             prefixes=("browser_",), gateways=("browser-use",),
             reach="It runs a browser for the tool, which can open any public page."),
    Category("image_gen", "Image generation", tools=("image_generate",), gateways=("fal-queue", "krea")),
    Category("video_gen", "Video generation", tools=("video_generate",), gateways=("fal-queue",)),
    Category("speech", "Speech", tools=("text_to_speech",), gateways=("openai-audio",)),
    Category("connected_apps", "Connected apps", tools=("manage_connections",), prefixes=("connectors__",),
             gateways=("connector",)),
    # A terminal that runs on a hosted machine. No tool name: the terminal tool usually runs in the sandbox.
    Category("remote_terminal", "Remote terminal", gateways=("modal",)),
)
_BY_ID = {category.id: category for category in CATEGORIES}

# Keys of web services Hermes's own code places on the wire, by variable: the categories whose tools use them.
KEY_CATEGORIES = {
    "TAVILY_API_KEY": ("web_search", "web_extract"),
    "KEENABLE_API_KEY": ("web_search", "web_extract"),
    "PERPLEXITY_API_KEY": ("web_search", "web_extract"),
    "BRAVE_SEARCH_API_KEY": ("web_search",),
}


def by_id(category_id: str) -> Optional[Category]:
    return _BY_ID.get(str(category_id or ""))


def of_tool(tool: Optional[str]) -> Optional[Category]:
    """The category of a Hermes tool, by its name."""
    name = str(tool or "")
    if not name:
        return None
    for category in CATEGORIES:
        if name in category.tools:
            return category
    for category in CATEGORIES:
        if name.startswith(category.prefixes) and category.prefixes:
            return category
    return None


def of_rule(rule_name: str) -> Optional[Category]:
    """The category a saved approval's rule name stands for."""
    name = str(rule_name or "")
    return by_id(name[len(RULE_PREFIX):]) if name.startswith(RULE_PREFIX) else None


def granted(*approved: Optional[dict]) -> set:
    """The ids of the categories approved in *approved* (maps of rules by name: the saved ones and the ones that
    last until the sandbox is switched off)."""
    out = set()
    for rules in approved:
        for name in rules or {}:
            category = of_rule(name)
            if category is not None:
                out.add(category.id)
    return out


def gateway_url(vendor: str) -> str:
    """The address Hermes's tools use for one vendor of the Nous tool gateway, as Hermes builds it."""
    try:
        from tools.managed_tool_gateway import build_vendor_gateway_url
    except ImportError:
        return f"https://{vendor}-gateway.{GATEWAY_DOMAIN}"
    try:
        return str(build_vendor_gateway_url(vendor))
    except ValueError:
        return f"https://{vendor}-gateway.{GATEWAY_DOMAIN}"


def endpoint_of(url: str) -> Optional[tuple]:
    """``(host, port)`` of an address, or None."""
    parts = urlsplit(str(url or ""))
    if not parts.hostname:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    return parts.hostname.lower(), int(port or (80 if parts.scheme == "http" else 443))


def gateway_endpoints(category: Category) -> list:
    """``[(host, port)]`` of the Nous tool gateway for *category*, in the order of its vendors."""
    out = []
    for vendor in category.gateways:
        endpoint = endpoint_of(gateway_url(vendor))
        if endpoint is not None and endpoint not in out:
            out.append(endpoint)
    return out


def of_gateway(host: str, port: Optional[int] = None) -> Optional[Category]:
    """The category a host of the Nous tool gateway belongs to: the one whose tools ask for it first, else the
    first that uses it at all. None for any other host, a gateway vendor no category names included."""
    host = str(host or "").lower()
    found = None
    for category in CATEGORIES:
        for position, (name, at) in enumerate(gateway_endpoints(category)):
            if name == host and (port is None or int(port) == at):
                if position == 0:
                    return category
                found = found or category
    return found


def key_categories(env: str) -> tuple:
    return KEY_CATEGORIES.get(str(env or ""), ())


def use_label(host: str, port: Optional[int] = None, env: Optional[str] = None,
              approved: Optional[Iterable[str]] = None, was: Optional[str] = None) -> Optional[str]:
    """What a host a credential is used at is for, when that is a tool category: its label (the labels of
    both, for a key or a host two categories share). With *approved* (category ids), only the categories whose
    approval opened it are named. A host none of them opened is still bound while its approval is on the way
    out (the sandbox restarts to take it away): it keeps the name it had (*was*), else that of the first
    category that uses it, never the names of approvals nobody gave. None for a model's host."""
    ids = list(key_categories(env or ""))
    if not ids:
        host = str(host or "").lower()
        ids = [category.id for category in CATEGORIES
               if any(name == host and (port is None or int(port) == at) for name, at in gateway_endpoints(category))]
    if approved is not None:
        named = [cid for cid in ids if cid in set(approved)]
        if not named and ids and was:
            return was
        first = None if named or key_categories(env or "") else of_gateway(host, port)
        ids = named or ([first.id] if first is not None else ids[:1])
    elif not key_categories(env or ""):
        category = of_gateway(host, port)
        ids = [category.id] if category is not None else []
    return " and ".join(dict.fromkeys(labels(ids))) or None


def host_text(host: str, port: Optional[int]) -> str:
    """A service as a card and a grant's row name it: the host, with its port when that is not the https one."""
    return str(host) if port in (None, 443) else f"{host}:{port}"


def labels(ids: Iterable[str]) -> list:
    return [by_id(cid).label for cid in ids if by_id(cid) is not None]
