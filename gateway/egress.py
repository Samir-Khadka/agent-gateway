"""Egress controls: where an agent may send data.

An agent exfiltrates data through a URL, an email, or a tool
argument. The policy's `egress_allowlist` is the list of domains an
agent may reach. Any call that would send data somewhere else — a
`web.fetch` URL, an `email.send` recipient — is denied unless its
destination is on the list. A policy without an allowlist imposes no
egress restriction (not every agent needs one); a policy with one
enforces it on every call.
"""
from __future__ import annotations

from urllib.parse import urlsplit


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def destination_of(tool: str, args: dict) -> str:
    """The destination a call would send data to, or '' when the call
    sends nothing anywhere."""
    if "url" in args:
        return _host_of(str(args["url"])).lower()
    if "to" in args:
        return str(args["to"]).rsplit("@", 1)[-1].strip().lower()
    return ""


def _allowed(dest: str, entry: str) -> bool:
    """Whether a destination is covered by one allowlist entry. A
    plain entry covers the domain and its subdomains; a wildcard
    entry (*.company.com) covers subdomains only."""
    entry = entry.lower()
    if entry.startswith("*."):
        return dest.endswith(entry[1:]) and dest != entry[2:]
    return dest == entry or dest.endswith("." + entry)


def check_egress(allowlist: list[str] | None, tool: str,
                 args: dict) -> str | None:
    """A reason to deny, or None when the destination is allowed (or
    the call sends nothing, or the policy has no allowlist)."""
    if not allowlist:
        return None
    dest = destination_of(tool, args)
    if not dest:
        return None
    if any(_allowed(dest, entry) for entry in allowlist):
        return None
    return (f"egress denied: {dest} is not on this agent's "
            f"allowlist ({', '.join(allowlist)})")
