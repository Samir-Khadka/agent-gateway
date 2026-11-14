"""Taint tracking: a session that touched untrusted content gets
tighter rules.

The strongest defense against indirect prompt injection is not a
text filter — it is what the gateway does *after* the injection.
Data is labeled by trust. A session starts clean. Once it has
received content from an untrusted source (a web page, an email, a
file — anything a tool fetched from outside), the session is tainted,
and the policy's `deny_when_tainted` rules apply to every later
call. A tainted session stays tainted until a human clears it.

Taint sources (tools whose results are untrusted by definition):
  web.fetch, email.read, file.read — plus any tool the policy lists
  under `taint_sources`. The upstream can also label a single result
  as untrusted by returning `{"tainted": true}` in it.
"""
from __future__ import annotations

import json
from pathlib import Path

# Tools whose results are untrusted by definition — they fetch
# content from outside the agent's control.
DEFAULT_TAINT_SOURCES = {"web.fetch", "email.read", "file.read"}


class TaintTracker:
    """The set of tainted session ids, persisted so a restart does
    not silently clean a session."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.tainted: set[str] = self._load()

    def _load(self) -> set[str]:
        if not self.path.exists():
            return set()
        try:
            return set(json.loads(self.path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return set()

    def _save(self) -> None:
        self.path.write_text(json.dumps(sorted(self.tainted)),
                             encoding="utf-8")

    def is_tainted(self, session_id: str) -> bool:
        return session_id in self.tainted

    def taint(self, session_id: str) -> None:
        self.tainted.add(session_id)
        self._save()

    def clear(self, session_id: str) -> None:
        self.tainted.discard(session_id)
        self._save()


def result_is_untrusted(tool: str, result: dict,
                       policy_taint_sources: set[str] | None = None) -> bool:
    """Whether a tool result should taint the session: the tool is a
    known untrusted source, the policy lists it, or the result itself
    is labeled untrusted by the upstream."""
    sources = DEFAULT_TAINT_SOURCES | (policy_taint_sources or set())
    if tool in sources:
        return True
    payload = result.get("result", result)
    if isinstance(payload, dict) and payload.get("tainted") is True:
        return True
    return False
