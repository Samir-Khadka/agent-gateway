"""Tamper-evident audit log: append-only, hash-chained.

Every tool call the gateway sees — allowed, denied, held, or
forwarded — is one line of JSONL. Each entry carries the SHA-256 of
the previous entry, so deleting or editing a line breaks the chain
and `verify` reports the first bad entry. That is the answer to
threat #7 (repudiation): after an incident, every tool call, its
arguments, its result, and its trigger can be replayed and proven.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class AuditEntry:
    seq: int
    ts: str
    agent: str
    tool: str
    args: dict
    decision: str
    reason: str
    result: str = ""
    tainted: bool = False
    prev_hash: str = ""
    hash: str = ""

    def canonical(self) -> str:
        """The entry without its hash, in a fixed form — what the
        hash is computed over."""
        data = asdict(self)
        data.pop("hash")
        return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _hash(entry: AuditEntry) -> str:
    return hashlib.sha256(entry.canonical().encode()).hexdigest()


class AuditLog:
    """An append-only log file. One log per gateway (the path is
    configured); the chain is verified in full on demand."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = self._count()

    def _count(self) -> int:
        if not self.path.exists():
            return 0
        return sum(1 for _ in self.path.open(encoding="utf-8"))

    def _last_hash(self) -> str:
        if self._seq == 0 or not self.path.exists():
            return "0" * 64
        last = None
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        return json.loads(last)["hash"] if last else "0" * 64

    def append(self, agent: str, tool: str, args: dict, decision: str,
               reason: str, result: str = "",
               tainted: bool = False) -> AuditEntry:
        entry = AuditEntry(
            seq=self._seq + 1,
            ts=datetime.now(timezone.utc).isoformat(),
            agent=agent, tool=tool, args=args, decision=decision,
            reason=reason, result=result, tainted=tainted,
            prev_hash=self._last_hash())
        entry.hash = _hash(entry)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry)) + "\n")
        self._seq += 1
        return entry

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def verify(self) -> tuple[bool, str]:
        """Recompute the chain. Returns (ok, message); on failure the
        message names the first bad entry."""
        prev = "0" * 64
        for i, raw in enumerate(self.read(), start=1):
            entry = AuditEntry(**{k: v for k, v in raw.items()
                                  if k in AuditEntry.__dataclass_fields__})
            if entry.prev_hash != prev:
                return False, (f"entry {i}: prev_hash does not match "
                               f"entry {i - 1}")
            if _hash(entry) != entry.hash:
                return False, f"entry {i}: hash does not match its content"
            prev = entry.hash
        return True, f"chain intact ({len(self.read())} entries)"
