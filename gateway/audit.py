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
    cost: float = 0.0  # what this call cost (dollars), for spend budgets
    rows: int = 0  # rows read by this call, for row budgets
    prev_hash: str = ""
    hash: str = ""

    def canonical(self) -> str:
        """The entry as a fixed-form string — what the hash is
        computed over. Note: verify() hashes the stored dict, not
        this, so an entry written by an older version (without the
        cost/rows fields) still verifies."""
        data = asdict(self)
        data.pop("hash")
        return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _hash_dict(data: dict) -> str:
    """The hash of a stored entry dict (its own fields, minus the
    hash itself). Hashing the stored dict — not a dataclass rebuilt
    from it — is what keeps old entries verifiable after the schema
    grows a field."""
    body = {k: v for k, v in data.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()


def _hash(entry: AuditEntry) -> str:
    return _hash_dict(asdict(entry))


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
               tainted: bool = False, cost: float = 0.0,
               rows: int = 0) -> AuditEntry:
        entry = AuditEntry(
            seq=self._seq + 1,
            ts=datetime.now(timezone.utc).isoformat(),
            agent=agent, tool=tool, args=args, decision=decision,
            reason=reason, result=result, tainted=tainted,
            cost=cost, rows=rows,
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
        entries = self.read()
        for i, raw in enumerate(entries, start=1):
            if raw.get("prev_hash") != prev:
                return False, (f"entry {i}: prev_hash does not match "
                               f"entry {i - 1}")
            if _hash_dict(raw) != raw.get("hash"):
                return False, f"entry {i}: hash does not match its content"
            prev = raw["hash"]
        return True, f"chain intact ({len(entries)} entries)"
