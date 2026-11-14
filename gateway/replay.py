"""Incident replay: reconstruct what happened from the audit log.

After an incident, the question is not "what did the agent do" —
it is "what happened, in order, and what caused it". Replay reads
the hash-chained log and rebuilds the sequence: which call tainted
a session, which calls were blocked or held after that, and what
the session spent and read. It is the answer to threat #7
(repudiation) in usable form.

Run: python -m gateway.replay data/audit.jsonl [--agent X]
         [--session Y] [--decision deny]
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Incident:
    entries: list[dict] = field(default_factory=list)
    taint_event: dict | None = None  # the first call that tainted
    # the session (the entry after which it was tainted)
    blocked_after_taint: list[dict] = field(default_factory=list)
    held: list[dict] = field(default_factory=list)
    total_spend: float = 0.0
    total_rows: int = 0

    @property
    def decisions(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self.entries:
            counts[e["decision"]] = counts.get(e["decision"], 0) + 1
        return counts


def load_log(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None


def replay(path: str | Path, agent: str | None = None,
           session_id: str | None = None,
           decision: str | None = None,
           since: str | None = None,
           until: str | None = None) -> Incident:
    """Filter the log and summarise it as an incident."""
    entries = load_log(path)
    if agent:
        entries = [e for e in entries if e.get("agent") == agent]
    if session_id:
        entries = [e for e in entries
                   if e.get("session_id", "default") == session_id]
    if decision:
        entries = [e for e in entries if e.get("decision") == decision]
    if since:
        start = _parse_ts(since)
        entries = [e for e in entries
                   if (t := _parse_ts(e.get("ts", ""))) and t >= start]
    if until:
        end = _parse_ts(until)
        entries = [e for e in entries
                   if (t := _parse_ts(e.get("ts", ""))) and t <= end]
    incident = Incident(entries=entries)
    incident.total_spend = sum(float(e.get("cost", 0.0))
                               for e in entries)
    incident.total_rows = sum(int(e.get("rows", 0)) for e in entries)
    incident.held = [e for e in entries
                     if e.get("decision") == "require_approval"]
    # The taint event is the first entry after which the session was
    # tainted — the call whose result was untrusted. The audit log
    # marks entries with the session's taint state at the time of
    # the call, so the tainting call is the last clean entry before
    # the first tainted one.
    tainted = [e for e in entries if e.get("tainted")]
    if tainted:
        first_tainted = tainted[0]
        idx = entries.index(first_tainted)
        incident.taint_event = entries[idx - 1] if idx > 0 else None
        incident.blocked_after_taint = [
            e for e in entries[idx:]
            if e.get("decision") == "deny"]
    return incident


def render_text(incident: Incident) -> str:
    lines = []
    lines.append(f"{len(incident.entries)} entries")
    if incident.decisions:
        lines.append("decisions: " + ", ".join(
            f"{k} {v}" for k, v in sorted(incident.decisions.items())))
    lines.append(f"spend ${incident.total_spend:.2f} · "
                 f"{incident.total_rows} rows read")
    if incident.taint_event:
        e = incident.taint_event
        lines.append(f"tainted by: #{e['seq']} {e['tool']} "
                     f"({e.get('ts', '')})")
        for b in incident.blocked_after_taint:
            lines.append(f"  blocked after taint: #{b['seq']} {b['tool']} "
                         f"— {b.get('reason', '')}")
    for e in incident.entries:
        taint = " [tainted]" if e.get("tainted") else ""
        lines.append(f"  #{e['seq']} {e.get('ts', '')} {e['agent']} "
                     f"{e['tool']} -> {e['decision']}{taint}")
        if e.get("reason"):
            lines.append(f"      {e['reason']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay an incident from the audit log.")
    parser.add_argument("log", help="audit log file (JSONL)")
    parser.add_argument("--agent", help="only this agent")
    parser.add_argument("--session", help="only this session id")
    parser.add_argument("--decision",
                        help="only this decision (allow/deny/...)")
    parser.add_argument("--since", help="ISO timestamp, inclusive")
    parser.add_argument("--until", help="ISO timestamp, inclusive")
    args = parser.parse_args(argv)
    incident = replay(args.log, agent=args.agent,
                      session_id=args.session, decision=args.decision,
                      since=args.since, until=args.until)
    print(render_text(incident))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
