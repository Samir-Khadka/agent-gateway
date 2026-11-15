"""Metrics: what the gateway is doing, in numbers.

Two views of the same state, both computed from the audit log and
the gateway's in-memory counters (so a restart rebuilds them from
the log):
  GET /metrics      — Prometheus text format, for scraping
  GET /admin/stats  — the same numbers as JSON, for the dashboard
"""
from __future__ import annotations


def compute_stats(gateway) -> dict:
    """The gateway's numbers: calls, decisions, taint, spend, rows,
    approvals. Read from the audit log (the source of truth) plus
    the live taint and approval stores."""
    entries = gateway.audit.read()
    decisions: dict[str, int] = {}
    per_agent: dict[str, dict] = {}
    spend = 0.0
    rows = 0
    for e in entries:
        decisions[e["decision"]] = decisions.get(e["decision"], 0) + 1
        spend += float(e.get("cost", 0.0))
        rows += int(e.get("rows", 0))
        agent = e["agent"]
        stats = per_agent.setdefault(
            agent, {"calls": 0, "spend": 0.0, "rows": 0})
        stats["calls"] += 1
        stats["spend"] += float(e.get("cost", 0.0))
        stats["rows"] += int(e.get("rows", 0))
    tainted = sorted(gateway.taint.tainted)
    return {
        "total_calls": len(entries),
        "decisions": decisions,
        "per_agent": per_agent,
        "total_spend": round(spend, 4),
        "total_rows": rows,
        "tainted_sessions": tainted,
        "tainted_session_count": len(tainted),
        "pending_approvals": len(gateway.approvals.pending()),
        "killed_agents": sorted(gateway.killed),
    }


def render_prometheus(stats: dict) -> str:
    lines = [
        "# HELP agent_gateway_calls_total Total MCP calls seen",
        "# TYPE agent_gateway_calls_total counter",
        f"agent_gateway_calls_total {stats['total_calls']}",
        "# HELP agent_gateway_decisions_total Calls by decision",
        "# TYPE agent_gateway_decisions_total counter",
    ]
    for decision, count in sorted(stats["decisions"].items()):
        lines.append(f'agent_gateway_decisions_total{{decision="{decision}"}} {count}')
    lines += [
        "# HELP agent_gateway_spend_total Total spend in dollars",
        "# TYPE agent_gateway_spend_total counter",
        f"agent_gateway_spend_total {stats['total_spend']}",
        "# HELP agent_gateway_rows_total Total rows read",
        "# TYPE agent_gateway_rows_total counter",
        f"agent_gateway_rows_total {stats['total_rows']}",
        "# HELP agent_gateway_tainted_sessions Tainted sessions now",
        "# TYPE agent_gateway_tainted_sessions gauge",
        f"agent_gateway_tainted_sessions {stats['tainted_session_count']}",
        "# HELP agent_gateway_pending_approvals Approvals waiting",
        "# TYPE agent_gateway_pending_approvals gauge",
        f"agent_gateway_pending_approvals {stats['pending_approvals']}",
    ]
    for agent, s in sorted(stats["per_agent"].items()):
        lines.append(
            f'agent_gateway_agent_calls_total{{agent="{agent}"}} '
            f"{s['calls']}")
    return "\n".join(lines) + "\n"
