"""Timeline dashboard: the audit log as a readable page.

A single server-rendered HTML page (no build step, no JavaScript
framework): a summary bar, filters by agent / session / decision,
and the entries as a timeline — decision badges, taint markers, and
the reason for every call. It reuses the Incident Copilot timeline
idea: the point is to see, at a glance, what an agent did and what
stopped it.
"""
from __future__ import annotations

import html

COLORS = {
    "allow": "#1a7f37",
    "deny": "#cf222e",
    "require_approval": "#9a6700",
}

CSS = """
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;
padding:0 1rem;color:#1f2328;background:#fff}
h1{font-size:1.4rem} .summary{display:flex;gap:1rem;flex-wrap:wrap;
margin:1rem 0} .stat{border:1px solid #d0d7de;border-radius:6px;
padding:.5rem 1rem} .stat b{font-size:1.2rem;display:block}
.filters{margin:1rem 0} .filters a{margin-right:.75rem}
.entry{border-left:3px solid #d0d7de;padding:.4rem .8rem;margin:.4rem 0}
.entry.deny{border-color:#cf222e} .entry.allow{border-color:#1a7f37}
.entry.require_approval{border-color:#9a6700}
.badge{display:inline-block;color:#fff;border-radius:4px;padding:0 .4rem;
font-size:.8rem} .taint{color:#8250df;font-weight:600}
.reason{color:#57606a;font-size:.9rem} .meta{color:#57606a;font-size:.85rem}
"""


def render_dashboard(entries: list[dict], agent: str | None = None,
                     session_id: str | None = None,
                     decision: str | None = None) -> str:
    counts: dict[str, int] = {}
    spend = 0.0
    rows = 0
    tainted_sessions = set()
    for e in entries:
        counts[e["decision"]] = counts.get(e["decision"], 0) + 1
        spend += float(e.get("cost", 0.0))
        rows += int(e.get("rows", 0))
        if e.get("tainted"):
            tainted_sessions.add(e.get("session_id", "default"))
    filtered = entries
    if agent:
        filtered = [e for e in filtered if e.get("agent") == agent]
    if session_id:
        filtered = [e for e in filtered
                    if e.get("session_id", "default") == session_id]
    if decision:
        filtered = [e for e in filtered if e.get("decision") == decision]

    def esc(value) -> str:
        return html.escape(str(value))

    stats = "".join(
        f'<div class="stat"><b>{counts.get(k, 0)}</b>{k}</div>'
        for k in ("allow", "deny", "require_approval"))
    stats += (f'<div class="stat"><b>{len(tainted_sessions)}</b>'
              f'tainted sessions</div>'
              f'<div class="stat"><b>${spend:.2f}</b>spend</div>'
              f'<div class="stat"><b>{rows}</b>rows read</div>')
    agents = sorted({e["agent"] for e in entries})
    filter_links = "".join(
        f'<a href="?agent={esc(a)}">{esc(a)}</a>' for a in agents)
    rows_html = []
    for e in reversed(filtered):
        color = COLORS.get(e["decision"], "#57606a")
        taint = (' <span class="taint">[tainted]</span>'
                 if e.get("tainted") else "")
        rows_html.append(
            f'<div class="entry {esc(e["decision"])}">'
            f'<span class="badge" style="background:{color}">'
            f'{esc(e["decision"])}</span> '
            f'<b>{esc(e["tool"])}</b>{taint}<br>'
            f'<span class="meta">#{e["seq"]} {esc(e.get("ts", ""))} · '
            f'{esc(e["agent"])} · session '
            f'{esc(e.get("session_id", "default"))}</span><br>'
            f'<span class="reason">{esc(e.get("reason", ""))}</span>'
            f'</div>')
    return (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>Agent Gateway — timeline</title>"
            f"<style>{CSS}</style></head><body>"
            f"<h1>Agent Gateway — timeline</h1>"
            f"<div class='summary'>{stats}</div>"
            f"<div class='filters'><a href='?'>all</a>{filter_links}</div>"
            f"{''.join(rows_html) or '<p>No entries yet.</p>'}"
            f"</body></html>")
