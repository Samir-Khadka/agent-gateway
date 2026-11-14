"""The gateway itself: an MCP proxy (JSON-RPC over HTTP).

An agent talks to the gateway, never to a tool server directly. The
gateway authenticates the agent (an API key per agent), checks the
call against that agent's YAML policy, holds it for approval if it
is risky, forwards it to the upstream MCP server if it is allowed,
and logs everything to the hash-chained audit log. It fails closed:
no key, no policy, or an unknown tool means the call does not go
through. Added policy latency is a single in-memory lookup plus a
log append — well under the 10 ms budget.

JSON-RPC methods:
  tools/list — the tools this agent may call (filtered by policy)
  tools/call — call a tool: {name, arguments}
Admin (needs the admin key in X-Admin-Key):
  GET  /admin/audit        — the audit log
  GET  /admin/audit/verify — verify the hash chain
  POST /admin/kill/{agent} — stop an agent immediately
  POST /admin/revive/{agent} — lift the kill switch
  GET  /admin/policies     — the loaded policies
"""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from .approvals import ApprovalStore
from .audit import AuditLog
from .egress import check_egress
from .policy import Decision, Policy, evaluate
from .taint import TaintTracker, result_is_untrusted

UPSTREAM_TIMEOUT = 30.0


class Gateway:
    """One gateway instance: policies, keys, audit log, budgets."""

    def __init__(self, policy_dir: str | Path, keys: dict[str, str],
                 upstream_url: str, audit_path: str | Path,
                 data_dir: str | Path = "data",
                 admin_key: str | None = None,
                 telegram_token: str | None = None,
                 telegram_chat_id: str | None = None,
                 telegram_webhook_secret: str | None = None):
        self.policy_dir = Path(policy_dir)
        self.keys = keys  # api key -> agent id
        self.upstream_url = upstream_url
        self.audit = AuditLog(audit_path)
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.admin_key = admin_key or os.environ.get("GATEWAY_ADMIN_KEY")
        self.telegram_token = telegram_token or \
            os.environ.get("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = telegram_chat_id or \
            os.environ.get("TELEGRAM_CHAT_ID")
        self.telegram_webhook_secret = telegram_webhook_secret or \
            os.environ.get("TELEGRAM_WEBHOOK_SECRET")
        self.taint = TaintTracker(self.data_dir / "tainted.json")
        self.approvals = ApprovalStore(self.data_dir / "approvals.json")
        self.policies = self._load_policies()
        self.calls_made: dict[str, int] = {}
        self.spend: dict[str, float] = {}
        self.rows_read: dict[str, int] = {}
        # (agent, tool) -> timestamps of recent calls, for rate limits
        self.call_times: dict[tuple[str, str], deque] = defaultdict(deque)
        for entry in self.audit.read():
            agent = entry["agent"]
            self.calls_made[agent] = self.calls_made.get(agent, 0) + 1
            self.spend[agent] = self.spend.get(agent, 0.0) + \
                float(entry.get("cost", 0.0))
            self.rows_read[agent] = self.rows_read.get(agent, 0) + \
                int(entry.get("rows", 0))
        self.killed = self._load_killed()

    def _load_policies(self) -> dict[str, Policy]:
        policies = {}
        for path in sorted(self.policy_dir.glob("*.yaml")):
            policy = Policy.from_file(path)
            policies[policy.agent] = policy
        return policies

    def _killed_path(self) -> Path:
        return self.data_dir / "killed.json"

    def _load_killed(self) -> set[str]:
        path = self._killed_path()
        if not path.exists():
            return set()
        try:
            return set(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return set()

    def _save_killed(self) -> None:
        self._killed_path().write_text(
            json.dumps(sorted(self.killed)), encoding="utf-8")

    def agent_for_key(self, key: str | None) -> str | None:
        return self.keys.get(key) if key else None

    def policy_for(self, agent: str) -> Policy | None:
        return self.policies.get(agent)

    def kill(self, agent: str) -> None:
        self.killed.add(agent)
        self._save_killed()

    def revive(self, agent: str) -> None:
        self.killed.discard(agent)
        self._save_killed()

    def notify_approval(self, approval) -> None:
        """Tell a human a call is waiting. Telegram when it is
        configured; otherwise the approval simply waits in the admin
        API. A failed send never blocks the hold itself."""
        if not (self.telegram_token and self.telegram_chat_id):
            return
        try:
            from .telegram import send_approval_request
            send_approval_request(self.telegram_token,
                                  self.telegram_chat_id, approval)
        except Exception as e:
            print(f"agent-gateway: telegram notify failed — {e}",
                  file=__import__("sys").stderr)

    def check_budget(self, agent: str, policy: Policy, tool: str = "",
                     args: dict | None = None) -> str | None:
        """A reason to deny, or None when the budgets allow the call.
        Checks the call budget, the spend budget, the row budget, and
        the per-tool rate limit, in that order."""
        budgets = policy.budgets or {}
        max_calls = budgets.get("max_calls")
        if max_calls is not None and \
                self.calls_made.get(agent, 0) >= int(max_calls):
            return f"call budget exhausted ({max_calls} calls)"
        max_spend = budgets.get("max_spend")
        if max_spend is not None and tool:
            if self.spend.get(agent, 0.0) + policy.cost_of(tool) \
                    > float(max_spend):
                return (f"spend budget exhausted "
                        f"(${self.spend.get(agent, 0.0):.2f} of "
                        f"${float(max_spend):.2f})")
        max_rows = budgets.get("max_rows_read")
        if max_rows is not None and tool and args is not None:
            if self.rows_read.get(agent, 0) + \
                    policy.rows_of(tool, args) > int(max_rows):
                return (f"row budget exhausted "
                        f"({self.rows_read.get(agent, 0)} of {max_rows} "
                        f"rows)")
        rate_limits = budgets.get("rate_limits") or {}
        if tool and tool in rate_limits:
            window = self.call_times[(agent, tool)]
            now = time.monotonic()
            while window and window[0] <= now - 60:
                window.popleft()
            if len(window) >= int(rate_limits[tool]):
                return (f"rate limit: {tool} is limited to "
                        f"{rate_limits[tool]} calls per minute")
        return None

    def record_call(self, agent: str, tool: str) -> None:
        """Count a completed call for the rate limiter."""
        self.call_times[(agent, tool)].append(time.monotonic())
        self.calls_made[agent] = self.calls_made.get(agent, 0) + 1

    def decide(self, agent: str, policy: Policy, tool: str,
               args: dict, session_id: str = "default") -> Decision:
        """Decide one call for one session. Order: kill switch, then
        budgets, then the policy (whose taint rules fire first when
        the session is tainted — so an injection's exfiltration is
        reported as tainted, not as a generic deny), and finally the
        egress allowlist, which blocks calls the policy would
        otherwise allow from reaching an outside destination."""
        if agent in self.killed or policy.kill_switch:
            return Decision("deny", "kill switch is on for this agent")
        budget = self.check_budget(agent, policy, tool, args)
        if budget:
            return Decision("deny", budget)
        tainted = self.taint.is_tainted(session_id)
        decision = evaluate(policy, tool, args, tainted=tainted)
        if decision.outcome != "allow":
            return decision
        egress = check_egress(policy.egress_allowlist, tool, args)
        if egress:
            return Decision("deny", egress)
        return decision

    async def forward(self, method: str, params: dict) -> dict:
        """Forward a JSON-RPC request to the upstream MCP server."""
        payload = {"jsonrpc": "2.0", "id": 1, "method": method,
                   "params": params}
        # trust_env=False: the upstream is an internal tool server, so
        # connect directly instead of via any egress proxy in the
        # environment (a sandbox proxy would mangle a localhost URL).
        async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT,
                                     trust_env=False) as client:
            resp = await client.post(self.upstream_url, json=payload)
            resp.raise_for_status()
            return resp.json()


def create_app(gateway: Gateway) -> FastAPI:
    app = FastAPI(title="Agent Gateway", version="0.4.0")

    def _agent(request: Request) -> str:
        key = request.headers.get("x-agent-key")
        agent = gateway.agent_for_key(key)
        if not agent:
            raise HTTPException(401, "missing or unknown agent key")
        return agent

    def _admin(request: Request) -> None:
        if not gateway.admin_key or \
                request.headers.get("x-admin-key") != gateway.admin_key:
            raise HTTPException(401, "missing or wrong admin key")

    @app.get("/health")
    def health():
        return {"status": "ok", "agents": sorted(gateway.policies)}

    @app.post("/mcp")
    async def mcp(request: Request):
        agent = _agent(request)
        policy = gateway.policy_for(agent)
        if policy is None:
            raise HTTPException(403, f"no policy for agent {agent}")
        body = await request.json()
        method = body.get("method", "")
        params = body.get("params", {}) or {}
        req_id = body.get("id")

        def _rpc_error(code: int, message: str) -> JSONResponse:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": req_id,
                 "error": {"code": code, "message": message}})

        def _rpc_result(result: dict) -> JSONResponse:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": req_id, "result": result})

        if method == "tools/list":
            upstream = await gateway.forward("tools/list", {})
            tools = upstream.get("result", {}).get("tools", [])
            allowed = {r["tool"] for r in policy.allow}
            visible = [t for t in tools if t.get("name") in allowed]
            return _rpc_result({"tools": visible})
        if method != "tools/call":
            return _rpc_error(-32601, f"method not supported: {method}")

        tool = params.get("name", "")
        args = params.get("arguments", {}) or {}
        session_id = request.headers.get("x-session-id", "default")
        tainted = gateway.taint.is_tainted(session_id)

        # Re-sending a held call with its approval id: if a human
        # approved it, run it now (bypassing the approval rule);
        # if denied or still pending, refuse or hold again.
        approval_id = params.get("approval_id")
        approved_resend = False
        if approval_id:
            approval = gateway.approvals.get(approval_id)
            if approval is None:
                return _rpc_error(-32000,
                                  f"unknown approval id: {approval_id}")
            if approval.status == "denied":
                gateway.audit.append(agent, tool, args, "deny",
                                     "approval was denied",
                                     tainted=tainted,
                                     session_id=session_id)
                return _rpc_error(
                    -32000, "blocked by Agent Gateway: approval was denied")
            if approval.status == "pending":
                return _rpc_result(
                    {"held_for_approval": True,
                     "reason": approval.reason,
                     "approval_id": approval.id})
            # approved: skip the policy decision below and forward
            approved_resend = True

        if approved_resend:
            decision = Decision("allow", "approved by a human")
        else:
            decision = gateway.decide(agent, policy, tool, args,
                                      session_id=session_id)
        if decision.outcome == "deny":
            gateway.audit.append(agent, tool, args, "deny",
                                 decision.reason, tainted=tainted,
                                 session_id=session_id)
            return _rpc_error(-32000,
                              f"blocked by Agent Gateway: {decision.reason}")
        if decision.outcome == "require_approval":
            approval = gateway.approvals.request(
                agent, session_id, tool, args, decision.reason)
            gateway.audit.append(agent, tool, args, "require_approval",
                                 decision.reason, tainted=tainted,
                                 session_id=session_id)
            gateway.notify_approval(approval)
            return _rpc_result(
                {"held_for_approval": True,
                 "reason": decision.reason,
                 "approval_id": approval.id,
                 "tool": tool, "arguments": args})
        upstream = await gateway.forward("tools/call", params)
        gateway.record_call(agent, tool)
        cost = policy.cost_of(tool)
        rows = policy.rows_of(tool, args)
        gateway.spend[agent] = gateway.spend.get(agent, 0.0) + cost
        gateway.rows_read[agent] = gateway.rows_read.get(agent, 0) + rows
        result_text = json.dumps(upstream.get("result", {}))[:500]
        gateway.audit.append(agent, tool, args, "allow",
                             decision.reason, result=result_text,
                             tainted=tainted,
                             session_id=session_id,
                             cost=cost, rows=rows)
        # A result from an untrusted source taints the session, so
        # the next call faces the tighter rules.
        if result_is_untrusted(tool, upstream,
                               set(policy.taint_sources)):
            gateway.taint.taint(session_id)
        return JSONResponse(upstream)

    @app.get("/admin/audit")
    def audit(request: Request):
        _admin(request)
        return {"entries": gateway.audit.read()}

    @app.get("/admin/audit/verify")
    def audit_verify(request: Request):
        _admin(request)
        ok, message = gateway.audit.verify()
        return {"ok": ok, "message": message}

    @app.post("/admin/kill/{agent}")
    def kill_agent(agent: str, request: Request):
        _admin(request)
        gateway.kill(agent)
        return {"agent": agent, "killed": True}

    @app.post("/admin/revive/{agent}")
    def revive_agent(agent: str, request: Request):
        _admin(request)
        gateway.revive(agent)
        return {"agent": agent, "killed": False}

    @app.get("/admin/policies")
    def policies(request: Request):
        _admin(request)
        return {"agents": sorted(gateway.policies)}

    @app.get("/admin/dashboard")
    def dashboard(request: Request, agent: str | None = None,
                  session: str | None = None,
                  decision: str | None = None):
        _admin(request)
        from .dashboard import render_dashboard
        from fastapi.responses import HTMLResponse
        return HTMLResponse(render_dashboard(
            gateway.audit.read(), agent=agent, session_id=session,
            decision=decision))

    @app.get("/admin/replay")
    def replay_incident(request: Request, agent: str | None = None,
                        session: str | None = None):
        """Reconstruct an incident from the log, as JSON."""
        _admin(request)
        from .replay import replay
        incident = replay(gateway.audit.path, agent=agent,
                          session_id=session)
        return {
            "entries": incident.entries,
            "decisions": incident.decisions,
            "total_spend": incident.total_spend,
            "total_rows": incident.total_rows,
            "taint_event": incident.taint_event,
            "blocked_after_taint": incident.blocked_after_taint,
            "held": incident.held,
        }

    @app.get("/admin/sessions/{session_id}/taint")
    def session_taint(session_id: str, request: Request):
        _admin(request)
        return {"session_id": session_id,
                "tainted": gateway.taint.is_tainted(session_id)}

    @app.post("/admin/sessions/{session_id}/taint")
    def taint_session(session_id: str, request: Request):
        _admin(request)
        gateway.taint.taint(session_id)
        return {"session_id": session_id, "tainted": True}

    @app.post("/admin/sessions/{session_id}/clear")
    def clear_session(session_id: str, request: Request):
        _admin(request)
        gateway.taint.clear(session_id)
        return {"session_id": session_id, "tainted": False}

    @app.get("/admin/approvals")
    def list_approvals(request: Request):
        _admin(request)
        from dataclasses import asdict
        return {"pending": [asdict(a) for a in gateway.approvals.pending()]}

    @app.post("/admin/approvals/{approval_id}/approve")
    def approve_approval(approval_id: str, request: Request):
        _admin(request)
        approval = gateway.approvals.resolve(approval_id, True, "admin")
        if approval is None:
            raise HTTPException(404, "no such pending approval")
        return {"approval_id": approval_id, "status": "approved"}

    @app.post("/admin/approvals/{approval_id}/deny")
    def deny_approval(approval_id: str, request: Request):
        _admin(request)
        approval = gateway.approvals.resolve(approval_id, False, "admin")
        if approval is None:
            raise HTTPException(404, "no such pending approval")
        return {"approval_id": approval_id, "status": "denied"}

    @app.post("/telegram/webhook")
    async def telegram_webhook(request: Request):
        """Telegram sends button taps here. If a webhook secret is
        configured, Telegram must send it in the
        X-Telegram-Bot-Api-Secret-Token header."""
        if gateway.telegram_webhook_secret:
            secret = request.headers.get(
                "x-telegram-bot-api-secret-token", "")
            if secret != gateway.telegram_webhook_secret:
                raise HTTPException(401, "bad webhook secret")
        body = await request.json()
        query = body.get("callback_query") or {}
        data = query.get("data", "")
        action, _, approval_id = data.partition(":")
        if action not in ("approve", "deny") or not approval_id:
            return {"ok": True}
        by = str((query.get("from") or {}).get("username", "telegram"))
        approval = gateway.approvals.resolve(
            approval_id, action == "approve", by)
        if approval is None:
            return {"ok": True}
        return {"ok": True, "approval_id": approval_id,
                "status": approval.status}

    return app
