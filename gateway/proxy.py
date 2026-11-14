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

from .audit import AuditLog
from .policy import Decision, Policy, evaluate

UPSTREAM_TIMEOUT = 30.0


class Gateway:
    """One gateway instance: policies, keys, audit log, budgets."""

    def __init__(self, policy_dir: str | Path, keys: dict[str, str],
                 upstream_url: str, audit_path: str | Path,
                 data_dir: str | Path = "data",
                 admin_key: str | None = None):
        self.policy_dir = Path(policy_dir)
        self.keys = keys  # api key -> agent id
        self.upstream_url = upstream_url
        self.audit = AuditLog(audit_path)
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.admin_key = admin_key or os.environ.get("GATEWAY_ADMIN_KEY")
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
               args: dict, tainted: bool = False) -> Decision:
        if agent in self.killed or policy.kill_switch:
            return Decision("deny", "kill switch is on for this agent")
        budget = self.check_budget(agent, policy, tool, args)
        if budget:
            return Decision("deny", budget)
        return evaluate(policy, tool, args, tainted=tainted)

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
    app = FastAPI(title="Agent Gateway", version="0.2.0")

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
        decision = gateway.decide(agent, policy, tool, args)
        if decision.outcome == "deny":
            gateway.audit.append(agent, tool, args, "deny",
                                 decision.reason)
            return _rpc_error(-32000,
                              f"blocked by Agent Gateway: {decision.reason}")
        if decision.outcome == "require_approval":
            gateway.audit.append(agent, tool, args, "require_approval",
                                 decision.reason)
            return _rpc_result(
                {"held_for_approval": True,
                 "reason": decision.reason,
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
                             cost=cost, rows=rows)
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

    return app
