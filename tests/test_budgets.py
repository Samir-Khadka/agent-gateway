"""Budgets: spend, rows, and per-tool rate limits stop a runaway."""
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
        kwargs={"host": "127.0.0.1", "port": 8002, "log_level": "error"},
        daemon=True)
    thread.start()
    time.sleep(1.0)
    yield "http://127.0.0.1:8002/mcp"


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


def _call(client, tool, args):
    return client.post("/mcp", headers={"x-agent-key": AGENT_KEY},
                       json={"jsonrpc": "2.0", "id": 1,
                             "method": "tools/call",
                             "params": {"name": tool,
                                        "arguments": args}})


def test_spend_budget_denies_when_exceeded(client, gateway):
    gateway.policies["support-bot"].budgets = {"max_spend": 0.05}
    # email.send costs 0.02: two go through (0.04), the third is denied
    for _ in range(2):
        resp = _call(client, "email.send",
                     {"to": "team@company.com", "subject": "s",
                      "body": "b"})
        assert "error" not in resp.json()
    resp = _call(client, "email.send",
                 {"to": "team@company.com", "subject": "s", "body": "b"})
    assert "spend budget exhausted" in resp.json()["error"]["message"]


def test_row_budget_denies_when_exceeded(client, gateway):
    gateway.policies["support-bot"].budgets = {"max_rows_read": 10}
    _call(client, "crm.read_customer",
          {"customer_id": "cust_1", "limit": 5})
    resp = _call(client, "crm.read_customer",
                 {"customer_id": "cust_1", "limit": 6})
    assert "row budget exhausted" in resp.json()["error"]["message"]


def test_rate_limit_denies_after_the_per_minute_cap(client, gateway):
    gateway.policies["support-bot"].budgets = {
        "rate_limits": {"email.send": 2}}
    for _ in range(2):
        assert "error" not in _call(
            client, "email.send",
            {"to": "team@company.com", "subject": "s",
             "body": "b"}).json()
    resp = _call(client, "email.send",
                 {"to": "team@company.com", "subject": "s", "body": "b"})
    assert "rate limit" in resp.json()["error"]["message"]


def test_spend_and_rows_are_in_the_audit_log(client, gateway):
    _call(client, "crm.read_customer",
          {"customer_id": "cust_1", "limit": 5})
    _call(client, "email.send",
          {"to": "team@company.com", "subject": "s", "body": "b"})
    entries = gateway.audit.read()
    assert entries[0]["cost"] == 0.01 and entries[0]["rows"] == 5
    assert entries[1]["cost"] == 0.02 and entries[1]["rows"] == 0
    assert gateway.spend["support-bot"] == 0.03
    assert gateway.rows_read["support-bot"] == 5


def test_budgets_survive_a_restart(tmp_path, upstream):
    gateway = Gateway(policy_dir="policies",
                      keys={AGENT_KEY: "support-bot"},
                      upstream_url=upstream,
                      audit_path=tmp_path / "audit.jsonl",
                      data_dir=tmp_path / "data")
    client = TestClient(create_app(gateway))
    _call(client, "crm.read_customer",
          {"customer_id": "cust_1", "limit": 5})
    # a fresh gateway over the same audit log remembers the spend
    gateway2 = Gateway(policy_dir="policies",
                       keys={AGENT_KEY: "support-bot"},
                       upstream_url=upstream,
                       audit_path=tmp_path / "audit.jsonl",
                       data_dir=tmp_path / "data")
    assert gateway2.spend["support-bot"] == 0.01
    assert gateway2.rows_read["support-bot"] == 5
    assert gateway2.calls_made["support-bot"] == 1
