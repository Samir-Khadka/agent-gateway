"""v1.0: metrics (Prometheus + JSON stats)."""
from __future__ import annotations

import shutil
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from fastapi.testclient import TestClient

from gateway.demo_server import create_demo_server
from gateway.metrics import compute_stats, render_prometheus
from gateway.proxy import Gateway, create_app

AGENT_KEY = "demo-key-support-bot"
ADMIN_KEY = "admin-secret"


@pytest.fixture(scope="module")
def upstream():
    thread = threading.Thread(
        target=uvicorn.run,
        args=(create_demo_server(),),
        kwargs={"host": "127.0.0.1", "port": 8014, "log_level": "error"},
        daemon=True)
    thread.start()
    time.sleep(1.0)
    yield "http://127.0.0.1:8014/mcp"


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


def test_metrics_counts_calls_and_decisions(client, gateway):
    _call(client, "crm.read_customer", {"customer_id": "cust_1"})
    _call(client, "db.delete_all", {})
    stats = compute_stats(gateway)
    assert stats["total_calls"] == 2
    assert stats["decisions"] == {"allow": 1, "deny": 1}
    assert stats["per_agent"]["support-bot"]["calls"] == 2
    assert stats["total_spend"] == 0.01


def test_metrics_counts_taint_and_approvals(client, gateway):
    _call(client, "web.fetch",
          {"url": "https://docs.company.com/help"}, session="m1")
    _call(client, "refund.create",
          {"customer_id": "cust_1", "amount": 150})
    stats = compute_stats(gateway)
    assert stats["tainted_sessions"] == ["m1"]
    assert stats["pending_approvals"] == 1


def test_metrics_endpoint_is_prometheus_text(client, gateway):
    _call(client, "crm.read_customer", {"customer_id": "cust_1"})
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "agent_gateway_calls_total 1" in resp.text
    assert 'agent_gateway_decisions_total{decision="allow"} 1' \
        in resp.text


def test_stats_endpoint_needs_the_admin_key(client):
    assert client.get("/admin/stats").status_code == 401
    resp = client.get("/admin/stats",
                      headers={"x-admin-key": ADMIN_KEY})
    assert resp.status_code == 200
    assert "total_calls" in resp.json()


def test_changelog_covers_all_versions():
    text = Path("CHANGELOG.md").read_text(encoding="utf-8")
    for version in ("1.0.0", "0.9.0", "0.8.0", "0.7.0", "0.6.0",
                    "0.5.0", "0.4.0", "0.3.0", "0.2.0", "0.1.0"):
        assert version in text
