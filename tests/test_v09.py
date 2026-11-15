"""v0.9: policy versioning with rollback, and the interactive demo
page."""
from __future__ import annotations

import os
import shutil
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from fastapi.testclient import TestClient

from gateway.demo_server import create_demo_server
from gateway.proxy import Gateway, create_app

AGENT_KEY = "demo-key-support-bot"
ADMIN_KEY = "admin-secret"


@pytest.fixture(scope="module")
def upstream():
    thread = threading.Thread(
        target=uvicorn.run,
        args=(create_demo_server(),),
        kwargs={"host": "127.0.0.1", "port": 8013, "log_level": "error"},
        daemon=True)
    thread.start()
    time.sleep(1.0)
    yield "http://127.0.0.1:8013/mcp"


@pytest.fixture()
def policy_dir(tmp_path):
    dest = tmp_path / "policies"
    shutil.copytree(Path("policies"), dest)
    return dest


@pytest.fixture()
def gateway(tmp_path, upstream, policy_dir):
    return Gateway(policy_dir=policy_dir,
                   keys={AGENT_KEY: "support-bot"},
                   upstream_url=upstream,
                   audit_path=tmp_path / "audit.jsonl",
                   data_dir=tmp_path / "data",
                   admin_key=ADMIN_KEY)


@pytest.fixture()
def client(gateway):
    return TestClient(create_app(gateway))


def _admin():
    return {"x-admin-key": ADMIN_KEY}


def test_save_keeps_the_previous_version(gateway, policy_dir):
    data = {"agent": "support-bot",
            "allow": [{"tool": "crm.read_customer",
                       "limits": {"max_rows": 5}}]}
    gateway.save_policy("support-bot", data)
    history = gateway.policy_history("support-bot")
    assert len(history) == 1
    # the saved version is the old policy (row limit 20)
    import yaml
    old = yaml.safe_load(
        (policy_dir / ".history" / "support-bot" /
         history[0]).read_text(encoding="utf-8"))
    assert old["allow"][0]["limits"] == {"max_rows": 20}


def test_restore_rolls_back(gateway):
    data = {"agent": "support-bot",
            "allow": [{"tool": "crm.read_customer",
                       "limits": {"max_rows": 5}}]}
    gateway.save_policy("support-bot", data)
    assert gateway.policy_for("support-bot").allow[0]["limits"] == \
        {"max_rows": 5}
    version = gateway.policy_history("support-bot")[0]
    gateway.restore_policy("support-bot", version)
    assert gateway.policy_for("support-bot").allow[0]["limits"] == \
        {"max_rows": 20}


def test_restore_rejects_an_unknown_version(gateway):
    import pytest as pt
    with pt.raises(ValueError, match="no such version"):
        gateway.restore_policy("support-bot", "20990101-000000.yaml")


def test_history_endpoint(client, gateway):
    data = {"agent": "support-bot",
            "allow": [{"tool": "crm.read_customer",
                       "limits": {"max_rows": 5}}]}
    gateway.save_policy("support-bot", data)
    resp = client.get("/admin/policies/support-bot/history",
                      headers=_admin())
    assert resp.status_code == 200
    assert len(resp.json()["versions"]) == 1


def test_restore_endpoint(client, gateway):
    data = {"agent": "support-bot",
            "allow": [{"tool": "crm.read_customer",
                       "limits": {"max_rows": 5}}]}
    gateway.save_policy("support-bot", data)
    version = gateway.policy_history("support-bot")[0]
    resp = client.post(
        f"/admin/policies/support-bot/restore/{version}",
        headers=_admin())
    assert resp.status_code == 200
    assert gateway.policy_for("support-bot").allow[0]["limits"] == \
        {"max_rows": 20}


def test_history_needs_the_admin_key(client):
    assert client.get(
        "/admin/policies/support-bot/history").status_code == 401


def test_demo_page_is_off_by_default(client):
    assert client.get("/demo").status_code == 404


def test_demo_page_loads_when_enabled(tmp_path, upstream, policy_dir,
                                      monkeypatch):
    monkeypatch.setenv("GATEWAY_DEMO_PAGE", "1")
    gateway = Gateway(policy_dir=policy_dir,
                      keys={AGENT_KEY: "support-bot"},
                      upstream_url=upstream,
                      audit_path=tmp_path / "audit.jsonl",
                      data_dir=tmp_path / "data",
                      admin_key=ADMIN_KEY)
    client = TestClient(create_app(gateway))
    resp = client.get("/demo")
    assert resp.status_code == 200
    assert "Session B" in resp.text
    assert "demo-key-support-bot" in resp.text
