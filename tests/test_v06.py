"""v0.6: the policy editor, the deployment files, and the
realistic agent shift."""
from __future__ import annotations

import shutil
import threading
import time
from pathlib import Path

import pytest
import uvicorn
import yaml
from fastapi.testclient import TestClient

from gateway.demo_server import create_demo_server
from gateway.policy import Policy
from gateway.proxy import Gateway, create_app

AGENT_KEY = "demo-key-support-bot"
ADMIN_KEY = "admin-secret"


@pytest.fixture(scope="module")
def upstream():
    thread = threading.Thread(
        target=uvicorn.run,
        args=(create_demo_server(),),
        kwargs={"host": "127.0.0.1", "port": 8007, "log_level": "error"},
        daemon=True)
    thread.start()
    time.sleep(1.0)
    yield "http://127.0.0.1:8007/mcp"


@pytest.fixture()
def policy_dir(tmp_path):
    src = Path("policies")
    dest = tmp_path / "policies"
    shutil.copytree(src, dest)
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


def test_editor_page_loads(client):
    resp = client.get("/admin/editor")
    assert resp.status_code == 200
    assert "policy editor" in resp.text
    assert "Save policy" in resp.text


def test_get_policy_returns_the_policy_as_json(client):
    resp = client.get("/admin/policies/support-bot", headers=_admin())
    assert resp.status_code == 200
    assert resp.json()["agent"] == "support-bot"
    assert any(r["tool"] == "email.send"
               for r in resp.json()["allow"])


def test_get_policy_needs_the_admin_key(client):
    assert client.get("/admin/policies/support-bot").status_code == 401


def test_save_policy_takes_effect_live(client, gateway):
    data = client.get("/admin/policies/support-bot",
                      headers=_admin()).json()
    # tighten the row limit from 20 to 5
    for rule in data["allow"]:
        if rule["tool"] == "crm.read_customer":
            rule["limits"] = {"max_rows": 5}
    resp = client.post("/admin/policies/support-bot",
                       headers=_admin(), json=data)
    assert resp.status_code == 200
    assert gateway.policy_for("support-bot").allow[0]["limits"] == \
        {"max_rows": 5}
    # and the new limit is enforced immediately
    resp = client.post(
        "/mcp", headers={"x-agent-key": AGENT_KEY},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "crm.read_customer",
                         "arguments": {"customer_id": "cust_1",
                                       "limit": 10}}})
    assert "max_rows" in resp.json()["error"]["message"]


def test_save_policy_rejects_an_empty_policy(client):
    resp = client.post("/admin/policies/support-bot",
                       headers=_admin(),
                       json={"agent": "support-bot", "allow": [],
                             "require_approval": []})
    assert resp.status_code == 400
    assert "at least one" in resp.json()["detail"]


def test_save_policy_rejects_a_rule_without_a_tool(client):
    resp = client.post("/admin/policies/support-bot",
                       headers=_admin(),
                       json={"agent": "support-bot",
                             "allow": [{"where": {}}]})
    assert resp.status_code == 400
    assert "needs a tool" in resp.json()["detail"]


def test_save_policy_rejects_a_mismatched_agent(client):
    resp = client.post("/admin/policies/support-bot",
                       headers=_admin(),
                       json={"agent": "other-bot",
                             "allow": [{"tool": "crm.read_customer"}]})
    assert resp.status_code == 400


def test_save_policy_writes_valid_yaml(policy_dir, gateway):
    data = {"agent": "support-bot",
            "allow": [{"tool": "crm.read_customer",
                       "limits": {"max_rows": 5}}]}
    gateway.save_policy("support-bot", data)
    loaded = yaml.safe_load(
        (policy_dir / "support-bot.yaml").read_text(encoding="utf-8"))
    assert loaded["allow"][0]["limits"] == {"max_rows": 5}
    assert Policy.from_dict(loaded).agent == "support-bot"


def test_deploy_files_exist_and_parse():
    assert Path("render.yaml").exists()
    assert Path("Dockerfile").exists()
    assert Path("DEPLOY.md").exists()
    render = yaml.safe_load(Path("render.yaml").read_text())
    assert render["services"][0]["name"] == "agent-gateway"
    assert "GATEWAY_ADMIN_KEY" in str(render)


def test_server_module_builds_an_app():
    from gateway.server import app, gateway
    assert app is not None
    assert gateway.policy_for("support-bot") is not None


def test_real_agent_shift_blocks_the_injection(tmp_path, upstream):
    """The support-agent example: the poisoned page tells the agent
    to exfiltrate, the gateway blocks it, and the legitimate work
    still completes."""
    import subprocess
    import sys
    result = subprocess.run(
        [sys.executable, "examples/support_agent.py", "--port", "8008"],
        capture_output=True, text=True, cwd=Path.cwd(), timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BLOCKED — blocked by Agent Gateway: denied while tainted" \
        in result.stdout
    assert "sent to team@company.com" in result.stdout
    assert "audit log: chain intact" in result.stdout
