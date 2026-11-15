"""v0.8: Slack approvals, the analyst bot, and editor validation
against policy test cases."""
from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import threading
import time
from pathlib import Path
from unittest import mock

import pytest
import uvicorn
from fastapi.testclient import TestClient

from gateway.approvals import Approval
from gateway.demo_server import create_demo_server
from gateway.proxy import Gateway, create_app
from gateway.slack import (approval_blocks,
                           parse_interactive_payload,
                           send_approval_request,
                           verify_slack_signature)

AGENT_KEY = "demo-key-support-bot"
ANALYST_KEY = "demo-key-analyst-bot"
ADMIN_KEY = "admin-secret"


@pytest.fixture(scope="module")
def upstream():
    thread = threading.Thread(
        target=uvicorn.run,
        args=(create_demo_server(),),
        kwargs={"host": "127.0.0.1", "port": 8012, "log_level": "error"},
        daemon=True)
    thread.start()
    time.sleep(1.0)
    yield "http://127.0.0.1:8012/mcp"


@pytest.fixture()
def policy_dir(tmp_path):
    dest = tmp_path / "policies"
    shutil.copytree(Path("policies"), dest)
    return dest


@pytest.fixture()
def gateway(tmp_path, upstream, policy_dir):
    return Gateway(policy_dir=policy_dir,
                   keys={AGENT_KEY: "support-bot",
                         ANALYST_KEY: "analyst-bot"},
                   upstream_url=upstream,
                   audit_path=tmp_path / "audit.jsonl",
                   data_dir=tmp_path / "data",
                   admin_key=ADMIN_KEY)


@pytest.fixture()
def client(gateway):
    return TestClient(create_app(gateway))


def _admin():
    return {"x-admin-key": ADMIN_KEY}


def _call(client, tool, args, key=AGENT_KEY, session="default"):
    return client.post("/mcp", headers={"x-agent-key": key,
                                        "x-session-id": session},
                       json={"jsonrpc": "2.0", "id": 1,
                             "method": "tools/call",
                             "params": {"name": tool,
                                        "arguments": args}})


def test_slack_blocks_carry_the_full_context():
    approval = Approval(id="abc123", agent="support-bot",
                        session_id="s1", tool="refund.create",
                        args={"customer_id": "cust_1", "amount": 150},
                        reason="needs a human approval")
    blocks = approval_blocks(approval)
    text = json.dumps(blocks)
    assert "support-bot" in text and "refund.create" in text
    assert "amount=150" in text and "abc123" in text
    buttons = blocks[2]["elements"]
    assert buttons[0]["value"] == "approve:abc123"
    assert buttons[1]["value"] == "deny:abc123"


def test_slack_send_posts_to_the_webhook():
    approval = Approval(id="abc123", agent="support-bot",
                        session_id="s1", tool="refund.create",
                        args={"amount": 150},
                        reason="needs approval")
    with mock.patch("gateway.slack.httpx.post") as post:
        post.return_value.status_code = 200
        send_approval_request(
            "https://hooks.slack.com/services/T/XXX", approval)
        url, kwargs = post.call_args[0][0], post.call_args[1]
        assert url == "https://hooks.slack.com/services/T/XXX"
        assert kwargs["json"]["blocks"][2]["elements"][0]["value"] == \
            "approve:abc123"


def test_slack_signature_verification():
    secret = "secret123"
    body = b"payload={}"
    ts = str(int(time.time()))
    sig = "v0=" + hmac.new(
        secret.encode(), f"v0:{ts}:".encode() + body,
        hashlib.sha256).hexdigest()
    assert verify_slack_signature(secret, body, ts, sig)
    assert not verify_slack_signature(secret, body, ts, "v0=wrong")
    assert not verify_slack_signature(secret, body, "1", sig)


def test_slack_interactive_resolves_an_approval(client, gateway):
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150})
    aid = resp.json()["result"]["approval_id"]
    payload = {"actions": [{"value": f"approve:{aid}"}],
               "user": {"username": "samir"}}
    resp = client.post("/slack/interactive",
                       data={"payload": json.dumps(payload)})
    assert resp.json()["status"] == "approved"
    assert gateway.approvals.get(aid).status == "approved"
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150},
                 )
    # re-send with the approval id to confirm it runs
    resp = client.post(
        "/mcp", headers={"x-agent-key": AGENT_KEY},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "refund.create",
                         "arguments": {"customer_id": "cust_1",
                                       "amount": 150},
                         "approval_id": aid}})
    assert "refund of 150" in \
        resp.json()["result"]["content"][0]["text"]


def test_slack_interactive_rejects_a_bad_signature(tmp_path, upstream,
                                                   policy_dir):
    gateway = Gateway(policy_dir=policy_dir,
                      keys={AGENT_KEY: "support-bot"},
                      upstream_url=upstream,
                      audit_path=tmp_path / "audit.jsonl",
                      data_dir=tmp_path / "data",
                      admin_key=ADMIN_KEY,
                      slack_signing_secret="secret123")
    client = TestClient(create_app(gateway))
    resp = client.post("/slack/interactive",
                       data={"payload": "{}"})
    assert resp.status_code == 401


def test_parse_interactive_payload():
    action, aid, by = parse_interactive_payload(
        {"actions": [{"value": "deny:abc123"}],
         "user": {"username": "samir"}})
    assert (action, aid, by) == ("deny", "abc123", "samir")
    assert parse_interactive_payload({}) == ("", "", "")


def test_analyst_bot_can_read_but_not_email(client):
    resp = _call(client, "crm.read_customer",
                 {"customer_id": "cust_1", "limit": 5},
                 key=ANALYST_KEY)
    assert "Asha Sharma" in resp.json()["result"]["content"][0]["text"]
    resp = _call(client, "email.send",
                 {"to": "team@company.com", "subject": "hi",
                  "body": "hello"}, key=ANALYST_KEY)
    assert "not in this agent's capabilities" in \
        resp.json()["error"]["message"]


def test_analyst_bot_cannot_refund(client):
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 10},
                 key=ANALYST_KEY)
    assert resp.json()["error"]["message"].startswith(
        "blocked by Agent Gateway")


def test_analyst_bot_policy_cases_pass():
    from gateway.policy import Policy
    from gateway.test_policy import load_cases, run_cases
    policy = Policy.from_file("policies/analyst-bot.yaml")
    results = run_cases(
        policy, load_cases("tests/policies/analyst-bot.cases.yaml"))
    assert len(results) == 7
    assert all(r.passed for r in results), \
        [r for r in results if not r.passed]


def test_save_policy_rejects_an_edit_that_breaks_its_cases(
        client, gateway):
    data = client.get("/admin/policies/support-bot",
                      headers=_admin()).json()
    # break the email rule: allow email to any domain
    for rule in data["allow"]:
        if rule["tool"] == "email.send":
            rule["where"] = {}
    resp = client.post("/admin/policies/support-bot",
                       headers=_admin(), json=data)
    assert resp.status_code == 400
    assert "test cases" in resp.json()["detail"]
    # and the old policy is still in force
    assert gateway.policy_for("support-bot").allow[1]["where"] == \
        {"to_domain": ["company.com"]}


def test_notify_approval_sends_to_slack_when_configured(
        tmp_path, upstream, policy_dir):
    gateway = Gateway(policy_dir=policy_dir,
                      keys={AGENT_KEY: "support-bot"},
                      upstream_url=upstream,
                      audit_path=tmp_path / "audit.jsonl",
                      data_dir=tmp_path / "data",
                      admin_key=ADMIN_KEY,
                      slack_webhook_url="https://hooks.slack.com/x")
    with mock.patch("gateway.slack.httpx.post") as post:
        post.return_value.status_code = 200
        approval = gateway.approvals.request(
            "support-bot", "s1", "refund.create",
            {"amount": 150}, "needs approval")
        gateway.notify_approval(approval)
        assert post.called
