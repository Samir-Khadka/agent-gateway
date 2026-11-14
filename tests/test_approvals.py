"""Human approvals: held, approved on Telegram (or the admin API),
then run — or denied, and refused."""
from __future__ import annotations

import threading
import time
from unittest import mock

import pytest
import uvicorn
from fastapi.testclient import TestClient

from gateway.approvals import Approval
from gateway.demo_server import create_demo_server
from gateway.proxy import Gateway, create_app
from gateway.telegram import approval_message, send_approval_request

AGENT_KEY = "demo-key-support-bot"
ADMIN_KEY = "admin-secret"


@pytest.fixture(scope="module")
def upstream():
    thread = threading.Thread(
        target=uvicorn.run,
        args=(create_demo_server(),),
        kwargs={"host": "127.0.0.1", "port": 8004, "log_level": "error"},
        daemon=True)
    thread.start()
    time.sleep(1.0)
    yield "http://127.0.0.1:8004/mcp"


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


def _call(client, tool, args, approval_id=None):
    params = {"name": tool, "arguments": args}
    if approval_id:
        params["approval_id"] = approval_id
    return client.post("/mcp", headers={"x-agent-key": AGENT_KEY},
                       json={"jsonrpc": "2.0", "id": 1,
                             "method": "tools/call", "params": params})


def _admin_headers():
    return {"x-admin-key": ADMIN_KEY}


def test_held_call_creates_a_pending_approval(client, gateway):
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150})
    result = resp.json()["result"]
    assert result["held_for_approval"] is True
    approval = gateway.approvals.get(result["approval_id"])
    assert approval is not None and approval.status == "pending"
    assert approval.tool == "refund.create"


def test_approved_call_runs_on_resend(client, gateway):
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150})
    approval_id = resp.json()["result"]["approval_id"]
    assert client.post(f"/admin/approvals/{approval_id}/approve",
                       headers=_admin_headers()).status_code == 200
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150},
                 approval_id=approval_id)
    assert "refund of 150" in \
        resp.json()["result"]["content"][0]["text"]


def test_denied_call_is_refused_on_resend(client, gateway):
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150})
    approval_id = resp.json()["result"]["approval_id"]
    assert client.post(f"/admin/approvals/{approval_id}/deny",
                       headers=_admin_headers()).status_code == 200
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150},
                 approval_id=approval_id)
    assert "approval was denied" in resp.json()["error"]["message"]


def test_pending_approval_keeps_the_call_held(client):
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150})
    approval_id = resp.json()["result"]["approval_id"]
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150},
                 approval_id=approval_id)
    assert resp.json()["result"]["held_for_approval"] is True


def test_unknown_approval_id_is_an_error(client):
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150},
                 approval_id="nope")
    assert "unknown approval id" in resp.json()["error"]["message"]


def test_telegram_webhook_approves(client, gateway):
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150})
    approval_id = resp.json()["result"]["approval_id"]
    webhook = client.post("/telegram/webhook", json={
        "callback_query": {
            "data": f"approve:{approval_id}",
            "from": {"username": "samir"}}})
    assert webhook.json()["status"] == "approved"
    assert gateway.approvals.get(approval_id).status == "approved"
    resp = _call(client, "refund.create",
                 {"customer_id": "cust_1", "amount": 150},
                 approval_id=approval_id)
    assert "refund of 150" in \
        resp.json()["result"]["content"][0]["text"]


def test_telegram_webhook_rejects_a_bad_secret(tmp_path, upstream):
    gateway = Gateway(policy_dir="policies",
                      keys={AGENT_KEY: "support-bot"},
                      upstream_url=upstream,
                      audit_path=tmp_path / "audit.jsonl",
                      data_dir=tmp_path / "data",
                      admin_key=ADMIN_KEY,
                      telegram_webhook_secret="secret123")
    client = TestClient(create_app(gateway))
    resp = client.post("/telegram/webhook", json={
        "callback_query": {"data": "approve:abc", "from": {}}})
    assert resp.status_code == 401
    resp = client.post("/telegram/webhook",
                       headers={"x-telegram-bot-api-secret-token":
                                "secret123"},
                       json={"callback_query": {"data": "approve:abc",
                                                "from": {}}})
    assert resp.status_code == 200


def test_telegram_message_has_the_full_context():
    approval = Approval(id="abc123", agent="support-bot",
                        session_id="s1", tool="refund.create",
                        args={"customer_id": "cust_1", "amount": 150},
                        reason="refund.create needs a human approval")
    text = approval_message(approval)
    assert "support-bot" in text and "refund.create" in text
    assert "amount=150" in text and "abc123" in text


def test_telegram_send_posts_to_the_bot_api():
    approval = Approval(id="abc123", agent="support-bot",
                        session_id="s1", tool="refund.create",
                        args={"amount": 150},
                        reason="needs approval")
    with mock.patch("gateway.telegram.httpx.post") as post:
        post.return_value.json.return_value = {"ok": True}
        send_approval_request("token123", "chat456", approval)
        url, kwargs = post.call_args[0][0], post.call_args[1]
        assert url == ("https://api.telegram.org/bot"
                       "token123/sendMessage")
        assert kwargs["json"]["chat_id"] == "chat456"
        buttons = kwargs["json"]["reply_markup"]["inline_keyboard"][0]
        assert buttons[0]["callback_data"] == "approve:abc123"
        assert buttons[1]["callback_data"] == "deny:abc123"
