"""Slack approvals: ask a human on Slack, with the full context.

When a call is held, the gateway posts a Block Kit message to the
configured Slack channel with the agent, the tool, the arguments,
and the reason — plus Approve / Deny buttons. Clicking one resolves
the approval, and the agent's next re-send runs or refuses the call.

Setup (the one step only Samir can do — a webhook is his):
  1. In Slack, create an app (or use an existing one), enable
     Incoming Webhooks, and add one to the channel where approvals
     should land. Copy the webhook URL.
  2. Enable Interactivity, and set the Request URL to
     <gateway>/slack/interactive.
  3. Set SLACK_WEBHOOK_URL (and SLACK_SIGNING_SECRET, from the app's
     Basic Information page, so the gateway can verify that button
     clicks really came from Slack).
Without a webhook URL, approvals still work through the admin API
(POST /admin/approvals/{id}/approve) — Slack is the notifier, not
the gate. Telegram and Slack can both be configured; the gateway
notifies on every channel that is set.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import httpx

from .approvals import Approval


def approval_blocks(approval: Approval) -> list[dict]:
    """The Block Kit message: the approval, then two buttons."""
    args = ", ".join(f"{k}={v}" for k, v in approval.args.items())
    return [
        {"type": "header",
         "text": {"type": "plain_text",
                  "text": "Agent Gateway — approval needed"}},
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": (f"*Agent:* {approval.agent}\n"
                           f"*Tool:* {approval.tool}\n"
                           f"*Arguments:* {args or '(none)'}\n"
                           f"*Reason:* {approval.reason}\n"
                           f"*Approval:* `{approval.id}`")}},
        {"type": "actions",
         "elements": [
             {"type": "button", "text": {"type": "plain_text",
                                         "text": "Approve"},
              "style": "primary",
              "value": f"approve:{approval.id}",
              "action_id": "approve"},
             {"type": "button", "text": {"type": "plain_text",
                                         "text": "Deny"},
              "style": "danger",
              "value": f"deny:{approval.id}",
              "action_id": "deny"},
         ]},
    ]


def send_approval_request(webhook_url: str,
                          approval: Approval) -> dict:
    """Post the approval request to Slack. Returns the response
    body. Raises on a non-200 response."""
    resp = httpx.post(webhook_url,
                      json={"blocks": approval_blocks(approval)},
                      timeout=30)
    resp.raise_for_status()
    return {"ok": True, "status": resp.status_code}


def verify_slack_signature(signing_secret: str, body: bytes,
                           timestamp: str, signature: str) -> bool:
    """Verify a Slack request signature (HMAC-SHA256 over
    v0:<timestamp>:<body>). Rejects stale timestamps outright."""
    try:
        if abs(time.time() - int(timestamp)) > 300:
            return False
    except (TypeError, ValueError):
        return False
    base = f"v0:{timestamp}:".encode() + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base,
                                hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_interactive_payload(payload: dict) -> tuple[str, str, str]:
    """Pull (action, approval_id, username) out of a Slack
    interactive payload. Returns ("", "", "") when it is not an
    approval button click."""
    actions = payload.get("actions") or []
    if not actions:
        return "", "", ""
    value = str(actions[0].get("value", ""))
    action, _, approval_id = value.partition(":")
    user = payload.get("user") or {}
    username = str(user.get("username") or user.get("name") or "slack")
    if action not in ("approve", "deny") or not approval_id:
        return "", "", ""
    return action, approval_id, username
