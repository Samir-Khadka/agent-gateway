"""Telegram approvals: ask a human on Telegram, with the full context.

When a call is held, the gateway sends a Telegram message to the
configured chat with the agent, the tool, the arguments, and the
reason — plus Approve / Deny buttons. Tapping one resolves the
approval, and the agent's next re-send runs or refuses the call.

Setup (the one step only Samir can do — a bot token is his):
  1. Talk to @BotFather on Telegram, create a bot, copy the token.
  2. Message the bot once, then open
     https://api.telegram.org/bot<token>/getUpdates to find the
     chat id.
  3. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, and optionally
     TELEGRAM_WEBHOOK_SECRET (then set the webhook to
     <gateway>/telegram/webhook with that secret token).
Without a token, approvals still work through the admin API
(POST /admin/approvals/{id}/approve) — Telegram is the notifier,
not the gate.
"""
from __future__ import annotations

import httpx

from .approvals import Approval

TELEGRAM_API = "https://api.telegram.org"


def approval_message(approval: Approval) -> str:
    args = ", ".join(f"{k}={v}" for k, v in approval.args.items())
    return (
        f"Agent Gateway — approval needed\n"
        f"Agent: {approval.agent}\n"
        f"Tool: {approval.tool}\n"
        f"Arguments: {args or '(none)'}\n"
        f"Reason: {approval.reason}\n"
        f"Approval: {approval.id}")


def send_approval_request(token: str, chat_id: str,
                          approval: Approval) -> dict:
    """Send the approval request to Telegram. Returns the API
    response. Raises on a non-200 response."""
    payload = {
        "chat_id": chat_id,
        "text": approval_message(approval),
        "reply_markup": {
            "inline_keyboard": [[
                {"text": "Approve",
                 "callback_data": f"approve:{approval.id}"},
                {"text": "Deny",
                 "callback_data": f"deny:{approval.id}"},
            ]],
        },
    }
    resp = httpx.post(f"{TELEGRAM_API}/bot{token}/sendMessage",
                      json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()
