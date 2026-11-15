"""The gateway's entry point for deployment: builds a Gateway from
environment variables and serves it with uvicorn.

  GATEWAY_ADMIN_KEY   — required (a long random secret)
  GATEWAY_KEYS        — JSON, agent key -> agent id
                        (default: {"demo-key-support-bot": "support-bot"})
  UPSTREAM_URL        — the MCP tool server (default: the demo server
                        on 127.0.0.1:8001, started alongside it)
  POLICY_DIR          — where the YAML policies live (default: policies)
  AUDIT_PATH          — where the audit log goes (default: data/audit.jsonl)
  DATA_DIR            — taint + approval state (default: data)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .proxy import Gateway, create_app

_keys = json.loads(os.environ.get(
    "GATEWAY_KEYS",
    '{"demo-key-support-bot": "support-bot", '
    '"demo-key-analyst-bot": "analyst-bot"}'))

gateway = Gateway(
    policy_dir=os.environ.get("POLICY_DIR", "policies"),
    keys=_keys,
    upstream_url=os.environ.get(
        "UPSTREAM_URL", "http://127.0.0.1:8001/mcp"),
    audit_path=os.environ.get("AUDIT_PATH", "data/audit.jsonl"),
    data_dir=os.environ.get("DATA_DIR", "data"),
)

app = create_app(gateway)
