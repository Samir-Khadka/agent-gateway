# Changelog

## 1.0.0 — 2026-11-15

The first stable release. Everything in the plan is built, tested,
and documented.

- **Metrics.** `GET /metrics` (Prometheus text format) and
  `GET /admin/stats` (JSON): total calls, decisions by outcome,
  spend, rows read, tainted sessions, pending approvals, killed
  agents — computed from the audit log, so a restart rebuilds them.

## 0.9.0 — 2026-11-15

- Policy versioning: every save keeps the previous version under
  `policies/.history/<agent>/<timestamp>.yaml`; history and
  rollback endpoints.
- Interactive demo page (`GET /demo`, off by default,
  `GATEWAY_DEMO_PAGE=1`): run sessions A–D live in the browser.

## 0.8.0 — 2026-11-15

- Slack approvals (Block Kit message + `/slack/interactive` with
  signature verification). Telegram and Slack can both be set.
- Second agent policy: `analyst-bot` (read-only). Demo Session D.
- The editor runs the policy's test cases on save and rejects the
  edit if any fail.
- Added the missing `requirements.txt`; CI installs from it.

## 0.7.0 — 2026-11-15

- LLM agent harness (`examples/llm_agent.py`): a ReAct loop over any
  OpenAI-compatible API, plus `--simulate` for no-key runs and CI.
- Launch announcement (`LAUNCH.md`) and a LinkedIn launch draft
  (not published).

## 0.6.0 — 2026-11-15

- Policy editor (`GET /admin/editor`): edit rules, budgets, costs,
  egress, taint sources, and the kill switch in the browser; saves
  validate and take effect live.
- Deployment: `render.yaml`, `Dockerfile`, `gateway/server.py`,
  `DEPLOY.md`.
- Realistic agent example (`examples/support_agent.py`).

## 0.5.0 — 2026-11-15

- Hardening: request size limits, malformed-JSON rejection,
  gateway-wide rate limit (60/min, 429), upstream errors sanitised.
- 55-scenario attack benchmark (`python -m gateway.attack_benchmark`,
  55/55 pass, runs in CI).
- Latency (`python -m gateway.latency`): policy decision p50
  0.003 ms.
- Launch docs: MIT LICENSE, SECURITY.md, CONTRIBUTING.md.
- Fixed: negative refunds denied; `to_domain` covers subdomains;
  denials name the failing condition.

## 0.4.0 — 2026-11-14

- Log replay (`python -m gateway.replay`): names the call that
  tainted a session and what was blocked after it.
- Timeline dashboard (`GET /admin/dashboard`) and
  `GET /admin/replay`.
- Every audit entry records its `session_id`.

## 0.3.0 — 2026-11-14

- Taint tracking (per-session, persisted; cleared only by a human).
- Egress allowlist.
- Telegram approvals (Bot API notifier, webhook, admin API).
- Audit fix: the hash is computed over the stored dict, so old
  entries still verify after a schema change.

## 0.2.0 — 2026-11-14

- Policy test suite (`python -m gateway.test_policy`).
- Spend budgets, row budgets, per-tool rate limits (survive a
  restart via the audit log).

## 0.1.0 — 2026-11-14

- MCP proxy (JSON-RPC over HTTP), agent identity via API key, YAML
  capability policies (fail closed), hash-chained append-only audit
  log, per-agent call budgets, persistent kill switch, demo server
  and `demo.py`.
