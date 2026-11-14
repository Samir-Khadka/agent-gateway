# Agent Gateway

A firewall for what AI agents **do**, not what they say. It controls
which tools an agent may call, with what arguments, and under whose
approval — so a prompt injection that succeeds anyway can only do
what the agent was already allowed to do.

## The bet

Some prompt injections will always succeed, so text filters alone
are not enough. The gateway limits the damage a successful injection
can cause by enforcing least privilege on every tool call.

## v0.1 — the core proxy (Phase 1)

- **MCP proxy.** Agents talk to the gateway (JSON-RPC over HTTP);
  the gateway forwards allowed calls to the upstream MCP server.
- **Agent identity.** One API key per agent (`X-Agent-Key`), mapped
  to a YAML policy. No key, no policy, no call.
- **Capability-based policies.** Each agent gets explicit tools,
  argument limits (`max_rows`), and `where` conditions (`to_domain`),
  never blanket access. Anything not listed is denied — fail closed.
- **Risk-tiered approvals.** A call matching `require_approval`
  (e.g. a refund over 100) is held and never run.
- **Budgets and kill switch.** A per-agent call budget, and an admin
  endpoint that stops an agent immediately (persisted, survives a
  restart).
- **Tamper-evident audit log.** Append-only JSONL, hash-chained:
  every tool call, its arguments, its decision, and its result. Edit
  or delete a line and `GET /admin/audit/verify` says so.

## Quick start

```bash
# 1. Start a tool server (the demo one, on :8001)
python -m gateway.demo_server

# 2. Start the gateway (on :8000, upstream = the demo server)
python -m gateway --policy-dir policies \
  --upstream http://127.0.0.1:8001/mcp

# 3. Call through the gateway as the support bot
curl -X POST http://127.0.0.1:8000/mcp \
  -H "x-agent-key: demo-key-support-bot" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"crm.read_customer",
                 "arguments":{"customer_id":"cust_1","limit":5}}}'
```

Or run the whole story at once:

```bash
python demo.py
```

It plays an agent that tries six calls — a read, an email outside
the company (blocked), an email inside (allowed), a large refund
(held for a human), a small refund (allowed), and a destructive call
(blocked) — then prints the audit log and verifies the hash chain.

## Example policy

```yaml
agent: support-bot
risk_tier: medium
allow:
  - tool: crm.read_customer
    limits: { max_rows: 20 }
  - tool: email.send
    where: { to_domain: ["company.com"] }
require_approval:
  - tool: refund.create
    when: { amount_gt: 100 }
deny_when_tainted:
  - tool: email.send
    where: { to_domain_not: ["company.com"] }
budgets:
  max_calls: 100
```

## Configuration

| Setting | How |
|---|---|
| Agent keys | `AGENT_KEYS` env var (JSON: key → agent) or `--keys-file` |
| Admin key | `GATEWAY_ADMIN_KEY` env var |
| Policies | `--policy-dir` (one YAML file per agent) |
| Upstream | `--upstream` (the MCP server URL) |
| Audit log | `--audit` (default `data/audit.jsonl`) |

Admin endpoints (need `X-Admin-Key`): `GET /admin/audit`,
`GET /admin/audit/verify`, `POST /admin/kill/{agent}`,
`POST /admin/revive/{agent}`, `GET /admin/policies`.

## v0.2 — policy tests and budgets (Phase 2)

- **Policy test suite.** Prove a policy does what it says before an
  agent ever runs under it. Cases are YAML (`tool`, `args`, `tainted`,
  `expected`); run them with:

  ```bash
  python -m gateway.test_policy policies/support-bot.yaml \
    tests/policies/support-bot.cases.yaml
  ```

  Exit 0 when every case passes. The support bot's nine cases cover
  the row limit, the domain rule, the refund threshold, the unknown
  tool, and both taint cases.
- **Spend budgets.** Each tool has a cost (`costs:` in the policy);
  `budgets.max_spend` stops the agent when it has spent that much.
- **Row budgets.** `budgets.max_rows_read` caps how many rows an
  agent may read (a read counts the rows it asked for).
- **Per-tool rate limits.** `budgets.rate_limits` caps calls per
  minute per tool — the answer to a runaway loop repeating a costly
  action.
- Spend and rows are recorded in the audit log, so budgets survive
  a gateway restart.

## Roadmap

- **v0.3 (Phase 3)** — taint tracking (a session that touched
  untrusted content gets tighter rules), egress allowlist, Telegram
  and Slack approvals.
- **v0.4 (Phase 4)** — hash-chained log replay, timeline dashboard,
  incident reconstruction.
- **v0.5 (Phase 5–6)** — fail-closed load tests, published latency
  numbers, open-source launch with the attack benchmark.

## Security notes

- The gateway must be the **only** path an agent has to the tools.
  If an agent can reach the MCP server directly, the gateway is
  decoration.
- A good grade from a scanner, or a green audit, does not mean a
  system is secure. The gateway reduces blast radius and proves what
  happened; it does not promise perfect security.
