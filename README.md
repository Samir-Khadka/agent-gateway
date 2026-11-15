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

## v0.3 — taint tracking, egress, Telegram approvals (Phase 3)

- **Taint tracking.** A session starts clean. Once it receives
  content from an untrusted source — a `web.fetch`, an `email.read`,
  or any tool the policy lists under `taint_sources` — the session
  is tainted, and the policy's `deny_when_tainted` rules apply to
  every later call. The demo proves it: a fetched page tells the
  agent to email the customer list out, and the tainted session's
  external email is blocked while its internal email still works.
  Taint is per-session, persisted, and cleared only by a human
  (`POST /admin/sessions/{id}/clear`).
- **Egress allowlist.** `egress_allowlist` in the policy lists the
  domains an agent may reach. A `web.fetch` or `email.send` to
  anywhere else is denied. A plain entry covers its subdomains;
  `*.company.com` covers subdomains only.
- **Telegram approvals.** When a call is held, the gateway can
  message a human on Telegram with the agent, tool, arguments, and
  reason, plus Approve / Deny buttons. Tapping one resolves the
  approval; the agent re-sends the call with the `approval_id` and
  it runs or is refused. Setup needs a bot token from @BotFather
  (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, optional
  `TELEGRAM_WEBHOOK_SECRET`). Without a token, approvals still work
  through the admin API (`POST /admin/approvals/{id}/approve`).
- **Audit log fix.** Adding `cost`/`rows` in v0.2 broke
  verification of v0.1 entries (the hash was recomputed over a
  dataclass with defaults). The hash is now computed over the
  stored dict, so old entries still verify — with a regression test
  proving it.

## v0.4 — log replay, timeline dashboard, incident reconstruction (Phase 4)

- **Log replay.** `python -m gateway.replay data/audit.jsonl
  [--agent X] [--session Y] [--decision deny]` rebuilds an incident
  from the hash-chained log: which call tainted the session, which
  calls were blocked after that, what it spent and read. The demo's
  session B replays as three lines: tainted by the fetch, the
  exfiltration blocked, the internal email still allowed.
- **Timeline dashboard.** `GET /admin/dashboard` is a single
  server-rendered page: a summary bar (allowed / denied / held,
  tainted sessions, spend, rows), filters by agent and session, and
  the entries as a timeline with decision badges and taint markers.
  `GET /admin/replay?session=B` returns the same reconstruction
  as JSON, for the dashboard or any other tool.
- **Sessions in the log.** Every audit entry now records its
  `session_id`, so replay can filter to one session — the old
  entries (without it) still verify, because the hash is computed
  over the fields each entry actually has.

## v0.5 — hardening, attack benchmark, latency, launch (Phases 5–6)

- **Attack benchmark.** `python -m gateway.attack_benchmark`
  runs **55 scenarios** from the threat model against a live
  gateway, each asserting the call is blocked, held, or allowed as
  it should be: injection (10), exfiltration (8), privilege
  escalation (6), budgets (6), approval bypass (6), kill switch
  (4), egress (6), audit tampering (4), hardening (5). **55/55
  pass.** The benchmark runs in CI, so a change that weakens a
  control is a regression, not a feature.
- **Hardening.** The gateway now rejects oversized requests (1 MB
  body, 100 KB of arguments), malformed JSON, non-object requests,
  and calls with a non-dict `arguments`; a gateway-wide rate limit
  (60 requests/minute per agent key, 429 on excess) sits above the
  policy's per-tool limits; and an upstream failure returns a
  generic "upstream unavailable" instead of leaking the upstream's
  internals. Two real gaps the benchmark found are fixed: a
  negative refund (a charge, not a refund) is now denied by the
  policy, and the policy's `to_domain` now covers subdomains —
  the same rule as the egress allowlist, so the two controls cannot
  disagree about what "company.com" means. Denials now say *why*
  (max_rows, to_domain, amount, taint, budget, egress) instead of
  only "not in this agent's capabilities".
- **Latency.** The policy decision itself — the gateway's own
  added cost — is **p50 0.003 ms, p95 0.005 ms** (n=200), well
  under the 10 ms budget. End to end, a forwarded call in the test
  harness averages 44 ms against 6 ms direct to the upstream; the
  difference is the extra HTTP hop to the tool server (the gateway
  is a proxy, and it talks to the tool server over real HTTP),
  plus test-client overhead — not the policy check. Run it:
  `python -m gateway.latency`.
- **Open-source launch.** MIT license (`LICENSE`), a security
  policy (`SECURITY.md` — report privately to
  samirshirjan890@gmail.com), and contribution rules
  (`CONTRIBUTING.md` — fail closed, denials must say why, the
  audit log is append-only, no new dependencies without a reason).

## v0.6 — policy editor, deployment, a realistic agent (first real deployment)

- **Policy editor.** `GET /admin/editor` is a browser page for
  editing a policy without hand-editing YAML: add/remove allow,
  approval, and taint rules, set budgets and costs, edit the egress
  allowlist and taint sources, flip the kill switch. Saving
  validates the policy the same way the gateway does at startup —
  an empty policy, a rule without a tool, or a mismatched agent is
  rejected and the old file is left untouched — and the new policy
  takes effect immediately, live, with no restart.
  (`GET /admin/policies/{agent}`, `POST /admin/policies/{agent}`.)
- **Deployment.** `render.yaml` (a Render Blueprint), a
  `Dockerfile`, `gateway/server.py` (the entry point, configured
  from env vars), and `DEPLOY.md`. A live Render deploy waits for
  1 Dec — Samir's workspace is suspended until then — but Docker
  and local both work now. The guide is honest about what a real
  deployment needs: a persistent disk for the audit log, your own
  tool server as `UPSTREAM_URL`, a real admin key, HTTPS.
- **A realistic agent.** `examples/support_agent.py` runs a
  support agent's shift through the gateway: a ticket comes in,
  the agent reads the customer, fetches the billing help page —
  which has been poisoned with an instruction to email the
  customer list out — and the gateway blocks the exfiltration
  while the legitimate work (an internal email, a small refund)
  still completes. The audit log verifies intact at the end.

## v0.7 — an LLM agent, and the launch (Phase 7)

- **An LLM agent.** `examples/llm_agent.py` is a ReAct loop: the
  model gets the ticket and the tools the gateway allows it to
  see, picks a tool call, the gateway checks it, and the result
  (or the block) goes back to the model. It works with any
  OpenAI-compatible API (`LLM_API_KEY`, `LLM_BASE_URL`,
  `LLM_MODEL`) — and with `--simulate`, a deterministic stand-in
  plays the model, so the harness runs without a key and CI can
  test it. In simulate mode the transcript is the proof: the model
  follows the injected instruction, the gateway blocks the
  exfiltration, and the legitimate work still completes.
- **Launch.** `LAUNCH.md` is the announcement: what it does, the
  numbers (55/55, p50 0.003 ms), and what it is not. The hosted
  demo still waits for the Render reset on 1 Dec — that is the one
  piece of the launch that cannot be done today.

## v0.8 — Slack approvals, a second agent, a safer editor

- **Slack approvals.** Phase 3 said "Telegram and Slack" — Slack
  is the half that was missing. `SLACK_WEBHOOK_URL` posts the
  approval request as a Block Kit message with Approve / Deny
  buttons; `POST /slack/interactive` receives the click, verifies
  the request signature when `SLACK_SIGNING_SECRET` is set, and
  resolves the approval. Telegram and Slack can both be configured;
  the gateway notifies on every channel that is set. (Also fixed
  along the way: the repo had no `requirements.txt` even though
  `render.yaml` and the `Dockerfile` referenced it — it exists
  now, including `python-multipart`, which Slack's form-encoded
  payloads need.)
- **A second agent.** `policies/analyst-bot.yaml` is a read-only
  analyst: it may read customers and fetch pages, but never email
  or refund. The demo's new Session D shows the same call allowed
  for the support bot and denied for the analyst — the gateway
  enforces a different policy per agent.
- **A safer editor.** Saving a policy now runs that policy's test
  cases first, and rejects the save if any fail — so an edit cannot
  silently break the behaviour the tests pin down. The old file is
  left untouched.

## Roadmap

- **v0.9 (1 Dec)** — the hosted demo goes live once Render resets,
  and the launch announcement is published.
- **v0.5 (Phase 5–6)** — fail-closed load tests, published latency
  numbers, open-source launch with the attack benchmark.

## Security notes

- The gateway must be the **only** path an agent has to the tools.
  If an agent can reach the MCP server directly, the gateway is
  decoration.
- A good grade from a scanner, or a green audit, does not mean a
  system is secure. The gateway reduces blast radius and proves what
  happened; it does not promise perfect security.
