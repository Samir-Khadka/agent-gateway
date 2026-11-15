# Contributing

Agent Gateway is a small project with a sharp scope: a firewall for
what AI agents *do*. Contributions that make the enforcement
tighter, the audit clearer, or the setup simpler are welcome.
Contributions that add a new tool server, a new chat platform, or a
new agent framework are out of scope — the gateway is deliberately
tool- and framework-agnostic.

## How to contribute

1. Fork the repo and create a branch.
2. Make your change, with a test that proves it. The test suite is
   `pytest tests/ -q` (Python 3.11+; `fastapi`, `httpx`, `pyyaml`,
   `pytest`).
3. Run the attack benchmark: `python -m gateway.attack_benchmark`.
   It must stay green — a change that weakens a control is a
   regression, not a feature.
4. Open a pull request describing the change and the threat it
   addresses (or the usability problem it fixes).

## Ground rules

- **Fail closed.** A new control must deny by default; an unknown
  condition, an unparseable policy, or a missing field must block
  the call, never allow it.
- **Denials must say why.** A denial message names the rule that
  fired (max_rows, to_domain, taint, budget, egress) — never a bare
  "denied".
- **The audit log is append-only.** Never add a way to edit or
  delete entries. If the schema grows, old entries must still
  verify (there is a regression test for this).
- **No new dependencies** without a strong reason. The gateway
  runs on FastAPI + httpx + PyYAML; keep it that way.
- **Keep the demo honest.** The demo server is a stand-in for a
  real tool server. If you add a tool to it, add the policy rule
  and the benchmark scenario that covers it.
