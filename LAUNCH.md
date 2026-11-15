# Agent Gateway is live — a firewall for what AI agents do

AI agents are useful because they *do* things: read a customer
record, send an email, issue a refund. That is also what makes
them dangerous. A prompt injection is not a rude message — it is
an instruction smuggled into a web page, an email, or a file, and
the agent follows it because following instructions is its job.

Agent Gateway sits between the agent and its tools, and enforces
what the agent may do — not what it says.

## What it does

- **MCP proxy.** The agent talks to the gateway, never to a tool
  server directly. Every call is checked against a YAML policy for
  that agent.
- **Capability policies.** Allow rules with argument limits
  (`max_rows`), `where` conditions (`to_domain`), and
  `require_approval` rules for risky calls. Anything not listed is
  denied — fail closed.
- **Taint tracking.** Once a session has touched untrusted content
  (a web page, an email, a file), the tighter rules apply to every
  later call. The demo proves it: a poisoned help page tells the
  agent to email the customer list out, and the tainted session's
  external email is blocked while its internal email still works.
- **Egress allowlist.** The policy lists the domains an agent may
  reach. Anywhere else is denied.
- **Telegram approvals.** A held call messages a human with the
  agent, tool, arguments, and reason, plus Approve / Deny buttons.
- **Hash-chained audit log.** Every decision is appended to a
  tamper-evident chain. Edit or delete a line and verification
  names the first bad entry.
- **Budgets and kill switch.** Per-agent call, spend, and row
  budgets, per-tool rate limits, and a persistent kill switch.

## The numbers

- **55/55** attack scenarios blocked, held, or allowed as they
  should be (`python -m gateway.attack_benchmark`)
- **p50 0.003 ms** policy decision latency — well under the 10 ms
  budget (`python -m gateway.latency`)
- **74 tests**, CI green on Python 3.11 and 3.12

## Try it

```bash
git clone https://github.com/Samir-Khadka/agent-gateway
cd agent-gateway
pip install -r requirements.txt
python demo.py          # the injection demo, in one command
python examples/support_agent.py   # a realistic agent shift
python examples/llm_agent.py --simulate  # an LLM agent (no key needed)
```

The policy editor is at `/admin/editor` once the gateway is
running; the timeline dashboard at `/admin/dashboard`.

## What it is not

It is not a sandbox, and it does not inspect the *meaning* of
arguments — only their shape and the conditions in the policy. It
does not stop an agent from calling a tool the policy explicitly
allows. The threat model and the limits are in `SECURITY.md`.

Built by Samir Khadka, Kathmandu. MIT licensed.
