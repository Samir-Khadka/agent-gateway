# LinkedIn launch draft — Agent Gateway (DRAFT, NOT PUBLISHED)
# Awaiting Samir's approval of the exact text before anything is posted.
# The live demo link stays out until the Render reset on 1 Dec.

I built a firewall for what AI agents do — not what they say.

An agent is useful because it does things: read a customer record,
send an email, issue a refund. That's also what makes it dangerous.
A prompt injection isn't a rude message. It's an instruction smuggled
into a web page, and the agent follows it because following
instructions is its job.

Agent Gateway sits between the agent and its tools:

- Capability policies in YAML — allow, deny, require approval.
  Anything not listed is denied.
- Taint tracking — once a session touches untrusted content, the
  tighter rules apply to every later call.
- Telegram approvals for risky calls, a hash-chained audit log,
  budgets, an egress allowlist, and a kill switch.

The numbers: 55/55 attack scenarios stopped, policy decision in
0.003 ms.

Open source (MIT): https://github.com/Samir-Khadka/agent-gateway

The demo that convinced me it works: a poisoned help page tells the
agent to email the customer list out. The gateway blocks it, and the
agent's real work still gets done.

#AISecurity #MCP #OpenSource #Python #CyberSecurity
