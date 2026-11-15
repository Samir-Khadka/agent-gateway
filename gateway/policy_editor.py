"""Policy editor: a browser page for editing a policy without
hand-editing YAML.

The page itself needs no key to load (it holds no data); every API
call it makes sends the admin key the user types in, and the server
checks it. On save, the policy is validated the same way the
gateway validates it at startup — an invalid policy is rejected
and the old file is left untouched.
"""
from __future__ import annotations

PAGE = """<!DOCTYPE html>
<html><head><meta charset='utf-8'>
<title>Agent Gateway — policy editor</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;
padding:0 1rem;color:#1f2328}
h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:1.5rem}
label{display:block;margin:.4rem 0;font-size:.9rem;color:#57606a}
input,textarea,select{width:100%;padding:.4rem;border:1px solid #d0d7de;
border-radius:6px;font:inherit}
.rule{border:1px solid #d0d7de;border-radius:6px;padding:.6rem;
margin:.4rem 0}
.rule .row{display:flex;gap:.5rem}
.rule .row>*{flex:1}
button{padding:.5rem 1rem;border-radius:6px;border:1px solid #d0d7de;
background:#f6f8fa;cursor:pointer;font:inherit}
button.primary{background:#1f6feb;color:#fff;border-color:#1f6feb}
#status{margin:1rem 0;font-weight:600}
#status.err{color:#cf222e} #status.ok{color:#1a7f37}
</style></head><body>
<h1>Agent Gateway — policy editor</h1>
<label>Admin key <input id="key" type="password"
placeholder="the GATEWAY_ADMIN_KEY"></label>
<label>Agent <input id="agent" value="support-bot"></label>
<button id="load">Load policy</button>
<div id="status"></div>
<div id="form" style="display:none">
<h2>Allow</h2><div id="allow"></div>
<button data-add="allow">+ add allow rule</button>
<h2>Require approval</h2><div id="approval"></div>
<button data-add="approval">+ add approval rule</button>
<h2>Deny when tainted</h2><div id="tainted"></div>
<button data-add="tainted">+ add taint rule</button>
<h2>Budgets</h2>
<label>max calls <input id="max_calls" type="number"></label>
<label>max spend ($) <input id="max_spend" type="number" step="0.01"></label>
<label>max rows read <input id="max_rows" type="number"></label>
<label>rate limits (JSON, tool -&gt; calls/min)
<textarea id="rate_limits" rows="2">{}</textarea></label>
<h2>Costs (JSON, tool -&gt; $ per call)</h2>
<textarea id="costs" rows="3">{}</textarea>
<h2>Egress allowlist (one domain per line)</h2>
<textarea id="egress" rows="3"></textarea>
<h2>Taint sources (one tool per line)</h2>
<textarea id="taints" rows="3"></textarea>
<label><input id="kill" type="checkbox"> kill switch on</label>
<p><button id="save" class="primary">Save policy</button></p>
</div>
<script>
const $ = id => document.getElementById(id);
const status = (msg, ok) => {
  const el = $('status'); el.textContent = msg;
  el.className = ok ? 'ok' : 'err';
};
function ruleRow(section, rule) {
  const div = document.createElement('div');
  div.className = 'rule'; div.dataset.section = section;
  div.innerHTML = `<div class="row">
    <input class="tool" placeholder="tool, e.g. email.send"
           value="${rule.tool || ''}">
    <input class="where" placeholder='where / when as JSON, e.g. {"to_domain": ["company.com"]}'
           value='${JSON.stringify(rule.where || rule.when || {})}'>
    <input class="limits" placeholder='limits as JSON, e.g. {"max_rows": 20}'
           value='${JSON.stringify(rule.limits || {})}'>
    <button type="button" class="rm">remove</button></div>`;
  div.querySelector('.rm').onclick = () => div.remove();
  return div;
}
function render(policy) {
  $('form').style.display = 'block';
  for (const [section, el] of [['allow', 'allow'],
                               ['require_approval', 'approval'],
                               ['deny_when_tainted', 'tainted']]) {
    const box = $(el); box.innerHTML = '';
    (policy[section] || []).forEach(r => box.appendChild(ruleRow(section, r)));
  }
  const b = policy.budgets || {};
  $('max_calls').value = b.max_calls ?? '';
  $('max_spend').value = b.max_spend ?? '';
  $('max_rows').value = b.max_rows_read ?? '';
  $('rate_limits').value = JSON.stringify(b.rate_limits || {});
  $('costs').value = JSON.stringify(policy.costs || {});
  $('egress').value = (policy.egress_allowlist || []).join('\\n');
  $('taints').value = (policy.taint_sources || []).join('\\n');
  $('kill').checked = !!policy.kill_switch;
}
function collect() {
  const rules = section => [...document.querySelectorAll(
    `#${section} .rule`)].map(div => {
    const tool = div.querySelector('.tool').value.trim();
    const where = JSON.parse(div.querySelector('.where').value || '{}');
    const limits = JSON.parse(div.querySelector('.limits').value || '{}');
    const rule = {tool};
    if (Object.keys(where).length) rule.where = where;
    if (Object.keys(limits).length) rule.limits = limits;
    return rule;
  });
  const budgets = {};
  if ($('max_calls').value) budgets.max_calls = +$('max_calls').value;
  if ($('max_spend').value) budgets.max_spend = +$('max_spend').value;
  if ($('max_rows').value) budgets.max_rows_read = +$('max_rows').value;
  const rl = JSON.parse($('rate_limits').value || '{}');
  if (Object.keys(rl).length) budgets.rate_limits = rl;
  return {
    agent: $('agent').value.trim(),
    risk_tier: 'medium',
    allow: rules('allow'),
    require_approval: rules('approval'),
    deny_when_tainted: rules('tainted'),
    budgets, costs: JSON.parse($('costs').value || '{}'),
    egress_allowlist: $('egress').value.split('\\n')
      .map(s => s.trim()).filter(Boolean),
    taint_sources: $('taints').value.split('\\n')
      .map(s => s.trim()).filter(Boolean),
    kill_switch: $('kill').checked,
  };
}
document.querySelectorAll('[data-add]').forEach(btn => {
  btn.onclick = () => {
    const section = btn.dataset.add;
    const box = $(section === 'approval' ? 'approval' : section);
    box.appendChild(ruleRow(section, {}));
  };
});
$('load').onclick = async () => {
  const agent = $('agent').value.trim();
  const resp = await fetch(`/admin/policies/${agent}`, {
    headers: {'x-admin-key': $('key').value}});
  if (!resp.ok) { status('could not load: ' + resp.status, false); return; }
  render(await resp.json());
  status('loaded ' + agent, true);
};
$('save').onclick = async () => {
  let policy;
  try { policy = collect(); }
  catch (e) { status('invalid JSON in a rule: ' + e.message, false); return; }
  const resp = await fetch(`/admin/policies/${policy.agent}`, {
    method: 'POST',
    headers: {'x-admin-key': $('key').value,
              'content-type': 'application/json'},
    body: JSON.stringify(policy)});
  const data = await resp.json();
  if (!resp.ok) { status('not saved: ' + (data.detail || resp.status), false); return; }
  status('saved — the gateway is now enforcing the new policy', true);
};
</script></body></html>
"""


def render_editor_page() -> str:
    return PAGE
