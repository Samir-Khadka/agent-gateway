"""Policy engine: capability-based allow/deny, evaluated per tool call.

A policy is YAML (see policies/support-bot.yaml). Each agent session
gets explicit capabilities — a tool name, optional argument limits,
and optional `where` conditions — never blanket access. Anything not
explicitly allowed is denied (fail closed). A call that matches a
`require_approval` rule is held, never run. A call that matches a
`deny_when_tainted` rule is denied once the session has touched
untrusted content (taint is tracked by the gateway, Phase 3 wires
the Telegram/Slack approval; v0.1 returns the hold so the caller
knows a human is needed).

Conditions (all under `where` / `when`, matched against the tool's
arguments):
  to_domain:     the `to` argument's domain must be in the list
  to_domain_not: the `to` argument's domain must NOT be in the list
  max_rows:      a `limit` / `max_rows` argument must be <= this
  amount_gt:     an `amount` argument greater than this triggers the rule
  amount_lte:    an `amount` argument <= this triggers the rule
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

DECISIONS = ("allow", "deny", "require_approval")


@dataclass
class Decision:
    outcome: str  # one of DECISIONS
    reason: str
    rule: dict = field(default_factory=dict)


@dataclass
class Policy:
    agent: str
    risk_tier: str = "medium"
    allow: list = field(default_factory=list)
    require_approval: list = field(default_factory=list)
    deny_when_tainted: list = field(default_factory=list)
    budgets: dict = field(default_factory=dict)
    costs: dict = field(default_factory=dict)  # tool -> dollars per call
    egress_allowlist: list = field(default_factory=list)
    taint_sources: list = field(default_factory=list)
    kill_switch: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        return cls(
            agent=data.get("agent", "unknown"),
            risk_tier=data.get("risk_tier", "medium"),
            allow=data.get("allow", []),
            require_approval=data.get("require_approval", []),
            deny_when_tainted=data.get("deny_when_tainted", []),
            budgets=data.get("budgets", {}),
            costs=data.get("costs", {}),
            egress_allowlist=data.get("egress_allowlist", []),
            taint_sources=data.get("taint_sources", []),
            kill_switch=bool(data.get("kill_switch", False)),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        return cls.from_dict(
            yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})

    def cost_of(self, tool: str) -> float:
        """What one call of this tool costs (dollars)."""
        return float(self.costs.get(tool, 0.0))

    def rows_of(self, tool: str, args: dict) -> int:
        """How many rows this call reads. A read tool reads the rows
        it asked for (its limit, default 1); anything else reads 0."""
        if not any(word in tool for word in ("read", "list", "get")):
            return 0
        return int(args.get("limit", args.get("max_rows", 1)))


def _domain_of(to: str) -> str:
    """The domain of an email address (after the last @)."""
    return to.rsplit("@", 1)[-1].strip().lower() if "@" in to else ""


def _domain_matches(domain: str, entry: str) -> bool:
    """Whether a domain is covered by one listed domain. A plain
    entry covers the domain and its subdomains (company.com covers
    docs.company.com) — the same rule as the egress allowlist, so
    the two controls cannot disagree about what 'company.com'
    means. evilcompany.com is NOT a subdomain of company.com."""
    entry = entry.lower()
    return domain == entry or domain.endswith("." + entry)


def _matches(rule: dict, tool: str, args: dict) -> bool:
    """Whether this rule applies to the call: the tool name matches
    and every condition in `where` / `when` / `limits` holds."""
    if rule.get("tool") != tool:
        return False
    where = rule.get("where") or rule.get("when") or {}
    limits = rule.get("limits") or {}
    for key, value in {**where, **limits}.items():
        if key == "to_domain":
            domain = _domain_of(str(args.get("to", "")))
            if not any(_domain_matches(domain, entry)
                       for entry in value):
                return False
        elif key == "to_domain_not":
            domain = _domain_of(str(args.get("to", "")))
            if any(_domain_matches(domain, entry)
                   for entry in value):
                return False
        elif key == "max_rows":
            n = args.get("limit", args.get("max_rows"))
            if n is not None and int(n) > int(value):
                return False
        elif key == "amount_gt":
            if float(args.get("amount", 0)) <= float(value):
                return False
        elif key == "amount_lte":
            if float(args.get("amount", 0)) > float(value):
                return False
        else:
            # an unknown condition never matches — fail closed
            return False
    return True


def _failed_condition(rule: dict, tool: str, args: dict) -> str | None:
    """The first condition of a rule that does not hold, as a
    readable reason — so a denial says *why* (max_rows, domain,
    amount) instead of only 'not in this agent's capabilities'."""
    where = rule.get("where") or rule.get("when") or {}
    limits = rule.get("limits") or {}
    for key, value in {**where, **limits}.items():
        if key == "to_domain":
            domain = _domain_of(str(args.get("to", "")))
            if not any(_domain_matches(domain, entry)
                       for entry in value):
                return (f"to_domain: {domain} is not in "
                        f"{', '.join(value)}")
        elif key == "to_domain_not":
            domain = _domain_of(str(args.get("to", "")))
            if any(_domain_matches(domain, entry)
                   for entry in value):
                return f"to_domain_not: {domain} is in {value}"
        elif key == "max_rows":
            n = args.get("limit", args.get("max_rows"))
            if n is not None and int(n) > int(value):
                return f"max_rows: {n} exceeds {value}"
        elif key == "amount_gt":
            if float(args.get("amount", 0)) <= float(value):
                return (f"amount_gt: {args.get('amount')} is not "
                        f"greater than {value}")
        elif key == "amount_lte":
            if float(args.get("amount", 0)) > float(value):
                return (f"amount_lte: {args.get('amount')} exceeds "
                        f"{value}")
    return None


def evaluate(policy: Policy, tool: str, args: dict,
             tainted: bool = False) -> Decision:
    """Decide one tool call. Order matters: a kill switch denies
    everything; a taint denial beats an allow; an approval rule beats
    an allow; anything not allowed is denied."""
    if policy.kill_switch:
        return Decision("deny", "kill switch is on for this agent")
    if tainted:
        for rule in policy.deny_when_tainted:
            if _matches(rule, tool, args):
                return Decision("deny",
                                f"denied while tainted: {tool} is "
                                f"blocked after untrusted input",
                                rule)
    for rule in policy.require_approval:
        if _matches(rule, tool, args):
            return Decision("require_approval",
                            f"{tool} needs a human approval", rule)
    for rule in policy.allow:
        if _matches(rule, tool, args):
            return Decision("allow", f"{tool} is allowed", rule)
    # A rule exists for this tool but a condition failed — say which
    # one, so the denial is diagnosable instead of generic.
    for rule in policy.allow:
        if rule.get("tool") == tool:
            reason = _failed_condition(rule, tool, args)
            if reason:
                return Decision(
                    "deny",
                    f"{tool} is not allowed: {reason}")
    return Decision("deny", f"{tool} is not in this agent's capabilities")
