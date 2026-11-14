"""Policy engine: allow, deny, argument rules, approvals, taint."""
from __future__ import annotations

import pytest

from gateway.policy import Policy, evaluate

POLICY = {
    "agent": "support-bot",
    "risk_tier": "medium",
    "allow": [
        {"tool": "crm.read_customer", "limits": {"max_rows": 20}},
        {"tool": "email.send",
         "where": {"to_domain": ["company.com"]}},
        {"tool": "refund.create", "when": {"amount_lte": 100}},
    ],
    "require_approval": [
        {"tool": "refund.create", "when": {"amount_gt": 100}},
    ],
    "deny_when_tainted": [
        {"tool": "email.send",
         "where": {"to_domain_not": ["company.com"]}},
    ],
    "budgets": {"max_calls": 100},
}


@pytest.fixture()
def policy():
    return Policy.from_dict(POLICY)


def test_allowed_call(policy):
    d = evaluate(policy, "crm.read_customer",
                 {"customer_id": "cust_1", "limit": 5})
    assert d.outcome == "allow"


def test_row_limit_denies(policy):
    d = evaluate(policy, "crm.read_customer",
                 {"customer_id": "cust_1", "limit": 50})
    assert d.outcome == "deny"


def test_email_inside_the_company_allowed(policy):
    assert evaluate(policy, "email.send",
                    {"to": "team@company.com"}).outcome == "allow"


def test_email_outside_the_company_denied(policy):
    assert evaluate(policy, "email.send",
                    {"to": "x@evil.com"}).outcome == "deny"


def test_small_refund_allowed(policy):
    assert evaluate(policy, "refund.create",
                    {"amount": 50}).outcome == "allow"


def test_large_refund_needs_approval(policy):
    d = evaluate(policy, "refund.create", {"amount": 150})
    assert d.outcome == "require_approval"


def test_unknown_tool_denied_by_default(policy):
    assert evaluate(policy, "db.delete_all", {}).outcome == "deny"


def test_taint_blocks_external_email(policy):
    # untainted: the allow rule governs; tainted: the deny rule wins
    assert evaluate(policy, "email.send",
                    {"to": "x@evil.com"}).outcome == "deny"
    d = evaluate(policy, "email.send", {"to": "x@evil.com"},
                 tainted=True)
    assert d.outcome == "deny" and "tainted" in d.reason


def test_taint_does_not_block_internal_email(policy):
    d = evaluate(policy, "email.send", {"to": "team@company.com"},
                 tainted=True)
    assert d.outcome == "allow"


def test_kill_switch_denies_everything(policy):
    policy.kill_switch = True
    assert evaluate(policy, "crm.read_customer", {}).outcome == "deny"
    assert evaluate(policy, "email.send",
                    {"to": "team@company.com"}).outcome == "deny"
