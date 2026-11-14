"""Policy test suite: cases pass and fail for the right reasons."""
from __future__ import annotations

from gateway.policy import Policy
from gateway.test_policy import load_cases, run_cases, main

POLICY = {
    "agent": "support-bot",
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
}


def test_all_support_bot_cases_pass():
    policy = Policy.from_dict(POLICY)
    results = run_cases(
        policy, load_cases("tests/policies/support-bot.cases.yaml"))
    assert len(results) == 9
    assert all(r.passed for r in results)


def test_a_wrong_expectation_fails():
    policy = Policy.from_dict(POLICY)
    results = run_cases(policy, [
        {"name": "wrong", "tool": "email.send",
         "args": {"to": "x@evil.com"}, "expected": "allow"}])
    assert len(results) == 1 and not results[0].passed
    assert results[0].actual == "deny"


def test_cli_exits_0_when_all_pass(capsys):
    assert main(["policies/support-bot.yaml",
                 "tests/policies/support-bot.cases.yaml"]) == 0
    assert "9/9 cases passed" in capsys.readouterr().out


def test_cli_exits_1_when_a_case_fails(tmp_path, capsys):
    cases = tmp_path / "cases.yaml"
    cases.write_text(
        "cases:\n"
        "  - name: wrong\n"
        "    tool: email.send\n"
        "    args: {to: x@evil.com}\n"
        "    expected: allow\n", encoding="utf-8")
    assert main(["policies/support-bot.yaml", str(cases)]) == 1
    assert "FAIL" in capsys.readouterr().out
