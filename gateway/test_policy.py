"""Policy test suite: prove a policy does what it says, before an
agent ever runs under it.

A cases file is YAML:

    cases:
      - name: read within the row limit
        tool: crm.read_customer
        args: {customer_id: cust_1, limit: 5}
        expected: allow
      - name: email outside the company
        tool: email.send
        args: {to: x@evil.com, subject: s, body: b}
        expected: deny
      - name: tainted external email
        tool: email.send
        args: {to: x@evil.com, subject: s, body: b}
        tainted: true
        expected: deny

Run: python -m gateway.test_policy policies/support-bot.yaml
         tests/policies/support-bot.cases.yaml
Exit 0 when every case passes, 1 otherwise. This is the Phase 2
proof point: the policy test suite passes.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from .policy import Policy, evaluate

EXPECTED = ("allow", "deny", "require_approval")


@dataclass
class CaseResult:
    name: str
    expected: str
    actual: str
    passed: bool
    reason: str


def load_cases(path: str | Path) -> list[dict]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return data.get("cases", [])


def run_cases(policy: Policy, cases: list[dict]) -> list[CaseResult]:
    results = []
    for case in cases:
        expected = case.get("expected", "")
        decision = evaluate(policy, case.get("tool", ""),
                            case.get("args", {}) or {},
                            tainted=bool(case.get("tainted", False)))
        results.append(CaseResult(
            name=case.get("name", case.get("tool", "?")),
            expected=expected, actual=decision.outcome,
            passed=decision.outcome == expected,
            reason=decision.reason))
    return results


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        print("usage: python -m gateway.test_policy <policy.yaml> "
              "<cases.yaml>", file=sys.stderr)
        return 2
    policy = Policy.from_file(argv[0])
    results = run_cases(policy, load_cases(argv[1]))
    failed = 0
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        print(f"[{mark}] {r.name}: expected {r.expected}, "
              f"got {r.actual} ({r.reason})")
        if not r.passed:
            failed += 1
    print(f"{len(results) - failed}/{len(results)} cases passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
