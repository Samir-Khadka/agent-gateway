"""The attack benchmark runs clean: every scenario in the threat
model is stopped (or held, or allowed) as it should be."""
from __future__ import annotations

from gateway.attack_benchmark import _scenarios, render_report, run_benchmark


def test_benchmark_has_fifty_plus_scenarios():
    assert len(_scenarios()) >= 50


def test_benchmark_all_scenarios_pass():
    results, passed, total = run_benchmark(port=8006)
    assert passed == total, render_report(results, passed, total)
