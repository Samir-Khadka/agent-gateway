"""Latency benchmark: how much does the gateway add?

Measures the decision latency (policy check only, no upstream) and
the end-to-end latency (a call forwarded to the demo server), as
p50 / p95 / p99. The plan's budget is under 10 ms of added policy
latency. Run: python -m gateway.latency [--port 8001] [--n 200]
"""
from __future__ import annotations

import argparse
import statistics
import tempfile
import threading
import time
from pathlib import Path

import uvicorn
from fastapi.testclient import TestClient

from .attack_benchmark import _fresh_gateway
from .demo_server import create_demo_server
from .policy import evaluate
from .proxy import create_app

AGENT_KEY = "demo-key-support-bot"


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(len(ordered) * pct / 100))
    return ordered[idx]


def measure(port: int = 8001, n: int = 200) -> dict:
    thread = threading.Thread(
        target=uvicorn.run,
        args=(create_demo_server(),),
        kwargs={"host": "127.0.0.1", "port": port, "log_level": "error"},
        daemon=True)
    thread.start()
    time.sleep(1.0)
    upstream = f"http://127.0.0.1:{port}/mcp"
    with tempfile.TemporaryDirectory(prefix="agent-gateway-lat-") as td:
        gateway = _fresh_gateway(Path(td), upstream)
        policy = gateway.policy_for("support-bot")
        # decision only: the policy check, no network, no audit write
        decision_times = []
        for _ in range(n):
            start = time.perf_counter()
            evaluate(policy, "crm.read_customer",
                     {"customer_id": "cust_1", "limit": 5})
            decision_times.append(
                (time.perf_counter() - start) * 1000)
        # end to end: a real MCP call through the gateway
        client = TestClient(create_app(gateway))
        e2e_times = []
        for _ in range(n):
            start = time.perf_counter()
            client.post(
                "/mcp", headers={"x-agent-key": AGENT_KEY},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "crm.read_customer",
                                 "arguments": {"customer_id": "cust_1",
                                               "limit": 5}}})
            e2e_times.append((time.perf_counter() - start) * 1000)
        # baseline: the same call straight to the upstream, no
        # gateway — so the added cost is the difference, not the
        # absolute number (the test client dominates both)
        direct = TestClient(create_demo_server())
        direct_times = []
        for _ in range(n):
            start = time.perf_counter()
            direct.post(
                "/mcp", json={"jsonrpc": "2.0", "id": 1,
                              "method": "tools/call",
                              "params": {"name": "crm.read_customer",
                                         "arguments": {"customer_id":
                                                       "cust_1",
                                                       "limit": 5}}})
            direct_times.append((time.perf_counter() - start) * 1000)
        return {
            "decision_ms": {
                "p50": _percentile(decision_times, 50),
                "p95": _percentile(decision_times, 95),
                "p99": _percentile(decision_times, 99),
                "mean": statistics.mean(decision_times),
            },
            "end_to_end_ms": {
                "p50": _percentile(e2e_times, 50),
                "p95": _percentile(e2e_times, 95),
                "p99": _percentile(e2e_times, 99),
                "mean": statistics.mean(e2e_times),
            },
            "direct_ms": {
                "p50": _percentile(direct_times, 50),
                "p95": _percentile(direct_times, 95),
                "p99": _percentile(direct_times, 99),
                "mean": statistics.mean(direct_times),
            },
            "n": n,
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure the gateway's added latency.")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--n", type=int, default=200)
    args = parser.parse_args()
    result = measure(args.port, args.n)
    print(f"policy decision (n={result['n']}): "
          f"p50 {result['decision_ms']['p50']:.3f} ms, "
          f"p95 {result['decision_ms']['p95']:.3f} ms, "
          f"p99 {result['decision_ms']['p99']:.3f} ms, "
          f"mean {result['decision_ms']['mean']:.3f} ms")
    print(f"end to end, forwarded call (n={result['n']}): "
          f"p50 {result['end_to_end_ms']['p50']:.2f} ms, "
          f"p95 {result['end_to_end_ms']['p95']:.2f} ms, "
          f"p99 {result['end_to_end_ms']['p99']:.2f} ms, "
          f"mean {result['end_to_end_ms']['mean']:.2f} ms")
    print(f"direct to the upstream, no gateway (n={result['n']}): "
          f"p50 {result['direct_ms']['p50']:.2f} ms, "
          f"p95 {result['direct_ms']['p95']:.2f} ms, "
          f"p99 {result['direct_ms']['p99']:.2f} ms, "
          f"mean {result['direct_ms']['mean']:.2f} ms")
    added = (result['end_to_end_ms']['mean']
             - result['direct_ms']['mean'])
    print(f"gateway overhead (mean end-to-end minus direct): "
          f"{added:.2f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
