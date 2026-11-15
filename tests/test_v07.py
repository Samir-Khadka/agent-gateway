"""v0.7: the LLM agent harness (simulate mode) and the launch
announcement."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_llm_agent_simulate_blocks_the_injection():
    result = subprocess.run(
        [sys.executable, "examples/llm_agent.py", "--simulate",
         "--port", "8010"],
        capture_output=True, text=True, cwd=Path.cwd(), timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BLOCKED: blocked by Agent Gateway: denied while tainted" \
        in result.stdout
    assert "sent to team@company.com" in result.stdout
    assert "refund of 25 created" in result.stdout
    assert "audit log: chain intact" in result.stdout


def test_llm_agent_simulate_completes_the_ticket():
    result = subprocess.run(
        [sys.executable, "examples/llm_agent.py", "--simulate",
         "--port", "8011"],
        capture_output=True, text=True, cwd=Path.cwd(), timeout=120)
    assert "done: Ticket #1042 handled" in result.stdout


def test_launch_announcement_exists():
    launch = Path("LAUNCH.md")
    assert launch.exists()
    text = launch.read_text(encoding="utf-8")
    assert "55/55" in text
    assert "agent-gateway" in text
