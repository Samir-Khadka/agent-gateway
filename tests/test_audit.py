"""Audit log: append, verify, and tamper detection."""
from __future__ import annotations

import json

from gateway.audit import AuditLog


def test_append_and_verify(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("support-bot", "crm.read_customer",
               {"customer_id": "cust_1"}, "allow", "allowed")
    log.append("support-bot", "email.send", {"to": "x@evil.com"},
               "deny", "outside the company")
    ok, message = log.verify()
    assert ok and "2 entries" in message
    entries = log.read()
    assert entries[0]["seq"] == 1 and entries[1]["seq"] == 2
    assert entries[1]["prev_hash"] == entries[0]["hash"]


def test_tampering_breaks_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("support-bot", "crm.read_customer", {}, "allow", "ok")
    log.append("support-bot", "email.send", {"to": "x@evil.com"},
               "deny", "blocked")
    # rewrite the second entry's decision as if it had been allowed
    lines = path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["decision"] = "allow"
    lines[1] = json.dumps(second)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, message = AuditLog(path).verify()
    assert not ok and "entry 2" in message


def test_deleting_an_entry_breaks_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.append("support-bot", f"tool_{i}", {}, "allow", "ok")
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:1] + lines[2:]) + "\n",
                    encoding="utf-8")
    ok, message = AuditLog(path).verify()
    assert not ok
