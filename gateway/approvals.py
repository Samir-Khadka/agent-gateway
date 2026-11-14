"""Human approvals: a risky call is held until a human says yes.

When the policy holds a call (`require_approval`), the gateway
creates a pending approval and returns its id instead of running
the call. A human approves or denies it — on Telegram, or through
the admin API. The agent then re-sends the same call with the
`approval_id`; if it was approved, the gateway runs it, bypassing
the approval rule this once. If it was denied, the call is refused.
A pending approval keeps the call held.

Approvals are persisted, so a held call survives a gateway restart.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Approval:
    id: str
    agent: str
    session_id: str
    tool: str
    args: dict
    reason: str
    status: str = "pending"  # pending | approved | denied
    decided_by: str = ""
    decided_at: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(
        timezone.utc).isoformat())


class ApprovalStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.approvals: dict[str, Approval] = self._load()

    def _load(self) -> dict[str, Approval]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        out = {}
        for item in data:
            out[item["id"]] = Approval(**{k: v for k, v in item.items()
                                          if k in Approval.__dataclass_fields__})
        return out

    def _save(self) -> None:
        self.path.write_text(
            json.dumps([asdict(a) for a in self.approvals.values()],
                       indent=2), encoding="utf-8")

    def request(self, agent: str, session_id: str, tool: str,
                args: dict, reason: str) -> Approval:
        approval = Approval(id=secrets.token_hex(8), agent=agent,
                            session_id=session_id, tool=tool, args=args,
                            reason=reason)
        self.approvals[approval.id] = approval
        self._save()
        return approval

    def get(self, approval_id: str) -> Approval | None:
        return self.approvals.get(approval_id)

    def resolve(self, approval_id: str, approved: bool,
                by: str) -> Approval | None:
        approval = self.approvals.get(approval_id)
        if approval is None or approval.status != "pending":
            return None
        approval.status = "approved" if approved else "denied"
        approval.decided_by = by
        approval.decided_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return approval

    def pending(self) -> list[Approval]:
        return [a for a in self.approvals.values()
                if a.status == "pending"]
