"""No-op rollback guards: a filesystem-backed prepare/confirm/rollback state
machine for human-gated NOC remediation.

This is the first, deliberately inert step toward guarded remediation. A guard
records the *intent* to make a change and a TTL within which it must be
confirmed or rolled back; in ``mode="noop"`` it never touches a service, FRR,
PF/nftables, or WireGuard — only JSON files under the guard directory. Real
execution stays behind ``HYRULE_MCP_ENABLE_ACTIONS`` and is out of scope here.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

GUARD_SCHEMA_VERSION = 1
GUARD_ACTION_CLASS = "noop_rollback_guard"

GuardStatus = Literal["pending", "confirmed", "rolled_back", "expired"]


class GuardError(RuntimeError):
    """Raised on an invalid guard transition or a missing/expired guard."""


class AuditEvent(BaseModel):
    ts: str
    event: str
    operator: str


class RollbackGuard(BaseModel):
    schema_version: int = GUARD_SCHEMA_VERSION
    guard_id: str
    proposal_id: str
    action_id: str
    action_class: str = GUARD_ACTION_CLASS
    operator: str
    host: str
    service: str | None = None
    created_at: str
    expires_at: str
    status: GuardStatus = "pending"
    mode: Literal["noop"] = "noop"
    audit: list[AuditEvent] = Field(default_factory=list)


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat()


def _guard_path(guard_dir: Path, guard_id: str) -> Path:
    return Path(guard_dir) / f"{guard_id}.json"


def _save(guard_dir: Path, guard: RollbackGuard) -> RollbackGuard:
    Path(guard_dir).mkdir(parents=True, exist_ok=True)
    _guard_path(guard_dir, guard.guard_id).write_text(
        json.dumps(guard.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return guard


def load_guard(guard_dir: Path, guard_id: str) -> RollbackGuard | None:
    path = _guard_path(guard_dir, guard_id)
    if not path.is_file():
        return None
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    return RollbackGuard.model_validate(raw)


def _expire_if_due(guard_dir: Path, guard: RollbackGuard, now: datetime) -> RollbackGuard:
    if guard.status == "pending" and now >= datetime.fromisoformat(guard.expires_at):
        guard.status = "expired"
        guard.audit.append(AuditEvent(ts=_iso(now), event="expired", operator="system"))
        _save(guard_dir, guard)
    return guard


def prepare_guard(
    guard_dir: Path,
    *,
    proposal_id: str,
    action_id: str,
    operator: str,
    host: str,
    service: str | None = None,
    ttl_s: int,
    mode: str = "noop",
    now: datetime | None = None,
) -> RollbackGuard:
    if mode != "noop":
        raise GuardError(f"unsupported guard mode {mode!r}; only 'noop' is allowed")
    if ttl_s <= 0:
        raise GuardError("guard ttl must be positive")
    moment = _now(now)
    guard = RollbackGuard(
        guard_id=f"rg_{secrets.token_hex(8)}",
        proposal_id=proposal_id,
        action_id=action_id,
        operator=operator,
        host=host,
        service=service,
        created_at=_iso(moment),
        expires_at=_iso(moment + timedelta(seconds=ttl_s)),
        status="pending",
        audit=[AuditEvent(ts=_iso(moment), event="prepared", operator=operator)],
    )
    return _save(guard_dir, guard)


def _transition(
    guard_dir: Path,
    guard_id: str,
    *,
    operator: str,
    event: str,
    new_status: GuardStatus,
    now: datetime | None = None,
) -> RollbackGuard:
    moment = _now(now)
    guard = load_guard(guard_dir, guard_id)
    if guard is None:
        raise GuardError(f"guard not found: {guard_id}")
    guard = _expire_if_due(guard_dir, guard, moment)
    if guard.status != "pending":
        raise GuardError(f"guard {guard_id} is {guard.status}, not pending")
    guard.status = new_status
    guard.audit.append(AuditEvent(ts=_iso(moment), event=event, operator=operator))
    return _save(guard_dir, guard)


def confirm_guard(guard_dir: Path, guard_id: str, *, operator: str, now: datetime | None = None) -> RollbackGuard:
    return _transition(guard_dir, guard_id, operator=operator, event="confirmed", new_status="confirmed", now=now)


def rollback_guard(guard_dir: Path, guard_id: str, *, operator: str, now: datetime | None = None) -> RollbackGuard:
    return _transition(guard_dir, guard_id, operator=operator, event="rolled_back", new_status="rolled_back", now=now)


def list_pending_guards(guard_dir: Path, *, now: datetime | None = None) -> list[RollbackGuard]:
    moment = _now(now)
    root = Path(guard_dir)
    if not root.is_dir():
        return []
    pending: list[RollbackGuard] = []
    for path in sorted(root.glob("rg_*.json")):
        guard = load_guard(guard_dir, path.stem)
        if guard is None:
            continue
        guard = _expire_if_due(guard_dir, guard, moment)
        if guard.status == "pending":
            pending.append(guard)
    return pending
