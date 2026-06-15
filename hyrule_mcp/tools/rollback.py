"""No-op rollback guard MCP tools.

These tools are exposed only when ``HYRULE_MCP_ENABLE_NOOP_GUARDS=1`` and every
mutating call requires a signed ``noop_rollback_guard`` authorization. They
never restart a service or touch FRR/PF/nftables/WireGuard — only the guard
JSON files under ``HYRULE_MCP_ROLLBACK_GUARD_DIR``. Privileged execution stays
behind the separate ``HYRULE_MCP_ENABLE_ACTIONS`` flag.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hyrule_mcp.action_auth import validate_signed_authorization
from hyrule_mcp.rollback_guards import (
    GUARD_ACTION_CLASS,
    GUARD_SCHEMA_VERSION,
    GuardError,
    RollbackGuard,
    confirm_guard,
    list_pending_guards,
    prepare_guard,
    rollback_guard,
)
from hyrule_mcp.sanitize import error_result, sanitize_text
from hyrule_mcp.settings import SETTINGS


def _disabled(tool: str, target: str | None) -> dict[str, Any]:
    return error_result(
        tool=tool,
        target=target,
        summary="No-op rollback guards disabled",
        error_type="policy_blocked",
        sanitized_error="HYRULE_MCP_ENABLE_NOOP_GUARDS is not enabled.",
    )


def _guard_result(tool: str, guard: RollbackGuard) -> dict[str, Any]:
    return {
        "schema_version": GUARD_SCHEMA_VERSION,
        "tool": tool,
        "target": guard.host,
        "summary": f"guard {guard.guard_id} {guard.status}",
        "guard": guard.model_dump(mode="json"),
    }


def _guard_dir() -> Path:
    return Path(SETTINGS.rollback_guard_dir)


async def prepare_commit_confirm(
    host: str,
    action_authorization: dict[str, Any] | None = None,
    service: str | None = None,
    ttl_s: int | None = None,
) -> dict[str, Any]:
    """Prepare a pending no-op rollback guard for a signed, approved proposal."""
    if not SETTINGS.enable_noop_guards:
        return _disabled("prepare_commit_confirm", host)
    blocked = validate_signed_authorization(
        tool="prepare_commit_confirm",
        action_class=GUARD_ACTION_CLASS,
        target=host,
        action_authorization=action_authorization,
        settings=SETTINGS,
        host=host,
        service=service,
    )
    if blocked:
        return blocked
    auth = action_authorization or {}
    ttl = ttl_s if ttl_s and ttl_s > 0 else SETTINGS.rollback_guard_default_ttl_s
    try:
        guard = prepare_guard(
            _guard_dir(),
            proposal_id=str(auth.get("case_id", "")),
            action_id=str(auth.get("action_id", "")),
            operator=str(auth.get("operator", "")),
            host=host,
            service=service,
            ttl_s=ttl,
            mode="noop",
        )
    except GuardError as exc:
        return error_result(
            tool="prepare_commit_confirm", target=host,
            summary="Guard preparation rejected", error_type="policy_blocked",
            sanitized_error=sanitize_text(exc),
        )
    return _guard_result("prepare_commit_confirm", guard)


async def confirm_change(
    guard_id: str,
    action_authorization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Confirm a pending no-op rollback guard (the change is accepted)."""
    if not SETTINGS.enable_noop_guards:
        return _disabled("confirm_change", guard_id)
    blocked = validate_signed_authorization(
        tool="confirm_change", action_class=GUARD_ACTION_CLASS, target=guard_id,
        action_authorization=action_authorization, settings=SETTINGS,
    )
    if blocked:
        return blocked
    operator = str((action_authorization or {}).get("operator", ""))
    try:
        guard = confirm_guard(_guard_dir(), guard_id, operator=operator)
    except GuardError as exc:
        return error_result(
            tool="confirm_change", target=guard_id, summary="Guard confirm rejected",
            error_type="policy_blocked", sanitized_error=sanitize_text(exc),
        )
    return _guard_result("confirm_change", guard)


async def rollback_change(
    guard_id: str,
    action_authorization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Roll back a pending no-op rollback guard (the change is reverted)."""
    if not SETTINGS.enable_noop_guards:
        return _disabled("rollback_change", guard_id)
    blocked = validate_signed_authorization(
        tool="rollback_change", action_class=GUARD_ACTION_CLASS, target=guard_id,
        action_authorization=action_authorization, settings=SETTINGS,
    )
    if blocked:
        return blocked
    operator = str((action_authorization or {}).get("operator", ""))
    try:
        guard = rollback_guard(_guard_dir(), guard_id, operator=operator)
    except GuardError as exc:
        return error_result(
            tool="rollback_change", target=guard_id, summary="Guard rollback rejected",
            error_type="policy_blocked", sanitized_error=sanitize_text(exc),
        )
    return _guard_result("rollback_change", guard)


async def get_pending_rollback_guards() -> dict[str, Any]:
    """List pending no-op rollback guards (read-only; excludes terminal/expired)."""
    if not SETTINGS.enable_noop_guards:
        return _disabled("get_pending_rollback_guards", None)
    guards = list_pending_guards(_guard_dir())
    return {
        "schema_version": GUARD_SCHEMA_VERSION,
        "tool": "get_pending_rollback_guards",
        "summary": f"{len(guards)} pending guard(s)",
        "guards": [g.model_dump(mode="json") for g in guards],
    }
