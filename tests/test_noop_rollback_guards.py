from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from hyrule_mcp import rollback_guards as rg
from hyrule_mcp.action_auth import validate_signed_authorization
from hyrule_mcp.rollback_guards import GUARD_ACTION_CLASS, GuardError
from hyrule_mcp.settings import MCPSettings

SECRET = "test-signing-secret"


def _sign(payload: dict[str, Any], secret: str = SECRET) -> dict[str, Any]:
    signed = {k: payload[k] for k in sorted(payload) if k != "signature"}
    body = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    payload["signature"] = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return payload


def _auth(*, action_class: str = GUARD_ACTION_CLASS, expiry: int | None = None, operator: str = "alice") -> dict[str, Any]:
    return _sign({
        "action_id": "act-1",
        "case_id": "case-9",
        "operator": operator,
        "expiry": expiry if expiry is not None else int(time.time()) + 300,
        "action_class": action_class,
    })


def _settings(tmp_path: Path, *, noop: bool = True, secret: str = SECRET) -> MCPSettings:
    return MCPSettings(
        enable_actions=False,
        enable_noop_guards=noop,
        rollback_guard_dir=str(tmp_path / "rollback"),
        rollback_guard_default_ttl_s=300,
        action_signing_secret=secret,
    )


# --- guard state machine ----------------------------------------------------


def test_prepare_creates_pending_guard_with_audit(tmp_path: Path) -> None:
    guard = rg.prepare_guard(
        tmp_path, proposal_id="case-9", action_id="act-1", operator="alice",
        host="noc", service=None, ttl_s=300,
    )
    assert guard.status == "pending"
    assert guard.mode == "noop"
    assert guard.action_class == GUARD_ACTION_CLASS
    assert guard.proposal_id == "case-9" and guard.action_id == "act-1"
    assert guard.audit[0].event == "prepared" and guard.audit[0].operator == "alice"
    assert guard.audit[0].ts  # timestamp recorded
    assert rg.load_guard(tmp_path, guard.guard_id) is not None


def test_prepare_rejects_non_noop_mode(tmp_path: Path) -> None:
    with pytest.raises(GuardError):
        rg.prepare_guard(tmp_path, proposal_id="c", action_id="a", operator="o", host="noc", ttl_s=300, mode="execute")


def test_confirm_marks_confirmed(tmp_path: Path) -> None:
    g = rg.prepare_guard(tmp_path, proposal_id="c", action_id="a", operator="alice", host="noc", ttl_s=300)
    confirmed = rg.confirm_guard(tmp_path, g.guard_id, operator="alice")
    assert confirmed.status == "confirmed"
    assert confirmed.audit[-1].event == "confirmed"


def test_rollback_marks_rolled_back(tmp_path: Path) -> None:
    g = rg.prepare_guard(tmp_path, proposal_id="c", action_id="a", operator="alice", host="noc", ttl_s=300)
    rolled = rg.rollback_guard(tmp_path, g.guard_id, operator="bob")
    assert rolled.status == "rolled_back"
    assert rolled.audit[-1].event == "rolled_back" and rolled.audit[-1].operator == "bob"


def test_cannot_transition_terminal_guard(tmp_path: Path) -> None:
    g = rg.prepare_guard(tmp_path, proposal_id="c", action_id="a", operator="o", host="noc", ttl_s=300)
    rg.confirm_guard(tmp_path, g.guard_id, operator="o")
    with pytest.raises(GuardError):
        rg.rollback_guard(tmp_path, g.guard_id, operator="o")


def test_missing_guard_raises(tmp_path: Path) -> None:
    with pytest.raises(GuardError):
        rg.confirm_guard(tmp_path, "rg_does_not_exist", operator="o")


def test_expired_guard_is_marked_and_blocks_confirm(tmp_path: Path) -> None:
    past = datetime.now(UTC) - timedelta(seconds=600)
    g = rg.prepare_guard(tmp_path, proposal_id="c", action_id="a", operator="o", host="noc", ttl_s=300, now=past)
    with pytest.raises(GuardError):
        rg.confirm_guard(tmp_path, g.guard_id, operator="o")
    reloaded = rg.load_guard(tmp_path, g.guard_id)
    assert reloaded is not None and reloaded.status == "expired"
    assert reloaded.audit[-1].event == "expired"


def test_list_pending_excludes_terminal_and_expired(tmp_path: Path) -> None:
    pending = rg.prepare_guard(tmp_path, proposal_id="c", action_id="a1", operator="o", host="noc", ttl_s=300)
    confirmed = rg.prepare_guard(tmp_path, proposal_id="c", action_id="a2", operator="o", host="noc", ttl_s=300)
    rg.confirm_guard(tmp_path, confirmed.guard_id, operator="o")
    past = datetime.now(UTC) - timedelta(seconds=600)
    rg.prepare_guard(tmp_path, proposal_id="c", action_id="a3", operator="o", host="noc", ttl_s=300, now=past)
    listed = rg.list_pending_guards(tmp_path)
    assert [g.guard_id for g in listed] == [pending.guard_id]


# --- signed authorization ---------------------------------------------------


def test_validate_rejects_missing_auth(tmp_path: Path) -> None:
    blocked = validate_signed_authorization(
        tool="prepare_commit_confirm", action_class=GUARD_ACTION_CLASS, target="noc",
        action_authorization=None, settings=_settings(tmp_path),
    )
    assert blocked is not None and blocked["error_type"] == "policy_blocked"


def test_validate_rejects_bad_signature(tmp_path: Path) -> None:
    auth = _auth()
    auth["signature"] = "deadbeef"
    blocked = validate_signed_authorization(
        tool="confirm_change", action_class=GUARD_ACTION_CLASS, target="noc",
        action_authorization=auth, settings=_settings(tmp_path),
    )
    assert blocked is not None and blocked["data"]["reason"] == "invalid_signature"


def test_validate_rejects_expired(tmp_path: Path) -> None:
    auth = _auth(expiry=int(time.time()) - 10)
    blocked = validate_signed_authorization(
        tool="confirm_change", action_class=GUARD_ACTION_CLASS, target="noc",
        action_authorization=auth, settings=_settings(tmp_path),
    )
    assert blocked is not None and blocked["data"]["reason"] == "expired"


def test_validate_rejects_action_class_mismatch(tmp_path: Path) -> None:
    auth = _auth(action_class="restart_service")
    blocked = validate_signed_authorization(
        tool="prepare_commit_confirm", action_class=GUARD_ACTION_CLASS, target="noc",
        action_authorization=auth, settings=_settings(tmp_path),
    )
    assert blocked is not None and blocked["data"]["reason"] == "action_class_mismatch"


def test_validate_passes_valid_auth(tmp_path: Path) -> None:
    blocked = validate_signed_authorization(
        tool="prepare_commit_confirm", action_class=GUARD_ACTION_CLASS, target="noc",
        action_authorization=_auth(), settings=_settings(tmp_path),
    )
    assert blocked is None


# --- tool wrappers (feature flag + happy paths) -----------------------------


def _patch_settings(monkeypatch: pytest.MonkeyPatch, settings: MCPSettings) -> None:
    monkeypatch.setattr("hyrule_mcp.tools.rollback.SETTINGS", settings)


def test_tool_disabled_when_flag_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hyrule_mcp.tools import rollback
    _patch_settings(monkeypatch, _settings(tmp_path, noop=False))
    result = asyncio.run(rollback.prepare_commit_confirm("noc", action_authorization=_auth()))
    assert result["error_type"] == "policy_blocked"
    assert "ENABLE_NOOP_GUARDS" in result["sanitized_error"]


def test_tool_prepare_then_confirm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hyrule_mcp.tools import rollback
    _patch_settings(monkeypatch, _settings(tmp_path))
    prepared = asyncio.run(rollback.prepare_commit_confirm("noc", action_authorization=_auth()))
    guard_id = prepared["guard"]["guard_id"]
    assert prepared["guard"]["status"] == "pending"
    assert prepared["guard"]["proposal_id"] == "case-9"
    confirmed = asyncio.run(rollback.confirm_change(guard_id, action_authorization=_auth()))
    assert confirmed["guard"]["status"] == "confirmed"


def test_tool_prepare_then_rollback_and_pending_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hyrule_mcp.tools import rollback
    _patch_settings(monkeypatch, _settings(tmp_path))
    prepared = asyncio.run(rollback.prepare_commit_confirm("noc", action_authorization=_auth()))
    guard_id = prepared["guard"]["guard_id"]
    pending = asyncio.run(rollback.get_pending_rollback_guards())
    assert [g["guard_id"] for g in pending["guards"]] == [guard_id]
    rolled = asyncio.run(rollback.rollback_change(guard_id, action_authorization=_auth()))
    assert rolled["guard"]["status"] == "rolled_back"
    after = asyncio.run(rollback.get_pending_rollback_guards())
    assert after["guards"] == []


def test_tool_rejects_unsigned_confirm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hyrule_mcp.tools import rollback
    _patch_settings(monkeypatch, _settings(tmp_path))
    prepared = asyncio.run(rollback.prepare_commit_confirm("noc", action_authorization=_auth()))
    guard_id = prepared["guard"]["guard_id"]
    result = asyncio.run(rollback.confirm_change(guard_id, action_authorization=None))
    assert result["error_type"] == "policy_blocked"
