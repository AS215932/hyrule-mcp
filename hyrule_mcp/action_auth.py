from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from hyrule_mcp.sanitize import error_result, sanitize_text
from hyrule_mcp.settings import MCPSettings, SETTINGS


def validate_action_authorization(
    *,
    tool: str,
    action_class: str,
    target: str | None,
    action_authorization: dict[str, Any] | None,
    settings: MCPSettings = SETTINGS,
    host: str | None = None,
    service: str | None = None,
) -> dict[str, Any] | None:
    if not settings.enable_actions:
        return error_result(
            tool=tool,
            target=target,
            summary="Action tool disabled",
            error_type="policy_blocked",
            sanitized_error="HYRULE_MCP_ENABLE_ACTIONS is not enabled.",
        )
    if not settings.action_signing_secret:
        return _blocked(tool, target, "Action signing secret is not configured.", "missing_secret")
    if not isinstance(action_authorization, dict):
        return _blocked(tool, target, "Missing action authorization payload.", "missing_authorization")

    required = {"action_id", "case_id", "operator", "expiry", "signature", "action_class"}
    missing = sorted(required - set(action_authorization))
    if missing:
        return _blocked(tool, target, f"Action authorization is missing: {', '.join(missing)}.", "malformed_authorization")

    if str(action_authorization.get("action_class")) != action_class:
        return _blocked(tool, target, "Action authorization class does not match this tool.", "action_class_mismatch")

    expiry_value = action_authorization.get("expiry")
    if not isinstance(expiry_value, str | int | float):
        return _blocked(tool, target, "Action authorization expiry is invalid.", "invalid_expiry")
    try:
        expiry = int(expiry_value)
    except ValueError:
        return _blocked(tool, target, "Action authorization expiry is invalid.", "invalid_expiry")
    if expiry < int(time.time()):
        return _blocked(tool, target, "Action authorization is expired.", "expired")

    supplied = str(action_authorization.get("signature") or "")
    signed = {key: action_authorization[key] for key in sorted(action_authorization) if key != "signature"}
    body = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(settings.action_signing_secret.encode(), body, hashlib.sha256).hexdigest()
    if not supplied or not hmac.compare_digest(supplied, expected):
        return _blocked(tool, target, "Action authorization signature is invalid.", "invalid_signature")

    if host and settings.action_allowed_hosts and host not in settings.action_allowed_hosts:
        return _blocked(tool, target, f"Host '{sanitize_text(host)}' is outside the action allowlist.", "host_not_allowed")
    if service and settings.action_allowed_services and service not in settings.action_allowed_services:
        return _blocked(tool, target, f"Service '{sanitize_text(service)}' is outside the action allowlist.", "service_not_allowed")
    return None


def _blocked(tool: str, target: str | None, message: str, reason: str) -> dict[str, Any]:
    return error_result(
        tool=tool,
        target=target,
        summary="Action authorization rejected",
        error_type="policy_blocked",
        sanitized_error=message,
        data={"policy": "signed_approved_action", "reason": reason},
    )
