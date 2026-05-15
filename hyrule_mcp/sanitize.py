from __future__ import annotations

import re
from typing import Any

from hyrule_mcp.models import McpToolError, ToolResult, TruncatedText


SECRET_PATTERNS = (
    re.compile(r"(?i)(password|token|secret|api[_-]?key|private[_-]?key)=([^,\s]+)"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
)


def sanitize_text(value: Any) -> str:
    text = str(value or "")
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}[redacted]", text)
    return text


def truncate_text(value: Any, *, max_bytes: int, max_lines: int) -> TruncatedText:
    text = sanitize_text(value)
    original_bytes = len(text.encode("utf-8", errors="replace"))
    original_lines = len(text.splitlines())
    lines = text.splitlines()
    truncated = False
    reason = None
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        truncated = True
        reason = "line_limit"
    trimmed = "\n".join(lines)
    encoded = trimmed.encode("utf-8", errors="replace")
    if len(encoded) > max_bytes:
        trimmed = encoded[:max_bytes].decode("utf-8", errors="ignore")
        truncated = True
        reason = "byte_limit" if reason is None else f"{reason},byte_limit"
    return TruncatedText(
        text=trimmed,
        truncated=truncated,
        returned_bytes=len(trimmed.encode("utf-8", errors="replace")),
        returned_lines=len(trimmed.splitlines()),
        original_bytes=original_bytes,
        original_lines=original_lines,
        truncation_reason=reason,
    )


def error_result(
    *,
    tool: str,
    summary: str,
    error_type: str,
    sanitized_error: str,
    target: str | None = None,
    duration_ms: int | None = None,
    data: dict[str, Any] | list[Any] | None = None,
) -> dict[str, Any]:
    return McpToolError(
        tool=tool,
        target=target,
        summary=summary,
        error_type=error_type,
        sanitized_error=sanitize_text(sanitized_error),
        duration_ms=duration_ms,
        data=data,
    ).model_dump(mode="json")


def dump_result(result: ToolResult) -> dict[str, Any]:
    return result.model_dump(mode="json")

