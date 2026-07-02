from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


SCHEMA_VERSION = "2026-05-15.v1"
SensitivityClass = Literal["public", "internal", "restricted", "secret"]


class TruncatedText(BaseModel):
    text: str = ""
    truncated: bool = False
    returned_bytes: int = 0
    returned_lines: int = 0
    original_bytes: int = 0
    original_lines: int = 0
    truncation_reason: str | None = None


class McpToolError(BaseModel):
    schema_version: str = SCHEMA_VERSION
    ok: bool = False
    tool: str
    target: str | None = None
    summary: str
    data: dict[str, Any] | list[Any] | None = None
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    duration_ms: int | None = None
    evidence_id: str | None = None
    sensitivity_class: SensitivityClass = "internal"
    raw_ref: str | None = None
    truncated: bool = False
    returned_bytes: int = 0
    returned_lines: int = 0
    error_type: str
    sanitized_error: str


class ToolResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    ok: bool = True
    tool: str
    target: str | None = None
    summary: str
    data: dict[str, Any] | list[Any] | None = None
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    duration_ms: int | None = None
    evidence_id: str | None = None
    sensitivity_class: SensitivityClass = "internal"
    raw_ref: str | None = None
    truncated: bool = False
    returned_bytes: int = 0
    returned_lines: int = 0
    error_type: str | None = None
    sanitized_error: str | None = None


class CommandResult(ToolResult):
    transport: Literal["local", "ssh", "policy", "unsupported"] | str = "local"


class PrometheusQueryResult(ToolResult):
    result: list[dict[str, Any]] = Field(default_factory=list)


class PrometheusTargetsResult(ToolResult):
    targets: list[dict[str, Any]] = Field(default_factory=list)


class IcingaHostState(ToolResult):
    host: str
    services: list[dict[str, Any]] = Field(default_factory=list)


class IcingaProblems(ToolResult):
    object_type: str
    count: int = 0
    returned: int = 0
    problems: list[dict[str, Any]] = Field(default_factory=list)


class NeighborState(ToolResult):
    entries: list[dict[str, Any]] = Field(default_factory=list)


class FirewallState(ToolResult):
    pass


class ProbeResult(ToolResult):
    pass


class DnsProbeResult(ToolResult):
    pass
