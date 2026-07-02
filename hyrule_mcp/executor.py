from __future__ import annotations

import asyncio
import hashlib
import shlex
import time
from typing import Any

import paramiko

from hyrule_mcp.models import CommandResult
from hyrule_mcp.sanitize import dump_result, error_result, sanitize_text, truncate_text
from hyrule_mcp.settings import HostProfile, MCPSettings, SETTINGS


_SSH_SEMAPHORE = asyncio.Semaphore(SETTINGS.ssh_max_concurrency)


def command_args(*parts: Any) -> list[str]:
    return [str(part) for part in parts if part is not None and str(part) != ""]


def command_string(args: list[str]) -> str:
    return shlex.join(args)


async def execute_args(
    host: str,
    args: list[str],
    *,
    username: str | None = None,
    timeout_s: int | None = None,
    settings: MCPSettings = SETTINGS,
    tool: str = "command",
    raw_output_byte_limit: int | None = None,
    raw_output_line_limit: int | None = None,
) -> dict[str, Any]:
    profile = settings.resolve(host)
    timeout = timeout_s or settings.command_timeout_s
    if _is_local_target(profile, settings):
        return await _run_local(
            profile,
            args,
            timeout_s=timeout,
            settings=settings,
            tool=tool,
            raw_output_byte_limit=raw_output_byte_limit,
            raw_output_line_limit=raw_output_line_limit,
        )
    return await _run_ssh(
        profile,
        args,
        username=username,
        timeout_s=timeout,
        settings=settings,
        tool=tool,
        raw_output_byte_limit=raw_output_byte_limit,
        raw_output_line_limit=raw_output_line_limit,
    )


async def execute_raw_args(
    host: str,
    args: list[str],
    *,
    username: str | None = None,
    timeout_s: int | None = None,
    settings: MCPSettings = SETTINGS,
    tool: str = "command",
) -> dict[str, Any]:
    """Run a trusted internal command and return untruncated stdout/stderr.

    This is intentionally not used by public MCP tools. It exists for internal
    collectors, such as router table snapshots, where the command output is the
    artifact being collected and can legitimately exceed normal MCP response
    safety limits.
    """
    profile = settings.resolve(host)
    timeout = timeout_s or settings.command_timeout_s
    if _is_local_target(profile, settings):
        return await _run_local_raw(profile, args, timeout_s=timeout, settings=settings, tool=tool)

    async with _SSH_SEMAPHORE:
        started = time.perf_counter()
        command = command_string(args)
        context = _execution_context(profile, args, command=command, username=username, timeout_s=timeout, transport="ssh")
        try:
            raw = await asyncio.wait_for(
                asyncio.to_thread(_run_paramiko, profile, command, username, timeout),
                timeout=timeout + 12,
            )
            exit_code = raw.get("exit_code")
            return {
                "ok": exit_code == 0,
                "tool": tool,
                "target": profile.name,
                "summary": "Command completed" if exit_code == 0 else "Command exited non-zero",
                "stdout": raw.get("stdout", ""),
                "stderr": raw.get("stderr", ""),
                "exit_code": exit_code,
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "transport": "ssh",
                "data": context,
            }
        except TimeoutError:
            return error_result(
                tool=tool,
                target=profile.name,
                summary="SSH command timed out",
                error_type="timeout",
                sanitized_error=f"SSH command timed out after {timeout}s.",
                duration_ms=int((time.perf_counter() - started) * 1000),
                data=context,
            )
        except Exception as exc:
            return error_result(
                tool=tool,
                target=profile.name,
                summary="SSH command failed",
                error_type="transport_error",
                sanitized_error=sanitize_text(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
                data={**context, "exception_type": type(exc).__name__},
            )


async def _run_local_raw(
    profile: HostProfile,
    args: list[str],
    *,
    timeout_s: int,
    settings: MCPSettings,
    tool: str,
) -> dict[str, Any]:
    started = time.perf_counter()
    command = command_string(args)
    context = _execution_context(profile, args, command=command, username=None, timeout_s=timeout_s, transport="local")
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        return {
            "ok": proc.returncode == 0,
            "tool": tool,
            "target": profile.name,
            "summary": "Command completed" if proc.returncode == 0 else "Command exited non-zero",
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "exit_code": proc.returncode,
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "transport": "local",
            "data": context,
        }
    except TimeoutError:
        if "proc" in locals():
            proc.kill()
            await proc.wait()
        return error_result(
            tool=tool,
            target=profile.name,
            summary="Command timed out",
            error_type="timeout",
            sanitized_error=f"Command timed out after {timeout_s}s.",
            duration_ms=int((time.perf_counter() - started) * 1000),
            data=context,
        )
    except Exception as exc:
        return error_result(
            tool=tool,
            target=profile.name,
            summary="Local command failed",
            error_type="transport_error",
            sanitized_error=sanitize_text(exc),
            duration_ms=int((time.perf_counter() - started) * 1000),
            data={**context, "exception_type": type(exc).__name__},
        )


async def unsupported_os(tool: str, host: str, message: str, *, suggestion: str | None = None) -> dict[str, Any]:
    detail = message if suggestion is None else f"{message} {suggestion}"
    return error_result(
        tool=tool,
        target=host,
        summary=message,
        error_type="unsupported_os",
        sanitized_error=detail,
    )


async def _run_local(
    profile: HostProfile,
    args: list[str],
    *,
    timeout_s: int,
    settings: MCPSettings,
    tool: str,
    raw_output_byte_limit: int | None = None,
    raw_output_line_limit: int | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    command = command_string(args)
    context = _execution_context(profile, args, command=command, username=None, timeout_s=timeout_s, transport="local")
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        return _command_payload(
            tool=tool,
            target=profile.name,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            exit_code=proc.returncode,
            duration_ms=int((time.perf_counter() - started) * 1000),
            transport="local",
            settings=settings,
            data=context,
            raw_output_byte_limit=raw_output_byte_limit,
            raw_output_line_limit=raw_output_line_limit,
        )
    except TimeoutError:
        if "proc" in locals():
            proc.kill()
            await proc.wait()
        return error_result(
            tool=tool,
            target=profile.name,
            summary="Command timed out",
            error_type="timeout",
            sanitized_error=f"Command timed out after {timeout_s}s.",
            duration_ms=int((time.perf_counter() - started) * 1000),
            data=context,
        )
    except Exception as exc:
        return error_result(
            tool=tool,
            target=profile.name,
            summary="Local command failed",
            error_type="transport_error",
            sanitized_error=sanitize_text(exc),
            duration_ms=int((time.perf_counter() - started) * 1000),
            data={**context, "exception_type": type(exc).__name__},
        )


async def _run_ssh(
    profile: HostProfile,
    args: list[str],
    *,
    username: str | None,
    timeout_s: int,
    settings: MCPSettings,
    tool: str,
    raw_output_byte_limit: int | None = None,
    raw_output_line_limit: int | None = None,
) -> dict[str, Any]:
    async with _SSH_SEMAPHORE:
        started = time.perf_counter()
        command = command_string(args)
        context = _execution_context(profile, args, command=command, username=username, timeout_s=timeout_s, transport="ssh")
        try:
            raw = await asyncio.wait_for(
                asyncio.to_thread(_run_paramiko, profile, command, username, timeout_s),
                timeout=timeout_s + 12,
            )
            return _command_payload(
                tool=tool,
                target=profile.name,
                stdout=raw.get("stdout", ""),
                stderr=raw.get("stderr", ""),
                exit_code=raw.get("exit_code"),
                duration_ms=int((time.perf_counter() - started) * 1000),
                transport="ssh",
                settings=settings,
                data=context,
                raw_output_byte_limit=raw_output_byte_limit,
                raw_output_line_limit=raw_output_line_limit,
            )
        except TimeoutError:
            return error_result(
                tool=tool,
                target=profile.name,
                summary="SSH command timed out",
                error_type="timeout",
                sanitized_error=f"SSH command timed out after {timeout_s}s.",
                duration_ms=int((time.perf_counter() - started) * 1000),
                data=context,
            )
        except Exception as exc:
            return error_result(
                tool=tool,
                target=profile.name,
                summary="SSH command failed",
                error_type="transport_error",
                sanitized_error=sanitize_text(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
                data={**context, "exception_type": type(exc).__name__},
            )


def _run_paramiko(profile: HostProfile, command: str, username: str | None, timeout_s: int) -> dict[str, Any]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = {
            "hostname": profile.address,
            "username": username or profile.user,
            "timeout": 10,
            "allow_agent": profile.key is None,
            "look_for_keys": profile.key is None,
        }
        if profile.key:
            connect_kwargs["key_filename"] = profile.key
        client.connect(**connect_kwargs)
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout_s)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return {"stdout": out, "stderr": err, "exit_code": stdout.channel.recv_exit_status()}
    finally:
        client.close()


def _command_payload(
    *,
    tool: str,
    target: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    duration_ms: int,
    transport: str,
    settings: MCPSettings,
    data: dict[str, Any] | None = None,
    raw_output_byte_limit: int | None = None,
    raw_output_line_limit: int | None = None,
) -> dict[str, Any]:
    max_bytes = raw_output_byte_limit or settings.raw_output_byte_limit
    max_lines = raw_output_line_limit or settings.raw_output_line_limit
    out = truncate_text(stdout, max_bytes=max_bytes, max_lines=max_lines)
    err = truncate_text(stderr, max_bytes=max_bytes, max_lines=max_lines)
    evidence_id = _evidence_id(
        tool=tool,
        target=target,
        transport=transport,
        data=data,
        stdout=out.text,
        stderr=err.text,
        exit_code=exit_code,
    )
    evidence_ref = {
        "evidence_id": evidence_id,
        "sensitivity_class": "internal",
        "raw_ref": f"mcp://{target}/{tool}/{evidence_id}",
    }
    result_data = dict(data or {})
    result_data["evidence_ref"] = evidence_ref
    result = CommandResult(
        ok=exit_code == 0,
        tool=tool,
        target=target,
        summary="Command completed" if exit_code == 0 else "Command exited non-zero",
        stdout=out.text,
        stderr=err.text,
        exit_code=exit_code,
        duration_ms=duration_ms,
        truncated=out.truncated or err.truncated,
        returned_bytes=out.returned_bytes + err.returned_bytes,
        returned_lines=out.returned_lines + err.returned_lines,
        evidence_id=evidence_id,
        sensitivity_class="internal",
        raw_ref=evidence_ref["raw_ref"],
        error_type=None if exit_code == 0 else "command_failed",
        sanitized_error=None if exit_code == 0 else (err.text or "Command exited non-zero"),
        transport=transport,
        data=result_data,
    )
    return dump_result(result)


def _evidence_id(
    *,
    tool: str,
    target: str,
    transport: str,
    data: dict[str, Any] | None,
    stdout: str,
    stderr: str,
    exit_code: int | None,
) -> str:
    payload = {
        "tool": tool,
        "target": target,
        "transport": transport,
        "data": data or {},
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
    }
    raw = json_dumps_stable(payload)
    return "ev_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def json_dumps_stable(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _is_local_target(profile: HostProfile, settings: MCPSettings) -> bool:
    return profile.name in settings.local_aliases or profile.address in settings.local_aliases


def _execution_context(
    profile: HostProfile,
    args: list[str],
    *,
    command: str,
    username: str | None,
    timeout_s: int,
    transport: str,
) -> dict[str, Any]:
    effective_username = username or profile.user
    sanitized_username = sanitize_text(effective_username) if effective_username else None
    return {
        "command": sanitize_text(command),
        "argv": [sanitize_text(arg) for arg in args],
        "transport": transport,
        "timeout_s": timeout_s,
        "resolved_target": {
            "name": sanitize_text(profile.name),
            "address": sanitize_text(profile.address),
            "username": sanitized_username,
            "key_configured": profile.key is not None,
        },
    }
