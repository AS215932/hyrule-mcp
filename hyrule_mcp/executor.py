from __future__ import annotations

import asyncio
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
) -> dict[str, Any]:
    profile = settings.resolve(host)
    timeout = timeout_s or settings.command_timeout_s
    if _is_local_target(profile, settings):
        return await _run_local(profile, args, timeout_s=timeout, settings=settings, tool=tool)
    return await _run_ssh(profile, args, username=username, timeout_s=timeout, settings=settings, tool=tool)


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
) -> dict[str, Any]:
    started = time.perf_counter()
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
        )
    except Exception as exc:
        return error_result(
            tool=tool,
            target=profile.name,
            summary="Local command failed",
            error_type="transport_error",
            sanitized_error=sanitize_text(exc),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


async def _run_ssh(
    profile: HostProfile,
    args: list[str],
    *,
    username: str | None,
    timeout_s: int,
    settings: MCPSettings,
    tool: str,
) -> dict[str, Any]:
    async with _SSH_SEMAPHORE:
        started = time.perf_counter()
        try:
            raw = await asyncio.wait_for(
                asyncio.to_thread(_run_paramiko, profile, command_string(args), username, timeout_s),
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
            )
        except TimeoutError:
            return error_result(
                tool=tool,
                target=profile.name,
                summary="SSH command timed out",
                error_type="timeout",
                sanitized_error=f"SSH command timed out after {timeout_s}s.",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:
            return error_result(
                tool=tool,
                target=profile.name,
                summary="SSH command failed",
                error_type="transport_error",
                sanitized_error=sanitize_text(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
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
) -> dict[str, Any]:
    out = truncate_text(stdout, max_bytes=settings.raw_output_byte_limit, max_lines=settings.raw_output_line_limit)
    err = truncate_text(stderr, max_bytes=settings.raw_output_byte_limit, max_lines=settings.raw_output_line_limit)
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
        error_type=None if exit_code == 0 else "command_failed",
        sanitized_error=None if exit_code == 0 else (err.text or "Command exited non-zero"),
        transport=transport,
    )
    return dump_result(result)


def _is_local_target(profile: HostProfile, settings: MCPSettings) -> bool:
    return profile.name in settings.local_aliases or profile.address in settings.local_aliases

