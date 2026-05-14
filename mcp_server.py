from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import paramiko
import requests
import structlog
import uvicorn
import yaml
from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse


structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
        structlog.contextvars.merge_contextvars,
        structlog.processors.dict_tracebacks,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    cache_logger_on_first_use=True,
)
log = structlog.get_logger().bind(service="hyrule-mcp")

mcp = FastMCP(
    "Hyrule MCP",
    instructions=(
        "AS215932 infrastructure MCP daemon. Prefer specialized tools over raw SSH. "
        "Return bounded structured telemetry; never emit unbounded raw dumps."
    ),
)

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://[2a0c:b641:b50:2::50]:9090")
ICINGA_API_BASE = os.environ.get("ICINGA_API_BASE", "https://[2a0c:b641:b50:2::50]:5665")
HYRULE_MCP_ENABLE_ACTIONS = os.environ.get("HYRULE_MCP_ENABLE_ACTIONS", "0") == "1"
ICINGA_API_USER = os.environ.get("ICINGA_API_USER", "root")
ICINGA_API_PASSWORD = os.environ.get("ICINGA_API_PASSWORD", "")
ICINGA_VERIFY_TLS = os.environ.get("ICINGA_VERIFY_TLS", "0") == "1"

COMMAND_TIMEOUT_S = int(os.getenv("HYRULE_MCP_COMMAND_TIMEOUT_S", "30"))
RAW_OUTPUT_LINE_LIMIT = int(os.getenv("HYRULE_MCP_RAW_OUTPUT_LINE_LIMIT", "100"))
TCPDUMP_MAX_COUNT = int(os.getenv("HYRULE_MCP_TCPDUMP_MAX_COUNT", "100"))
TCPDUMP_MAX_DURATION_S = int(os.getenv("HYRULE_MCP_TCPDUMP_MAX_DURATION_S", "20"))
TCPDUMP_MAX_SNAPLEN = int(os.getenv("HYRULE_MCP_TCPDUMP_MAX_SNAPLEN", "512"))
DNS_BURST_MAX_COUNT = int(os.getenv("HYRULE_MCP_DNS_BURST_MAX_COUNT", "20"))
DNS_BURST_MIN_INTERVAL_MS = int(os.getenv("HYRULE_MCP_DNS_BURST_MIN_INTERVAL_MS", "50"))
MULTI_PROBE_MAX_SOURCES = int(os.getenv("HYRULE_MCP_MULTI_PROBE_MAX_SOURCES", "8"))
ECMP_MAX_FLOWS = int(os.getenv("HYRULE_MCP_ECMP_MAX_FLOWS", "32"))

_HOSTS_CONFIG_PATH = os.environ.get("HYRULE_MCP_HOSTS_CONFIG", "/etc/hyrule-mcp/hosts.yml")
try:
    with open(_HOSTS_CONFIG_PATH) as f:
        _HOSTS_CFG = yaml.safe_load(f) or {}
except FileNotFoundError:
    _HOSTS_CFG = {}

_DEFAULT_USER = _HOSTS_CFG.get("default_user", "root")
_DEFAULT_KEY = _HOSTS_CFG.get("ssh_key")
_HOSTS_MAP = _HOSTS_CFG.get("hosts", {}) or {}
_LOCAL_ALIASES = {
    item.strip()
    for item in os.getenv("HYRULE_MCP_LOCAL_ALIASES", "noc,localhost,127.0.0.1,::1").split(",")
    if item.strip()
}
_LOCAL_ALIASES.add(socket.gethostname())

_MUTATIVE_PATTERNS = (
    r"\brm\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bsystemctl\s+(?:restart|stop|start|enable|disable)\b",
    r"\brcctl\s+(?:restart|stop|start|enable|disable)\b",
    r"\bpfctl\s+-[fe]\b",
    r"\bnft\s+(?:add|delete|flush|insert|replace)\b",
    r"\bvtysh\b.*\bconfigure\b",
)


def _resolve(host: str) -> tuple[str, str, str | None]:
    entry = _HOSTS_MAP.get(host)
    if entry:
        return (
            entry.get("address", host),
            entry.get("user", _DEFAULT_USER),
            entry.get("key", _DEFAULT_KEY),
        )
    return host, _DEFAULT_USER, _DEFAULT_KEY


def _is_local_target(host: str, address: str) -> bool:
    return host in _LOCAL_ALIASES or address in _LOCAL_ALIASES


def action_tool():
    if HYRULE_MCP_ENABLE_ACTIONS:
        return mcp.tool()

    def _skip(fn):
        return fn

    return _skip


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _truncate_text(value: str, *, max_lines: int = RAW_OUTPUT_LINE_LIMIT) -> str:
    lines = (value or "").splitlines()
    if len(lines) <= max_lines:
        return "\n".join(lines)
    return "\n".join([*lines[:max_lines], f"... truncated {len(lines) - max_lines} lines ..."])


def _blocked(command: str) -> str | None:
    for pattern in _MUTATIVE_PATTERNS:
        if re.search(pattern, command, flags=re.IGNORECASE):
            return pattern
    return None


def _command_result(
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = None,
    duration_ms: int = 0,
    ssh_error: str | None = None,
    transport: str,
) -> dict[str, Any]:
    return {
        "stdout": _truncate_text(stdout),
        "stderr": _truncate_text(stderr),
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "ssh_error": ssh_error,
        "transport": transport,
    }


def _run_local(command: str, *, timeout_s: int = COMMAND_TIMEOUT_S) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return _command_result(
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            duration_ms=int((time.perf_counter() - started) * 1000),
            transport="local",
        )
    except subprocess.TimeoutExpired as exc:
        return _command_result(
            stdout=exc.stdout or "",
            stderr=(exc.stderr or "") + f"\nCommand timed out after {timeout_s}s.",
            exit_code=None,
            duration_ms=int((time.perf_counter() - started) * 1000),
            transport="local",
        )


def _run_ssh(
    address: str,
    user: str,
    key_path: str | None,
    command: str,
    *,
    timeout_s: int = COMMAND_TIMEOUT_S,
) -> dict[str, Any]:
    started = time.perf_counter()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = dict(
            hostname=address,
            username=user,
            timeout=10,
            allow_agent=key_path is None,
            look_for_keys=key_path is None,
        )
        if key_path:
            connect_kwargs["key_filename"] = key_path
        client.connect(**connect_kwargs)
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout_s)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        return _command_result(
            stdout=out,
            stderr=err,
            exit_code=exit_code,
            duration_ms=int((time.perf_counter() - started) * 1000),
            transport="ssh",
        )
    except Exception as exc:
        return _command_result(
            ssh_error=str(exc),
            duration_ms=int((time.perf_counter() - started) * 1000),
            transport="ssh",
        )
    finally:
        client.close()


def _execute(host: str, command: str, username: str | None = None, *, timeout_s: int = COMMAND_TIMEOUT_S):
    address, default_user, key_path = _resolve(host)
    if _is_local_target(host, address):
        return _run_local(command, timeout_s=timeout_s)
    return _run_ssh(address, username or default_user, key_path, command, timeout_s=timeout_s)


def _ok(result: dict[str, Any]) -> bool:
    return result.get("exit_code") == 0 and not result.get("ssh_error")


@mcp.tool()
def prometheus_query(query: str) -> dict[str, Any]:
    try:
        response = requests.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": query}, timeout=10)
        response.raise_for_status()
        payload = response.json()
        compact = []
        for item in payload.get("data", {}).get("result", []):
            value = item.get("value") or item.get("values") or []
            epoch = None
            metric_value = None
            if isinstance(value, list) and len(value) >= 2 and not isinstance(value[0], list):
                epoch, metric_value = value[0], value[1]
            compact.append(
                {
                    "metric": item.get("metric", {}),
                    "value": metric_value,
                    "ts_epoch": epoch,
                    "ts_iso": datetime.fromtimestamp(float(epoch), timezone.utc).isoformat() if epoch else None,
                }
            )
        return {"status": payload.get("status", "unknown"), "result": compact}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "result": []}


@mcp.tool()
def prometheus_list_targets(filter: str | None = None) -> dict[str, Any]:
    try:
        response = requests.get(f"{PROMETHEUS_URL}/api/v1/targets", timeout=10)
        response.raise_for_status()
        targets = []
        needle = (filter or "").lower()
        for item in response.json().get("data", {}).get("activeTargets", []):
            labels = item.get("labels", {})
            summary = {
                "instance": labels.get("instance"),
                "job": labels.get("job"),
                "role": labels.get("role"),
                "site": labels.get("site"),
                "health": item.get("health"),
            }
            if not needle or needle in json.dumps(summary, sort_keys=True).lower():
                targets.append(summary)
        return {"targets": targets}
    except Exception as exc:
        return {"targets": [], "error": str(exc)}


@mcp.tool()
def ssh_run_command(host: str, command: str, username: str | None = None) -> dict[str, Any]:
    blocked = _blocked(command)
    if blocked:
        return _command_result(
            stderr=f"Command rejected by diagnostic escape-hatch blocklist: {blocked}",
            exit_code=None,
            duration_ms=0,
            transport="policy",
        )
    return _execute(host, command, username=username)


@mcp.tool()
def frr_vtysh_cmd(host: str, command: str) -> dict[str, Any]:
    return _execute(host, f"vtysh -c {shlex.quote(command)}")


@mcp.tool()
def net_ping(host: str, target: str, count: int = 4) -> dict[str, Any]:
    count = max(1, min(int(count), 20))
    return _execute(host, f"ping -c {count} {shlex.quote(target)}")


@mcp.tool()
def net_traceroute(host: str, target: str) -> dict[str, Any]:
    return _execute(host, f"traceroute -n {shlex.quote(target)}")


@mcp.tool()
def tcpdump_capture(
    host: str,
    iface: str,
    filter: str,
    duration_s: int = 10,
    count: int = 100,
    snaplen: int = 256,
    action_command: str | None = None,
    action_delay_s: int = 1,
) -> dict[str, Any]:
    duration_s = max(1, min(int(duration_s), TCPDUMP_MAX_DURATION_S))
    count = max(1, min(int(count), TCPDUMP_MAX_COUNT))
    snaplen = max(64, min(int(snaplen), TCPDUMP_MAX_SNAPLEN))
    iface_q = shlex.quote(iface)
    filter_q = shlex.quote(filter)
    action = ""
    if action_command:
        action = f"sleep {max(0, min(int(action_delay_s), duration_s))}; {action_command}; "
    command = (
        f"ip link show {iface_q} >/dev/null 2>&1 || ifconfig {iface_q} >/dev/null 2>&1; "
        f"{action}timeout {duration_s} tcpdump -tttt -nn -s {snaplen} -c {count} -i {iface_q} {filter_q}"
    )
    result = _execute(host, command, timeout_s=duration_s + COMMAND_TIMEOUT_S)
    packets = [{"ts": line.split(" ", 2)[0], "summary": line} for line in result["stdout"].splitlines() if line]
    return {
        "capture": result,
        "packets": packets[:count],
        "raw_pcap_path": None,
        "limits": {"duration_s": duration_s, "count": count, "snaplen": snaplen},
    }


@mcp.tool()
def system_tcpdump(host: str, iface: str, filter_str: str, duration: int = 10) -> dict[str, Any]:
    return tcpdump_capture(host, iface, filter_str, duration_s=duration, count=min(TCPDUMP_MAX_COUNT, 100))


@mcp.tool()
def wg_show(host: str) -> dict[str, Any]:
    return _execute(host, "wg show")


@mcp.tool()
def os_systemd_status(host: str, unit: str) -> dict[str, Any]:
    return _execute(host, f"systemctl status {shlex.quote(unit)} --no-pager")


@action_tool()
def os_systemd_restart(host: str, unit: str) -> dict[str, Any]:
    return _execute(host, f"systemctl restart {shlex.quote(unit)}")


@mcp.tool()
def os_rcctl_check(host: str, service: str) -> dict[str, Any]:
    return _execute(host, f"rcctl check {shlex.quote(service)}")


@mcp.tool()
def os_journalctl(host: str, unit: str, lines: int = 50) -> dict[str, Any]:
    lines = max(1, min(int(lines), 500))
    return _execute(host, f"journalctl -u {shlex.quote(unit)} -n {lines} --no-pager")


@mcp.tool()
def dmesg_tail(host: str, lines: int = 50) -> dict[str, Any]:
    lines = max(1, min(int(lines), 500))
    return _execute(host, f"dmesg | tail -n {lines}")


@mcp.tool()
def icinga_get_host_state(host: str) -> dict[str, Any]:
    auth = (ICINGA_API_USER, ICINGA_API_PASSWORD)
    headers = {"Accept": "application/json"}
    try:
        host_response = requests.get(
            f"{ICINGA_API_BASE}/v1/objects/hosts",
            params={"filter": f'host.name=="{host}"'},
            headers=headers,
            auth=auth,
            verify=ICINGA_VERIFY_TLS,
            timeout=10,
        )
        host_response.raise_for_status()
        service_response = requests.get(
            f"{ICINGA_API_BASE}/v1/objects/services",
            params={"filter": f'service.host_name=="{host}"'},
            headers=headers,
            auth=auth,
            verify=ICINGA_VERIFY_TLS,
            timeout=10,
        )
        service_response.raise_for_status()
        services = []
        for item in service_response.json().get("results", []):
            attrs = item.get("attrs", {})
            services.append(
                {
                    "name": attrs.get("name") or item.get("name"),
                    "state": attrs.get("state"),
                    "last_check": attrs.get("last_check"),
                    "last_change": attrs.get("last_state_change"),
                    "output": attrs.get("last_check_result", {}).get("output"),
                }
            )
        return {"host": host, "objects": host_response.json().get("results", []), "services": services}
    except Exception as exc:
        return {"host": host, "services": [], "error": str(exc)}


@action_tool()
def icinga_acknowledge_alert(host_name: str, service_name: str, author: str, comment: str) -> dict[str, Any]:
    type_param = "Service" if service_name else "Host"
    filter_str = f'host.name=="{host_name}"'
    if service_name:
        filter_str += f' && service.name=="{service_name}"'
    try:
        response = requests.post(
            f"{ICINGA_API_BASE}/v1/actions/acknowledge-problem",
            params={"type": type_param, "filter": filter_str},
            headers={"Accept": "application/json"},
            auth=(ICINGA_API_USER, ICINGA_API_PASSWORD),
            json={"author": author, "comment": comment},
            verify=ICINGA_VERIFY_TLS,
            timeout=10,
        )
        response.raise_for_status()
        return {"status": "ok", "response": response.json()}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


@mcp.tool()
def dns_dig(host: str, target: str, query_type: str = "A", nameserver: str | None = None) -> dict[str, Any]:
    command = f"dig +short {shlex.quote(target)} {shlex.quote(query_type)}"
    if nameserver:
        command += f" @{shlex.quote(nameserver)}"
    return _execute(host, command)


@mcp.tool()
def knot_zone_status(host: str) -> dict[str, Any]:
    return _execute(host, "knotc zone-status")


@mcp.tool()
def pf_log_tail(host: str, count: int = 50, filter: str | None = None, since: str | None = None) -> dict[str, Any]:
    count = max(1, min(int(count), 500))
    command = f"tcpdump -nn -tttt -c {count} -r /var/log/pflog"
    if filter:
        command += f" {shlex.quote(filter)}"
    result = _execute(host, command)
    return {"entries": _parse_packet_log(result["stdout"]), "command": result, "since": since}


@mcp.tool()
def nft_log_tail(host: str, count: int = 50, filter: str | None = None, since: str | None = None) -> dict[str, Any]:
    count = max(1, min(int(count), 500))
    journal_filter = shlex.quote(filter) if filter else ""
    command = f"journalctl -k -n {count} --no-pager {journal_filter}".strip()
    result = _execute(host, command)
    return {"entries": _parse_packet_log(result["stdout"]), "command": result, "since": since}


@mcp.tool()
def firewall_state(host: str) -> dict[str, Any]:
    pf_rules = _execute(host, "pfctl -vsr 2>/dev/null")
    pf_tables = _execute(host, "pfctl -s Tables 2>/dev/null")
    nft_rules = _execute(host, "nft -j list ruleset 2>/dev/null")
    reload_probe = _execute(host, "journalctl -n 20 --no-pager | grep -Ei 'pfctl|nftables|firewall' | tail -n 1")
    return {
        "pf": {"rules": _line_summaries(pf_rules["stdout"]), "tables": _line_summaries(pf_tables["stdout"])},
        "nft": {"ruleset_json": _json_or_none(nft_rules["stdout"])},
        "last_reload": reload_probe["stdout"].strip() or None,
        "commands": {"pf_rules": pf_rules, "pf_tables": pf_tables, "nft_rules": nft_rules},
    }


@mcp.tool()
def ndp_state(host: str, addr: str | None = None, iface: str | None = None) -> dict[str, Any]:
    command = "ip -6 neigh show 2>/dev/null || ndp -an"
    result = _execute(host, command)
    entries = _parse_neighbor_lines(result["stdout"])
    entries = _filter_neighbors(entries, addr=addr, iface=iface)
    return {"entries": entries, "command": result}


@mcp.tool()
def arp_state(host: str, addr: str | None = None, iface: str | None = None) -> dict[str, Any]:
    command = "ip neigh show 2>/dev/null || arp -an"
    result = _execute(host, command)
    entries = _parse_neighbor_lines(result["stdout"])
    entries = _filter_neighbors(entries, addr=addr, iface=iface)
    return {"entries": entries, "command": result}


@mcp.tool()
def multi_source_probe(
    target: str,
    sources: list[str],
    protocol: str = "icmp",
    port: int | None = None,
    count: int = 4,
    parallel: bool = True,
) -> dict[str, Any]:
    sources = sources[:MULTI_PROBE_MAX_SOURCES]
    count = max(1, min(int(count), 20))

    def _probe(source: str):
        if protocol == "tcp" and port:
            result = _execute(source, f"nc -zvw3 {shlex.quote(target)} {int(port)}")
        else:
            result = net_ping(source, target, count=count)
        return source, _summarize_probe(result)

    if parallel and len(sources) > 1:
        with ThreadPoolExecutor(max_workers=min(len(sources), MULTI_PROBE_MAX_SOURCES)) as pool:
            pairs = list(pool.map(_probe, sources))
    else:
        pairs = [_probe(source) for source in sources]
    return {"target": target, "protocol": protocol, "results": dict(pairs)}


@mcp.tool()
def path_explain(from_host: str, to_addr: str, protocol: str = "icmp", src_port: int | None = None) -> dict[str, Any]:
    ip_cmd = f"ip -6 route get {shlex.quote(to_addr)}"
    route_result = _execute(from_host, ip_cmd)
    if not route_result["stdout"]:
        route_result = _execute(from_host, f"route -6 get {shlex.quote(to_addr)}")
    next_hop = _extract_next_hop(route_result["stdout"])
    neighbors = ndp_state(from_host, addr=next_hop) if next_hop else {"entries": []}
    return {
        "from": from_host,
        "to": to_addr,
        "protocol": protocol,
        "src_port": src_port,
        "route": route_result["stdout"],
        "next_hop": next_hop,
        "neighbor_state": neighbors["entries"],
    }


@mcp.tool()
def ecmp_path_select(
    from_host: str,
    to_addr: str,
    n_flows: int = 8,
    protocol: str = "tcp",
    vary: str = "src_port",
) -> dict[str, Any]:
    n_flows = max(1, min(int(n_flows), ECMP_MAX_FLOWS))
    flows = []
    for offset in range(n_flows):
        src_port = 40000 + offset if vary == "src_port" else None
        explanation = path_explain(from_host, to_addr, protocol=protocol, src_port=src_port)
        flows.append({"flow": offset, "src_port": src_port, "next_hop": explanation["next_hop"], "ok": bool(explanation["route"])})
    return {"from": from_host, "to": to_addr, "vary": vary, "flows": flows}


@mcp.tool()
def service_restart_history(host: str, unit: str, since: str = "1 hour ago") -> dict[str, Any]:
    result = _execute(
        host,
        f"journalctl -u {shlex.quote(unit)} --since {shlex.quote(since)} --no-pager | "
        "grep -E 'Started|Stopped|Main process exited|Failed with result'",
    )
    events = []
    for line in result["stdout"].splitlines():
        action = "started" if "Started" in line else "stopped" if "Stopped" in line else "crashed"
        events.append({"ts": line[:24].strip(), "action": action, "summary": line})
    cadence_s = _cadence_seconds(events)
    return {"events": events, "cadence_seconds": cadence_s, "command": result}


@mcp.tool()
def vault_agent_status(host: str) -> dict[str, Any]:
    status_result = _execute(host, "systemctl status vault-agent.service --no-pager")
    config_result = _execute(host, "grep -R -nE 'template|source|destination|command' /etc/vault* /etc/systemd/system/vault-agent.service.d 2>/dev/null")
    return {
        "status": status_result,
        "templates": _line_summaries(config_result["stdout"]),
        "config_probe": config_result,
    }


@mcp.tool()
def dns_probe_burst(host: str, target: str, query: str, count: int = 5, interval_ms: int = 250) -> dict[str, Any]:
    count = max(1, min(int(count), DNS_BURST_MAX_COUNT))
    interval_ms = max(DNS_BURST_MIN_INTERVAL_MS, int(interval_ms))
    rows = []
    for _ in range(count):
        started = time.perf_counter()
        result = dns_dig(host, target, query)
        rows.append(
            {
                "ts": _iso_now(),
                "rtt_ms": int((time.perf_counter() - started) * 1000),
                "status": "ok" if _ok(result) else "error",
                "response_size": len(result.get("stdout", "")),
            }
        )
        time.sleep(interval_ms / 1000)
    return {"host": host, "target": target, "query": query, "results": rows}


def _line_summaries(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()][:RAW_OUTPUT_LINE_LIMIT]


def _json_or_none(value: str):
    try:
        return json.loads(value) if value.strip() else None
    except json.JSONDecodeError:
        return None


def _parse_packet_log(value: str) -> list[dict[str, Any]]:
    entries = []
    for line in value.splitlines():
        if not line.strip():
            continue
        entries.append(
            {
                "ts": line.split(" ", 1)[0],
                "rule_id": _first_match(r"rule\s+(\d+)", line),
                "action": "block" if "block" in line.lower() else "pass" if "pass" in line.lower() else None,
                "summary": line,
            }
        )
    return entries


def _parse_neighbor_lines(value: str) -> list[dict[str, Any]]:
    entries = []
    for line in value.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        addr = parts[0].strip("()") if parts else None
        entries.append(
            {
                "addr": addr,
                "iface": parts[2] if len(parts) > 2 and parts[1] == "dev" else None,
                "mac": _first_match(r"(?:lladdr|at)\s+([0-9a-f:.-]+)", line, flags=re.IGNORECASE),
                "state": _first_match(r"\b(REACHABLE|STALE|PROBE|INCOMPLETE|DELAY|FAILED)\b", line, flags=re.IGNORECASE) or "unknown",
                "summary": line,
            }
        )
    return entries


def _filter_neighbors(entries: list[dict[str, Any]], *, addr: str | None, iface: str | None):
    filtered = entries
    if addr:
        filtered = [item for item in filtered if item.get("addr") == addr]
    if iface:
        filtered = [item for item in filtered if item.get("iface") == iface or iface in item.get("summary", "")]
    return filtered


def _summarize_probe(result: dict[str, Any]) -> dict[str, Any]:
    stdout = result.get("stdout", "")
    sent = int(_first_match(r"(\d+)\s+packets transmitted", stdout) or 0)
    received = int(_first_match(r"(\d+)\s+(?:packets )?received", stdout) or 0)
    loss = _first_match(r"([0-9.]+)%\s+packet loss", stdout)
    rtt = _first_match(r"=\s*[0-9.]+/([0-9.]+)/", stdout)
    return {
        "sent": sent,
        "received": received,
        "loss_pct": float(loss) if loss is not None else None,
        "rtt_ms": float(rtt) if rtt is not None else None,
        "ok": _ok(result),
    }


def _extract_next_hop(value: str) -> str | None:
    candidate = _first_match(r"\bvia\s+([0-9a-fA-F:]+)", value)
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return candidate


def _cadence_seconds(events: list[dict[str, Any]]) -> int | None:
    return None if len(events) < 2 else 0


def _first_match(pattern: str, value: str, *, flags: int = 0) -> str | None:
    match = re.search(pattern, value, flags=flags)
    return match.group(1) if match else None


def build_http_app():
    app = mcp.streamable_http_app()

    async def health(request):
        return JSONResponse({"status": "ok", "service": "hyrule-mcp", "transport": "streamable-http"})

    app.add_route("/health", health, methods=["GET"])
    return app


def main():
    transport = os.getenv("HYRULE_MCP_TRANSPORT", "stdio").strip().lower()
    if transport in {"http", "daemon", "streamable-http"}:
        host = os.getenv("HYRULE_MCP_BIND", "127.0.0.1")
        port = int(os.getenv("HYRULE_MCP_PORT", "8765"))
        uvicorn.run(build_http_app(), host=host, port=port, log_level="info")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
