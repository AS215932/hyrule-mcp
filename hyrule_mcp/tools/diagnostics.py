from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import shlex
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from hyrule_mcp.executor import command_args, execute_args, unsupported_os
from hyrule_mcp.models import (
    DnsProbeResult,
    FirewallState,
    IcingaHostState,
    IcingaProblems,
    NeighborState,
    ProbeResult,
    PrometheusQueryResult,
    PrometheusTargetsResult,
    ToolResult,
)
from hyrule_mcp.sanitize import dump_result, error_result, sanitize_text
from hyrule_mcp.settings import MCPSettings, SETTINGS


READ_ONLY_COMMANDS = {
    "arp",
    "cat",
    "date",
    "df",
    "dig",
    "dmesg",
    "du",
    "find",
    "free",
    "grep",
    "hostname",
    "head",
    "id",
    "ifconfig",
    "ip",
    "journalctl",
    "knotc",
    "ls",
    "lsblk",
    "mount",
    "ndp",
    "netstat",
    "nft",
    "ping",
    "pfctl",
    "ps",
    "pwd",
    "rcctl",
    "route",
    "service",
    "ss",
    "sockstat",
    "stat",
    "systemctl",
    "tail",
    "traceroute",
    "uname",
    "uptime",
    "vtysh",
    "wc",
    "wg",
    "whoami",
}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _result(model: ToolResult) -> dict[str, Any]:
    return dump_result(model)


async def prometheus_query(query: str) -> dict[str, Any]:
    tool = "prometheus_query"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{SETTINGS.prometheus_url}/api/v1/query", params={"query": query})
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
        return _result(
            PrometheusQueryResult(
                tool=tool,
                summary="Prometheus query completed",
                result=compact,
                data={"status": payload.get("status", "unknown"), "result": compact},
            )
        )
    except httpx.TimeoutException:
        return error_result(tool=tool, summary="Prometheus query timed out", error_type="timeout", sanitized_error="Timed out querying Prometheus")
    except Exception as exc:
        return error_result(tool=tool, summary="Prometheus query failed", error_type="transport_error", sanitized_error=sanitize_text(exc))


async def prometheus_list_targets(filter: str | None = None) -> dict[str, Any]:
    tool = "prometheus_list_targets"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{SETTINGS.prometheus_url}/api/v1/targets")
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
        return _result(
            PrometheusTargetsResult(
                tool=tool,
                summary="Prometheus targets listed",
                targets=targets,
                data={"targets": targets},
            )
        )
    except Exception as exc:
        return error_result(tool=tool, summary="Prometheus target listing failed", error_type="transport_error", sanitized_error=sanitize_text(exc))


async def ssh_run_command(host: str, command: str, username: str | None = None) -> dict[str, Any]:
    tool = "ssh_run_command"
    try:
        args = shlex.split(command)
    except ValueError as exc:
        return error_result(
            tool=tool,
            target=host,
            summary="Command parse failed",
            error_type="policy_blocked",
            sanitized_error=sanitize_text(exc),
            data={"requested_command": sanitize_text(command), "policy": "read_only_diagnostics"},
        )
    policy_error = _read_only_policy_error(args)
    if policy_error:
        return error_result(
            tool=tool,
            target=host,
            summary="Command rejected by diagnostic policy",
            error_type="policy_blocked",
            sanitized_error=policy_error,
            data={
                "requested_command": sanitize_text(command),
                "parsed_argv": [sanitize_text(part) for part in args],
                "policy": "read_only_diagnostics",
                "allowed_commands": sorted(READ_ONLY_COMMANDS),
            },
        )
    return await execute_args(host, args, username=username, tool=tool)


async def frr_vtysh_cmd(host: str, command: str) -> dict[str, Any]:
    if not command.lower().strip().startswith("show "):
        return error_result(
            tool="frr_vtysh_cmd",
            target=host,
            summary="FRR command rejected",
            error_type="policy_blocked",
            sanitized_error="Only read-only vtysh show commands are allowed.",
        )
    return await execute_args(host, command_args("vtysh", "-c", command), tool="frr_vtysh_cmd")


async def net_ping(host: str, target: str, count: int = 4) -> dict[str, Any]:
    count = max(1, min(int(count), 20))
    return await execute_args(host, command_args("ping", "-c", count, target), tool="net_ping")


async def net_traceroute(host: str, target: str) -> dict[str, Any]:
    return await execute_args(host, command_args("traceroute", "-n", target), tool="net_traceroute")


async def tcpdump_capture(
    host: str,
    iface: str,
    filter: str,
    duration_s: int = 10,
    count: int = 100,
    snaplen: int = 256,
    action_command: str | None = None,
    action_delay_s: int = 1,
) -> dict[str, Any]:
    duration_s = max(1, min(int(duration_s), SETTINGS.tcpdump_max_duration_s))
    count = max(1, min(int(count), SETTINGS.tcpdump_max_count))
    snaplen = max(64, min(int(snaplen), SETTINGS.tcpdump_max_snaplen))
    if action_command:
        return error_result(
            tool="tcpdump_capture",
            target=host,
            summary="Capture action command rejected",
            error_type="policy_blocked",
            sanitized_error="Action commands are not allowed in diagnostic tcpdump captures.",
        )
    result = await execute_args(
        host,
        command_args("tcpdump", "-tttt", "-nn", "-s", snaplen, "-c", count, "-i", iface, filter),
        timeout_s=duration_s + SETTINGS.command_timeout_s,
        tool="tcpdump_capture",
    )
    packets = [{"ts": line.split(" ", 2)[0], "summary": line} for line in str(result.get("stdout") or "").splitlines() if line]
    result["data"] = {
        "packets": packets[:count],
        "raw_pcap_path": None,
        "limits": {"duration_s": duration_s, "count": count, "snaplen": snaplen},
    }
    result["summary"] = "Packet capture completed" if result.get("ok") else result.get("summary", "Packet capture failed")
    return result


async def system_tcpdump(host: str, iface: str, filter_str: str, duration: int = 10) -> dict[str, Any]:
    return await tcpdump_capture(host, iface, filter_str, duration_s=duration, count=min(SETTINGS.tcpdump_max_count, 100))


async def wg_show(host: str) -> dict[str, Any]:
    return await execute_args(host, command_args("wg", "show"), tool="wg_show")


async def os_systemd_status(host: str, unit: str) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    if not profile.supports_systemd:
        return await unsupported_os(
            "os_systemd_status",
            host,
            "systemd status is not supported on this host.",
            suggestion="Use os_rcctl_check for OpenBSD/rcctl hosts.",
        )
    return await execute_args(host, command_args("systemctl", "status", unit, "--no-pager"), tool="os_systemd_status")


async def os_systemd_restart(host: str, unit: str) -> dict[str, Any]:
    if not SETTINGS.enable_actions:
        return error_result(
            tool="os_systemd_restart",
            target=host,
            summary="Action tool disabled",
            error_type="policy_blocked",
            sanitized_error="HYRULE_MCP_ENABLE_ACTIONS is not enabled.",
        )
    profile = SETTINGS.resolve(host)
    if not profile.supports_systemd:
        return await unsupported_os("os_systemd_restart", host, "systemd restart is not supported on this host.")
    return await execute_args(host, command_args("systemctl", "restart", unit), tool="os_systemd_restart")


async def os_service_status(host: str, service: str) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    service = _safe_service_name(service)
    if profile.supports_service:
        return await execute_args(host, command_args("service", service, "onestatus"), tool="os_service_status")
    if profile.supports_rcctl:
        return await execute_args(host, command_args("rcctl", "check", service), tool="os_service_status")
    if profile.supports_systemd:
        return await execute_args(host, command_args("systemctl", "status", service, "--no-pager"), tool="os_service_status")
    return await unsupported_os("os_service_status", host, "No supported service status command is known for this host.")


async def os_service_logs(host: str, service: str, lines: int = 100) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    service = _safe_service_name(service)
    lines = max(1, min(int(lines), 500))
    if profile.supports_systemd:
        return await execute_args(host, command_args("journalctl", "-u", service, "-n", lines, "--no-pager"), tool="os_service_logs")
    if not profile.supports_service and not profile.supports_rcctl:
        return await unsupported_os("os_service_logs", host, "No supported service log source is known for this host.")

    log_path = f"/var/log/{service}.log"
    dedicated = await execute_args(host, command_args("tail", "-n", lines, log_path), tool="os_service_logs")
    if dedicated.get("ok"):
        dedicated["summary"] = "Service log collected from dedicated log file"
        dedicated["data"] = {**(dedicated.get("data") or {}), "source": log_path, "fallback_used": False}
        return dedicated

    fallback = await execute_args(host, command_args("grep", "-i", service, "/var/log/messages"), tool="os_service_logs")
    if fallback.get("stdout"):
        selected = "\n".join(str(fallback["stdout"]).splitlines()[-lines:])
        fallback["stdout"] = selected
        fallback["returned_lines"] = len(selected.splitlines())
    fallback["summary"] = "Service log collected from /var/log/messages" if fallback.get("ok") else "Service logs unavailable"
    fallback["data"] = {
        **(fallback.get("data") or {}),
        "source": "/var/log/messages",
        "fallback_used": True,
        "dedicated_log": dedicated,
    }
    return fallback


async def os_service_restart(host: str, service: str) -> dict[str, Any]:
    if not SETTINGS.enable_actions:
        return error_result(
            tool="os_service_restart",
            target=host,
            summary="Action tool disabled",
            error_type="policy_blocked",
            sanitized_error="HYRULE_MCP_ENABLE_ACTIONS is not enabled.",
        )
    profile = SETTINGS.resolve(host)
    service = _safe_service_name(service)
    if profile.supports_service:
        return await execute_args(host, command_args("service", service, "restart"), tool="os_service_restart")
    if profile.supports_rcctl:
        return await execute_args(host, command_args("rcctl", "restart", service), tool="os_service_restart")
    if profile.supports_systemd:
        return await execute_args(host, command_args("systemctl", "restart", service), tool="os_service_restart")
    return await unsupported_os("os_service_restart", host, "No supported service restart command is known for this host.")


async def os_rcctl_check(host: str, service: str) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    if not profile.supports_rcctl:
        return await unsupported_os(
            "os_rcctl_check",
            host,
            "rcctl is not supported on this host.",
            suggestion="Use os_systemd_status for Linux/systemd hosts.",
        )
    return await execute_args(host, command_args("rcctl", "check", service), tool="os_rcctl_check")


async def os_journalctl(host: str, unit: str, lines: int = 50) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    if not profile.supports_systemd:
        return await unsupported_os("os_journalctl", host, "journalctl is not supported on this host.")
    lines = max(1, min(int(lines), 500))
    return await execute_args(host, command_args("journalctl", "-u", unit, "-n", lines, "--no-pager"), tool="os_journalctl")


async def dmesg_tail(host: str, lines: int = 50) -> dict[str, Any]:
    lines = max(1, min(int(lines), 500))
    result = await execute_args(host, command_args("dmesg"), tool="dmesg_tail")
    if result.get("stdout"):
        selected = "\n".join(str(result["stdout"]).splitlines()[-lines:])
        result["stdout"] = selected
        result["returned_lines"] = len(selected.splitlines())
    return result


async def icinga_get_host_state(host: str) -> dict[str, Any]:
    tool = "icinga_get_host_state"
    auth = (SETTINGS.icinga_api_user, SETTINGS.icinga_api_password)
    headers = {"Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=10, verify=SETTINGS.icinga_verify_tls) as client:
            host_response = await client.get(
                f"{SETTINGS.icinga_api_base}/v1/objects/hosts",
                params={"filter": f'host.name=="{host}"'},
                headers=headers,
                auth=auth,
            )
            host_response.raise_for_status()
            service_response = await client.get(
                f"{SETTINGS.icinga_api_base}/v1/objects/services",
                params={"filter": f'service.host_name=="{host}"'},
                headers=headers,
                auth=auth,
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
        return _result(
            IcingaHostState(
                tool=tool,
                target=host,
                summary="Icinga host state loaded",
                host=host,
                services=services,
                data={"objects": host_response.json().get("results", []), "services": services},
            )
        )
    except Exception as exc:
        return error_result(tool=tool, target=host, summary="Icinga host state failed", error_type="transport_error", sanitized_error=sanitize_text(exc))


async def icinga_list_problems(object_type: str = "service", limit: int = 20) -> dict[str, Any]:
    tool = "icinga_list_problems"
    object_type = object_type.lower().strip()
    limit = max(1, min(int(limit), 100))
    endpoint = "hosts" if object_type == "host" else "services"
    filter_expr = "host.state!=0" if endpoint == "hosts" else "service.state!=0"
    try:
        async with httpx.AsyncClient(timeout=10, verify=SETTINGS.icinga_verify_tls) as client:
            response = await client.get(
                f"{SETTINGS.icinga_api_base}/v1/objects/{endpoint}",
                params={"filter": filter_expr},
                headers={"Accept": "application/json"},
                auth=(SETTINGS.icinga_api_user, SETTINGS.icinga_api_password),
            )
            response.raise_for_status()
        results = response.json().get("results", [])
        problems = []
        for item in results[:limit]:
            attrs = item.get("attrs", {})
            name = item.get("name") or attrs.get("name")
            problems.append(
                {
                    "name": name,
                    "host": attrs.get("host_name") or name,
                    "state": attrs.get("state"),
                    "last_check": attrs.get("last_check"),
                    "last_change": attrs.get("last_state_change"),
                    "output": attrs.get("last_check_result", {}).get("output"),
                }
            )
        return _result(
            IcingaProblems(
                tool=tool,
                summary="Icinga problems listed",
                object_type=endpoint[:-1],
                count=len(results),
                returned=len(problems),
                problems=problems,
                data={"problems": problems},
            )
        )
    except Exception as exc:
        return error_result(tool=tool, summary="Icinga problem listing failed", error_type="transport_error", sanitized_error=sanitize_text(exc))


async def icinga_acknowledge_alert(host_name: str, service_name: str, author: str, comment: str) -> dict[str, Any]:
    tool = "icinga_acknowledge_alert"
    if not SETTINGS.enable_actions:
        return error_result(tool=tool, target=host_name, summary="Action tool disabled", error_type="policy_blocked", sanitized_error="HYRULE_MCP_ENABLE_ACTIONS is not enabled.")
    type_param = "Service" if service_name else "Host"
    filter_str = f'host.name=="{host_name}"'
    if service_name:
        filter_str += f' && service.name=="{service_name}"'
    try:
        async with httpx.AsyncClient(timeout=10, verify=SETTINGS.icinga_verify_tls) as client:
            response = await client.post(
                f"{SETTINGS.icinga_api_base}/v1/actions/acknowledge-problem",
                params={"type": type_param, "filter": filter_str},
                headers={"Accept": "application/json"},
                auth=(SETTINGS.icinga_api_user, SETTINGS.icinga_api_password),
                json={"author": author, "comment": comment},
            )
            response.raise_for_status()
        return _result(ToolResult(tool=tool, target=host_name, summary="Icinga alert acknowledged", data={"response": response.json()}))
    except Exception as exc:
        return error_result(tool=tool, target=host_name, summary="Icinga acknowledgement failed", error_type="transport_error", sanitized_error=sanitize_text(exc))


async def dns_dig(host: str, target: str, query_type: str = "A", nameserver: str | None = None) -> dict[str, Any]:
    args = ["dig", "+short", target, query_type]
    if nameserver:
        args.append(f"@{nameserver}")
    return await execute_args(host, args, tool="dns_dig")


async def knot_zone_status(host: str) -> dict[str, Any]:
    return await execute_args(host, command_args("knotc", "zone-status"), tool="knot_zone_status")


async def pf_log_tail(host: str, count: int = 50, filter: str | None = None, since: str | None = None) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    if not profile.supports_pf:
        return await unsupported_os("pf_log_tail", host, "pf logs are not supported on this host.", suggestion="Use nft_log_tail for Linux/nftables hosts.")
    count = max(1, min(int(count), 500))
    args = ["tcpdump", "-nn", "-tttt", "-c", str(count), "-r", "/var/log/pflog"]
    if filter:
        args.append(filter)
    result = await execute_args(host, args, tool="pf_log_tail")
    result["data"] = {"entries": _parse_packet_log(result.get("stdout") or ""), "since": since}
    return result


async def nft_log_tail(host: str, count: int = 50, filter: str | None = None, since: str | None = None) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    if not profile.supports_nft:
        return await unsupported_os("nft_log_tail", host, "nftables logs are not supported on this host.", suggestion="Use pf_log_tail for OpenBSD/pf hosts.")
    count = max(1, min(int(count), 500))
    args = ["journalctl", "-k", "-n", str(count), "--no-pager"]
    result = await execute_args(host, args, tool="nft_log_tail")
    entries = _parse_packet_log(result.get("stdout") or "")
    if filter:
        entries = [entry for entry in entries if filter.lower() in entry.get("summary", "").lower()]
    result["data"] = {"entries": entries, "since": since}
    return result


async def firewall_state(host: str) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    data: dict[str, Any] = {"pf": None, "nft": None}
    commands: dict[str, Any] = {}
    if profile.supports_pf:
        pf_rules = await execute_args(host, command_args("pfctl", "-vsr"), tool="firewall_state")
        pf_tables = await execute_args(host, command_args("pfctl", "-s", "Tables"), tool="firewall_state")
        data["pf"] = {"rules": _line_summaries(pf_rules.get("stdout") or ""), "tables": _line_summaries(pf_tables.get("stdout") or "")}
        commands["pf_rules"] = pf_rules
        commands["pf_tables"] = pf_tables
    if profile.supports_nft:
        nft_rules = await execute_args(host, command_args("nft", "-j", "list", "ruleset"), tool="firewall_state")
        data["nft"] = {"ruleset_json": _json_or_none(nft_rules.get("stdout") or "")}
        commands["nft_rules"] = nft_rules
    if not commands:
        return await unsupported_os("firewall_state", host, "No supported firewall capability is known for this host.")
    data["commands"] = commands
    return _result(FirewallState(tool="firewall_state", target=host, summary="Firewall state collected", data=data))


async def ndp_state(host: str, addr: str | None = None, iface: str | None = None) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    args = command_args("ndp", "-an") if profile.os_family in {"openbsd", "freebsd"} else command_args("ip", "-6", "neigh", "show")
    result = await execute_args(host, args, tool="ndp_state")
    entries = _filter_neighbors(_parse_neighbor_lines(result.get("stdout") or ""), addr=addr, iface=iface)
    return _result(NeighborState(tool="ndp_state", target=host, summary="NDP state collected", entries=entries, data={"entries": entries}))


async def arp_state(host: str, addr: str | None = None, iface: str | None = None) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    args = command_args("arp", "-an") if profile.os_family in {"openbsd", "freebsd"} else command_args("ip", "neigh", "show")
    result = await execute_args(host, args, tool="arp_state")
    entries = _filter_neighbors(_parse_neighbor_lines(result.get("stdout") or ""), addr=addr, iface=iface)
    return _result(NeighborState(tool="arp_state", target=host, summary="ARP state collected", entries=entries, data={"entries": entries}))


async def multi_source_probe(
    target: str,
    sources: list[str],
    protocol: str = "icmp",
    port: int | None = None,
    count: int = 4,
    parallel: bool = True,
) -> dict[str, Any]:
    sources = sources[: SETTINGS.multi_probe_max_sources]
    count = max(1, min(int(count), 20))

    async def _probe(source: str):
        if protocol == "tcp" and port:
            result = await execute_args(source, command_args("nc", "-zvw3", target, int(port)), tool="multi_source_probe")
        else:
            result = await net_ping(source, target, count=count)
        return source, _summarize_probe(result)

    if parallel and len(sources) > 1:
        pairs = await asyncio.gather(*[_probe(source) for source in sources])
    else:
        pairs = [await _probe(source) for source in sources]
    return _result(ProbeResult(tool="multi_source_probe", target=target, summary="Multi-source probe completed", data={"target": target, "protocol": protocol, "results": dict(pairs)}))


async def path_explain(from_host: str, to_addr: str, protocol: str = "icmp", src_port: int | None = None) -> dict[str, Any]:
    profile = SETTINGS.resolve(from_host)
    if profile.os_family == "freebsd":
        route_result = await execute_args(from_host, command_args("route", "-n", "get", to_addr), tool="path_explain")
        route_fields = _parse_freebsd_route_get(route_result.get("stdout") or "")
        next_hop = route_fields.get("gateway")
    else:
        route_result = await execute_args(from_host, command_args("ip", "-6", "route", "get", to_addr), tool="path_explain")
        route_fields = {}
        next_hop = _extract_next_hop(route_result.get("stdout") or "")
    if next_hop and "." in next_hop:
        neighbors = await arp_state(from_host, addr=next_hop)
    else:
        neighbors = await ndp_state(from_host, addr=next_hop) if next_hop else {"data": {"entries": []}}
    return _result(
        ProbeResult(
            tool="path_explain",
            target=to_addr,
            summary="Path explanation completed",
            data={
                "from": from_host,
                "to": to_addr,
                "protocol": protocol,
                "src_port": src_port,
                "route": route_result.get("stdout"),
                "route_fields": route_fields,
                "next_hop": next_hop,
                "interface": route_fields.get("interface"),
                "neighbor_state": (neighbors.get("data") or {}).get("entries", []),
            },
        )
    )


async def ecmp_path_select(from_host: str, to_addr: str, n_flows: int = 8, protocol: str = "tcp", vary: str = "src_port") -> dict[str, Any]:
    n_flows = max(1, min(int(n_flows), SETTINGS.ecmp_max_flows))
    flows = []
    for offset in range(n_flows):
        src_port = 40000 + offset if vary == "src_port" else None
        explanation = await path_explain(from_host, to_addr, protocol=protocol, src_port=src_port)
        data = explanation.get("data") or {}
        flows.append({"flow": offset, "src_port": src_port, "next_hop": data.get("next_hop"), "ok": bool(data.get("route"))})
    return _result(ProbeResult(tool="ecmp_path_select", target=to_addr, summary="ECMP path selection sampled", data={"from": from_host, "to": to_addr, "vary": vary, "flows": flows}))


async def service_restart_history(host: str, unit: str, since: str = "1 hour ago") -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    if not profile.supports_systemd:
        return await unsupported_os("service_restart_history", host, "systemd journal history is not supported on this host.")
    result = await execute_args(host, command_args("journalctl", "-u", unit, "--since", since, "--no-pager"), tool="service_restart_history")
    events = []
    for line in str(result.get("stdout") or "").splitlines():
        if not re.search(r"Started|Stopped|Main process exited|Failed with result", line):
            continue
        action = "started" if "Started" in line else "stopped" if "Stopped" in line else "crashed"
        events.append({"ts": line[:24].strip(), "action": action, "summary": line})
    return _result(ToolResult(tool="service_restart_history", target=host, summary="Service restart history collected", data={"events": events, "cadence_seconds": _cadence_seconds(events), "command": result}))


async def socket_listeners(host: str) -> dict[str, Any]:
    profile = SETTINGS.resolve(host)
    if profile.os_family == "freebsd":
        result = await execute_args(host, command_args("sockstat", "-46", "-l"), tool="socket_listeners")
    elif profile.os_family == "openbsd":
        result = await execute_args(host, command_args("netstat", "-an", "-f", "inet", "-f", "inet6"), tool="socket_listeners")
    else:
        result = await execute_args(host, command_args("ss", "-lntup"), tool="socket_listeners")
    result["data"] = {**(result.get("data") or {}), "listeners": _parse_socket_listeners(result.get("stdout") or "", profile.os_family)}
    return result


async def vault_agent_status(host: str) -> dict[str, Any]:
    status_result = await os_systemd_status(host, "vault-agent.service")
    return _result(ToolResult(tool="vault_agent_status", target=host, summary="Vault agent status collected", data={"status": status_result, "templates": []}))


async def dns_probe_burst(host: str, target: str, query: str, count: int = 5, interval_ms: int = 250) -> dict[str, Any]:
    count = max(1, min(int(count), SETTINGS.dns_burst_max_count))
    interval_ms = max(SETTINGS.dns_burst_min_interval_ms, int(interval_ms))
    rows = []
    for idx in range(count):
        started = time.perf_counter()
        result = await dns_dig(host, target, query)
        rows.append({"ts": _iso_now(), "rtt_ms": int((time.perf_counter() - started) * 1000), "status": "ok" if result.get("ok") else "error", "response_size": len(result.get("stdout") or "")})
        if idx < count - 1:
            await asyncio.sleep(interval_ms / 1000)
    return _result(DnsProbeResult(tool="dns_probe_burst", target=target, summary="DNS probe burst completed", data={"host": host, "target": target, "query": query, "results": rows}))


def _looks_mutative(args: list[str]) -> bool:
    blob = " ".join(args).lower()
    return bool(re.search(r"\b(restart|stop|start|enable|disable|rm|shutdown|reboot|configure|delete|flush|insert|replace|add)\b", blob))


def _read_only_policy_error(args: list[str]) -> str | None:
    if not args:
        return "Raw command is empty."
    command = args[0]
    if command not in READ_ONLY_COMMANDS:
        return f"Raw command '{sanitize_text(command)}' is not in the read-only diagnostic allowlist."
    if _looks_mutative(args):
        return "Raw command contains a mutative verb and is blocked by the read-only diagnostic allowlist policy."
    return None


def _safe_service_name(service: str) -> str:
    service = service.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@+-]+", service):
        raise ValueError("Service name contains unsupported characters.")
    return service


def _line_summaries(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()][: SETTINGS.raw_output_line_limit]


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
        entries.append({"ts": line.split(" ", 1)[0], "rule_id": _first_match(r"rule\s+(\d+)", line), "action": "block" if "block" in line.lower() else "pass" if "pass" in line.lower() else None, "summary": line})
    return entries


def _parse_neighbor_lines(value: str) -> list[dict[str, Any]]:
    entries = []
    for line in value.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        addr = parts[0].strip("()") if parts else None
        entries.append({"addr": addr, "iface": parts[2] if len(parts) > 2 and parts[1] == "dev" else None, "mac": _first_match(r"(?:lladdr|at)\s+([0-9a-f:.-]+)", line, flags=re.IGNORECASE), "state": _first_match(r"\b(REACHABLE|STALE|PROBE|INCOMPLETE|DELAY|FAILED)\b", line, flags=re.IGNORECASE) or "unknown", "summary": line})
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
    return {"sent": sent, "received": received, "loss_pct": float(loss) if loss is not None else None, "rtt_ms": float(rtt) if rtt is not None else None, "ok": bool(result.get("ok"))}


def _extract_next_hop(value: str) -> str | None:
    candidate = _first_match(r"\bvia\s+([0-9a-fA-F:]+)", value)
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return candidate


def _parse_freebsd_route_get(value: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for line in value.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        fields[key.strip().lower().replace(" ", "_")] = raw.strip()
    return fields


def _parse_socket_listeners(value: str, os_family: str) -> list[dict[str, Any]]:
    listeners = []
    for line in value.splitlines():
        if not line.strip() or line.lower().startswith("user"):
            continue
        parts = line.split()
        if os_family == "freebsd" and len(parts) >= 6:
            listeners.append(
                {
                    "user": parts[0],
                    "command": parts[1],
                    "pid": parts[2],
                    "protocol": parts[4],
                    "local": parts[5],
                    "summary": line,
                }
            )
        else:
            listeners.append({"summary": line})
    return listeners


def _cadence_seconds(events: list[dict[str, Any]]) -> int | None:
    return None if len(events) < 2 else 0


def _first_match(pattern: str, value: str, *, flags: int = 0) -> str | None:
    match = re.search(pattern, value, flags=flags)
    return match.group(1) if match else None
