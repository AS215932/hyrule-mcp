from __future__ import annotations

import logging
import os
import sys

import structlog
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse

from hyrule_mcp.tools import diagnostics


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
        "AS215932 infrastructure MCP daemon. Prefer specialized read-only tools over raw SSH. "
        "Return bounded structured telemetry with schema_version and truncation metadata."
    ),
)


def action_tool():
    from hyrule_mcp.settings import SETTINGS

    if SETTINGS.enable_actions:
        return mcp.tool()

    def _skip(fn):
        return fn

    return _skip


def register_tools() -> None:
    for name in (
        "prometheus_query",
        "prometheus_list_targets",
        "ssh_run_command",
        "frr_vtysh_cmd",
        "net_ping",
        "net_traceroute",
        "tcpdump_capture",
        "system_tcpdump",
        "wg_show",
        "os_service_status",
        "os_service_logs",
        "os_systemd_status",
        "os_rcctl_check",
        "os_journalctl",
        "dmesg_tail",
        "icinga_get_host_state",
        "icinga_list_problems",
        "dns_dig",
        "knot_zone_status",
        "pf_log_tail",
        "nft_log_tail",
        "firewall_state",
        "ndp_state",
        "arp_state",
        "multi_source_probe",
        "path_explain",
        "ecmp_path_select",
        "service_restart_history",
        "socket_listeners",
        "vault_agent_status",
        "dns_probe_burst",
    ):
        mcp.tool()(getattr(diagnostics, name))
    action_tool()(diagnostics.os_systemd_restart)
    action_tool()(diagnostics.os_service_restart)
    action_tool()(diagnostics.icinga_acknowledge_alert)


register_tools()


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
