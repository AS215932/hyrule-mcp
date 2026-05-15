"""Compatibility shim for the Hyrule MCP server.

New code should import from ``hyrule_mcp``. This module keeps the historical
``mcp_server`` script/import path working for packaging, tests, and operators.
"""

from __future__ import annotations

from hyrule_mcp.executor import execute_args as _execute_args
from hyrule_mcp.server import action_tool, build_http_app, main, mcp
from hyrule_mcp.settings import SETTINGS
from hyrule_mcp.tools.diagnostics import *  # noqa: F401,F403


COMMAND_TIMEOUT_S = SETTINGS.command_timeout_s
RAW_OUTPUT_LINE_LIMIT = SETTINGS.raw_output_line_limit
TCPDUMP_MAX_COUNT = SETTINGS.tcpdump_max_count
TCPDUMP_MAX_DURATION_S = SETTINGS.tcpdump_max_duration_s
TCPDUMP_MAX_SNAPLEN = SETTINGS.tcpdump_max_snaplen
DNS_BURST_MAX_COUNT = SETTINGS.dns_burst_max_count
DNS_BURST_MIN_INTERVAL_MS = SETTINGS.dns_burst_min_interval_ms
MULTI_PROBE_MAX_SOURCES = SETTINGS.multi_probe_max_sources
ECMP_MAX_FLOWS = SETTINGS.ecmp_max_flows

_HOSTS_MAP = SETTINGS.hosts
_LOCAL_ALIASES = SETTINGS.local_aliases


def _resolve(host: str):
    profile = SETTINGS.resolve(host)
    return profile.address, profile.user, profile.key


async def _execute(host: str, command: str, username: str | None = None, timeout_s: int = COMMAND_TIMEOUT_S):
    import shlex

    return await _execute_args(host, shlex.split(command), username=username, timeout_s=timeout_s)


if __name__ == "__main__":
    main()
