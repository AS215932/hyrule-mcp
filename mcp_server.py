import logging
import os
import shlex
import sys

import paramiko
import requests
import structlog
import yaml
from mcp.server.fastmcp import FastMCP

# Structured logging per the AS215932 application logging contract
# (hyrule-infra/docs/application-logging.md). hyrule-mcp speaks the MCP
# stdio protocol on stdout, so logs MUST go to stderr — the parent
# process (noc-agent) captures stderr into journald, where Vector picks
# them up. SSH command output is intentionally returned as the tool
# result, not logged — but if a future log line needs to include it,
# keep `stdout` / `stderr` as named fields so the aggregator's redact
# step can size-cap or strip them per docs/application-logging.md §4.
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
        "Unified MCP Server for AS215932 Infrastructure. "
        "Provides God-mode tools for interacting with Prometheus, SSH, and routers."
    ),
)

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://[2a0c:b641:b50:2::50]:9090")
HYRULE_MCP_ENABLE_ACTIONS = os.environ.get("HYRULE_MCP_ENABLE_ACTIONS", "0") == "1"
ICINGA_API_USER = os.environ.get("ICINGA_API_USER", "root")
ICINGA_API_PASSWORD = os.environ.get("ICINGA_API_PASSWORD", "")

_HOSTS_CONFIG_PATH = os.environ.get("HYRULE_MCP_HOSTS_CONFIG", "/etc/hyrule-mcp/hosts.yml")
try:
    with open(_HOSTS_CONFIG_PATH) as f:
        _HOSTS_CFG = yaml.safe_load(f) or {}
except FileNotFoundError:
    _HOSTS_CFG = {}

_DEFAULT_USER = _HOSTS_CFG.get("default_user", "root")
_DEFAULT_KEY = _HOSTS_CFG.get("ssh_key")
_HOSTS_MAP = _HOSTS_CFG.get("hosts", {}) or {}


def _resolve(host: str) -> tuple[str, str, str | None]:
    """Resolve logical name → (address, user, key_path). Falls back to literal host + defaults."""
    entry = _HOSTS_MAP.get(host)
    if entry:
        return (
            entry.get("address", host),
            entry.get("user", _DEFAULT_USER),
            entry.get("key", _DEFAULT_KEY),
        )
    return host, _DEFAULT_USER, _DEFAULT_KEY


def action_tool():
    """@mcp.tool() variant that only registers when HYRULE_MCP_ENABLE_ACTIONS=1 (shadow-mode gate)."""
    if HYRULE_MCP_ENABLE_ACTIONS:
        return mcp.tool()
    def _skip(fn):
        return fn
    return _skip


@mcp.tool()
def prometheus_query(query: str) -> dict:
    """
    Execute a PromQL query against the AS215932 Prometheus server.

    Args:
        query: The Prometheus PromQL query string to execute.

    Returns:
        The JSON response from Prometheus containing the evaluated metrics.
    """
    try:
        response = requests.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": query}, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def ssh_run_command(host: str, command: str, username: str | None = None) -> str:
    """
    Execute an SSH command on a target host within the AS215932 infrastructure.
    Make sure a command is safe (e.g., read-only) unless taking a remediation action.

    Args:
        host: Logical hostname (rtr, dns, api, ...) or an explicit IP/FQDN.
        command: The shell command to run.
        username: Optional SSH user override; resolves via /etc/hyrule-mcp/hosts.yml when omitted.

    Returns:
        The stdout/stderr output from the command, or an error string.
    """
    address, default_user, key_path = _resolve(host)
    user = username or default_user

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
        stdin, stdout, stderr = client.exec_command(command, timeout=30)
        opt_out = stdout.read().decode('utf-8')
        err_out = stderr.read().decode('utf-8')

        result = ""
        if opt_out:
            result += f"STDOUT:\n{opt_out}\n"
        if err_out:
            result += f"STDERR:\n{err_out}\n"

        return result.strip() if result else "(executed successfully with no output)"
    except Exception as e:
        return f"SSH Error: {str(e)}"
    finally:
        client.close()

@mcp.tool()
def frr_vtysh_cmd(host: str, command: str) -> str:
    """
    Execute an FRR vtysh command on a target router (e.g. rtr, cr1-nl1) via SSH.
    Useful for querying BGP/OSPF states (e.g. 'show bgp summary', 'show ipv6 ospf6 neighbor').
    """
    return ssh_run_command(host, f"vtysh -c '{command}'")

@mcp.tool()
def net_ping(host: str, target: str, count: int = 4) -> str:
    """
    Execute a ping from a specific host in the AS215932 network to a target IP/domain.
    """
    return ssh_run_command(host, f"ping -c {count} {target}")

@mcp.tool()
def net_traceroute(host: str, target: str) -> str:
    """
    Execute a traceroute from a specific host to a target IP/domain.
    """
    return ssh_run_command(host, f"traceroute -n {target}")

@mcp.tool()
def system_tcpdump(host: str, iface: str, filter_str: str, duration: int = 10) -> str:
    """
    Capture a brief network flow (tcpdump) on an edge node.
    """
    return ssh_run_command(host, f"timeout {duration} tcpdump -i {iface} -nn '{filter_str}'")

@mcp.tool()
def wg_show(host: str) -> str:
    """
    Query WireGuard states (handshakes/transfers) on a host.
    """
    return ssh_run_command(host, "wg show")

@mcp.tool()
def os_systemd_status(host: str, unit: str) -> str:
    """
    Check the status of a systemd service on a Debian/Linux host.
    """
    return ssh_run_command(host, f"systemctl status {unit} --no-pager")

@action_tool()
def os_systemd_restart(host: str, unit: str) -> str:
    """
    Safely restart a Debian/Linux systemd service.
    Gated by HYRULE_MCP_ENABLE_ACTIONS=1 (shadow mode disables registration).
    """
    return ssh_run_command(host, f"systemctl restart {unit}")

@mcp.tool()
def os_rcctl_check(host: str, service: str) -> str:
    """
    Check OpenBSD service management (rc.d) status.
    """
    return ssh_run_command(host, f"rcctl check {service}")

@mcp.tool()
def os_journalctl(host: str, unit: str, lines: int = 50) -> str:
    """
    Fetch the latest systemd service logs from a host.
    """
    return ssh_run_command(host, f"journalctl -u {unit} -n {lines} --no-pager")

@mcp.tool()
def dmesg_tail(host: str, lines: int = 50) -> str:
    """
    Check for kernel panics or hardware issues.
    """
    return ssh_run_command(host, f"dmesg | tail -n {lines}")

@mcp.tool()
def icinga_get_host_state(host: str) -> str:
    """
    Get the Icinga2 monitoring state for a specific host by querying the icinga DB on 'mon'.
    """
    return ssh_run_command("mon", f"icinga2 object list --type Host --name {host}")

@action_tool()
def icinga_acknowledge_alert(host_name: str, service_name: str, author: str, comment: str) -> str:
    """
    Autonomously acknowledge an alert in Icinga2 on the 'mon' server.
    Provide the host_name (and optionally service_name if not a host alert).
    Gated by HYRULE_MCP_ENABLE_ACTIONS=1 (shadow mode disables registration).
    """
    if service_name:
        filter_str = f'host.name==\\"{host_name}\\" && service.name==\\"{service_name}\\"'
        type_param = "Service"
    else:
        filter_str = f'host.name==\\"{host_name}\\"'
        type_param = "Host"

    auth = shlex.quote(f"{ICINGA_API_USER}:{ICINGA_API_PASSWORD}")
    cmd = (
        f"curl -k -s -u {auth} -H 'Accept: application/json' -X POST "
        f"'https://localhost:5665/v1/actions/acknowledge-problem?type={type_param}&filter={filter_str}' "
        f"-d '{{\"author\":\"{author}\", \"comment\":\"{comment}\"}}'"
    )
    return ssh_run_command("mon", cmd)

@mcp.tool()
def dns_dig(host: str, target: str, query_type: str = "A", nameserver: str = None) -> str:
    """
    Directly verify upstream/downstream DNS resolution.
    Query executed on the specified 'host'.
    """
    cmd = f"dig +short {target} {query_type}"
    if nameserver:
        cmd += f" @{nameserver}"
    return ssh_run_command(host, cmd)

@mcp.tool()
def knot_zone_status(host: str) -> str:
    """
    Fetch Knot DNS zone serial version to verify if automation pipeline lagged.
    Executed on the target nameserver host.
    """
    return ssh_run_command(host, "knotc zone-status")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
