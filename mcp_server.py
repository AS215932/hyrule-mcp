import os
import requests
import paramiko
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "Hyrule MCP",
    instructions=(
        "Unified MCP Server for AS215932 Infrastructure. "
        "Provides God-mode tools for interacting with Prometheus, SSH, and routers."
    ),
)

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://2a0c:b641:b50:2::50:9090") # default to 'mon' IPv6

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
def ssh_run_command(host: str, command: str, username: str = "root") -> str:
    """
    Execute an SSH command on a target host within the AS215932 infrastructure.
    Make sure a command is safe (e.g., read-only) unless taking a remediation action.
    
    Args:
        host: The IP address or hostname to SSH into.
        command: The shell command to run.
        username: SSH username (defaults to root).
        
    Returns:
        The stdout/stderr output from the command, or an error string.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # In a real environment we would load the proper SSH keys from the system context
    # (e.g. via an agent or a specific path like ~/.ssh/id_rsa or ed25519)
    try:
        # Assuming the agent running this has access to the local SSH agent or default keys
        client.connect(hostname=host, username=username, timeout=10)
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
    Execute an FRR vtysh command on a target router (e.g. fw, rtr1) via SSH.
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

@mcp.tool()
def os_systemd_restart(host: str, unit: str) -> str:
    """
    Safely restart a Debian/Linux systemd service.
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

@mcp.tool()
def icinga_acknowledge_alert(host_name: str, service_name: str, author: str, comment: str) -> str:
    """
    Autonomously acknowledge an alert in Icinga2 on the 'mon' server.
    Provide the host_name (and optionally service_name if not a host alert).
    """
    # Use Icinga's REST API over curl on the 'mon' host
    # This requires local icinga API setup on mon. Alternatively icingacli can be used.
    # Here we use the icinga console / API to acknowledge.
    if service_name:
        filter_str = f'host.name==\\"{host_name}\\" && service.name==\\"{service_name}\\"'
        type_param = "Service"
    else:
        filter_str = f'host.name==\\"{host_name}\\"'
        type_param = "Host"
        
    cmd = (
        f"curl -k -s -u root:icinga -H 'Accept: application/json' -X POST "
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

if __name__ == "__main__":
    mcp.run()
