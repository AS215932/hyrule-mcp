# Hyrule MCP

`hyrule-mcp` is the live diagnostic substrate for AS215932. It exposes narrow,
bounded Model Context Protocol tools for monitoring, routing, host, firewall,
and packet-path inspection.

## Runtime shape

- Runs as either the legacy stdio server or a supervised local daemon on `noc`.
- The daemon serves MCP over loopback streamable HTTP and exposes `/health`.
- Host-targeted tools short-circuit to local subprocess execution when the
  target resolves to the MCP host itself.
- Remote host work uses the configured noc MCP SSH key and host resolver.

The intended production daemon mode is:

```bash
HYRULE_MCP_TRANSPORT=http \
HYRULE_MCP_BIND=127.0.0.1 \
HYRULE_MCP_PORT=8765 \
python mcp_server.py
```

NOC Agent then connects to `http://127.0.0.1:8765/mcp`.

## Tool design

The server follows three layers:

1. Specialized read tools first.
2. Purpose-built diagnostic helpers for correlation-heavy checks.
3. Raw SSH only as a bounded escape hatch.

Command-style returns preserve:

- `stdout`
- `stderr`
- `exit_code`
- `duration_ms`
- `transport`
- `data.command`
- `data.argv`
- `data.resolved_target`

`data.resolved_target` reports the resolved target name, address, username, and
whether an SSH key is configured; it does not include private key paths.

## Core diagnostic families

- Monitoring:
  - `prometheus_query`
  - `prometheus_list_targets`
  - `icinga_get_host_state`
- Routing and path:
  - `frr_vtysh_cmd`
  - `path_explain`
  - `ecmp_path_select`
  - `multi_source_probe`
- Packet and firewall:
  - `tcpdump_capture`
  - `pf_log_tail`
  - `nft_log_tail`
  - `firewall_state`
  - `ndp_state`
  - `arp_state`
- Host/service:
  - `os_systemd_status`
  - `os_journalctl`
  - `dmesg_tail`
  - `service_restart_history`
  - `vault_agent_status`
- DNS/WireGuard:
  - `dns_dig`
  - `dns_probe_burst`
  - `knot_zone_status`
  - `wg_show`

Write-oriented tools remain shadow-mode gated.

## Resource safety

Potentially heavy diagnostics are constrained server-side:

- packet capture duration, count, and snaplen are capped
- DNS bursts have count and interval bounds
- multi-source probes cap fan-out
- ECMP probes cap flow count
- raw SSH output is truncated
- raw SSH rejects mutative command patterns

These limits are configurable through `HYRULE_MCP_*` environment variables and
default conservatively.

## Icinga behavior

Icinga state queries are API-first. The server talks to the REST API using:

- `ICINGA_API_BASE`
- `ICINGA_API_USER`
- `ICINGA_API_PASSWORD`
- `ICINGA_VERIFY_TLS`

This replaces the prior shell-based `icinga2 object list` dependency.

## Tests

See [TESTING.md](TESTING.md).
