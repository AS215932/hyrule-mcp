import asyncio
from dataclasses import replace
from types import SimpleNamespace

import mcp_server
from hyrule_mcp.settings import HostProfile, MCPSettings, SETTINGS
from hyrule_mcp.sanitize import truncate_text
from hyrule_mcp.tools import diagnostics


def run(coro):
    return asyncio.run(coro)


def _response(payload):
    return SimpleNamespace(
        json=lambda: payload,
        raise_for_status=lambda: None,
    )


class FakeAsyncClient:
    responses = []
    seen = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, *args, **kwargs):
        self.seen.append(("get", args, kwargs))
        return self.responses.pop(0)

    async def post(self, *args, **kwargs):
        self.seen.append(("post", args, kwargs))
        return self.responses.pop(0)


def _settings_with_hosts(**hosts):
    profiles = {
        name: HostProfile(
            name=name,
            address=entry.get("address", name),
            user=entry.get("user", "root"),
            key=entry.get("key"),
            os_family=entry.get("os_family", "linux"),
            init_system=entry.get("init_system", "systemd"),
            firewall=entry.get("firewall", "nft"),
        )
        for name, entry in hosts.items()
    }
    return replace(SETTINGS, hosts=profiles)


def test_resolve_uses_host_map(monkeypatch):
    settings = _settings_with_hosts(noc={"address": "::1", "user": "noc-agent", "key": "/tmp/key"})
    monkeypatch.setattr(mcp_server, "SETTINGS", settings)

    assert mcp_server._resolve("noc") == ("::1", "noc-agent", "/tmp/key")


def test_ssh_escape_hatch_blocks_mutative_commands():
    result = run(mcp_server.ssh_run_command("noc", "systemctl restart noc-agent.service"))

    assert result["ok"] is False
    assert result["error_type"] == "policy_blocked"
    assert "allowlist" in result["sanitized_error"]


def test_wrapper_tools_construct_allowlisted_commands(monkeypatch):
    calls = []

    async def fake_execute(host, args, username=None, timeout_s=None, settings=SETTINGS, tool="command"):
        calls.append((tool, host, args, timeout_s))
        return {
            "schema_version": "test",
            "ok": True,
            "tool": tool,
            "target": host,
            "summary": "ok",
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 1,
            "truncated": False,
            "returned_bytes": 0,
            "returned_lines": 0,
            "error_type": None,
            "sanitized_error": None,
        }

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)

    run(mcp_server.frr_vtysh_cmd("rtr", "show bgp summary"))
    run(mcp_server.net_ping("mon", "2001:db8::1", count=4))
    run(mcp_server.os_journalctl("noc", "noc-agent.service", lines=25))
    run(mcp_server.wg_show("vpn"))
    run(mcp_server.os_systemd_status("noc", "noc-agent.service"))
    run(mcp_server.dmesg_tail("noc", lines=20))
    run(mcp_server.dns_dig("dns", "as215932.net", "AAAA", nameserver="::1"))
    run(mcp_server.knot_zone_status("dns"))

    assert calls[0][2] == ["vtysh", "-c", "show bgp summary"]
    assert calls[1][2] == ["ping", "-c", "4", "2001:db8::1"]
    assert calls[2][2] == ["journalctl", "-u", "noc-agent.service", "-n", "25", "--no-pager"]
    assert calls[3][2] == ["wg", "show"]
    assert calls[4][2] == ["systemctl", "status", "noc-agent.service", "--no-pager"]
    assert calls[5][2] == ["dmesg"]
    assert calls[6][2] == ["dig", "+short", "as215932.net", "AAAA", "@::1"]
    assert calls[7][2] == ["knotc", "zone-status"]


def test_prometheus_query_returns_compact_timestamped_rows(monkeypatch):
    FakeAsyncClient.responses = [
        _response({"status": "success", "data": {"result": [{"metric": {"job": "node"}, "value": [1710000000, "1"]}]}})
    ]
    FakeAsyncClient.seen = []
    monkeypatch.setattr(diagnostics.httpx, "AsyncClient", FakeAsyncClient)

    result = run(mcp_server.prometheus_query("up"))

    assert result["schema_version"]
    assert result["ok"] is True
    assert result["result"][0]["metric"]["job"] == "node"
    assert result["result"][0]["ts_iso"].endswith("+00:00")


def test_icinga_host_state_uses_rest_payload(monkeypatch):
    FakeAsyncClient.responses = [
        _response({"results": [{"name": "noc", "attrs": {"state": 0}}]}),
        _response({"results": [{"name": "noc!disk", "attrs": {"name": "disk", "state": 2, "last_check": 1, "last_state_change": 2, "last_check_result": {"output": "full"}}}]}),
    ]
    FakeAsyncClient.seen = []
    monkeypatch.setattr(diagnostics.httpx, "AsyncClient", FakeAsyncClient)

    result = run(mcp_server.icinga_get_host_state("noc"))

    assert result["host"] == "noc"
    assert result["services"][0]["name"] == "disk"
    assert result["services"][0]["output"] == "full"


def test_icinga_list_service_problems_uses_rest_filter(monkeypatch):
    FakeAsyncClient.responses = [
        _response(
            {
                "results": [
                    {
                        "name": "noc!disk",
                        "attrs": {
                            "host_name": "noc",
                            "name": "disk",
                            "state": 2,
                            "last_check": 1,
                            "last_state_change": 2,
                            "last_check_result": {"output": "full"},
                        },
                    }
                ]
            }
        )
    ]
    FakeAsyncClient.seen = []
    monkeypatch.setattr(diagnostics.httpx, "AsyncClient", FakeAsyncClient)

    result = run(mcp_server.icinga_list_problems("service"))

    assert result["object_type"] == "service"
    assert result["count"] == 1
    assert result["problems"][0]["host"] == "noc"
    assert FakeAsyncClient.seen[0][2]["params"]["filter"] == "service.state!=0"


def test_icinga_acknowledge_alert_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(diagnostics, "SETTINGS", replace(SETTINGS, enable_actions=False))

    result = run(mcp_server.icinga_acknowledge_alert("noc", "disk", "svag", "ack"))

    assert result["ok"] is False
    assert result["error_type"] == "policy_blocked"


def test_tcpdump_capture_enforces_resource_caps(monkeypatch):
    seen = {}

    async def fake_execute(host, args, username=None, timeout_s=None, settings=SETTINGS, tool="command"):
        seen["args"] = args
        seen["timeout"] = timeout_s
        return {
            "schema_version": "test",
            "ok": True,
            "tool": tool,
            "target": host,
            "summary": "ok",
            "stdout": "2026-05-13 packet",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 1,
            "truncated": False,
            "returned_bytes": 18,
            "returned_lines": 1,
            "error_type": None,
            "sanitized_error": None,
        }

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)

    result = run(mcp_server.tcpdump_capture("rtr", "enX4", "icmp6", duration_s=999, count=999, snaplen=9999))

    limits = result["data"]["limits"]
    assert limits["duration_s"] == mcp_server.TCPDUMP_MAX_DURATION_S
    assert limits["count"] == mcp_server.TCPDUMP_MAX_COUNT
    assert limits["snaplen"] == mcp_server.TCPDUMP_MAX_SNAPLEN
    assert result["data"]["packets"]


def test_multi_source_probe_caps_sources(monkeypatch):
    async def fake_ping(source, target, count=4):
        return {"stdout": "4 packets transmitted, 4 received, 0% packet loss", "ok": True}

    monkeypatch.setattr(diagnostics, "net_ping", fake_ping)
    sources = [f"host-{idx}" for idx in range(mcp_server.MULTI_PROBE_MAX_SOURCES + 3)]

    result = run(mcp_server.multi_source_probe("2001:db8::1", sources))

    assert len(result["data"]["results"]) == mcp_server.MULTI_PROBE_MAX_SOURCES


def test_firewall_and_neighbor_helpers_shape_structured_results(monkeypatch):
    settings = _settings_with_hosts(rtr={"firewall": "pf", "os_family": "openbsd", "init_system": "rcctl"})
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)
    outputs = iter(
        [
            {"stdout": "@0 pass in quick", "ok": True},
            {"stdout": "bogons6", "ok": True},
            {"stdout": "fe80::1 dev enX0 lladdr aa:bb:cc REACHABLE", "ok": True},
        ]
    )

    async def fake_execute(*args, **kwargs):
        return next(outputs)

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)

    firewall = run(mcp_server.firewall_state("rtr"))
    ndp = run(mcp_server.ndp_state("rtr", addr="fe80::1"))

    assert firewall["data"]["pf"]["rules"]
    assert ndp["entries"][0]["state"] == "REACHABLE"


def test_os_aware_feedback_for_incompatible_service_tool(monkeypatch):
    settings = _settings_with_hosts(mail={"os_family": "openbsd", "init_system": "rcctl", "firewall": "pf"})
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)

    result = run(mcp_server.os_systemd_status("mail", "smtpd"))

    assert result["ok"] is False
    assert result["error_type"] == "unsupported_os"
    assert "os_rcctl_check" in result["sanitized_error"]


def test_truncation_reports_hard_limits():
    truncated = truncate_text("\n".join(f"line-{idx}" for idx in range(20)), max_bytes=40, max_lines=5)

    assert truncated.truncated is True
    assert truncated.returned_lines <= 5
    assert truncated.returned_bytes <= 40
    assert truncated.truncation_reason is not None


def test_http_app_exposes_streamable_mcp_at_documented_path():
    app = mcp_server.build_http_app()
    mounted_paths = [getattr(route, "path", None) for route in app.routes]

    assert "/health" in mounted_paths
    assert "/mcp" in mounted_paths
