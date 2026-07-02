import asyncio
import hashlib
import hmac
import json
import time
from dataclasses import replace
from types import SimpleNamespace

import mcp_server
import pytest
from hyrule_mcp import executor
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
            aliases=tuple(entry.get("aliases", ())),
        )
        for name, entry in hosts.items()
    }
    return replace(SETTINGS, hosts=profiles)


def _auth(secret="sign-me", action_class="restart_service", expiry=None, action_id="act-1"):
    payload = {
        "action_id": action_id,
        "case_id": "case-1",
        "operator": "pytest",
        "action_class": action_class,
        "expiry": expiry or int(time.time()) + 60,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["signature"] = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return payload


def test_resolve_uses_host_map(monkeypatch):
    settings = _settings_with_hosts(noc={"address": "::1", "user": "noc-agent", "key": "/tmp/key"})
    monkeypatch.setattr(mcp_server, "SETTINGS", settings)

    assert mcp_server._resolve("noc") == ("::1", "noc-agent", "/tmp/key")


def test_ssh_escape_hatch_blocks_mutative_commands():
    result = run(mcp_server.ssh_run_command("noc", "systemctl restart noc-agent.service"))

    assert result["ok"] is False
    assert result["error_type"] == "policy_blocked"
    assert "allowlist" in result["sanitized_error"]
    assert result["data"]["requested_command"] == "systemctl restart noc-agent.service"
    assert result["data"]["parsed_argv"] == ["systemctl", "restart", "noc-agent.service"]


def test_ssh_escape_hatch_blocks_non_allowlisted_commands():
    result = run(mcp_server.ssh_run_command("noc", "rm-status --help"))

    assert result["ok"] is False
    assert result["error_type"] == "policy_blocked"
    assert "not in the read-only diagnostic allowlist" in result["sanitized_error"]
    assert result["data"]["requested_command"] == "rm-status --help"
    assert result["data"]["parsed_argv"] == ["rm-status", "--help"]
    assert result["data"]["policy"] == "read_only_diagnostics"
    assert result["data"]["allowed_commands"]
    assert "ls" in result["data"]["allowed_commands"]


def test_ssh_escape_hatch_reports_parse_failures():
    result = run(mcp_server.ssh_run_command("noc", "ls 'unclosed"))

    assert result["ok"] is False
    assert result["error_type"] == "policy_blocked"
    assert result["summary"] == "Command parse failed"
    assert result["data"]["requested_command"] == "ls 'unclosed"
    assert result["data"]["policy"] == "read_only_diagnostics"
    assert "parsed_argv" not in result["data"]


@pytest.mark.parametrize(
    "command, expected_args",
    [
        ("ls -la /tmp", ["ls", "-la", "/tmp"]),
        ("ps aux", ["ps", "aux"]),
        ("df -h", ["df", "-h"]),
        ("tail -n 50 /var/log/syslog", ["tail", "-n", "50", "/var/log/syslog"]),
        ("journalctl -n 10", ["journalctl", "-n", "10"]),
    ],
)
def test_ssh_escape_hatch_allows_common_read_only_commands(monkeypatch, command, expected_args):
    seen = {}

    async def fake_execute(host, args, username=None, timeout_s=None, settings=SETTINGS, tool="command"):
        seen["host"] = host
        seen["args"] = args
        return {
            "schema_version": "test",
            "ok": True,
            "tool": tool,
            "target": host,
            "summary": "ok",
            "stdout": "total 0",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 1,
            "truncated": False,
            "returned_bytes": 7,
            "returned_lines": 1,
            "error_type": None,
            "sanitized_error": None,
        }

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)

    result = run(mcp_server.ssh_run_command("ci", command))

    assert result["ok"] is True
    assert seen == {"host": "ci", "args": expected_args}


def test_ssh_transport_errors_include_command_context(monkeypatch):
    settings = _settings_with_hosts(ci={"address": "ci.example", "user": "noc-agent", "key": "/run/keys/noc"})

    def fail_auth(*args, **kwargs):
        raise RuntimeError("Authentication failed.")

    monkeypatch.setattr(executor, "_run_paramiko", fail_auth)

    result = run(executor.execute_args("ci", ["systemctl", "status", "hyrule-mcp.service", "--no-pager"], settings=settings, tool="os_systemd_status"))

    assert result["ok"] is False
    assert result["error_type"] == "transport_error"
    assert result["sanitized_error"] == "Authentication failed."
    assert result["data"]["command"] == "systemctl status hyrule-mcp.service --no-pager"
    assert result["data"]["argv"] == ["systemctl", "status", "hyrule-mcp.service", "--no-pager"]
    assert result["data"]["resolved_target"] == {
        "name": "ci",
        "address": "ci.example",
        "username": "noc-agent",
        "key_configured": True,
    }
    assert result["data"]["transport"] == "ssh"
    assert result["data"]["timeout_s"] == settings.command_timeout_s
    assert result["data"]["exception_type"] == "RuntimeError"


def test_command_results_include_evidence_reference():
    settings = replace(
        _settings_with_hosts(ci={"address": "ci"}),
        local_aliases={"ci"},
        command_timeout_s=5,
    )

    result = run(executor.execute_args("ci", ["/bin/echo", "ok"], settings=settings, tool="diagnostic_echo"))

    assert result["ok"] is True
    assert result["evidence_id"].startswith("ev_")
    assert result["sensitivity_class"] == "internal"
    assert result["raw_ref"].endswith(result["evidence_id"])
    assert result["data"]["evidence_ref"]["evidence_id"] == result["evidence_id"]


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


def test_action_tool_rejects_missing_authorization_when_enabled(monkeypatch):
    monkeypatch.setattr(diagnostics, "SETTINGS", replace(SETTINGS, enable_actions=True, action_signing_secret="sign-me"))

    result = run(mcp_server.os_service_restart("noc", "node_exporter"))

    assert result["ok"] is False
    assert result["error_type"] == "policy_blocked"
    assert result["data"]["reason"] == "missing_authorization"


def test_action_tool_rejects_expired_authorization(monkeypatch):
    monkeypatch.setattr(diagnostics, "SETTINGS", replace(SETTINGS, enable_actions=True, action_signing_secret="sign-me"))

    result = run(mcp_server.os_service_restart("noc", "node_exporter", action_authorization=_auth(expiry=int(time.time()) - 1)))

    assert result["ok"] is False
    assert result["data"]["reason"] == "expired"


def test_action_tool_rejects_disallowed_host_and_service(monkeypatch):
    settings = replace(
        SETTINGS,
        enable_actions=True,
        action_signing_secret="sign-me",
        action_allowed_hosts={"noc"},
        action_allowed_services={"node_exporter"},
    )
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)

    host_result = run(mcp_server.os_service_restart("mail", "node_exporter", action_authorization=_auth()))
    service_result = run(mcp_server.os_service_restart("noc", "postgres", action_authorization=_auth()))

    assert host_result["data"]["reason"] == "host_not_allowed"
    assert service_result["data"]["reason"] == "service_not_allowed"


def test_approved_service_restart_executes_bounded_helper(monkeypatch):
    calls = []
    settings = _settings_with_hosts(noc={"init_system": "systemd"})
    settings = replace(settings, enable_actions=True, action_signing_secret="sign-me")
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)

    async def fake_execute(host, args, username=None, timeout_s=None, settings=SETTINGS, tool="command"):
        calls.append((tool, host, args))
        return {"ok": True, "tool": tool, "target": host}

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)

    result = run(mcp_server.os_service_restart("noc", "node_exporter", action_authorization=_auth()))

    assert result["ok"] is True
    assert calls == [("os_service_restart", "noc", ["systemctl", "restart", "node_exporter"])]


def test_approved_icinga_acknowledge_posts_action(monkeypatch):
    settings = replace(SETTINGS, enable_actions=True, action_signing_secret="sign-me")
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)
    FakeAsyncClient.responses = [_response({"results": [{"code": 200.0, "status": "Acknowledged"}]})]
    FakeAsyncClient.seen = []
    monkeypatch.setattr(diagnostics.httpx, "AsyncClient", FakeAsyncClient)

    result = run(
        mcp_server.icinga_acknowledge_alert(
            "noc",
            "disk",
            "pytest",
            "ack",
            action_authorization=_auth(action_class="acknowledge_icinga"),
        )
    )

    assert result["ok"] is True
    assert FakeAsyncClient.seen[0][0] == "post"
    assert FakeAsyncClient.seen[0][2]["params"]["type"] == "Service"


def test_icinga_ack_passes_expiry_and_notify(monkeypatch):
    settings = replace(SETTINGS, enable_actions=True, action_signing_secret="sign-me")
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)
    FakeAsyncClient.responses = [_response({"results": [{"code": 200.0, "status": "Acknowledged"}]})]
    FakeAsyncClient.seen = []
    monkeypatch.setattr(diagnostics.httpx, "AsyncClient", FakeAsyncClient)

    deadline = int(time.time()) + 3600
    result = run(
        mcp_server.icinga_acknowledge_alert(
            "noc", "disk", "noc-agent", "auto-snooze",
            action_authorization=_auth(action_class="acknowledge_icinga"),
            expiry=deadline,
            notify=False,
        )
    )

    assert result["ok"] is True
    body = FakeAsyncClient.seen[0][2]["json"]
    assert body["expiry"] == deadline  # auto-clears at the deadline
    assert body["notify"] is False


def test_icinga_ack_uses_broad_ack_allowlist_not_restart_allowlist(monkeypatch):
    # Restart allowlist is narrow (noc only); acks use their own broad allowlist,
    # so the agent can ack a host it could never restart.
    settings = replace(
        SETTINGS,
        enable_actions=True,
        action_signing_secret="sign-me",
        action_allowed_hosts={"noc"},
        action_allowed_services={"node_exporter"},
        ack_allowed_hosts={"*"},
        ack_allowed_services={"*"},
    )
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)
    FakeAsyncClient.responses = [_response({"results": [{"code": 200.0, "status": "Acknowledged"}]})]
    FakeAsyncClient.seen = []
    monkeypatch.setattr(diagnostics.httpx, "AsyncClient", FakeAsyncClient)

    result = run(
        mcp_server.icinga_acknowledge_alert(
            "rtr", "disk", "noc-agent", "investigating",
            action_authorization=_auth(action_class="acknowledge_icinga"),
        )
    )
    assert result["ok"] is True  # rtr/disk allowed for acks despite the restart allowlist


def test_icinga_ack_respects_ack_allowlist_when_restricted(monkeypatch):
    settings = replace(
        SETTINGS,
        enable_actions=True,
        action_signing_secret="sign-me",
        ack_allowed_hosts={"noc"},
        ack_allowed_services={"*"},
    )
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)

    result = run(
        mcp_server.icinga_acknowledge_alert(
            "rtr", "disk", "noc-agent", "x",
            action_authorization=_auth(action_class="acknowledge_icinga"),
        )
    )
    assert result["ok"] is False
    assert result["data"]["reason"] == "host_not_allowed"


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


def test_resolve_uses_host_aliases():
    settings = _settings_with_hosts(**{"cr1-nl1": {"address": "2001:db8::a", "aliases": ["cr1.nl1", "cr1_nl1"]}})

    assert settings.resolve("cr1.nl1").name == "cr1-nl1"
    assert settings.resolve("cr1_nl1").address == "2001:db8::a"


def test_freebsd_service_status_uses_onestatus(monkeypatch):
    settings = _settings_with_hosts(**{"cr1-nl1": {"os_family": "freebsd", "init_system": "service", "firewall": "pf"}})
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)
    seen = {}

    async def fake_execute(host, args, username=None, timeout_s=None, settings=SETTINGS, tool="command"):
        seen["host"] = host
        seen["args"] = args
        return {"ok": True, "stdout": "node_exporter is running", "tool": tool}

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)

    result = run(mcp_server.os_service_status("cr1-nl1", "node_exporter"))

    assert result["ok"] is True
    assert seen == {"host": "cr1-nl1", "args": ["service", "node_exporter", "onestatus"]}


def test_service_tools_return_structured_error_for_invalid_service_name():
    result = run(mcp_server.os_service_status("cr1-nl1", "node_exporter;restart"))

    assert result["ok"] is False
    assert result["error_type"] == "policy_blocked"
    assert result["summary"] == "Invalid service name"


def test_freebsd_service_logs_falls_back_to_messages(monkeypatch):
    settings = _settings_with_hosts(**{"cr1-nl1": {"os_family": "freebsd", "init_system": "service", "firewall": "pf"}})
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)
    calls = []
    outputs = iter(
        [
            {"ok": False, "stdout": "", "stderr": "No such file"},
            {"ok": True, "stdout": "old\nnew node_exporter line\n", "stderr": ""},
        ]
    )

    async def fake_execute(host, args, username=None, timeout_s=None, settings=SETTINGS, tool="command"):
        calls.append(args)
        return next(outputs)

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)

    result = run(mcp_server.os_service_logs("cr1-nl1", "node_exporter", lines=1))

    assert calls[0] == ["tail", "-n", "1", "/var/log/node_exporter.log"]
    assert calls[1] == ["grep", "-i", "node_exporter", "/var/log/messages"]
    assert result["stdout"] == "new node_exporter line"
    assert result["data"]["fallback_used"] is True


def test_freebsd_path_explain_parses_route_get(monkeypatch):
    settings = _settings_with_hosts(**{"cr1-nl1": {"os_family": "freebsd", "init_system": "service", "firewall": "pf"}})
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)
    calls = []

    async def fake_execute(host, args, username=None, timeout_s=None, settings=SETTINGS, tool="command"):
        calls.append(args)
        if args[0] == "route":
            return {"ok": True, "stdout": "   route to: 2001:db8::1\ngateway: fe80::1\ninterface: vtnet0\nif address: fe80::2\n"}
        return {"ok": True, "stdout": "fe80::1 at aa:bb:cc on vtnet0 permanent"}

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)

    result = run(mcp_server.path_explain("cr1-nl1", "2001:db8::1"))

    assert calls[0] == ["route", "-n", "get", "2001:db8::1"]
    assert result["data"]["next_hop"] == "fe80::1"
    assert result["data"]["interface"] == "vtnet0"
    assert result["data"]["route_fields"]["if_address"] == "fe80::2"


def test_freebsd_path_explain_uses_arp_for_ipv4_next_hop(monkeypatch):
    settings = _settings_with_hosts(**{"cr1-nl1": {"os_family": "freebsd", "init_system": "service", "firewall": "pf"}})
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)

    async def fake_execute(host, args, username=None, timeout_s=None, settings=SETTINGS, tool="command"):
        return {"ok": True, "stdout": "route to: 192.0.2.100\ngateway: 192.0.2.1\ninterface: vtnet0\n"}

    arp_calls = []
    ndp_calls = []

    async def fake_arp_state(host, addr=None, iface=None):
        arp_calls.append((host, addr, iface))
        return {"data": {"entries": [{"addr": addr}]}}

    async def fake_ndp_state(host, addr=None, iface=None):
        ndp_calls.append((host, addr, iface))
        return {"data": {"entries": []}}

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)
    monkeypatch.setattr(diagnostics, "arp_state", fake_arp_state)
    monkeypatch.setattr(diagnostics, "ndp_state", fake_ndp_state)

    result = run(mcp_server.path_explain("cr1-nl1", "192.0.2.100"))

    assert result["data"]["next_hop"] == "192.0.2.1"
    assert arp_calls == [("cr1-nl1", "192.0.2.1", None)]
    assert ndp_calls == []


def test_freebsd_socket_listeners_uses_sockstat(monkeypatch):
    settings = _settings_with_hosts(**{"cr1-nl1": {"os_family": "freebsd", "init_system": "service", "firewall": "pf"}})
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)
    seen = {}

    async def fake_execute(host, args, username=None, timeout_s=None, settings=SETTINGS, tool="command"):
        seen["args"] = args
        return {"ok": True, "stdout": "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\nroot node_exporter 42 3 tcp6 [::]:9100 *:*"}

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)

    result = run(mcp_server.socket_listeners("cr1-nl1"))

    assert seen["args"] == ["sockstat", "-46", "-l"]
    assert result["data"]["listeners"][0]["command"] == "node_exporter"


def test_openbsd_socket_listeners_skips_netstat_headers(monkeypatch):
    settings = _settings_with_hosts(mail={"os_family": "openbsd", "init_system": "rcctl", "firewall": "pf"})
    monkeypatch.setattr(diagnostics, "SETTINGS", settings)

    async def fake_execute(host, args, username=None, timeout_s=None, settings=SETTINGS, tool="command"):
        return {
            "ok": True,
            "stdout": (
                "Active Internet connections (including servers)\n"
                "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n"
                "tcp6       0      0  *.22                   *.*                   LISTEN\n"
            ),
        }

    monkeypatch.setattr(diagnostics, "execute_args", fake_execute)

    result = run(mcp_server.socket_listeners("mail"))

    assert len(result["data"]["listeners"]) == 1
    assert result["data"]["listeners"][0]["protocol"] == "tcp6"


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


def test_http_health_is_independent_of_mcp_session():
    app = mcp_server.build_http_app()
    route = next(route for route in app.routes if getattr(route, "path", None) == "/health")

    response = run(route.endpoint(None))

    assert response.status_code == 200
    assert json.loads(response.body) == {
        "status": "ok",
        "service": "hyrule-mcp",
        "transport": "streamable-http",
    }
