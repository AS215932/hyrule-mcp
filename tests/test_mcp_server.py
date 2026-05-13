from types import SimpleNamespace

import mcp_server


def _response(payload):
    return SimpleNamespace(
        json=lambda: payload,
        raise_for_status=lambda: None,
    )


def test_resolve_uses_host_map(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "_HOSTS_MAP",
        {"noc": {"address": "::1", "user": "noc-agent", "key": "/tmp/key"}},
    )
    assert mcp_server._resolve("noc") == ("::1", "noc-agent", "/tmp/key")


def test_execute_short_circuits_local(monkeypatch):
    monkeypatch.setattr(mcp_server, "_LOCAL_ALIASES", {"noc"})
    monkeypatch.setattr(mcp_server, "_resolve", lambda host: ("noc", "svag", None))
    monkeypatch.setattr(
        mcp_server,
        "_run_local",
        lambda command, timeout_s=30: {"stdout": "ok", "stderr": "", "exit_code": 0, "duration_ms": 1, "ssh_error": None, "transport": "local"},
    )

    result = mcp_server._execute("noc", "hostname")

    assert result["transport"] == "local"
    assert result["stdout"] == "ok"


def test_ssh_escape_hatch_blocks_mutative_commands():
    result = mcp_server.ssh_run_command("noc", "systemctl restart noc-agent.service")
    assert result["transport"] == "policy"
    assert "rejected" in result["stderr"].lower()


def test_wrapper_tools_construct_commands(monkeypatch):
    calls = []

    def fake_execute(host, command, username=None, timeout_s=30):
        calls.append((host, command))
        return {"stdout": "", "stderr": "", "exit_code": 0, "duration_ms": 1, "ssh_error": None, "transport": "ssh"}

    monkeypatch.setattr(mcp_server, "_execute", fake_execute)

    mcp_server.frr_vtysh_cmd("rtr", "show bgp summary")
    mcp_server.net_ping("mon", "2001:db8::1", count=4)
    mcp_server.os_journalctl("noc", "noc-agent.service", lines=25)
    mcp_server.wg_show("vpn")
    mcp_server.os_systemd_status("noc", "noc-agent.service")
    mcp_server.os_rcctl_check("mail", "smtpd")
    mcp_server.dmesg_tail("noc", lines=20)
    mcp_server.dns_dig("dns", "as215932.net", "AAAA", nameserver="::1")
    mcp_server.knot_zone_status("dns")

    assert "vtysh -c" in calls[0][1]
    assert "ping -c 4" in calls[1][1]
    assert "journalctl -u" in calls[2][1]
    assert calls[3][1] == "wg show"
    assert "systemctl status" in calls[4][1]
    assert "rcctl check" in calls[5][1]
    assert "dmesg | tail -n 20" in calls[6][1]
    assert "dig +short" in calls[7][1]
    assert calls[8][1] == "knotc zone-status"


def test_prometheus_query_returns_compact_timestamped_rows(monkeypatch):
    monkeypatch.setattr(
        mcp_server.requests,
        "get",
        lambda *args, **kwargs: _response(
            {
                "status": "success",
                "data": {"result": [{"metric": {"job": "node"}, "value": [1710000000, "1"]}]},
            }
        ),
    )

    result = mcp_server.prometheus_query("up")

    assert result["status"] == "success"
    assert result["result"][0]["metric"]["job"] == "node"
    assert result["result"][0]["ts_iso"].endswith("+00:00")


def test_icinga_host_state_uses_rest_payload(monkeypatch):
    responses = iter(
        [
            _response({"results": [{"name": "noc", "attrs": {"state": 0}}]}),
            _response({"results": [{"name": "noc!disk", "attrs": {"name": "disk", "state": 2, "last_check": 1, "last_state_change": 2, "last_check_result": {"output": "full"}}}]}),
        ]
    )
    monkeypatch.setattr(mcp_server.requests, "get", lambda *args, **kwargs: next(responses))

    result = mcp_server.icinga_get_host_state("noc")

    assert result["host"] == "noc"
    assert result["services"][0]["name"] == "disk"
    assert result["services"][0]["output"] == "full"


def test_icinga_acknowledge_alert_posts_rest_payload(monkeypatch):
    seen = {}

    def fake_post(*args, **kwargs):
        seen.update(kwargs)
        return _response({"results": [{"code": 200}]})

    monkeypatch.setattr(mcp_server.requests, "post", fake_post)

    result = mcp_server.icinga_acknowledge_alert("noc", "disk", "svag", "ack")

    assert result["status"] == "ok"
    assert seen["json"]["author"] == "svag"
    assert "Service" == seen["params"]["type"]


def test_tcpdump_capture_enforces_resource_caps(monkeypatch):
    seen = {}

    def fake_execute(host, command, username=None, timeout_s=30):
        seen["command"] = command
        seen["timeout"] = timeout_s
        return {"stdout": "2026-05-13 packet", "stderr": "", "exit_code": 0, "duration_ms": 1, "ssh_error": None, "transport": "ssh"}

    monkeypatch.setattr(mcp_server, "_execute", fake_execute)

    result = mcp_server.tcpdump_capture("rtr", "enX4", "icmp6", duration_s=999, count=999, snaplen=9999)

    assert result["limits"]["duration_s"] == mcp_server.TCPDUMP_MAX_DURATION_S
    assert result["limits"]["count"] == mcp_server.TCPDUMP_MAX_COUNT
    assert result["limits"]["snaplen"] == mcp_server.TCPDUMP_MAX_SNAPLEN
    assert result["packets"]


def test_multi_source_probe_caps_sources(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "net_ping",
        lambda source, target, count=4: {"stdout": "4 packets transmitted, 4 received, 0% packet loss", "stderr": "", "exit_code": 0, "duration_ms": 1, "ssh_error": None, "transport": "ssh"},
    )
    sources = [f"host-{idx}" for idx in range(mcp_server.MULTI_PROBE_MAX_SOURCES + 3)]

    result = mcp_server.multi_source_probe("2001:db8::1", sources)

    assert len(result["results"]) == mcp_server.MULTI_PROBE_MAX_SOURCES


def test_firewall_and_neighbor_helpers_shape_structured_results(monkeypatch):
    outputs = iter(
        [
            {"stdout": "@0 pass in quick", "stderr": "", "exit_code": 0, "duration_ms": 1, "ssh_error": None, "transport": "ssh"},
            {"stdout": "bogons6", "stderr": "", "exit_code": 0, "duration_ms": 1, "ssh_error": None, "transport": "ssh"},
            {"stdout": '{"nftables":[]}', "stderr": "", "exit_code": 0, "duration_ms": 1, "ssh_error": None, "transport": "ssh"},
            {"stdout": "reloaded", "stderr": "", "exit_code": 0, "duration_ms": 1, "ssh_error": None, "transport": "ssh"},
            {"stdout": "fe80::1 dev enX0 lladdr aa:bb:cc REACHABLE", "stderr": "", "exit_code": 0, "duration_ms": 1, "ssh_error": None, "transport": "ssh"},
        ]
    )
    monkeypatch.setattr(mcp_server, "_execute", lambda *args, **kwargs: next(outputs))

    firewall = mcp_server.firewall_state("rtr")
    ndp = mcp_server.ndp_state("rtr", addr="fe80::1")

    assert firewall["pf"]["rules"]
    assert firewall["nft"]["ruleset_json"] == {"nftables": []}
    assert ndp["entries"][0]["state"] == "REACHABLE"
