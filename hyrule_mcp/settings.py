from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class HostProfile:
    name: str
    address: str
    user: str
    key: str | None
    os_family: str = "linux"
    init_system: str = "systemd"
    firewall: str | None = "nft"
    aliases: tuple[str, ...] = ()

    @property
    def supports_systemd(self) -> bool:
        return self.init_system == "systemd" or self.os_family == "linux"

    @property
    def supports_rcctl(self) -> bool:
        return self.init_system == "rcctl" or self.os_family == "openbsd"

    @property
    def supports_service(self) -> bool:
        return self.init_system == "service" or self.os_family == "freebsd"

    @property
    def supports_pf(self) -> bool:
        return self.firewall == "pf" or self.os_family in {"openbsd", "freebsd"}

    @property
    def supports_nft(self) -> bool:
        return self.firewall == "nft" or self.os_family == "linux"


@dataclass(frozen=True)
class MCPSettings:
    prometheus_url: str = "http://[2a0c:b641:b50:2::50]:9090"
    icinga_api_base: str = "https://[2a0c:b641:b50:2::50]:5665"
    icinga_api_user: str = "root"
    icinga_api_password: str = ""
    icinga_verify_tls: bool = False
    enable_actions: bool = False
    action_signing_secret: str = ""
    action_allowed_hosts: set[str] = field(default_factory=set)
    action_allowed_services: set[str] = field(default_factory=set)
    # Acknowledging an Icinga problem is far lower-risk than a mutating action
    # (reversible, expiring, only mutes notifications), so acks use their own,
    # broader allowlist. Default {'*'} = any monitored host/service.
    ack_allowed_hosts: set[str] = field(default_factory=lambda: {"*"})
    ack_allowed_services: set[str] = field(default_factory=lambda: {"*"})
    command_timeout_s: int = 30
    raw_output_line_limit: int = 100
    raw_output_byte_limit: int = 16_384
    tcpdump_max_count: int = 100
    tcpdump_max_duration_s: int = 20
    tcpdump_max_snaplen: int = 512
    dns_burst_max_count: int = 20
    dns_burst_min_interval_ms: int = 50
    multi_probe_max_sources: int = 8
    ecmp_max_flows: int = 32
    ssh_max_concurrency: int = 8
    hosts: dict[str, HostProfile] = field(default_factory=dict)
    local_aliases: set[str] = field(default_factory=set)
    default_user: str = "root"
    default_key: str | None = None

    @classmethod
    def from_env(cls) -> "MCPSettings":
        hosts_cfg = _load_hosts_config(os.environ.get("HYRULE_MCP_HOSTS_CONFIG", "/etc/hyrule-mcp/hosts.yml"))
        default_user = hosts_cfg.get("default_user", "root")
        default_key = hosts_cfg.get("ssh_key")
        hosts = {
            name: HostProfile(
                name=name,
                address=str(entry.get("address", name)),
                user=str(entry.get("user", default_user)),
                key=entry.get("key", default_key),
                os_family=str(entry.get("os_family", entry.get("os", "linux"))).lower(),
                init_system=str(entry.get("init_system", _default_init_system(entry))).lower(),
                firewall=entry.get("firewall", "pf" if str(entry.get("os_family", entry.get("os", ""))).lower() in {"openbsd", "freebsd"} else "nft"),
                aliases=tuple(str(alias) for alias in (entry.get("aliases") or []) if str(alias)),
            )
            for name, entry in (hosts_cfg.get("hosts", {}) or {}).items()
            if isinstance(entry, dict)
        }
        local_aliases = {
            item.strip()
            for item in os.getenv("HYRULE_MCP_LOCAL_ALIASES", "noc,localhost,127.0.0.1,::1").split(",")
            if item.strip()
        }
        local_aliases.add(socket.gethostname())
        return cls(
            prometheus_url=os.getenv("PROMETHEUS_URL", cls.prometheus_url),
            icinga_api_base=os.getenv("ICINGA_API_BASE", cls.icinga_api_base),
            icinga_api_user=os.getenv("ICINGA_API_USER", cls.icinga_api_user),
            icinga_api_password=os.getenv("ICINGA_API_PASSWORD", ""),
            icinga_verify_tls=os.getenv("ICINGA_VERIFY_TLS", "0") == "1",
            enable_actions=os.getenv("HYRULE_MCP_ENABLE_ACTIONS", "0") == "1",
            action_signing_secret=os.getenv("HYRULE_MCP_ACTION_SIGNING_SECRET", os.getenv("NOC_APPROVAL_SIGNING_SECRET", "")),
            action_allowed_hosts=_csv_set(os.getenv("HYRULE_MCP_ACTION_ALLOWED_HOSTS", "")),
            action_allowed_services=_csv_set(os.getenv("HYRULE_MCP_ACTION_ALLOWED_SERVICES", "")),
            ack_allowed_hosts=_csv_set(os.getenv("HYRULE_MCP_ACK_ALLOWED_HOSTS", "*")),
            ack_allowed_services=_csv_set(os.getenv("HYRULE_MCP_ACK_ALLOWED_SERVICES", "*")),
            command_timeout_s=int(os.getenv("HYRULE_MCP_COMMAND_TIMEOUT_S", str(cls.command_timeout_s))),
            raw_output_line_limit=int(os.getenv("HYRULE_MCP_RAW_OUTPUT_LINE_LIMIT", str(cls.raw_output_line_limit))),
            raw_output_byte_limit=int(os.getenv("HYRULE_MCP_RAW_OUTPUT_BYTE_LIMIT", str(cls.raw_output_byte_limit))),
            tcpdump_max_count=int(os.getenv("HYRULE_MCP_TCPDUMP_MAX_COUNT", str(cls.tcpdump_max_count))),
            tcpdump_max_duration_s=int(os.getenv("HYRULE_MCP_TCPDUMP_MAX_DURATION_S", str(cls.tcpdump_max_duration_s))),
            tcpdump_max_snaplen=int(os.getenv("HYRULE_MCP_TCPDUMP_MAX_SNAPLEN", str(cls.tcpdump_max_snaplen))),
            dns_burst_max_count=int(os.getenv("HYRULE_MCP_DNS_BURST_MAX_COUNT", str(cls.dns_burst_max_count))),
            dns_burst_min_interval_ms=int(os.getenv("HYRULE_MCP_DNS_BURST_MIN_INTERVAL_MS", str(cls.dns_burst_min_interval_ms))),
            multi_probe_max_sources=int(os.getenv("HYRULE_MCP_MULTI_PROBE_MAX_SOURCES", str(cls.multi_probe_max_sources))),
            ecmp_max_flows=int(os.getenv("HYRULE_MCP_ECMP_MAX_FLOWS", str(cls.ecmp_max_flows))),
            ssh_max_concurrency=int(os.getenv("HYRULE_MCP_SSH_MAX_CONCURRENCY", str(cls.ssh_max_concurrency))),
            hosts=hosts,
            local_aliases=local_aliases,
            default_user=default_user,
            default_key=default_key,
        )

    def resolve(self, host: str) -> HostProfile:
        if host in self.hosts:
            return self.hosts[host]
        for profile in self.hosts.values():
            if host in profile.aliases:
                return profile
        return HostProfile(
            name=host,
            address=host,
            user=self.default_user,
            key=self.default_key,
        )


def _load_hosts_config(path: str) -> dict[str, Any]:
    try:
        with Path(path).open() as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _default_init_system(entry: dict[str, Any]) -> str:
    os_family = str(entry.get("os_family", entry.get("os", "linux"))).lower()
    if os_family == "openbsd":
        return "rcctl"
    if os_family == "freebsd":
        return "service"
    return "systemd"


def _csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


SETTINGS = MCPSettings.from_env()
