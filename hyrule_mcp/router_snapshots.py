from __future__ import annotations

import argparse
import asyncio
import gzip
import hashlib
import json
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from hyrule_mcp.executor import execute_raw_args

DEFAULT_ROUTERS = ["cr1-nl1", "cr1-de1", "cr1-ch1", "rtr"]
CIDR_RE = re.compile(r"^[0-9a-fA-F:.]+/\d{1,3}$")


def _command(router: str) -> list[str]:
    if router == "rtr":
        return ["vtysh", "-c", "show bgp vrf overlay ipv6 unicast json"]
    return ["vtysh", "-c", "show bgp ipv6 unicast json"]


def _snapshot_id(router: str) -> str:
    # Keep IDs <= 36 chars for the Hyrule Cloud bgp_snapshots.snapshot_id column.
    return f"bgps_{router}_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}_{secrets.token_hex(3)}"


def _write_gzip(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wb") as fh:
        fh.write(payload)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest


def _route_entries(raw: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    def walk(node: Any, prefix: str | None = None) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and CIDR_RE.match(key):
                    walk(value, key)
                elif key in {"routes", "paths"}:
                    walk(value, prefix)
                elif prefix and isinstance(value, (dict, list)):
                    walk(value, prefix)
        elif isinstance(node, list):
            for item in node:
                if prefix and isinstance(item, dict):
                    entries.append({"prefix": prefix, **_normalize_path(item)})
                else:
                    walk(item, prefix)

    walk(raw)
    return entries


def _normalize_path(path: dict[str, Any]) -> dict[str, Any]:
    return {
        "selected": bool(path.get("valid") or path.get("bestpath") or path.get("selected")),
        "aspath": path.get("path") or path.get("aspath") or path.get("asPath") or {},
        "nexthops": path.get("nexthops") or path.get("nexthop") or [],
        "peer": path.get("peer") or path.get("peerId") or path.get("neighbor"),
        "origin": path.get("origin"),
        "local_pref": path.get("locPrf") or path.get("localPref"),
        "med": path.get("metric") or path.get("med"),
    }


def _normalized_jsonl(router: str, raw: Any) -> bytes:
    lines = []
    for entry in _route_entries(raw):
        entry = {"router": router, "vrf": "overlay" if router == "rtr" else "default", **entry}
        lines.append(json.dumps(entry, sort_keys=True, separators=(",", ":")))
    return ("\n".join(lines) + ("\n" if lines else "")).encode()


async def snapshot_router(router: str, output_dir: Path, *, ingest_url: str | None, ingest_token: str | None) -> dict[str, Any]:
    result = await execute_raw_args(router, _command(router), timeout_s=180, tool="bgp_snapshot")
    if not result.get("ok"):
        return {"router": router, "ok": False, "error": result.get("sanitized_error") or result.get("stderr")}

    raw_text = result.get("stdout") or "{}"
    try:
        raw = json.loads(raw_text)
    except Exception as exc:
        return {"router": router, "ok": False, "error": f"FRR JSON parse failed: {exc}"}

    sid = _snapshot_id(router)
    created = datetime.now(UTC)
    base = output_dir / router / sid
    raw_path = base / "raw_frr_json.gz"
    normalized_path = base / "normalized_jsonl.gz"
    raw_sha = _write_gzip(raw_path, json.dumps(raw, sort_keys=True).encode())
    normalized_payload = _normalized_jsonl(router, raw)
    normalized_sha = _write_gzip(normalized_path, normalized_payload)
    metadata = {
        "snapshot_id": sid,
        "kind": "router_table",
        "source": "noc",
        "router": router,
        "asn": 215932,
        "artifact_format": "normalized_jsonl.gz",
        "artifact_path": str(normalized_path),
        "sha256": normalized_sha,
        "raw_sha256": raw_sha,
        "compressed_size_bytes": normalized_path.stat().st_size,
        "routes_normalized": normalized_payload.count(b"\n"),
        "created_at": created.isoformat(),
        "expires_at": (created + timedelta(days=7)).isoformat(),
    }
    (base / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True))

    if ingest_url and ingest_token:
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                await client.post(
                    ingest_url.rstrip("/") + "/ingest/snapshot",
                    headers={"X-Hyrule-BGP-Ingest-Token": ingest_token},
                    json=metadata,
                )
            except Exception as exc:
                metadata["ingest_error"] = str(exc)
    return {"ok": True, **metadata}


async def run(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    routers = args.routers or DEFAULT_ROUTERS
    results = [
        await snapshot_router(router, output_dir, ingest_url=args.ingest_url, ingest_token=args.ingest_token)
        for router in routers
    ]
    print(json.dumps({"results": results}, indent=2, sort_keys=True))
    return 0 if all(r.get("ok") for r in results) else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect read-only AS215932 FRR BGP table snapshots via hyrule-mcp host config.")
    parser.add_argument("--router", dest="routers", action="append", help="Router to snapshot; repeatable. Default: cr1-nl1, cr1-de1, cr1-ch1, rtr")
    parser.add_argument("--output-dir", default=os.environ.get("HYRULE_MCP_BGP_SNAPSHOT_DIR", "/var/lib/hyrule-mcp/bgp-snapshots"))
    parser.add_argument("--ingest-url", default=os.environ.get("HYRULE_BGP_INGEST_URL"))
    parser.add_argument("--ingest-token", default=os.environ.get("HYRULE_BGP_INGEST_TOKEN"))
    raise SystemExit(asyncio.run(run(parser.parse_args())))


if __name__ == "__main__":
    main()
