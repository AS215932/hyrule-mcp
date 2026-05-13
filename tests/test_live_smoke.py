import os
from urllib.error import URLError
from urllib.request import urlopen

import pytest


pytestmark = pytest.mark.skipif(
    os.getenv("HYRULE_MCP_LIVE_SMOKE") != "1",
    reason="Set HYRULE_MCP_LIVE_SMOKE=1 to run read-only live MCP smoke tests.",
)


def _get_json(path: str) -> dict:
    base_url = os.getenv("HYRULE_MCP_LIVE_BASE_URL", "http://127.0.0.1:8765")
    try:
        with urlopen(f"{base_url.rstrip('/')}{path}", timeout=10) as response:
            assert response.status == 200
            import json

            return json.loads(response.read().decode())
    except URLError as exc:
        pytest.fail(f"live MCP smoke endpoint unavailable: {exc}")


def test_live_mcp_daemon_health():
    payload = _get_json("/health")
    assert payload["status"] == "ok"
