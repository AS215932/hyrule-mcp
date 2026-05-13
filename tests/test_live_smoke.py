import os

import pytest


pytestmark = pytest.mark.skipif(
    os.getenv("HYRULE_MCP_LIVE_SMOKE") != "1",
    reason="Set HYRULE_MCP_LIVE_SMOKE=1 to run read-only live MCP smoke tests.",
)


def test_live_smoke_marker_is_explicit():
    assert os.getenv("HYRULE_MCP_LIVE_SMOKE") == "1"
