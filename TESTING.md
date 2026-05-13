# Testing

Run the hermetic MCP characterization and regression suite with:

```bash
uv run --group dev python -m pytest -q
```

Read-only live smoke coverage is opt-in:

```bash
HYRULE_MCP_LIVE_SMOKE=1 uv run --group dev python -m pytest -q tests/test_live_smoke.py
```

The normal suite uses mocks/fakes only and never mutates infrastructure.
