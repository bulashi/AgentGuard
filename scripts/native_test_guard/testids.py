from __future__ import annotations


def pytest_make_parametrize_id(config, val, argname):
    """Keep pytest's Windows PYTEST_CURRENT_TEST value bounded for large inputs."""
    if isinstance(val, (bytes, bytearray)) and len(val) > 256:
        return f"{argname}-bytes-{len(val)}"
    if isinstance(val, str) and len(val) > 256:
        return f"{argname}-text-{len(val)}"
    return None
