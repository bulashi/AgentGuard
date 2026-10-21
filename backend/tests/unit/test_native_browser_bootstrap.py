from __future__ import annotations

import threading

import httpx

from scripts.verify_browser_bootstrap import BootstrapBridge, browser_code, result_passed


def test_cli_code_contains_no_plaintext_credential():
    code = browser_code("http://127.0.0.1:12345/one-use", "http://127.0.0.1:8088/")
    assert "#launch_token=' + value.launch_token" in code
    assert "httpOnly" in code and "localStorage" in code
    assert "one-use" in code and "process" not in code and "require(" not in code


def test_cli_result_is_parsed_not_matched_by_whitespace():
    assert result_passed('### Result\n{"status":"PASS","token_removed":true}\n### Page')
    assert result_passed('### Result\n{"status": "PASS"}')
    assert not result_passed('### Error\nError: timed out {"status":"PASS"}')
    assert not result_passed('### Result\n{"status":"FAIL"}')


def test_bootstrap_bridge_rejects_wrong_path_then_serves_only_once():
    token = "a" * 64
    server = BootstrapBridge(token)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(
            base_url=f"http://127.0.0.1:{server.server_port}", trust_env=False
        ) as client:
            assert client.get("/wrong").status_code == 404
            assert server.consumed is False
            response = client.get(server.path)
            assert response.status_code == 200
            assert response.json() == {"launch_token": token}
            assert response.headers["cache-control"] == "no-store"
            assert server.token == ""
            assert client.get(server.path).status_code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_expired_bridge_never_releases_credential():
    server = BootstrapBridge("a" * 64)
    server.deadline = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = httpx.get(f"http://127.0.0.1:{server.server_port}{server.path}", trust_env=False)
        assert response.status_code == 404 and server.consumed is False
        assert "a" * 64 not in response.text
    finally:
        server.token = ""
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
