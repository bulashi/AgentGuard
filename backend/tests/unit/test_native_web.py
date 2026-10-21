from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from scripts import native_web
from scripts.native_web import NativeWebServer


@pytest.fixture
def web(tmp_path: Path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text('<html lang="zh"><body>AgentGuard</body></html>')
    (dist / "assets").mkdir()
    (dist / "assets/app.js").write_text('console.log("AgentGuard")')
    (dist / "assets/app.css").write_text("body { color: blue; }")
    (dist / "agentguard.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
    state = {"requests": [], "mode": "ok"}

    class Backend(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            pass

        def respond(self):
            state["requests"].append(
                {
                    "path": self.path,
                    "method": self.command,
                    "headers": dict(self.headers),
                    "body": self.rfile.read(int(self.headers.get("Content-Length", "0"))),
                }
            )
            if state["mode"] == "timeout":
                time.sleep(0.2)
                return
            if state["mode"] == "close":
                self.close_connection = True
                return
            if state["mode"] == "chunked":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n")
                return
            if state["mode"] == "empty":
                self.send_response(204)
                self.end_headers()
                return
            self.send_response(409 if state["mode"] == "conflict" else 200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Upstream", "kept")
            self.send_header("Connection", "X-Upstream-Hop, close")
            self.send_header("X-Upstream-Hop", "removed")
            if state["mode"] == "duplicate_length":
                self.send_header("Content-Length", "2")
            if state["mode"] == "mixed_framing":
                self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Length", "20" if state["mode"] == "truncated" else "2")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(b"{}")
            self.close_connection = True

        do_GET = respond
        do_HEAD = respond
        do_POST = respond
        do_PUT = respond
        do_PATCH = respond
        do_DELETE = respond
        do_OPTIONS = respond

    backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    backend.daemon_threads = True
    server = NativeWebServer(dist, 0, backend_port=backend.server_port, backend_timeout=0.08)
    threads = [
        threading.Thread(
            target=lambda item=item: item.serve_forever(poll_interval=0.01), daemon=True
        )
        for item in (backend, server)
    ]
    for thread in threads:
        thread.start()
    try:
        yield server, state
    finally:
        server.shutdown()
        backend.shutdown()
        server.server_close()
        backend.server_close()
        for thread in threads:
            thread.join(timeout=2)


def request(web, path="/", *, method="GET", body=None, headers=None):
    server, _ = web
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def raw(web, fields: bytes, body: bytes = b"", *, target: bytes = b"/api/echo", method=b"POST"):
    server, _ = web
    with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as connection:
        connection.sendall(
            method
            + b" "
            + target
            + b" HTTP/1.1\r\nHost: 127.0.0.1:"
            + str(server.server_port).encode()
            + b"\r\n"
            + fields
            + b"\r\n"
            + body
        )
        connection.shutdown(socket.SHUT_WR)
        received = bytearray()
        while data := connection.recv(65536):
            received.extend(data)
    return int(received.split(b" ", 2)[1]), bytes(received)


def test_static_server_is_loopback_only_and_health_is_not_an_api_probe(web):
    server, state = web
    assert server.server_address[0] == "127.0.0.1"
    status, headers, body = request(web, "/healthz")
    assert status == 200
    assert json.loads(body) == {"status": "ok", "service": "native-web", "static_ready": True}
    assert headers["Cache-Control"] == "no-store"
    assert not state["requests"]


@pytest.mark.parametrize(
    ("path", "mime"),
    [
        ("/", "text/html"),
        ("/assets/app.js", "text/javascript"),
        ("/assets/app.css", "text/css"),
        ("/agentguard.svg", "image/svg+xml"),
    ],
)
def test_static_assets_mime_lengths_and_security_headers(web, path, mime):
    status, headers, body = request(web, path)
    assert status == 200
    assert headers["Content-Type"].startswith(mime)
    assert int(headers["Content-Length"]) == len(body)
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Connection"] == "close"
    assert "Python" not in headers["Server"]


@pytest.mark.parametrize("path", ["/", "/healthz", "/assets/app.js", "/api/echo"])
def test_head_is_bodyless_with_correct_content_length(web, path):
    get = request(web, path)
    head = request(web, path, method="HEAD")
    assert head[0] == get[0] == 200
    assert head[1]["Content-Length"] == str(len(get[2]))
    assert head[2] == b""


@pytest.mark.parametrize("prefix", ["", "W/", "star"])
def test_static_conditional_get(web, prefix):
    _, headers, _ = request(web, "/assets/app.js")
    value = "*" if prefix == "star" else prefix + headers["ETag"]
    status, output, body = request(web, "/assets/app.js", headers={"If-None-Match": value})
    assert status == 304
    assert body == b""
    assert "Content-Length" not in output


@pytest.mark.parametrize(
    ("path", "accept", "status"),
    [
        ("/overview", "text/html", 200),
        ("/overview", "application/json", 404),
        ("/missing.js", "text/html", 404),
        ("/assets/missing", "text/html", 404),
        ("/assets/", "text/html", 404),
        ("/apix/echo", "application/json", 404),
    ],
)
def test_spa_fallback_is_not_used_for_missing_assets_or_api_like_paths(web, path, accept, status):
    actual, _, _ = request(web, path, headers={"Accept": accept})
    assert actual == status
    assert not web[1]["requests"]


@pytest.mark.parametrize(
    "path",
    [
        "/../config.json",
        "/%2e%2e/config.json",
        "/assets/../index.html",
        "/%252e%252e/config.json",
        "/assets%5c..%5cconfig.json",
        "/.env",
        "/.native/config.json",
        "/nul",
        "/con.txt",
        "/assets/app.js:secret",
        "/file.",
        "/file%20",
    ],
)
def test_unsafe_static_paths_cannot_escape_the_build(web, path):
    assert request(web, path)[0] == 403
    assert not web[1]["requests"]


@pytest.mark.parametrize(
    "target",
    [
        b"http://outside.invalid/api",
        b"//outside.invalid/api",
        b"/bad%G0",
        b"/%ff",
        b"/bad%00",
        b"/bad#fragment",
    ],
)
def test_invalid_request_targets_are_not_forwarded(web, target):
    status, _ = raw(web, b"Content-Length: 0\r\n", target=target)
    assert status == 400
    assert not web[1]["requests"]


@pytest.mark.parametrize(
    "host", ["outside.invalid", "127.0.0.1:1", "localhost:8090", "localhost@evil.invalid"]
)
def test_dns_rebinding_and_wrong_port_hosts_are_rejected(web, host):
    assert request(web, headers={"Host": host})[0] == 403


def test_localhost_host_and_same_origin_are_preserved_exactly(web):
    server, state = web
    host = f"localhost:{server.server_port}"
    payload = b'{"api_key":"TEST_ONLY_PRIVATE_VALUE"}'
    status, _, _ = request(
        web,
        "/api/model-configurations/one",
        method="PUT",
        body=payload,
        headers={
            "Host": host,
            "Origin": "http://" + host,
            "Content-Type": "application/json",
            "X-AgentGuard-Configuration": "1",
        },
    )
    assert status == 200
    saved = state["requests"][0]
    assert saved["headers"]["Host"] == host
    assert saved["headers"]["Origin"] == "http://" + host
    assert saved["headers"]["X-AgentGuard-Configuration"] == "1"
    assert saved["body"] == payload


def test_cross_origin_request_is_rejected_before_bff(web):
    assert request(web, "/api/echo", headers={"Origin": "http://outside.invalid"})[0] == 403
    assert not web[1]["requests"]


@pytest.mark.parametrize(
    ("headers", "body", "status"),
    [
        (b"Content-Length: -1\r\n", b"", 400),
        (b"Content-Length: 1.0\r\n", b"", 400),
        (b"Content-Length: 0\r\nContent-Length: 0\r\n", b"", 400),
        (b"Host: outside.invalid\r\nContent-Length: 0\r\n", b"", 400),
        (b"Content-Length: 0\r\nOrigin: null\r\nOrigin: null\r\n", b"", 400),
        (b"Transfer-Encoding: chunked\r\n", b"0\r\n\r\n", 400),
        (b"Content-Length: 0\r\nConnection: Origin\r\n", b"", 400),
        (b"Content-Length: 0\r\nConnection: X-AgentGuard-Configuration\r\n", b"", 400),
        (b"Content-Length: 9\r\n", b"abc", 400),
        (b"", b"", 411),
        (b"Content-Length: 0\r\nExpect: arbitrary\r\n", b"", 417),
        (f"Content-Length: {native_web.MAX_REQUEST_BYTES + 1}\r\n".encode(), b"", 413),
    ],
)
def test_request_framing_and_body_limits(web, headers, body, status):
    assert raw(web, headers, body)[0] == status
    assert not web[1]["requests"]


def test_get_body_is_rejected(web):
    assert raw(web, b"Content-Length: 1\r\n", b"x", method=b"GET")[0] == 400


def test_hop_by_hop_headers_are_not_forwarded_or_returned(web):
    status, headers, _ = request(
        web,
        "/api/echo?query=%E4%B8%AD%E6%96%87",
        headers={"Connection": "X-Client-Hop", "X-Client-Hop": "removed"},
    )
    assert status == 200
    assert "X-Client-Hop" not in web[1]["requests"][0]["headers"]
    assert "X-Upstream-Hop" not in headers
    assert headers["X-Upstream"] == "kept"
    assert web[1]["requests"][0]["path"] == "/api/echo?query=%E4%B8%AD%E6%96%87"


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"])
def test_api_methods_are_preserved(web, method):
    assert (
        request(
            web,
            "/api/echo",
            method=method,
            body=b"" if method in {"POST", "PATCH", "PUT"} else None,
        )[0]
        == 200
    )
    assert web[1]["requests"][0]["method"] == method


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("conflict", 409),
        ("empty", 204),
        ("chunked", 200),
        ("close", 502),
        ("duplicate_length", 502),
        ("mixed_framing", 502),
        ("truncated", 502),
        ("timeout", 504),
    ],
)
def test_upstream_statuses_framing_timeout_and_failure_are_not_successes(web, mode, expected):
    web[1]["mode"] = mode
    status, headers, body = request(web, "/api/echo")
    assert status == expected
    if mode == "chunked":
        assert body == b"onetwo"
        assert headers["Content-Length"] == "6"
        assert "Transfer-Encoding" not in headers
    if mode == "empty":
        assert "Content-Length" not in headers and body == b""


def test_declared_and_streamed_response_limits(web, monkeypatch):
    monkeypatch.setattr(native_web, "MAX_RESPONSE_BYTES", 1)
    assert request(web, "/api/echo")[0] == 502
    web[1]["mode"] = "chunked"
    assert request(web, "/api/echo")[0] == 502


def test_static_file_limit(web, monkeypatch):
    monkeypatch.setattr(native_web, "MAX_STATIC_BYTES", 1)
    assert request(web, "/assets/app.js")[0] == 413


def test_header_size_limit(web):
    assert request(web, headers={"X-Large": "a" * (native_web.MAX_HEADER_BYTES + 1)})[0] == 431


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"])
def test_static_mutation_and_unsafe_methods_are_not_available(web, method):
    assert request(web, "/", method=method, body=b"")[0] == 405


def test_static_options_is_bodyless_and_limited(web):
    status, headers, body = request(web, method="OPTIONS")
    assert status == 204 and body == b""
    assert headers["Allow"] == "GET, HEAD, OPTIONS"


def test_symlinks_cannot_expose_files_or_trigger_spa_fallback(web, tmp_path):
    outside = tmp_path / "outside.html"
    outside.write_text("NOT_PUBLIC")
    link = web[0].dist / "linked.html"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("this test user cannot create filesystem symlinks")
    assert request(web, "/linked.html")[0] == 403
    outside.unlink()
    assert request(web, "/linked.html")[0] == 403


def test_missing_build_is_rejected(tmp_path):
    with pytest.raises((ValueError, FileNotFoundError)):
        NativeWebServer(tmp_path / "missing", 0)
    with pytest.raises(ValueError, match=r"index\.html"):
        NativeWebServer(tmp_path, 0)
