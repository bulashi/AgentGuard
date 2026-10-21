from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import mimetypes
import re
import stat
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
API_PORT = 8090
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_HEADER_BYTES = 32 * 1024
MAX_STATIC_BYTES = 16 * 1024 * 1024
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
SECURITY_HEADERS = {
    "host",
    "content-length",
    "content-type",
    "origin",
    "x-agentguard-configuration",
    "authorization",
}
STATIC_SUFFIXES = {
    ".html",
    ".css",
    ".js",
    ".mjs",
    ".json",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".avif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".wasm",
    ".txt",
}
RESERVED_NAMES = {"con", "prn", "aux", "nul"} | {
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)
}


def is_link(path: Path) -> bool:
    details = path.lstat()
    return stat.S_ISLNK(details.st_mode) or bool(
        getattr(details, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def header_valid(name: str, value: str) -> bool:
    return bool(HEADER_NAME.fullmatch(name)) and not any(
        (ord(character) < 32 and character != "\t") or ord(character) == 127 for character in value
    )


def connection_headers(headers: list[tuple[str, str]]) -> set[str]:
    return HOP_HEADERS | {
        token.strip().lower()
        for name, value in headers
        if name.lower() == "connection"
        for token in value.split(",")
        if token.strip()
    }


class NativeWebServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(
        self,
        dist: Path,
        port: int = 8088,
        *,
        backend_port: int = API_PORT,
        backend_timeout: float = 330,
    ) -> None:
        if is_link(dist) or not dist.is_dir():
            raise ValueError("the static build directory must be a regular directory")
        self.dist = dist.resolve()
        index = self.dist / "index.html"
        if not index.is_file() or is_link(index):
            raise ValueError("frontend/dist/index.html is missing or unsafe; build the frontend")
        if not 0 <= port <= 65535 or not 1 <= backend_port <= 65535:
            raise ValueError("invalid local port")
        self.backend_port = backend_port
        self.backend_timeout = backend_timeout
        super().__init__(("127.0.0.1", port), NativeWebHandler)


class NativeWebHandler(BaseHTTPRequestHandler):
    server: NativeWebServer
    protocol_version = "HTTP/1.1"
    server_version = "AgentGuardWeb/1.0"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format: str, *args: object) -> None:
        # URLs, request bodies and configuration headers may contain private data.
        pass

    def _reply(
        self,
        status: int,
        body: bytes = b"",
        headers: list[tuple[str, str]] | None = None,
        *,
        length: int | None = None,
    ) -> None:
        self.close_connection = True
        self.send_response(status)
        for name, value in headers or []:
            self.send_header(name, value)
        if status not in {204, 304} and not 100 <= status < 200:
            self.send_header("Content-Length", str(len(body) if length is None else length))
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.end_headers()
        if self.command != "HEAD" and status not in {204, 304}:
            self.wfile.write(body)

    def _error(self, status: int, code: str) -> None:
        body = json.dumps({"reason_code": code, "message": HTTPStatus(status).phrase}).encode()
        self._reply(
            status, body, [("Content-Type", "application/json"), ("Cache-Control", "no-store")]
        )

    def _validate(self) -> bool:
        entries = list(self.headers.raw_items())
        names = [name.lower() for name, _ in entries]
        if len(names) != len(set(names)) or not all(header_valid(*item) for item in entries):
            self._error(400, "INVALID_HEADERS")
            return False
        if sum(len(name) + len(value) + 4 for name, value in entries) > MAX_HEADER_BYTES:
            self._error(431, "HEADERS_TOO_LARGE")
            return False
        if "transfer-encoding" in names or "upgrade" in names:
            self._error(400, "UNSUPPORTED_REQUEST_FRAMING")
            return False
        if (connection_headers(entries) - HOP_HEADERS) & SECURITY_HEADERS:
            self._error(400, "INVALID_CONNECTION_HEADERS")
            return False
        host = self.headers.get("Host", "")
        allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        if self.server.server_port == 80:
            allowed |= {"127.0.0.1", "localhost"}
        if host.lower() not in allowed:
            self._error(403, "LOCAL_HOST_REQUIRED")
            return False
        origin = self.headers.get("Origin")
        if origin and origin.lower() != "http://" + host.lower():
            self._error(403, "CROSS_ORIGIN_DENIED")
            return False
        if self.headers.get("Expect", "").lower() not in {"", "100-continue"}:
            self._error(417, "UNSUPPORTED_EXPECTATION")
            return False
        length = self.headers.get("Content-Length", "0").strip()
        if not re.fullmatch(r"[0-9]{1,10}", length):
            self._error(400, "INVALID_CONTENT_LENGTH")
            return False
        self.request_length = int(length)
        if self.request_length > MAX_REQUEST_BYTES:
            self._error(413, "REQUEST_TOO_LARGE")
            return False
        if self.command in {"POST", "PUT", "PATCH"} and "content-length" not in names:
            self._error(411, "CONTENT_LENGTH_REQUIRED")
            return False
        if self.command in {"GET", "HEAD"} and self.request_length:
            self._error(400, "UNEXPECTED_REQUEST_BODY")
            return False
        return True

    def handle_expect_100(self) -> bool:
        if not self._validate():
            return False
        self.send_response_only(100)
        self.end_headers()
        return True

    def _target(self) -> tuple[str, list[str]] | None:
        # BaseHTTPRequestHandler normalizes leading // before dispatch; inspect the wire target.
        target = self.requestline.split()[1]
        try:
            if (
                not target.startswith("/")
                or target.startswith("//")
                or "#" in target
                or any(ord(character) <= 32 or ord(character) > 126 for character in target)
                or re.search(r"%(?![0-9a-fA-F]{2})", target)
            ):
                raise ValueError
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc:
                raise ValueError
            decoded = unquote(parsed.path, encoding="utf-8", errors="strict")
            if any(ord(character) < 32 or ord(character) == 127 for character in decoded):
                raise ValueError
            segments = decoded.removeprefix("/").split("/")
            if "\\" in decoded or "%" in decoded or any(part in {".", ".."} for part in segments):
                self._error(403, "UNSAFE_PATH")
                return None
            return decoded, segments
        except (ValueError, UnicodeError):
            self._error(400, "INVALID_REQUEST_TARGET")
            return None

    def _proxy(self) -> None:
        try:
            body = self.rfile.read(self.request_length)
        except TimeoutError:
            self._error(408, "REQUEST_BODY_TIMEOUT")
            return
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.server.backend_port,
            timeout=self.server.backend_timeout,
        )
        try:
            if len(body) != self.request_length:
                self._error(400, "TRUNCATED_REQUEST_BODY")
                return
            entries = list(self.headers.raw_items())
            excluded = connection_headers(entries) | {"content-length"}
            forwarded = {name: value for name, value in entries if name.lower() not in excluded}
            forwarded["Content-Length"] = str(len(body))
            forwarded["Connection"] = "close"
            # Preserve the browser's Host and Origin for the BFF's same-origin guard.
            connection.request(self.command, self.path, body=body, headers=forwarded)
            response = connection.getresponse()
            headers = response.getheaders()
            if (
                response.status < 200
                or not all(header_valid(*item) for item in headers)
                or sum(len(name) + len(value) + 4 for name, value in headers) > 65536
            ):
                raise ValueError("invalid upstream response")
            lengths = [value.strip() for name, value in headers if name.lower() == "content-length"]
            transfer = [
                value.lower().strip()
                for name, value in headers
                if name.lower() == "transfer-encoding"
            ]
            if (
                len(lengths) > 1
                or len(transfer) > 1
                or (lengths and transfer)
                or (transfer and transfer != ["chunked"])
            ):
                raise ValueError("ambiguous upstream response")
            declared = None
            if lengths:
                if not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
                    raise ValueError("invalid upstream length")
                declared = int(lengths[0])
                if declared > MAX_RESPONSE_BYTES:
                    raise ValueError("upstream response is too large")
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise ValueError("upstream response is too large")
            if (
                declared is not None
                and self.command != "HEAD"
                and response.status not in {204, 304}
                and len(payload) != declared
            ):
                raise ValueError("truncated upstream response")
            excluded = connection_headers(headers) | {
                "server",
                "date",
                "content-length",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
            }
            output = [(name, value) for name, value in headers if name.lower() not in excluded]
            self._reply(
                response.status,
                payload,
                output,
                length=declared if self.command == "HEAD" else None,
            )
        except TimeoutError:
            self._error(504, "API_TIMEOUT")
        except (OSError, http.client.HTTPException, ValueError):
            self._error(502, "API_UNAVAILABLE")
        finally:
            connection.close()

    def _static(self, decoded: str, segments: list[str]) -> None:
        if self.command == "OPTIONS":
            self._reply(204, headers=[("Allow", "GET, HEAD, OPTIONS")])
            return
        if self.command not in {"GET", "HEAD"}:
            self._reply(405, headers=[("Allow", "GET, HEAD, OPTIONS")])
            return
        for part in segments:
            if (
                part.startswith(".")
                or part.endswith((".", " "))
                or any(character in '<>:"\\|?*' for character in part)
                or part.split(".", 1)[0].lower() in RESERVED_NAMES
            ):
                self._error(403, "UNSAFE_STATIC_PATH")
                return
        candidate = self.server.dist
        try:
            for part in segments:
                if part:
                    candidate /= part
                    if (candidate.exists() or candidate.is_symlink()) and is_link(candidate):
                        self._error(403, "UNSAFE_STATIC_PATH")
                        return
            if decoded == "/":
                candidate = self.server.dist / "index.html"
            elif not candidate.exists():
                if (
                    not Path(segments[-1]).suffix
                    and segments[0] != "assets"
                    and "text/html" in self.headers.get("Accept", "")
                ):
                    candidate = self.server.dist / "index.html"
                else:
                    self._error(404, "STATIC_NOT_FOUND")
                    return
            if (
                not candidate.resolve().is_relative_to(self.server.dist)
                or is_link(candidate)
                or not candidate.is_file()
                or candidate.suffix.lower() not in STATIC_SUFFIXES
            ):
                self._error(404, "STATIC_NOT_FOUND")
                return
            with candidate.open("rb") as source:
                payload = source.read(MAX_STATIC_BYTES + 1)
            if len(payload) > MAX_STATIC_BYTES:
                self._error(413, "STATIC_TOO_LARGE")
                return
        except OSError:
            self._error(404, "STATIC_NOT_FOUND")
            return
        etag = '"' + hashlib.sha256(payload).hexdigest() + '"'
        suffix = candidate.suffix.lower()
        cache = "no-store" if suffix == ".html" else "no-cache"
        headers = [("ETag", etag), ("Cache-Control", cache)]
        matches = [
            part.strip().removeprefix("W/")
            for part in self.headers.get("If-None-Match", "").split(",")
        ]
        if etag in matches or "*" in matches:
            self._reply(304, headers=headers)
            return
        content_type = {
            ".js": "text/javascript",
            ".mjs": "text/javascript",
            ".css": "text/css",
            ".svg": "image/svg+xml",
        }.get(suffix)
        content_type = (
            content_type or mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        )
        if content_type.startswith("text/") or content_type in {
            "application/json",
            "image/svg+xml",
        }:
            content_type += "; charset=utf-8"
        headers.append(("Content-Type", content_type))
        if suffix == ".html":
            headers.append(
                (
                    "Content-Security-Policy",
                    "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
                )
            )
        self._reply(200, payload, headers)

    def _handle(self) -> None:
        if not self._validate():
            return
        target = self._target()
        if target is None:
            return
        decoded, segments = target
        if decoded == "/healthz" and self.command in {"GET", "HEAD"}:
            body = b'{"status":"ok","service":"native-web","static_ready":true}'
            self._reply(
                200, body, [("Content-Type", "application/json"), ("Cache-Control", "no-store")]
            )
        elif decoded == "/api" or decoded.startswith("/api/"):
            self._proxy()
        else:
            self._static(decoded, segments)

    do_GET = _handle
    do_HEAD = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_OPTIONS = _handle

    def do_TRACE(self) -> None:
        self._reply(405, headers=[("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")])

    do_CONNECT = do_TRACE


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AgentGuard loopback-only production static server"
    )
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args()
    try:
        with NativeWebServer(ROOT / "frontend/dist", args.port) as server:
            print(f"NATIVE_WEB_READY port={server.server_port} api_port={API_PORT}", flush=True)
            server.serve_forever()
    except (OSError, ValueError) as error:
        parser.exit(1, f"NATIVE_WEB_FAILED: {error}\n")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
