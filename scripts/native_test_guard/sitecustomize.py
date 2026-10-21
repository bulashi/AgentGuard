"""Evidence-only writes/test DBs; explicit cloud agents may reach one checked endpoint."""

import ipaddress
import os
import re
import socket
import sys
from pathlib import Path

if os.environ.get("AGENTGUARD_BACKEND_GUARD_ENABLED") == "1":
    _root = Path(os.environ["AGENTGUARD_BACKEND_PROJECT_ROOT"]).resolve()
    _evidence = Path(os.environ["AGENTGUARD_BACKEND_EVIDENCE_ROOT"]).resolve()
    _blocked_ports = {int(p) for p in os.environ["AGENTGUARD_BACKEND_BLOCKED_PORTS"].split(",")}
    _databases = set(os.environ.get("AGENTGUARD_BACKEND_ALLOWED_DATABASES", "").split(","))
    _cloud_host = ""
    _cloud_port = 0
    _cloud_addresses = set()
    _original_getaddrinfo = socket.getaddrinfo

    def _host(value):
        if isinstance(value, bytes):
            try:
                value = value.decode("ascii")
            except UnicodeError:
                return ""
        if not isinstance(value, str):
            return ""
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            return value.lower()

    def _public_address(value):
        try:
            address = ipaddress.ip_address(value)
            return address.is_global and not address.is_multicast
        except ValueError:
            return False

    if os.environ.get("AGENTGUARD_BACKEND_ACCEPTANCE_MODE") == "cloud" and os.environ.get(
        "AGENTGUARD_BACKEND_CLOUD_SERVICE"
    ) in {"coordinator-agent", "knowledge-agent", "case-agent", "refund-agent"}:
        candidate = _host(os.environ.get("AGENTGUARD_BACKEND_CLOUD_HOST", ""))
        try:
            candidate_port = int(os.environ.get("AGENTGUARD_BACKEND_CLOUD_PORT", ""))
        except ValueError:
            candidate_port = 0
        hostname = (
            bool(re.fullmatch(r"[a-zA-Z0-9.-]+", candidate))
            and "." in candidate
            and not candidate.endswith((".localhost", ".local", ".internal"))
        )
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            public_target = hostname
        else:
            public_target = _public_address(candidate)
        if public_target and 1 <= candidate_port <= 65535 and candidate_port not in _blocked_ports:
            _cloud_host, _cloud_port = candidate, candidate_port

    def _cloud_dns_allowed(host, port):
        return (
            bool(_cloud_host)
            and port == _cloud_port
            and (_host(host) == _cloud_host or _host(host) in _cloud_addresses)
        )

    def _audit(event, args):
        if event == "socket.connect":
            address = args[1]
            if isinstance(address, tuple):
                host, port = address[:2]
                local = host in {"127.0.0.1", "::1", "localhost"}
                checked_cloud = (
                    bool(_cloud_host) and port == _cloud_port and _host(host) in _cloud_addresses
                )
                if not (local or checked_cloud) or port in _blocked_ports:
                    raise PermissionError("backend evidence guard rejected network destination")
        elif event == "socket.getaddrinfo":
            if args[0] not in {None, "127.0.0.1", "::1", "localhost"} and not _cloud_dns_allowed(
                args[0], args[1]
            ):
                raise PermissionError("backend evidence guard rejected external DNS")
        elif event == "open":
            name, _mode, flags = args
            if isinstance(name, (str, bytes, os.PathLike)):
                path = Path(os.fsdecode(name)).resolve()
                writes = bool(
                    flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
                )
                if writes and not path.is_relative_to(_evidence) and str(path).lower() != "nul":
                    raise PermissionError("backend evidence guard rejected write outside evidence")
        elif event in {"os.mkdir", "os.remove", "os.rmdir", "os.rename", "os.chmod"}:
            paths = args[:2] if event == "os.rename" else args[:1]
            for name in paths:
                if isinstance(name, (str, bytes, os.PathLike)):
                    path = Path(os.fsdecode(name)).resolve()
                    if not path.is_relative_to(_evidence):
                        raise PermissionError(
                            "backend evidence guard rejected mutation outside evidence"
                        )

    def _getaddrinfo(host, port, *args, **kwargs):
        _audit("socket.getaddrinfo", (host, port))
        addresses = _original_getaddrinfo(host, port, *args, **kwargs)
        if _cloud_dns_allowed(host, port):
            checked = set()
            for family, kind, _protocol, _canonical_name, address in addresses:
                if (
                    family not in {socket.AF_INET, socket.AF_INET6}
                    or kind != socket.SOCK_STREAM
                    or address[1] != _cloud_port
                    or not _public_address(address[0])
                ):
                    raise PermissionError(
                        "backend evidence guard rejected non-public cloud resolution"
                    )
                checked.add(_host(address[0]))
            if not checked:
                raise PermissionError("backend evidence guard rejected empty cloud resolution")
            requested = _host(host)
            if requested != _cloud_host and checked != {requested}:
                raise PermissionError(
                    "backend evidence guard rejected a changed pinned cloud address"
                )
            if requested == _cloud_host:
                _cloud_addresses.update(checked)
        return addresses

    sys.addaudithook(_audit)
    if _cloud_host:
        socket.getaddrinfo = _getaddrinfo

    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    _original_connect = psycopg.connect

    def _connect(conninfo="", *args, **kwargs):
        parameters = conninfo_to_dict(
            conninfo,
            **{
                k: v
                for k, v in kwargs.items()
                if k
                not in {
                    "autocommit",
                    "row_factory",
                    "cursor_factory",
                    "context",
                    "prepare_threshold",
                }
            },
        )
        if parameters.get("dbname") not in _databases:
            raise PermissionError("backend evidence guard rejected non-test database")
        if parameters.get("host") not in {"127.0.0.1", "localhost", "::1"}:
            raise PermissionError("backend evidence guard rejected non-loopback database")
        return _original_connect(conninfo, *args, **kwargs)

    psycopg.connect = _connect
