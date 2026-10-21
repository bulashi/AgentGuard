"""Drive the real guard functions with DNS records; no network requests are performed."""

from __future__ import annotations

import ast
import ipaddress
import os
import re
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest
from psycopg.conninfo import conninfo_to_dict

from backend.config import model_profiles

REPOSITORY = Path(__file__).resolve().parents[2]


def address(ip: str, port: int = 443) -> tuple:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))


@pytest.fixture
def guard(tmp_path: Path):
    source = REPOSITORY / "scripts/native_test_guard/sitecustomize.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    guarded = next(node for node in tree.body if isinstance(node, ast.If))
    prefix = []
    for node in guarded.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value.func
            if isinstance(call, ast.Attribute) and call.attr == "addaudithook":
                break
        prefix.append(node)
    connect = next(
        node
        for node in guarded.body
        if isinstance(node, ast.FunctionDef) and node.name == "_connect"
    )

    def load(overrides=None, records=None):
        environment = {
            "AGENTGUARD_BACKEND_PROJECT_ROOT": str(tmp_path / "project"),
            "AGENTGUARD_BACKEND_EVIDENCE_ROOT": str(tmp_path / "evidence"),
            "AGENTGUARD_BACKEND_BLOCKED_PORTS": "8088,8090,18003",
            "AGENTGUARD_BACKEND_ALLOWED_DATABASES": "agentguard_test_backend_unit",
            "AGENTGUARD_BACKEND_ACCEPTANCE_MODE": "cloud",
            "AGENTGUARD_BACKEND_CLOUD_SERVICE": "coordinator-agent",
            "AGENTGUARD_BACKEND_CLOUD_HOST": "api.deepseek.com",
            "AGENTGUARD_BACKEND_CLOUD_PORT": "443",
        } | (overrides or {})
        queries = []
        answers = {
            "api.deepseek.com": [address("1.1.1.1")],
            "1.1.1.1": [address("1.1.1.1")],
            "127.0.0.1": [address("127.0.0.1", 28090)],
        } | (records or {})

        def resolve(host, port, *_args, **_kwargs):
            queries.append((host, port))
            return answers[host]

        namespace = {
            "os": SimpleNamespace(
                environ=environment,
                fsdecode=os.fsdecode,
                PathLike=os.PathLike,
                O_WRONLY=os.O_WRONLY,
                O_RDWR=os.O_RDWR,
                O_CREAT=os.O_CREAT,
                O_TRUNC=os.O_TRUNC,
                O_APPEND=os.O_APPEND,
            ),
            "ipaddress": ipaddress,
            "Path": Path,
            "re": re,
            "socket": SimpleNamespace(
                getaddrinfo=resolve,
                AF_INET=socket.AF_INET,
                AF_INET6=socket.AF_INET6,
                SOCK_STREAM=socket.SOCK_STREAM,
            ),
            "conninfo_to_dict": conninfo_to_dict,
            "_original_connect": lambda *_args, **_kwargs: "test-only-connect",
            "queries": queries,
            "environment": environment,
        }
        # Execute the production guard without installing an irreversible hook in pytest.
        exec(
            compile(ast.Module(body=[*prefix, connect], type_ignores=[]), str(source), "exec"),
            namespace,
        )
        return namespace

    return load


def connect(guard: dict, host: str, port: int = 443) -> None:
    guard["_audit"]("socket.connect", (None, (host, port)))


def test_approved_dns_registers_only_public_ips_and_allows_pinned_numeric_resolution(guard):
    value = guard()
    with pytest.raises(PermissionError, match="network destination"):
        connect(value, "1.1.1.1")
    records = value["_getaddrinfo"]("api.deepseek.com", 443, type=socket.SOCK_STREAM)
    assert records == [address("1.1.1.1")]
    assert value["_cloud_addresses"] == {"1.1.1.1"}
    assert value["_getaddrinfo"]("1.1.1.1", 443, type=socket.SOCK_STREAM) == records
    connect(value, "1.1.1.1")
    assert value["queries"] == [("api.deepseek.com", 443), ("1.1.1.1", 443)]


def test_real_model_public_resolution_uses_the_fixed_host_then_numeric_ip(guard, monkeypatch):
    value = guard()
    monkeypatch.setattr(model_profiles.socket, "getaddrinfo", value["_getaddrinfo"])
    pinned = model_profiles.require_public_resolution("https://api.deepseek.com")
    assert pinned == "1.1.1.1"
    value["_getaddrinfo"](pinned, 443, type=socket.SOCK_STREAM)
    connect(value, pinned)
    assert value["queries"] == [("api.deepseek.com", 443), ("1.1.1.1", 443)]


def test_unregistered_hosts_ips_and_ports_remain_blocked_without_dns_in_connect_hook(guard):
    value = guard()
    value["_getaddrinfo"]("api.deepseek.com", 443, type=socket.SOCK_STREAM)
    for host, port in [("other.example.com", 443), ("8.8.8.8", 443), ("api.deepseek.com", 444)]:
        with pytest.raises(PermissionError, match="external DNS"):
            value["_getaddrinfo"](host, port, type=socket.SOCK_STREAM)
    for host, port in [("8.8.8.8", 443), ("1.1.1.1", 444), ("api.deepseek.com", 443)]:
        with pytest.raises(PermissionError, match="network destination"):
            connect(value, host, port)
    assert value["queries"] == [("api.deepseek.com", 443)]


@pytest.mark.parametrize(
    "records",
    [
        [],
        [address("127.0.0.1")],
        [address("1.1.1.1"), address("10.0.0.1")],
        [address("::1")],
        [address("224.0.0.1")],
    ],
)
def test_empty_private_mixed_and_multicast_resolution_never_registers_ips(guard, records):
    value = guard(records={"api.deepseek.com": records})
    with pytest.raises(PermissionError, match="cloud resolution"):
        value["_getaddrinfo"]("api.deepseek.com", 443, type=socket.SOCK_STREAM)
    assert value["_cloud_addresses"] == set()
    with pytest.raises(PermissionError):
        connect(value, "1.1.1.1")


def test_checked_public_ipv6_connect_is_allowed_at_the_fixed_port(guard):
    ip = "2606:4700:4700::1111"
    value = guard(records={"api.deepseek.com": [address(ip)], ip: [address(ip)]})
    value["_getaddrinfo"]("api.deepseek.com", 443, type=socket.SOCK_STREAM)
    value["_getaddrinfo"](ip, 443, type=socket.SOCK_STREAM)
    value["_audit"]("socket.connect", (None, (ip, 443, 0, 0)))
    with pytest.raises(PermissionError):
        connect(value, ip, 80)


def test_numeric_pinned_resolution_cannot_change_the_selected_ip(guard):
    value = guard(records={"1.1.1.1": [address("8.8.8.8")]})
    value["_getaddrinfo"]("api.deepseek.com", 443, type=socket.SOCK_STREAM)
    with pytest.raises(PermissionError, match="changed pinned cloud address"):
        value["_getaddrinfo"]("1.1.1.1", 443, type=socket.SOCK_STREAM)
    assert value["_cloud_addresses"] == {"1.1.1.1"}


@pytest.mark.parametrize("mode", ["", "full", "proof", "handoff", "browser"])
def test_every_non_cloud_mode_keeps_external_dns_and_connect_forbidden(guard, mode):
    value = guard({"AGENTGUARD_BACKEND_ACCEPTANCE_MODE": mode})
    with pytest.raises(PermissionError, match="external DNS"):
        value["_getaddrinfo"]("api.deepseek.com", 443, type=socket.SOCK_STREAM)
    with pytest.raises(PermissionError, match="network destination"):
        connect(value, "1.1.1.1")
    assert value["queries"] == [] and value["_cloud_addresses"] == set()


@pytest.mark.parametrize("service", ["ui-api", "gateway", "refund-tool", "audit-worker"])
def test_non_model_services_are_not_authorized_by_cloud_mode(guard, service):
    value = guard({"AGENTGUARD_BACKEND_CLOUD_SERVICE": service})
    with pytest.raises(PermissionError, match="external DNS"):
        value["_getaddrinfo"]("api.deepseek.com", 443, type=socket.SOCK_STREAM)
    assert value["queries"] == []


@pytest.mark.parametrize(
    "override",
    [
        {"AGENTGUARD_BACKEND_CLOUD_HOST": "127.0.0.1"},
        {"AGENTGUARD_BACKEND_CLOUD_HOST": "metadata.internal"},
        {"AGENTGUARD_BACKEND_CLOUD_PORT": "invalid"},
        {"AGENTGUARD_BACKEND_CLOUD_PORT": "8090"},
    ],
)
def test_invalid_endpoint_permissions_fail_closed_with_the_original_guard(guard, override):
    value = guard(override)
    with pytest.raises(PermissionError, match="external DNS"):
        value["_getaddrinfo"]("api.deepseek.com", 443, type=socket.SOCK_STREAM)
    assert value["queries"] == []


def test_cloud_permission_retains_local_port_file_and_database_boundaries(guard):
    value = guard()
    value["_getaddrinfo"]("api.deepseek.com", 443, type=socket.SOCK_STREAM)
    connect(value, "127.0.0.1", 28090)
    for port in (8088, 8090, 18003):
        with pytest.raises(PermissionError, match="network destination"):
            connect(value, "127.0.0.1", port)
    evidence = Path(value["environment"]["AGENTGUARD_BACKEND_EVIDENCE_ROOT"])
    outside = Path(value["environment"]["AGENTGUARD_BACKEND_PROJECT_ROOT"]) / ".native/config.json"
    value["_audit"]("open", (str(evidence / "allowed.json"), "w", os.O_WRONLY | os.O_CREAT))
    with pytest.raises(PermissionError, match="write outside evidence"):
        value["_audit"]("open", (str(outside), "w", os.O_WRONLY | os.O_CREAT))
    with pytest.raises(PermissionError, match="mutation outside evidence"):
        value["_audit"]("os.remove", (str(outside), -1))
    assert (
        value["_connect"]("postgresql://reader@127.0.0.1:5432/agentguard_test_backend_unit")
        == "test-only-connect"
    )
    with pytest.raises(PermissionError, match="non-test database"):
        value["_connect"]("postgresql://reader@127.0.0.1:5432/agentguard")
    with pytest.raises(PermissionError, match="non-loopback database"):
        value["_connect"]("postgresql://reader@1.1.1.1:5432/agentguard_test_backend_unit")
