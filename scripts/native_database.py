from __future__ import annotations

import argparse
import os
from urllib.parse import quote, urlsplit, urlunsplit

import psycopg
from psycopg import sql

from backend.state.database import psycopg_url
from scripts.provision_ui_reader import provision
from scripts.provision_workflow_writer import provision as provision_writer

MAIN_DATABASE = "agentguard"
AUDIT_DATABASE = "agentguard_audit"
MAIN_ROLE = "agentguard"
AUDIT_ROLE = "audit"
UI_ROLE = "agentguard_ui"
WORKFLOW_ROLE = "agentguard_workflow"


def connect(url: str) -> psycopg.Connection:
    return psycopg.connect(psycopg_url(url), autocommit=True, connect_timeout=5)


def database_url(url: str, database: str) -> str:
    parsed = urlsplit(psycopg_url(url))
    return urlunsplit((parsed.scheme, parsed.netloc, f"/{database}", parsed.query, parsed.fragment))


def role_url(admin_url: str, role: str, password: str, database: str) -> str:
    parsed = urlsplit(psycopg_url(admin_url))
    if parsed.scheme != "postgresql" or not parsed.hostname:
        raise ValueError("an explicit PostgreSQL TCP connection URL is required")
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    authority = f"{quote(role, safe='')}:{quote(password, safe='')}@{host}:{parsed.port or 5432}"
    return urlunsplit(("postgresql+psycopg", authority, f"/{database}", parsed.query, ""))


def ensure_role(connection: psycopg.Connection, name: str, password: str) -> None:
    exists = connection.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,)).fetchone()
    role = sql.Identifier(name)
    if exists is None:
        connection.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(role, sql.Literal(password))
        )
    else:
        connection.execute(
            sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(role, sql.Literal(password))
        )


def ensure_database(connection: psycopg.Connection, name: str, owner: str) -> None:
    exists = connection.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,)).fetchone()
    if exists is None:
        connection.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(
                sql.Identifier(name), sql.Identifier(owner)
            )
        )


def provision_ui(admin_url: str, password: str) -> None:
    provision(database_url(admin_url, MAIN_DATABASE), UI_ROLE, password)


def provision_workflow(admin_url: str, password: str) -> None:
    provision_writer(database_url(admin_url, MAIN_DATABASE), WORKFLOW_ROLE, password)


def run(args: argparse.Namespace) -> None:
    if args.check:
        with connect(args.admin_url) as connection:
            version = connection.execute("SELECT version()").fetchone()[0]
        print(f"POSTGRES_NATIVE_READY=PASS version={version}")
        return

    if args.provision_ui:
        provision_ui(args.admin_url, args.ui_password)
        print(f"POSTGRES_NATIVE_UI_ROLE=PASS role={UI_ROLE}")
        return

    with connect(args.admin_url) as connection:
        ensure_role(connection, MAIN_ROLE, args.main_password)
        ensure_role(connection, AUDIT_ROLE, args.audit_password)
        ensure_database(connection, MAIN_DATABASE, MAIN_ROLE)
        ensure_database(connection, AUDIT_DATABASE, AUDIT_ROLE)
    print(f"POSTGRES_NATIVE_DATABASES=PASS main={MAIN_DATABASE} audit={AUDIT_DATABASE}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare native Windows PostgreSQL state")
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--main-password", default=os.getenv("AGENTGUARD_NATIVE_MAIN_DB_PASSWORD"))
    parser.add_argument(
        "--audit-password", default=os.getenv("AGENTGUARD_NATIVE_AUDIT_DB_PASSWORD")
    )
    parser.add_argument("--ui-password", default=os.getenv("AGENTGUARD_NATIVE_UI_DB_PASSWORD"))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--provision-ui", action="store_true")
    args = parser.parse_args()
    if not args.check:
        required = (
            (args.ui_password,) if args.provision_ui else (args.main_password, args.audit_password)
        )
        if not all(required):
            parser.error("explicit role passwords or AGENTGUARD_NATIVE_*_DB_PASSWORD are required")

    try:
        run(args)
    except Exception as exc:
        print(f"NATIVE_DATABASE_RESULT=FAIL error_type={type(exc).__name__}")
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
