from __future__ import annotations

import argparse

import psycopg
from psycopg import sql

from backend.state.database import psycopg_url


def provision(database_url: str, role_name: str, password: str) -> None:
    if not role_name or not password:
        raise ValueError("role name and password must be non-empty")
    role = sql.Identifier(role_name)
    with psycopg.connect(psycopg_url(database_url), autocommit=True) as connection:
        exists = connection.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s", (role_name,)
        ).fetchone()
        command = (
            "ALTER ROLE {} LOGIN PASSWORD {}" if exists else "CREATE ROLE {} LOGIN PASSWORD {}"
        )
        connection.execute(sql.SQL(command).format(role, sql.Literal(password)))
        connection.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(role))
        connection.execute(
            sql.SQL("GRANT SELECT, INSERT, UPDATE ON TABLE agent_workflow_runs TO {}").format(role)
        )
        connection.execute(
            sql.SQL("GRANT SELECT, INSERT ON TABLE agent_workflow_events TO {}").format(role)
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision the operational workflow writer")
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--role-name", default="agentguard_workflow")
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    provision(args.database_url, args.role_name, args.password)
    print(f"provisioned operational-only role: {args.role_name}")


if __name__ == "__main__":
    main()
