from __future__ import annotations

import argparse

import psycopg
from psycopg import sql

from backend.state.database import psycopg_url

READ_TABLES = (
    "key_registry",
    "tasks",
    "credentials",
    "credential_revocations",
    "dispatch_cancellations",
    "credential_budget_state",
    "business_actions",
    "execution_records",
    "execution_receipts",
    "refunds",
    "notifications",
    "audit_outbox",
    "audit_chain_head",
    "audit_events",
    "tickets",
    "knowledge_documents",
    "ticket_document_relations",
    "refund_eligibility",
    "business_payment_verifications",
    "business_case_facts",
    "business_case_payment_ids",
    "business_fact_evaluations",
    "agent_workflow_runs",
    "agent_workflow_events",
)


def provision(database_url: str, role_name: str, password: str) -> None:
    if not role_name or not password:
        raise ValueError("role name and password must be non-empty")
    role = sql.Identifier(role_name)
    with psycopg.connect(psycopg_url(database_url), autocommit=True) as connection:
        exists = connection.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s", (role_name,)
        ).fetchone()
        if exists is None:
            connection.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(role, sql.Literal(password))
            )
        else:
            connection.execute(
                sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(role, sql.Literal(password))
            )
        connection.execute(
            sql.SQL("ALTER ROLE {} SET default_transaction_read_only = on").format(role)
        )
        connection.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(role))
        for table_name in READ_TABLES:
            connection.execute(
                sql.SQL("GRANT SELECT ON TABLE {} TO {}").format(sql.Identifier(table_name), role)
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision the read-only Phase 16 UI role")
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--role-name", default="agentguard_ui")
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    provision(args.database_url, args.role_name, args.password)
    print(f"provisioned read-only role: {args.role_name}")


if __name__ == "__main__":
    main()
