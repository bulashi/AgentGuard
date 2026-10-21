from __future__ import annotations

import argparse
import hashlib
import time
from pathlib import Path

import psycopg

from backend.state.database import psycopg_url


def connect_with_retry(database_url: str, attempts: int = 30) -> psycopg.Connection:
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            return psycopg.connect(psycopg_url(database_url), autocommit=True)
        except psycopg.OperationalError as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError("database did not become available") from last_error


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply AgentGuard SQL migrations")
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()

    migration_dir = Path(args.directory)
    migrations = sorted(migration_dir.glob("*.sql"))
    if not migrations:
        raise RuntimeError(f"no SQL migrations found in {migration_dir}")

    with connect_with_retry(args.database_url) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                checksum_sha256 TEXT NOT NULL,
                applied_at BIGINT NOT NULL
            )
            """
        )
        for migration in migrations:
            sql = migration.read_text(encoding="utf-8")
            checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
            row = connection.execute(
                "SELECT checksum_sha256 FROM schema_migrations WHERE version = %s",
                (migration.name,),
            ).fetchone()
            if row is not None:
                if row[0] != checksum:
                    raise RuntimeError(f"migration checksum changed: {migration.name}")
                print(f"already applied: {migration.name}")
                continue
            connection.execute(sql)
            connection.execute(
                """
                INSERT INTO schema_migrations (version, checksum_sha256, applied_at)
                VALUES (%s, %s, %s)
                """,
                (migration.name, checksum, int(time.time())),
            )
            print(f"applied: {migration.name}")


if __name__ == "__main__":
    main()
