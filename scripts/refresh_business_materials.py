"""Update only recognized versions of bundled business documents, preserving user edits."""

from __future__ import annotations

import hashlib
import json

from backend.common.time import now_unix
from backend.config.settings import get_settings
from backend.state.database import connect
from backend.tools.demo_materials import (
    LEGACY_POLICY_CONTENT,
    LEGACY_TICKET_DESCRIPTION,
    MATERIAL_PROFILE,
    POLICY_CONTENT,
    TICKET_DESCRIPTION,
)


def refresh_business_materials(database_url: str) -> list[dict[str, str]]:
    # MD5 identifies known text versions here; authorization uses SM2/SM3 elsewhere.
    ticket_versions = {"d7ea962b6420230920206a5835e63452", "0399cea364ee66a91f580fa9e5bd7b4a"}
    policy_versions = {"6775c34360386bfb5d5914d3b6714c1d", "69c0a55cdddf2b8fdb081c8f56d03751"}
    ticket_versions.update(hashlib.md5(text.encode()).hexdigest()
                           for text in (LEGACY_TICKET_DESCRIPTION, TICKET_DESCRIPTION))
    policy_versions.update(hashlib.md5(text.encode()).hexdigest()
                           for text in (LEGACY_POLICY_CONTENT, POLICY_CONTENT))
    results = []
    with connect(database_url) as connection, connection.transaction():
        for ticket_id, tenant_id, customer_id, document_id in (
            ("T10086", "tenant-A", "C9527", "DOC-001"),
            ("T10088", "演示企业", "张三", "DOC-CHINESE-001"),
        ):
            ticket = connection.execute(
                "SELECT tenant_id, customer_id, md5(description) FROM tickets "
                "WHERE ticket_id = %s FOR UPDATE", (ticket_id,),
            ).fetchone()
            if (
                ticket is not None
                and ticket[:2] == (tenant_id, customer_id)
                and ticket[2] in ticket_versions
            ):
                connection.execute(
                    "UPDATE tickets SET description = %s, updated_at = %s WHERE ticket_id = %s",
                    (TICKET_DESCRIPTION, now_unix(), ticket_id),
                )
                results.append({"record": ticket_id, "status": "CURRENT"})
            else:
                results.append({"record": ticket_id, "status": "PRESERVED_UNKNOWN_VERSION"})
            document = connection.execute(
                "SELECT tenant_id, md5(content) FROM knowledge_documents "
                "WHERE document_id = %s FOR UPDATE", (document_id,),
            ).fetchone()
            if document is not None and document[0] == tenant_id and document[1] in policy_versions:
                connection.execute(
                    "UPDATE knowledge_documents SET title = %s, content = %s "
                    "WHERE document_id = %s",
                    ("重复扣款退款处理规范", POLICY_CONTENT, document_id),
                )
                results.append({"record": document_id, "status": "CURRENT"})
            else:
                results.append({"record": document_id, "status": "PRESERVED_UNKNOWN_VERSION"})
    return results


def main() -> None:
    results = refresh_business_materials(get_settings().database_url)
    print(json.dumps({"profile": MATERIAL_PROFILE, "records": results}, ensure_ascii=True))


if __name__ == "__main__":
    main()
