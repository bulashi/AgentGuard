from __future__ import annotations

from pathlib import Path

import pytest

from scripts import verify_current_cloud as cloud

MAIN_NAME = "agentguard_test_backend_0123456789abcdef"
AUDIT_NAME = "agentguard_audit_test_backend_0123456789abcdef"
OPERATOR_SECRET = "a" * 64


@pytest.fixture
def isolated_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    root = tmp_path / "project"
    artifact_root = root / "artifacts"
    artifact_root.mkdir(parents=True)
    monkeypatch.setattr(cloud, "ROOT", root)
    return root, artifact_root


def isolated_urls(main_name: str = MAIN_NAME, audit_name: str = AUDIT_NAME) -> dict[str, str]:
    return {
        "AGENTGUARD_DATABASE_URL": f"postgresql://agentguard:secret@127.0.0.1:5432/{main_name}",
        "AGENTGUARD_AUDIT_DATABASE_URL": f"postgresql://audit:secret@127.0.0.1:5432/{audit_name}",
        "AGENTGUARD_WORKFLOW_DATABASE_URL": f"postgresql://workflow:secret@127.0.0.1:5432/{main_name}",
        "AGENTGUARD_UI_DATABASE_URL": f"postgresql://ui:secret@127.0.0.1:5432/{main_name}",
        "AGENTGUARD_UI_API_URL": "http://127.0.0.1:28090",
        "AGENTGUARD_CHECKPOINT_SERVICE_URL": "http://127.0.0.1:28008",
        "AGENTGUARD_AUDIT_SERVICE_URL": "http://127.0.0.1:28007",
        "AGENTGUARD_GATEWAY_URL": "http://127.0.0.1:28003",
    }


@pytest.mark.parametrize("scheme", ["postgresql", "postgresql+psycopg"])
def test_isolated_context_accepts_stack_urls_and_returns_no_operator_secret(
    isolated_root: tuple[Path, Path],
    scheme: str,
) -> None:
    _root, artifact_root = isolated_root
    urls = {
        key: value.replace("postgresql://", scheme + "://", 1)
        for key, value in isolated_urls().items()
    }

    context = cloud.validate_isolated_cloud_context(
        urls,
        OPERATOR_SECRET,
        "native-cloud-unit-1",
        artifact_root / "run-1",
    )

    assert context["main"] == urls["AGENTGUARD_DATABASE_URL"]
    assert context["audit"] == urls["AGENTGUARD_AUDIT_DATABASE_URL"]
    assert context["workflow"] == urls["AGENTGUARD_WORKFLOW_DATABASE_URL"]
    assert context["ui"] == urls["AGENTGUARD_UI_DATABASE_URL"]
    assert context["ui_api_url"] == "http://127.0.0.1:28090"
    assert context["main_database_name"] == MAIN_NAME
    assert context["audit_database_name"] == AUDIT_NAME
    assert OPERATOR_SECRET not in context.values()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("AGENTGUARD_DATABASE_URL", "postgresql://127.0.0.1/agentguard"),
        ("AGENTGUARD_DATABASE_URL", "postgresql+psycopg://127.0.0.1/agentguard"),
        ("AGENTGUARD_DATABASE_URL", f"postgresql+psycopg://db.example/{MAIN_NAME}"),
        (
            "AGENTGUARD_DATABASE_URL",
            f"postgresql+psycopg://127.0.0.1/{MAIN_NAME}?host=db.example",
        ),
        (
            "UNRECOGNIZED_DATABASE",
            f"postgresql+psycopg://127.0.0.1/{MAIN_NAME}",
        ),
        (
            "AGENTGUARD_DATABASE_URL",
            f"postgresql://db.example/{MAIN_NAME}",
        ),
        (
            "AGENTGUARD_DATABASE_URL",
            f"postgresql://127.0.0.1/{MAIN_NAME}?host=db.example",
        ),
        (
            "AGENTGUARD_AUDIT_DATABASE_URL",
            "postgresql://127.0.0.1/agentguard_audit_test_backend_ffffffffffffffff",
        ),
        ("AGENTGUARD_UI_API_URL", "http://127.0.0.1:8088"),
        ("AGENTGUARD_CHECKPOINT_SERVICE_URL", "http://127.0.0.1:8090"),
        ("AGENTGUARD_AUDIT_SERVICE_URL", "http://10.0.0.5:28007"),
        ("AGENTGUARD_GATEWAY_URL", "https://example.com:28003"),
    ],
)
def test_isolated_context_rejects_non_test_or_non_loopback_targets(
    isolated_root: tuple[Path, Path], key: str, value: str
) -> None:
    _root, artifact_root = isolated_root
    urls = isolated_urls()
    urls[key] = value

    with pytest.raises(ValueError):
        cloud.validate_isolated_cloud_context(
            urls, OPERATOR_SECRET, "native-cloud-unit-1", artifact_root / "run-1"
        )


def test_isolated_context_requires_all_distinct_roles_to_use_the_same_fresh_databases(
    isolated_root: tuple[Path, Path],
) -> None:
    _root, artifact_root = isolated_root
    urls = isolated_urls()
    urls["AGENTGUARD_UI_DATABASE_URL"] = (
        "postgresql://ui:secret@127.0.0.1:5432/agentguard_test_backend_ffffffffffffffff"
    )

    with pytest.raises(ValueError, match="same test stack"):
        cloud.validate_isolated_cloud_context(
            urls, OPERATOR_SECRET, "native-cloud-unit-1", artifact_root / "run-1"
        )


@pytest.mark.parametrize("run_id", ["", "../escape", "path\\escape", "a" * 129])
def test_isolated_context_rejects_unsafe_run_ids(
    isolated_root: tuple[Path, Path], run_id: str
) -> None:
    _root, artifact_root = isolated_root

    with pytest.raises(ValueError, match="run ID"):
        cloud.validate_isolated_cloud_context(
            isolated_urls(), OPERATOR_SECRET, run_id, artifact_root / "run-1"
        )


def test_isolated_context_requires_new_artifact_path_and_rejects_docs(
    isolated_root: tuple[Path, Path],
) -> None:
    root, artifact_root = isolated_root
    docs = root / "docs"
    docs.mkdir()
    existing = artifact_root / "already-used"
    existing.mkdir()

    for destination in (docs / "prompt.md", existing):
        with pytest.raises(ValueError, match="evidence directory"):
            cloud.validate_isolated_cloud_context(
                isolated_urls(), OPERATOR_SECRET, "native-cloud-unit-1", destination
            )


def test_isolated_operator_auth_material_is_required(isolated_root: tuple[Path, Path]) -> None:
    _root, artifact_root = isolated_root

    with pytest.raises(ValueError, match="operator secret"):
        cloud.validate_isolated_cloud_context(
            isolated_urls(), "short", "native-cloud-unit-1", artifact_root / "run-1"
        )
