from reconix_api.models import Base

ERD_V3_TABLES = {
    "sessions",
    "messages",
    "assessments",
    "scope_manifests",
    "scope_targets",
    "agent_runs",
    "llm_providers",
    "actions",
    "tool_runs",
    "approvals",
    "evidences",
    "findings",
    "finding_sources",
    "validation_runs",
    "reports",
    "report_assessments",
}


def test_all_16_erd_v3_tables_exist() -> None:
    assert set(Base.metadata.tables) == ERD_V3_TABLES


def test_sessions_has_no_role_column() -> None:
    # ERD V3 has no sessions.role, and Reconix has no roles.
    assert "role" not in Base.metadata.tables["sessions"].c


def test_enum_values_are_uppercase() -> None:
    for table in Base.metadata.tables.values():
        for column in table.columns:
            for value in getattr(column.type, "enums", []):
                assert value == value.upper(), f"{table.name}.{column.name}: {value}"
