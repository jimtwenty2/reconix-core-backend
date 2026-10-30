"""scope_manifests.allowed_ports: the ports nmap may scan (empty puts no limit).

Revision ID: b7c1d2e3f4a5
Revises: 4f56ae9e0a55
Create Date: 2026-10-30 18:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b7c1d2e3f4a5"
down_revision: str | Sequence[str] | None = "4f56ae9e0a55"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scope_manifests",
        sa.Column(
            "allowed_ports",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("scope_manifests", "allowed_ports")
