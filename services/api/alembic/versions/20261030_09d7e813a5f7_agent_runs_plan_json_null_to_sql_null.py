"""agent_runs plan: JSON null to SQL NULL

The model saved "no plan" as the JSON value null, so the lookup for a person's open run
(plan IS NULL) never matched and every action opened a new run. The model now stores
SQL NULL (JSONB(none_as_null=True)); this turns the rows already saved into SQL NULL too.
Data only: the column type does not change.

Revision ID: 09d7e813a5f7
Revises: 4f56ae9e0a55
Create Date: 2026-10-30 15:24:00.941643

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "09d7e813a5f7"
down_revision: str | Sequence[str] | None = "4f56ae9e0a55"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("UPDATE agent_runs SET plan = NULL WHERE plan = 'null'::jsonb")


def downgrade() -> None:
    # Back to how the old model saved "no plan".
    op.execute("UPDATE agent_runs SET plan = 'null'::jsonb WHERE plan IS NULL")
