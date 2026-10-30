"""dm_envelope encryption_mode column

Revision ID: a1b2c3d4e5f6
Revises: 2dcf0a424610
Create Date: 2026-10-24

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "2dcf0a424610"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "dm_envelope",
        sa.Column(
            "encryption_mode",
            sa.String(length=32),
            nullable=False,
            server_default="compliance",
        ),
    )
    op.alter_column("dm_envelope", "encryption_mode", server_default=None)


def downgrade() -> None:
    op.drop_column("dm_envelope", "encryption_mode")
