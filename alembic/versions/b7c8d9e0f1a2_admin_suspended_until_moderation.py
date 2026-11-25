"""admin suspended_until and moderation_events

Revision ID: b7c8d9e0f1a2
Revises: a1b2c3d4e5f6
Create Date: 2026-11-25

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b7c8d9e0f1a2"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("user", sa.Column("suspended_until", sa.DateTime(), nullable=True))
    op.create_index("ix_user_suspended_until", "user", ["suspended_until"], unique=False)

    op.create_table(
        "moderation_event",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("text_preview", sa.String(length=500), nullable=True),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("reason_detail", sa.String(length=255), nullable=False),
        sa.Column("message_id", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_moderation_event_created_at", "moderation_event", ["created_at"], unique=False)
    op.create_index("ix_moderation_event_source", "moderation_event", ["source"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_moderation_event_source", table_name="moderation_event")
    op.drop_index("ix_moderation_event_created_at", table_name="moderation_event")
    op.drop_table("moderation_event")
    op.drop_index("ix_user_suspended_until", table_name="user")
    op.drop_column("user", "suspended_until")