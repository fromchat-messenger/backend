"""Admin suspension_until and moderation_event

Revision ID: a8f3c2e91b04
Revises: 2dcf0a424610
Create Date: 2026-11-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a8f3c2e91b04"
down_revision: Union[str, Sequence[str], None] = "2dcf0a424610"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("user", sa.Column("suspension_until", sa.DateTime(), nullable=True))
    op.create_index("ix_user_suspension_until", "user", ["suspension_until"], unique=False)
    op.create_table(
        "moderation_event",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("message_id", sa.Integer(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("detail_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_moderation_event_type", "moderation_event", ["type"], unique=False)
    op.create_index("ix_moderation_event_user_id", "moderation_event", ["user_id"], unique=False)
    op.create_index("ix_moderation_event_message_id", "moderation_event", ["message_id"], unique=False)
    op.create_index("ix_moderation_event_created_at", "moderation_event", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_moderation_event_created_at", table_name="moderation_event")
    op.drop_index("ix_moderation_event_message_id", table_name="moderation_event")
    op.drop_index("ix_moderation_event_user_id", table_name="moderation_event")
    op.drop_index("ix_moderation_event_type", table_name="moderation_event")
    op.drop_table("moderation_event")
    op.drop_index("ix_user_suspension_until", table_name="user")
    op.drop_column("user", "suspension_until")
