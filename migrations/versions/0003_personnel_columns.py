"""Personnel accounts: forced password change and the read/acknowledge split.

Revision ID: 0003_personnel_columns
Revises: 0002_personnel_mobile
Create Date: 2026-11-02

Both columns are additive and both have a safe default, so an existing monitoring deployment
upgrades without any data migration and without invalidating a single dashboard session:

  * `users.must_change_password` defaults to false. Accounts keep signing in exactly as
    before; only an administrator explicitly setting the flag forces a change.
  * `notifications.read_at` is nullable. Older rows keep their existing `state`, and the new
    column simply stays empty where nobody recorded a read.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_personnel_columns"
down_revision = "0002_personnel_mobile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "notifications",
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("notifications", "read_at")
    op.drop_column("users", "must_change_password")
