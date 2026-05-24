"""Initial Coreline Auth schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-24 19:35:00
"""

from __future__ import annotations

from alembic import op

from coreline_auth.storage.sqlalchemy_schema import metadata

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    metadata.create_all(op.get_bind())


def downgrade() -> None:
    metadata.drop_all(op.get_bind())
