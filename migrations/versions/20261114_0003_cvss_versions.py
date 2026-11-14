"""Persist the CVSS metric version with vulnerability scores.

Revision ID: 20261114_0003
Revises: 20261114_0002
Create Date: 2026-11-14
"""

import sqlalchemy as sa
from alembic import op

revision = "20261114_0003"
down_revision = "20261114_0002"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    for table in ("cve_references", "vulnerability_findings"):
        columns = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        if "cvss_version" not in columns:
            op.add_column(
                table,
                sa.Column("cvss_version", sa.String(length=8), nullable=True),
            )


def downgrade():
    bind = op.get_bind()
    for table in ("vulnerability_findings", "cve_references"):
        columns = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        if "cvss_version" in columns:
            op.drop_column(table, "cvss_version")
