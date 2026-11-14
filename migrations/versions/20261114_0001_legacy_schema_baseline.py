"""Baseline the existing BastionIX schema without replacing existing rows.

Revision ID: 20261114_0001
Revises:
Create Date: 2026-11-14
"""

from alembic import op

from models import db
from models.attack_log import AttackLog
from models.password_analysis import PasswordAnalysis
from models.settings import UserSettings
from models.system_log import SystemLog
from models.url_analysis import URLAnalysis
from models.user import User

revision = "20261114_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # checkfirst makes the baseline safe for the legacy database where these
    # tables already exist, and also provisions the same tables on fresh installs.
    db.metadata.create_all(
        bind=op.get_bind(),
        tables=[
            User.__table__,
            PasswordAnalysis.__table__,
            URLAnalysis.__table__,
            AttackLog.__table__,
            SystemLog.__table__,
            UserSettings.__table__,
        ],
        checkfirst=True,
    )


def downgrade():
    # The baseline represents pre-existing user data and is intentionally kept.
    pass
