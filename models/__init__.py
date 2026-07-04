"""
models package
---------------
Exposes the SQLAlchemy `db` instance and all ORM models used across the
application. Models are intentionally kept free of Flask request context so
they can be unit-tested in isolation.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Import models AFTER `db` is defined to avoid circular imports.
from .user import User               # noqa: E402,F401
from .password_analysis import PasswordAnalysis   # noqa: E402,F401
from .url_analysis import URLAnalysis             # noqa: E402,F401
from .attack_log import AttackLog                 # noqa: E402,F401
from .system_log import SystemLog                 # noqa: E402,F401
from .settings import UserSettings                # noqa: E402,F401
