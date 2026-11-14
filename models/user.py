"""
models/user.py
----------------
User account model. Passwords are NEVER stored in plaintext - only a salted
Werkzeug hash is persisted.
"""

from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from . import db


class User(UserMixin, db.Model):
    """Represents an authenticated application user."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login_at = db.Column(db.DateTime, nullable=True)
    is_active_account = db.Column(db.Boolean, default=True)

    # Relationships
    password_analyses = db.relationship(
        "PasswordAnalysis", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )
    url_analyses = db.relationship(
        "URLAnalysis", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )
    attack_logs = db.relationship(
        "AttackLog", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )
    settings = db.relationship(
        "UserSettings", backref="user", uselist=False, cascade="all, delete-orphan"
    )
    network_scans = db.relationship(
        "NetworkScan", back_populates="user", cascade="all, delete-orphan"
    )

    # --- Password helpers ----------------------------------------------------
    def set_password(self, raw_password: str) -> None:
        """Hash and store a password. Uses PBKDF2-SHA256 via Werkzeug."""
        self.password_hash = generate_password_hash(raw_password, method="pbkdf2:sha256", salt_length=16)

    def check_password(self, raw_password: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, raw_password)

    # Flask-Login required property
    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"<User {self.username}>"
