"""
models/password_analysis.py
-----------------------------
Stores the RESULT of a password strength analysis. The raw password itself is
NEVER persisted - only derived, non-reversible metrics.
"""

from datetime import datetime, timezone

from . import db


class PasswordAnalysis(db.Model):
    __tablename__ = "password_analysis"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    # Derived / non-reversible data only
    password_length = db.Column(db.Integer, nullable=False)
    entropy = db.Column(db.Float, nullable=False)
    strength_score = db.Column(db.Float, nullable=False)   # 0-100
    strength_category = db.Column(db.String(20), nullable=False)  # Very Weak..Very Strong
    ml_prediction = db.Column(db.String(20), nullable=True)
    ml_confidence = db.Column(db.Float, nullable=True)

    has_upper = db.Column(db.Boolean, default=False)
    has_lower = db.Column(db.Boolean, default=False)
    has_digit = db.Column(db.Boolean, default=False)
    has_symbol = db.Column(db.Boolean, default=False)

    is_dictionary_word = db.Column(db.Boolean, default=False)
    is_keyboard_pattern = db.Column(db.Boolean, default=False)
    has_repeated_chars = db.Column(db.Boolean, default=False)
    has_sequential_chars = db.Column(db.Boolean, default=False)
    has_common_substitution = db.Column(db.Boolean, default=False)

    estimated_crack_time_seconds = db.Column(db.Float, nullable=True)
    estimated_crack_time_display = db.Column(db.String(50), nullable=True)

    recommendations = db.Column(db.Text, nullable=True)  # JSON-encoded list

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f"<PasswordAnalysis {self.id} {self.strength_category}>"
