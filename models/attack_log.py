"""
models/attack_log.py
----------------------
Logs simulated attack scenarios run against a password analysis
(dictionary attack, brute force, hybrid, pattern, keyboard-walk).
No plaintext passwords are ever stored here.
"""

from datetime import datetime, timezone

from . import db


class AttackLog(db.Model):
    __tablename__ = "attack_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    password_analysis_id = db.Column(db.Integer, db.ForeignKey("password_analysis.id"), nullable=True)

    attack_type = db.Column(db.String(30), nullable=False)  # dictionary/brute_force/hybrid/pattern/keyboard_walk
    success_likelihood = db.Column(db.String(20), nullable=False)  # Very Low..Very High
    estimated_time_seconds = db.Column(db.Float, nullable=True)
    estimated_time_display = db.Column(db.String(50), nullable=True)
    details = db.Column(db.Text, nullable=True)  # JSON-encoded details

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f"<AttackLog {self.attack_type}>"
