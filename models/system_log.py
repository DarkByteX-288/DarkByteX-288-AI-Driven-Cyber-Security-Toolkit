"""
models/system_log.py
----------------------
Generic application/security event log (logins, failed logins, model
retraining events, errors) used for the admin/system-status view.
"""

from datetime import datetime, timezone

from . import db


class SystemLog(db.Model):
    __tablename__ = "system_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)

    event_type = db.Column(db.String(50), nullable=False)  # login, logout, failed_login, retrain, error...
    message = db.Column(db.String(500), nullable=False)
    level = db.Column(db.String(20), default="INFO")  # INFO / WARNING / ERROR
    ip_address = db.Column(db.String(45), nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f"<SystemLog {self.event_type} {self.level}>"
