"""
models/settings.py
--------------------
Per-user application preferences (theme, etc).
"""

from . import db


class UserSettings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)

    theme = db.Column(db.String(10), default="dark")  # 'dark' or 'light'
    email_notifications = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<UserSettings user_id={self.user_id} theme={self.theme}>"
