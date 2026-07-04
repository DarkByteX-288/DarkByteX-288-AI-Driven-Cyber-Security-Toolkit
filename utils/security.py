"""
utils/security.py
--------------------
Small helper functions for input validation, rate limiting keys, and
system-event logging used across route blueprints.
"""

from flask import request

from models import db
from models.system_log import SystemLog


def get_client_ip() -> str:
    """Best-effort client IP extraction, honoring a single trusted proxy hop."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def log_event(event_type: str, message: str, level: str = "INFO", user_id: int = None) -> None:
    """Persist a system/security event. Never raises - logging must never
    break the primary request flow."""
    try:
        entry = SystemLog(
            user_id=user_id,
            event_type=event_type,
            message=message[:500],
            level=level,
            ip_address=get_client_ip(),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()
