"""
utils/security.py
--------------------
Small helper functions for input validation, rate limiting keys, and
system-event logging used across route blueprints.
"""

import logging

from flask import request

from models import db
from models.system_log import SystemLog

logger = logging.getLogger("bastionix.security")


def get_client_ip() -> str:
    """Return the transport peer address; forwarded headers are untrusted by default."""
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
        logger.exception("Could not persist a BastionIX security event.")
