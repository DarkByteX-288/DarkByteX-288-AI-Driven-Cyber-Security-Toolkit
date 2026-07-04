"""
models/url_analysis.py
------------------------
Stores the result of a phishing URL analysis.
"""

from datetime import datetime, timezone

from . import db


class URLAnalysis(db.Model):
    __tablename__ = "url_analysis"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    url = db.Column(db.String(2048), nullable=False)
    domain = db.Column(db.String(255), nullable=True)

    verdict = db.Column(db.String(20), nullable=False)   # Safe / Suspicious / Phishing
    confidence = db.Column(db.Float, nullable=False)
    threat_level = db.Column(db.String(20), nullable=False)  # Low / Medium / High / Critical

    uses_https = db.Column(db.Boolean, default=False)
    url_length = db.Column(db.Integer, nullable=True)
    domain_length = db.Column(db.Integer, nullable=True)
    subdomain_count = db.Column(db.Integer, nullable=True)
    has_ip_address = db.Column(db.Boolean, default=False)
    has_at_symbol = db.Column(db.Boolean, default=False)
    has_double_slash_redirect = db.Column(db.Boolean, default=False)
    is_shortened = db.Column(db.Boolean, default=False)
    has_suspicious_keywords = db.Column(db.Boolean, default=False)
    special_char_count = db.Column(db.Integer, nullable=True)
    tld = db.Column(db.String(30), nullable=True)

    reasons = db.Column(db.Text, nullable=True)          # JSON-encoded list
    recommendations = db.Column(db.Text, nullable=True)  # JSON-encoded list

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f"<URLAnalysis {self.id} {self.verdict}>"
