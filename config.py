"""
config.py
---------
Central configuration for BastionIX.

Uses environment variables for deployment secrets and scanner scope.
"""

import os
import secrets

from scanners.target_validation import parse_approved_networks

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration shared by every environment."""

    # --- Core Flask / security settings -----------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # --- Database ------------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'database.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Session / cookie security -------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_DURATION = 60 * 60 * 24 * 7  # 7 days

    # Set to True automatically when served over HTTPS (see app.py)
    SESSION_COOKIE_SECURE = os.environ.get("FORCE_HTTPS", "false").lower() == "true"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE

    # --- CSRF ------------------------------------------------------------------
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

    # --- ML model paths ----------------------------------------------------------
    PASSWORD_MODEL_PATH = os.path.join(BASE_DIR, "trained_models", "password_model.pkl")
    URL_MODEL_PATH = os.path.join(BASE_DIR, "trained_models", "url_model.pkl")
    PASSWORD_DATASET_PATH = os.path.join(BASE_DIR, "datasets", "password_dataset.csv")
    URL_DATASET_PATH = os.path.join(BASE_DIR, "datasets", "phishing_urls.csv")

    # --- App metadata (for Settings / About page) ---------------------------
    APP_NAME = "BastionIX"
    APP_VERSION = "1.0.0"
    APP_DESCRIPTION = "AI-Powered Cybersecurity & Network Intelligence Platform"
    APP_TAGLINE = "Intelligent Security. Continuous Visibility. Stronger Defense."
    APP_LOGGER_NAME = "bastionix"

    NMAP_PATH = os.environ.get("NMAP_PATH") or None
    SCANNER_ALLOW_LOOPBACK = (
        os.environ.get("BASTIONIX_SCANNER_ALLOW_LOOPBACK", "false").lower() == "true"
    )

    # Authorized scanner limits. Asset ranges must be explicitly configured
    # through BASTIONIX_APPROVED_NETWORKS to extend the private defaults.
    SCANNER_APPROVED_NETWORKS = parse_approved_networks(
        os.environ.get("BASTIONIX_APPROVED_NETWORKS")
    )
    SCANNER_MAX_HOSTS = int(os.environ.get("BASTIONIX_SCANNER_MAX_HOSTS", "64"))
    SCANNER_MAX_ACTIVE = int(os.environ.get("BASTIONIX_SCANNER_MAX_ACTIVE", "2"))
    SCANNER_WORKERS = int(os.environ.get("BASTIONIX_SCANNER_WORKERS", "2"))
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    AUTO_CREATE_DB = False


class DevelopmentConfig(Config):
    DEBUG = True
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    AUTO_CREATE_DB = False


class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "test-only-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    AUTO_CREATE_DB = True
    SCANNER_APPROVED_NETWORKS = parse_approved_networks(
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
    )
    SCANNER_MAX_HOSTS = 64
    SCANNER_MAX_ACTIVE = 2
    SCANNER_WORKERS = 1


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
