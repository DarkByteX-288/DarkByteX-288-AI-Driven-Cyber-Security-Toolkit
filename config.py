"""
config.py
---------
Central configuration for the AI Cyber Security Toolkit.

Uses environment variables where possible so secrets never live in source
control. Falls back to safe development defaults.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration shared by every environment."""

    # --- Core Flask / security settings -----------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

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

    # --- Rate limiting ---------------------------------------------------------
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STORAGE_URI = "memory://"

    # --- ML model paths ----------------------------------------------------------
    PASSWORD_MODEL_PATH = os.path.join(BASE_DIR, "trained_models", "password_model.pkl")
    URL_MODEL_PATH = os.path.join(BASE_DIR, "trained_models", "url_model.pkl")
    PASSWORD_DATASET_PATH = os.path.join(BASE_DIR, "datasets", "password_dataset.csv")
    URL_DATASET_PATH = os.path.join(BASE_DIR, "datasets", "phishing_urls.csv")

    # --- App metadata (for Settings / About page) ---------------------------
    APP_NAME = "AI Cyber Security Toolkit"
    APP_VERSION = "1.0.0"


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
