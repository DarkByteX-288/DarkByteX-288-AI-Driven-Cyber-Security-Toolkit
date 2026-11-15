"""
app.py
--------
Application factory for BastionIX. Run directly with
`flask run` for local development after copying `.env.example` to `.env`,
or import `app:app` with explicit production environment variables.
"""

import logging
import os
import threading

from flask import Flask, render_template
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import config_by_name
from models import db
from models.user import User

login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger("bastionix.app")


def create_app(env=None):
    app = Flask(__name__, instance_relative_config=False)

    env = env or os.environ.get("FLASK_ENV") or "production"
    if env not in config_by_name:
        raise ValueError(f"Unknown application environment: {env}")
    app.config.from_object(config_by_name[env])
    if env == "production":
        secret_key = os.environ.get("SECRET_KEY")
        flask_debug = os.environ.get("FLASK_DEBUG", "").lower()
        known_weak_secrets = {
            "development-only-not-for-production",
            "test-only-secret",
        }
        if flask_debug in {"1", "true", "yes", "on"}:
            raise RuntimeError("FLASK_DEBUG must be disabled in production.")
        if (
            not isinstance(secret_key, str)
            or len(secret_key) < 32
            or secret_key in known_weak_secrets
        ):
            raise RuntimeError(
                "Production requires an environment-provided SECRET_KEY "
                "of at least 32 characters."
            )
        app.config["SECRET_KEY"] = secret_key
        app.config["DEBUG"] = False
    if app.config["SCANNER_MAX_HOSTS"] < 1 or app.config["SCANNER_MAX_HOSTS"] > 256:
        raise RuntimeError("BASTIONIX_SCANNER_MAX_HOSTS must be between 1 and 256.")
    if (
        app.config["SCANNER_MAX_ACTIVE"] < 1
        or app.config["SCANNER_MAX_ACTIVE"] > 16
        or app.config["SCANNER_WORKERS"] < 1
        or app.config["SCANNER_WORKERS"] > 8
    ):
        raise RuntimeError("Scanner concurrency must be at most 16 active scans and 8 workers.")

    # Ensure instance folder exists for the SQLite file
    os.makedirs(os.path.join(app.root_path, "instance"), exist_ok=True)
    os.makedirs(os.path.join(app.root_path, "trained_models"), exist_ok=True)
    os.makedirs(os.path.join(app.root_path, "datasets"), exist_ok=True)

    # --- Extensions -------------------------------------------------------------
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # --- Blueprints ---------------------------------------------------------------
    from routes.auth import auth_bp
    from routes.main import main_bp
    from routes.password_checker import password_bp
    from routes.url_checker import url_bp
    from routes.history import history_bp
    from routes.settings import settings_bp
    from routes.reports import reports_bp
    from routes.network_scanner import scanner_bp
    from routes.network_scanner_page import scanner_pages_bp
    from routes.network_pages import network_pages_bp
    from routes.attack_simulation import attack_simulation_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(password_bp)
    app.register_blueprint(url_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(scanner_pages_bp)
    app.register_blueprint(network_pages_bp)
    app.register_blueprint(attack_simulation_bp)
    app.extensions["scan_submission_lock"] = threading.RLock()
    from tasks.scanner_tasks import init_scan_manager
    init_scan_manager(app)

    # --- Error handlers -----------------------------------------------------------
    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        db.session.rollback()
        logger.error(
            "Unhandled BastionIX request error.",
            exc_info=(type(e), e, e.__traceback__),
        )
        return render_template("500.html"), 500

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template("500.html", message="Too many requests. Please slow down."), 429

    # --- Security headers -----------------------------------------------------------
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # --- Template globals -----------------------------------------------------------
    @app.context_processor
    def inject_globals():
        return {
            "app_name": app.config["APP_NAME"],
            "app_version": app.config["APP_VERSION"],
            "app_description": app.config["APP_DESCRIPTION"],
            "app_tagline": app.config["APP_TAGLINE"],
        }

    # Development/testing bootstrap retains the existing no-migration startup;
    # production schema changes are applied with `flask db upgrade`.
    if app.config["AUTO_CREATE_DB"]:
        with app.app_context():
            db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=bool(app.config.get("DEBUG", False)))
