"""
app.py
--------
Application factory for the AI Cyber Security Toolkit. Run directly with
`flask run` (after setting FLASK_APP=app.py, done automatically by the
.flaskenv) or `python app.py`.
"""

import os

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


def create_app(env=None):
    app = Flask(__name__, instance_relative_config=False)

    env = env or os.environ.get("FLASK_ENV", "development")
    app.config.from_object(config_by_name.get(env, config_by_name["development"]))

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

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(password_bp)
    app.register_blueprint(url_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(reports_bp)

    # --- Error handlers -----------------------------------------------------------
    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        db.session.rollback()
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
        return response

    # --- Template globals -----------------------------------------------------------
    @app.context_processor
    def inject_globals():
        return {"app_name": app.config["APP_NAME"], "app_version": app.config["APP_VERSION"]}

    # --- Create tables on first run --------------------------------------------------
    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=app.config.get("DEBUG", True))
