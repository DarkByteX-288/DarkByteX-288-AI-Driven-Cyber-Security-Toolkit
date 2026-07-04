"""
routes/settings.py
---------------------
Application settings: dark/light mode, data export, history clearing,
AI model retraining, and database/application information.
"""

import os

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user

from models import db
from models.password_analysis import PasswordAnalysis
from models.url_analysis import URLAnalysis
from models.attack_log import AttackLog
from models.settings import UserSettings
from models.user import User
from utils.security import log_event
from ml.model_loader import retrain_password_model, retrain_url_model

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings")
@login_required
def settings():
    user_settings = current_user.settings
    if user_settings is None:
        user_settings = UserSettings(user_id=current_user.id, theme="dark")
        db.session.add(user_settings)
        db.session.commit()

    db_path = current_app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
    db_size_kb = round(os.path.getsize(db_path) / 1024, 1) if os.path.exists(db_path) else 0

    db_info = {
        "engine": "SQLite",
        "path": db_path,
        "size_kb": db_size_kb,
        "total_users": User.query.count(),
    }

    app_info = {
        "name": current_app.config["APP_NAME"],
        "version": current_app.config["APP_VERSION"],
    }

    return render_template("settings.html", user_settings=user_settings, db_info=db_info, app_info=app_info)


@settings_bp.route("/settings/theme", methods=["POST"])
@login_required
def update_theme():
    theme = request.form.get("theme", "dark")
    if theme not in ("dark", "light"):
        theme = "dark"
    user_settings = current_user.settings
    if user_settings is None:
        user_settings = UserSettings(user_id=current_user.id)
        db.session.add(user_settings)
    user_settings.theme = theme
    db.session.commit()
    flash(f"Theme switched to {theme} mode.", "success")
    return redirect(url_for("settings.settings"))


@settings_bp.route("/settings/clear-history", methods=["POST"])
@login_required
def clear_history():
    AttackLog.query.filter_by(user_id=current_user.id).delete()
    PasswordAnalysis.query.filter_by(user_id=current_user.id).delete()
    URLAnalysis.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    log_event("clear_history", f"User cleared history: {current_user.username}", user_id=current_user.id)
    flash("Your analysis history has been cleared.", "info")
    return redirect(url_for("settings.settings"))


@settings_bp.route("/settings/retrain", methods=["POST"])
@login_required
def retrain_models():
    target = request.form.get("target", "both")
    try:
        if target in ("password", "both"):
            retrain_password_model()
        if target in ("url", "both"):
            retrain_url_model()
        log_event("retrain", f"Models retrained ({target}) by {current_user.username}", user_id=current_user.id)
        flash("AI model(s) retrained successfully.", "success")
    except Exception as exc:
        log_event("error", f"Retrain failed: {exc}", level="ERROR", user_id=current_user.id)
        flash("Model retraining failed. Check server logs for details.", "danger")
    return redirect(url_for("settings.settings"))
