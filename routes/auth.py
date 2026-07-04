"""
routes/auth.py
-----------------
Authentication blueprint: registration, login, logout, and profile.
"""

from datetime import datetime, timezone

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from models import db
from models.user import User
from models.settings import UserSettings
from utils.forms import RegistrationForm, LoginForm
from utils.security import log_event

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        existing = User.query.filter(
            (User.username == form.username.data) | (User.email == form.email.data)
        ).first()
        if existing:
            flash("A user with that username or email already exists.", "danger")
            return render_template("register.html", form=form)

        user = User(username=form.username.data.strip(), email=form.email.data.strip().lower())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()  # obtain user.id before commit

        settings = UserSettings(user_id=user.id, theme="dark")
        db.session.add(settings)
        db.session.commit()

        log_event("register", f"New user registered: {user.username}", user_id=user.id)
        flash("Account created successfully. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.username.data.strip()
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(form.password.data) and user.is_active_account:
            login_user(user, remember=form.remember_me.data)
            user.last_login_at = datetime.now(timezone.utc)
            db.session.commit()
            log_event("login", f"User logged in: {user.username}", user_id=user.id)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("main.dashboard"))

        log_event("failed_login", f"Failed login attempt for identifier: {identifier}", level="WARNING")
        flash("Invalid credentials. Please try again.", "danger")

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    log_event("logout", f"User logged out: {current_user.username}", user_id=current_user.id)
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)
