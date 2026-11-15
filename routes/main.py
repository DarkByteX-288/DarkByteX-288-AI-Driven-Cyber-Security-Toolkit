"""Landing page and owner-scoped security dashboard."""

from flask import Blueprint, render_template, request
from flask_login import login_required, current_user

from services.dashboard_analytics import get_dashboard_analytics

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    analytics = get_dashboard_analytics(
        current_user.id,
        time_range=request.args.get("range", "7d"),
    )
    return render_template("dashboard.html", **analytics)
