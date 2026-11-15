"""
routes/history.py
--------------------
Analysis history: browse, search, filter, and delete past password and URL
analyses belonging to the current user.
"""

import json

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from models import db
from models.password_analysis import PasswordAnalysis
from models.url_analysis import URLAnalysis

history_bp = Blueprint("history", __name__)


@history_bp.route("/history")
@login_required
def history():
    tab = request.args.get("tab", "password")
    if tab not in {"password", "url"}:
        tab = "password"
    query = request.args.get("q", "").strip()
    category_filter = request.args.get("category", "")
    page = max(request.args.get("page", 1, type=int), 1)

    pwd_query = PasswordAnalysis.query.filter_by(user_id=current_user.id)
    url_query = URLAnalysis.query.filter_by(user_id=current_user.id)

    if tab == "password" and category_filter:
        pwd_query = pwd_query.filter(PasswordAnalysis.strength_category == category_filter)
    if tab == "url" and category_filter:
        url_query = url_query.filter(URLAnalysis.verdict == category_filter)

    if tab == "url" and query:
        url_query = url_query.filter(URLAnalysis.url.ilike(f"%{query}%"))

    password_pagination = pwd_query.order_by(
        PasswordAnalysis.created_at.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    url_pagination = url_query.order_by(
        URLAnalysis.created_at.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    pwd_analyses = password_pagination.items
    url_analyses = url_pagination.items

    # Attach parsed recommendations for display
    for a in pwd_analyses:
        try:
            a.recommendations_list = json.loads(a.recommendations or "[]")
        except (json.JSONDecodeError, TypeError):
            a.recommendations_list = []

    for a in url_analyses:
        try:
            a.reasons_list = json.loads(a.reasons or "[]")
        except (json.JSONDecodeError, TypeError):
            a.reasons_list = []

    return render_template(
        "history.html",
        tab=tab,
        query=query,
        category_filter=category_filter,
        password_pagination=password_pagination,
        url_pagination=url_pagination,
        pwd_analyses=pwd_analyses,
        url_analyses=url_analyses,
    )


@history_bp.route("/history/password/<int:analysis_id>/delete", methods=["POST"])
@login_required
def delete_password_analysis(analysis_id):
    analysis = PasswordAnalysis.query.filter_by(id=analysis_id, user_id=current_user.id).first_or_404()
    db.session.delete(analysis)
    db.session.commit()
    flash("Password analysis deleted.", "info")
    return redirect(url_for("history.history", tab="password"))


@history_bp.route("/history/url/<int:analysis_id>/delete", methods=["POST"])
@login_required
def delete_url_analysis(analysis_id):
    analysis = URLAnalysis.query.filter_by(id=analysis_id, user_id=current_user.id).first_or_404()
    db.session.delete(analysis)
    db.session.commit()
    flash("URL analysis deleted.", "info")
    return redirect(url_for("history.history", tab="url"))
