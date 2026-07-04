"""
routes/main.py
-----------------
Landing page and the main security dashboard, including aggregated
statistics used to power the Chart.js visualizations.
"""

import json
from collections import Counter

from flask import Blueprint, render_template
from flask_login import login_required, current_user

from models.password_analysis import PasswordAnalysis
from models.url_analysis import URLAnalysis

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    pwd_analyses = PasswordAnalysis.query.filter_by(user_id=current_user.id)
    url_analyses = URLAnalysis.query.filter_by(user_id=current_user.id)

    total_password = pwd_analyses.count()
    total_url = url_analyses.count()

    weak_categories = {"Very Weak", "Weak"}
    strong_categories = {"Strong", "Very Strong"}
    weak_passwords = pwd_analyses.filter(
        PasswordAnalysis.strength_category.in_(weak_categories)
    ).count()
    strong_passwords = pwd_analyses.filter(
        PasswordAnalysis.strength_category.in_(strong_categories)
    ).count()

    phishing_urls = url_analyses.filter(URLAnalysis.verdict == "Phishing").count()
    safe_urls = url_analyses.filter(URLAnalysis.verdict == "Safe").count()

    # Risk distribution for pie/bar chart
    category_counts = Counter(a.strength_category for a in pwd_analyses.all())
    verdict_counts = Counter(a.verdict for a in url_analyses.all())

    # Line chart: analyses over time (last 14 entries by date, simplified)
    recent_pwd = pwd_analyses.order_by(PasswordAnalysis.created_at.desc()).limit(10).all()
    recent_url = url_analyses.order_by(URLAnalysis.created_at.desc()).limit(10).all()

    avg_score = (
        sum(a.strength_score for a in pwd_analyses.all()) / total_password
        if total_password else 0
    )

    # Simple composite security score (0-100): rewards strong passwords &
    # safe URLs, penalizes weak passwords & phishing hits.
    security_score = 100
    if total_password:
        security_score -= (weak_passwords / total_password) * 40
    if total_url:
        security_score -= (phishing_urls / total_url) * 40
    security_score = max(0, round(security_score))

    stats = {
        "total_password": total_password,
        "total_url": total_url,
        "weak_passwords": weak_passwords,
        "strong_passwords": strong_passwords,
        "phishing_urls": phishing_urls,
        "safe_urls": safe_urls,
        "avg_score": round(avg_score, 1),
        "security_score": security_score,
    }

    chart_data = {
        "category_labels": list(category_counts.keys()),
        "category_values": list(category_counts.values()),
        "verdict_labels": list(verdict_counts.keys()),
        "verdict_values": list(verdict_counts.values()),
    }

    return render_template(
        "dashboard.html",
        stats=stats,
        chart_data=json.dumps(chart_data),
        recent_pwd=recent_pwd,
        recent_url=recent_url,
    )
