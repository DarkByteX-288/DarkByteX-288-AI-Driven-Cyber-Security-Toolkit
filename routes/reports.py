"""
routes/reports.py
--------------------
Downloadable report generation: PDF and CSV for password analyses, URL
analyses, and the overall security summary.
"""

from flask import Blueprint, send_file
from flask_login import login_required, current_user

from models.password_analysis import PasswordAnalysis
from models.url_analysis import URLAnalysis
from utils.report_generator import generate_password_csv, generate_url_csv, generate_security_pdf

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports/password/csv")
@login_required
def password_csv():
    analyses = PasswordAnalysis.query.filter_by(user_id=current_user.id).order_by(
        PasswordAnalysis.created_at.desc()
    ).all()
    buffer = generate_password_csv(analyses)
    return send_file(
        buffer, mimetype="text/csv", as_attachment=True, download_name="password_analysis_report.csv"
    )


@reports_bp.route("/reports/url/csv")
@login_required
def url_csv():
    analyses = URLAnalysis.query.filter_by(user_id=current_user.id).order_by(
        URLAnalysis.created_at.desc()
    ).all()
    buffer = generate_url_csv(analyses)
    return send_file(
        buffer, mimetype="text/csv", as_attachment=True, download_name="url_analysis_report.csv"
    )


@reports_bp.route("/reports/security/pdf")
@login_required
def security_pdf():
    pwd_analyses = PasswordAnalysis.query.filter_by(user_id=current_user.id)
    url_analyses = URLAnalysis.query.filter_by(user_id=current_user.id)

    total_password = pwd_analyses.count()
    total_url = url_analyses.count()
    weak = pwd_analyses.filter(PasswordAnalysis.strength_category.in_(["Very Weak", "Weak"])).count()
    strong = pwd_analyses.filter(PasswordAnalysis.strength_category.in_(["Strong", "Very Strong"])).count()
    phishing = url_analyses.filter(URLAnalysis.verdict == "Phishing").count()
    safe = url_analyses.filter(URLAnalysis.verdict == "Safe").count()

    stats = {
        "Total Password Analyses": total_password,
        "Total URL Analyses": total_url,
        "Weak Passwords": weak,
        "Strong Passwords": strong,
        "Detected Phishing URLs": phishing,
        "Safe URLs": safe,
    }

    recent_pwd = pwd_analyses.order_by(PasswordAnalysis.created_at.desc()).limit(10).all()
    recent_url = url_analyses.order_by(URLAnalysis.created_at.desc()).limit(10).all()

    buffer = generate_security_pdf(stats, recent_pwd, recent_url, current_user.username)
    return send_file(
        buffer, mimetype="application/pdf", as_attachment=True, download_name="security_report.pdf"
    )
