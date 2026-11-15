"""
routes/reports.py
--------------------
Downloadable report generation: PDF and CSV for password analyses, URL
analyses, and the overall security summary.
"""

import csv
import io

from flask import Blueprint, render_template, send_file
from flask_login import login_required, current_user
from sqlalchemy.orm import selectinload

from models.network_scan import NetworkHost, NetworkPort, NetworkScan, VulnerabilityFinding
from models.password_analysis import PasswordAnalysis
from models.url_analysis import URLAnalysis
from utils.report_generator import (
    _safe_csv_cell,
    generate_password_csv,
    generate_url_csv,
    generate_security_pdf,
)

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports")
@login_required
def report_center():
    passwords = PasswordAnalysis.query.filter_by(user_id=current_user.id)
    urls = URLAnalysis.query.filter_by(user_id=current_user.id)
    scans = NetworkScan.query.filter_by(user_id=current_user.id).order_by(
        NetworkScan.created_at.desc()
    ).limit(10).all()
    return render_template(
        "reports.html",
        password_count=passwords.count(),
        url_count=urls.count(),
        finding_count=(
            VulnerabilityFinding.query.join(NetworkScan)
            .filter(NetworkScan.user_id == current_user.id)
            .count()
        ),
        latest_password=passwords.order_by(PasswordAnalysis.created_at.desc()).first(),
        latest_url=urls.order_by(URLAnalysis.created_at.desc()).first(),
        scans=scans,
    )


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


@reports_bp.route("/reports/vulnerabilities/csv")
@login_required
def vulnerability_csv():
    findings = (
        VulnerabilityFinding.query.join(NetworkScan)
        .filter(NetworkScan.user_id == current_user.id)
        .options(
            selectinload(VulnerabilityFinding.scan),
            selectinload(VulnerabilityFinding.port).selectinload(NetworkPort.host),
            selectinload(VulnerabilityFinding.port).selectinload(NetworkPort.service),
        )
        .order_by(VulnerabilityFinding.created_at.desc())
        .all()
    )
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow([
        "Classification", "CVE", "Title", "Severity", "CVSS", "Target",
        "Service", "Version", "Description", "Remediation", "Created",
    ])
    for finding in findings:
        port = finding.port
        host = port.host if port else None
        service = port.service if port else None
        writer.writerow([
            _safe_csv_cell(finding.classification),
            _safe_csv_cell(finding.cve_id or ""),
            _safe_csv_cell(finding.title),
            _safe_csv_cell(finding.severity),
            _safe_csv_cell(finding.cvss_score if finding.cvss_score is not None else ""),
            _safe_csv_cell(host.address if host else finding.scan.target),
            _safe_csv_cell((service.product or service.name) if service else ""),
            _safe_csv_cell(service.version if service else ""),
            _safe_csv_cell(finding.description),
            _safe_csv_cell(finding.remediation),
            _safe_csv_cell(finding.created_at.isoformat()),
        ])
    output = io.BytesIO(buffer.getvalue().encode("utf-8-sig"))
    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name="vulnerability_findings.csv",
    )
