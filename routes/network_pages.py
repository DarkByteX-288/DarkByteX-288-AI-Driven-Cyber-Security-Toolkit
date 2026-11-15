"""Owner-scoped network finding and scan-history pages."""

import json
from urllib.parse import urlsplit

from flask import Blueprint, request, render_template
from flask_login import current_user, login_required
from sqlalchemy import case, func, or_
from sqlalchemy.orm import selectinload

from models.network_scan import (
    NetworkHost,
    NetworkPort,
    NetworkScan,
    VulnerabilityFinding,
)


network_pages_bp = Blueprint("network_pages", __name__)

SEVERITIES = ("critical", "high", "medium", "low", "informational")
SORTS = {
    "recent": VulnerabilityFinding.created_at.desc(),
    "oldest": VulnerabilityFinding.created_at.asc(),
    "severity": case(
        (func.lower(VulnerabilityFinding.severity) == "critical", 0),
        (func.lower(VulnerabilityFinding.severity) == "high", 1),
        (func.lower(VulnerabilityFinding.severity) == "medium", 2),
        (func.lower(VulnerabilityFinding.severity) == "low", 3),
        else_=4,
    ),
    "cvss": VulnerabilityFinding.cvss_score.desc(),
}
SCAN_STATUSES = ("queued", "running", "completed", "failed", "cancelled")
SCAN_SORTS = {
    "recent": NetworkScan.created_at.desc(),
    "oldest": NetworkScan.created_at.asc(),
    "target": func.lower(NetworkScan.target),
    "status": case(
        (NetworkScan.status == "running", 0),
        (NetworkScan.status == "queued", 1),
        (NetworkScan.status == "failed", 2),
        (NetworkScan.status == "cancelled", 3),
        else_=4,
    ),
}


@network_pages_bp.route("/vulnerabilities")
@login_required
def vulnerabilities():
    search = request.args.get("q", "").strip()[:120]
    severity = request.args.get("severity", "").lower()
    sort_key = request.args.get("sort", "recent")
    page = max(request.args.get("page", 1, type=int), 1)

    owned = VulnerabilityFinding.query.join(NetworkScan).filter(
        NetworkScan.user_id == current_user.id
    )
    if search:
        pattern = f"%{search}%"
        owned = owned.filter(or_(
            VulnerabilityFinding.cve_id.ilike(pattern),
            VulnerabilityFinding.title.ilike(pattern),
            VulnerabilityFinding.description.ilike(pattern),
        ))
    if severity in SEVERITIES:
        owned = owned.filter(func.lower(VulnerabilityFinding.severity) == severity)
    elif severity:
        severity = ""

    summary_query = (
        VulnerabilityFinding.query.join(NetworkScan)
        .filter(NetworkScan.user_id == current_user.id)
    )
    severity_counts = dict(
        summary_query.with_entities(
            func.lower(VulnerabilityFinding.severity), func.count()
        ).group_by(func.lower(VulnerabilityFinding.severity)).all()
    )
    findings = (
        owned.options(
            selectinload(VulnerabilityFinding.scan),
            selectinload(VulnerabilityFinding.port).selectinload(NetworkPort.host),
            selectinload(VulnerabilityFinding.port).selectinload(NetworkPort.service),
        )
        .order_by(
            SORTS.get(sort_key, SORTS["recent"]),
            VulnerabilityFinding.id.desc(),
        )
        .paginate(page=page, per_page=20, error_out=False)
    )
    for finding in findings.items:
        try:
            references = json.loads(finding.reference_urls or "[]")
        except (json.JSONDecodeError, TypeError):
            references = []
        finding.safe_references = [
            link for link in references
            if isinstance(link, str) and urlsplit(link).scheme == "https"
        ]
    return render_template(
        "vulnerabilities.html",
        findings=findings,
        search=search,
        severity=severity,
        sort_key=sort_key if sort_key in SORTS else "recent",
        severity_counts=severity_counts,
        total_findings=summary_query.count(),
        critical_findings=severity_counts.get("critical", 0),
        potential_findings=summary_query.filter(
            VulnerabilityFinding.classification == "potential"
        ).count(),
    )


@network_pages_bp.route("/scan-history")
@login_required
def scan_history():
    search = request.args.get("q", "").strip()[:120]
    status = request.args.get("status", "").lower()
    sort_key = request.args.get("sort", "recent")
    page = max(request.args.get("page", 1, type=int), 1)
    owned = NetworkScan.query.filter_by(user_id=current_user.id)
    if search:
        owned = owned.filter(NetworkScan.target.ilike(f"%{search}%"))
    if status in SCAN_STATUSES:
        owned = owned.filter(NetworkScan.status == status)
    elif status:
        status = ""

    scans = (
        owned.options(
            selectinload(NetworkScan.hosts).selectinload(NetworkHost.ports),
            selectinload(NetworkScan.findings),
        )
        .order_by(
            SCAN_SORTS.get(sort_key, SCAN_SORTS["recent"]),
            NetworkScan.id.desc(),
        )
        .paginate(page=page, per_page=20, error_out=False)
    )
    return render_template(
        "scan_history.html",
        scans=scans,
        search=search,
        status=status,
        sort_key=sort_key if sort_key in SCAN_SORTS else "recent",
        statuses=SCAN_STATUSES,
    )
