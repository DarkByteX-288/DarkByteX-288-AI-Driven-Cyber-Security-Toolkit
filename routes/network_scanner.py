"""Owner-scoped JSON API for authorized network vulnerability assessments."""

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request, send_file
from flask_login import current_user, login_required
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import SQLAlchemyError

from models import db
from models.network_scan import (
    NetworkScan, NetworkHost, NetworkPort, ScanConfiguration,
    ScanAuditLog,
    VulnerabilityFinding,
)
from scanners.target_validation import TargetValidationError, validate_scan_request
from services.network_scanner import ScannerUnavailable, nmap_status, require_nmap
from tasks.scanner_tasks import ACTIVE_STATUSES
from utils.report_generator import generate_network_scan_pdf, _safe_csv_cell

scanner_bp = Blueprint("scanner", __name__, url_prefix="/api/scans")
AUTHORIZATION_STATEMENT = (
    "I am authorized to assess the specified assets and understand this scan is limited to "
    "non-exploitative discovery and service identification."
)


class OwnerScopedNotFound(Exception):
    """Resource is absent or not owned by the current user."""


@scanner_bp.errorhandler(OwnerScopedNotFound)
def owner_scoped_not_found(_error):
    return jsonify(error="Scan or finding not found."), 404


@scanner_bp.errorhandler(SQLAlchemyError)
def scanner_database_error(error):
    db.session.rollback()
    current_app.logger.exception("BastionIX scanner database operation failed.")
    return jsonify(error="Scanner storage is unavailable. Check the database and migrations."), 503


def _owned_scan(scan_id):
    scan = NetworkScan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if scan is None:
        raise OwnerScopedNotFound()
    return scan


def _finding_payload(finding):
    return {
        "id": finding.id,
        "classification": finding.classification,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "cvss_score": finding.cvss_score,
        "cvss_version": finding.cvss_version,
        "cve_id": finding.cve_id,
        "source": finding.source,
        "references": json.loads(finding.reference_urls or "[]"),
        "remediation": finding.remediation,
        "created_at": finding.created_at.isoformat(),
    }


def _scan_payload(scan, include_results=True):
    result = {
        "id": scan.id,
        "target": scan.target,
        "resolved_targets": json.loads(scan.resolved_targets),
        "ports": json.loads(scan.ports),
        "profile": scan.profile,
        "status": scan.status,
        "progress": scan.progress,
        "phase": scan.phase,
        "error": scan.error_message,
        "created_at": scan.created_at.isoformat(),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    }
    if include_results and scan.status in {"completed", "failed", "cancelled"}:
        result["hosts"] = [
            {
                "address": host.address,
                "hostname": host.hostname,
                "state": host.state,
                "ports": [
                    {
                        "port": port.port,
                        "protocol": port.protocol,
                        "state": port.state,
                        "reason": port.reason,
                        "service": {
                            "name": port.service.name,
                            "product": port.service.product,
                            "version": port.service.version,
                            "extra_info": port.service.extra_info,
                            "cpe": port.service.cpe,
                            "vulnerability_intelligence_status": (
                                port.service.vulnerability_intelligence_status
                            ),
                        } if port.service else None,
                    }
                    for port in host.ports
                ],
            }
            for host in scan.hosts
        ]
        result["findings"] = [_finding_payload(item) for item in scan.findings]
    return result


@scanner_bp.route("/health", methods=["GET"])
@login_required
def scanner_health():
    health = nmap_status(current_app.config.get("NMAP_PATH"))
    return jsonify(scanner=health), (200 if health["status"] == "operational" else 503)


@scanner_bp.route("", methods=["POST"])
@login_required
def start_scan():
    body = request.get_json(silent=True)
    if body is None:
        return jsonify(error="A JSON request body is required."), 400
    try:
        target, ports = validate_scan_request(
            body,
            current_app.config["SCANNER_APPROVED_NETWORKS"],
            max_hosts=current_app.config["SCANNER_MAX_HOSTS"],
            allow_loopback=current_app.config["SCANNER_ALLOW_LOOPBACK"],
        )
    except TargetValidationError as exc:
        return jsonify(error=str(exc)), 400

    manager = current_app.extensions["scan_manager"]
    with current_app.extensions["scan_submission_lock"]:
        rate_window = datetime.now(timezone.utc) - timedelta(hours=1)
        recent_starts = ScanAuditLog.query.filter(
            ScanAuditLog.user_id == current_user.id,
            ScanAuditLog.event_type == "scan_authorized",
            ScanAuditLog.created_at >= rate_window,
        ).count()
        if recent_starts >= 3:
            return jsonify(error="Scan rate limit reached. Try again after the one-hour window."), 429
        active_for_user = NetworkScan.query.filter(
            NetworkScan.user_id == current_user.id,
            NetworkScan.status.in_(ACTIVE_STATUSES),
        ).count()
        active_total = NetworkScan.query.filter(
            NetworkScan.status.in_(ACTIVE_STATUSES)
        ).count()
        if active_for_user:
            return jsonify(error="You already have an active scan."), 409
        if active_total >= current_app.config["SCANNER_MAX_ACTIVE"]:
            return jsonify(error="The scanner is at capacity. Try again later."), 429
        try:
            nmap_path = current_app.config.get("NMAP_PATH")
            if nmap_path:
                require_nmap(nmap_path)
            else:
                require_nmap()
        except ScannerUnavailable as exc:
            return jsonify(error=str(exc)), 503
        scan = NetworkScan(
            user_id=current_user.id,
            target=target.submitted,
            resolved_targets=json.dumps(target.addresses),
            ports=json.dumps(ports),
            profile="safe",
            authorization_confirmed=True,
        )
        db.session.add(scan)
        db.session.flush()
        scan.configuration = ScanConfiguration(
            profile="safe",
            options=json.dumps({
                "service_detection": "Nmap -sV --version-light",
                "timing": "Nmap -T3; one retry; 60 second host timeout",
                "ports": ports,
                "max_hosts": current_app.config["SCANNER_MAX_HOSTS"],
            }),
            approved_networks=json.dumps([
                str(network) for network in current_app.config["SCANNER_APPROVED_NETWORKS"]
            ]),
            authorization_statement=AUTHORIZATION_STATEMENT,
        )
        db.session.add(ScanAuditLog(
            scan_id=scan.id,
            user_id=current_user.id,
            event_type="scan_authorized",
            details=f"Authorization confirmed for {target.submitted} ({len(target.addresses)} resolved target(s)).",
            ip_address=request.remote_addr,
        ))
        db.session.commit()
        try:
            manager.submit(scan.id)
        except RuntimeError:
            scan.status = "failed"
            scan.phase = "failed"
            scan.error_message = "The background scanner is not accepting work."
            db.session.commit()
            return jsonify(error=scan.error_message), 503
    return jsonify(scan=_scan_payload(scan, include_results=False)), 202


@scanner_bp.route("", methods=["GET"])
@login_required
def list_scans():
    page = request.args.get("page", 1, type=int)
    page = max(1, page)
    pagination = NetworkScan.query.filter_by(user_id=current_user.id).order_by(
        NetworkScan.created_at.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    return jsonify(
        scans=[_scan_payload(scan, include_results=False) for scan in pagination.items],
        page=pagination.page,
        pages=pagination.pages,
        total=pagination.total,
    )


@scanner_bp.route("/<int:scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id):
    scan = NetworkScan.query.options(
        selectinload(NetworkScan.hosts)
        .selectinload(NetworkHost.ports)
        .selectinload(NetworkPort.service)
    ).filter_by(id=scan_id, user_id=current_user.id).first()
    if scan is None:
        raise OwnerScopedNotFound()
    return jsonify(scan=_scan_payload(scan))


@scanner_bp.route("/<int:scan_id>/findings/<int:finding_id>", methods=["GET"])
@login_required
def get_finding(scan_id, finding_id):
    scan = _owned_scan(scan_id)
    finding = VulnerabilityFinding.query.filter_by(
        id=finding_id, scan_id=scan.id
    ).first()
    if finding is None:
        raise OwnerScopedNotFound()
    return jsonify(finding=_finding_payload(finding))


@scanner_bp.route("/<int:scan_id>/cancel", methods=["POST"])
@login_required
def cancel_scan(scan_id):
    scan = _owned_scan(scan_id)
    if scan.status not in ACTIVE_STATUSES:
        return jsonify(error="Only queued or running scans can be cancelled."), 409
    scan.cancel_requested = True
    manager = current_app.extensions["scan_manager"]
    signalled = manager.cancel(scan.id)
    if not signalled and scan.status == "queued":
        scan.status = "cancelled"
        scan.phase = "cancelled"
        scan.finished_at = db.func.now()
    db.session.add(ScanAuditLog(
        scan_id=scan.id,
        user_id=current_user.id,
        event_type="cancellation_requested",
        details="The owning user requested cancellation.",
        ip_address=request.remote_addr,
    ))
    db.session.commit()
    return jsonify(scan=_scan_payload(scan, include_results=False)), 202


@scanner_bp.route("/<int:scan_id>/report.csv", methods=["GET"])
@login_required
def export_scan_csv(scan_id):
    scan = _owned_scan(scan_id)
    if scan.status != "completed":
        return jsonify(error="Reports are available after a scan completes."), 409
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Host", "Port", "Protocol", "Port State", "Service", "Product", "Version",
        "Finding Type", "CVE", "Severity", "CVSS Score", "CVSS Version",
        "Description", "Remediation",
    ])
    findings = VulnerabilityFinding.query.filter_by(scan_id=scan.id).all()
    findings_by_port = {}
    for finding in findings:
        if finding.port_id is not None:
            findings_by_port.setdefault(finding.port_id, []).append(finding)
    for host in scan.hosts:
        for port in host.ports:
            service = port.service
            port_findings = findings_by_port.get(port.id) or [None]
            for finding in port_findings:
                values = [
                    host.address,
                    port.port,
                    port.protocol,
                    port.state,
                    service.name if service else "",
                    service.product if service else "",
                    service.version if service else "",
                    finding.classification if finding else "",
                    (finding.cve_id or "") if finding else "",
                    finding.severity if finding else "",
                    (
                        finding.cvss_score
                        if finding and finding.cvss_score is not None
                        else ""
                    ),
                    (finding.cvss_version or "") if finding else "",
                    finding.description if finding else "",
                    finding.remediation if finding else "",
                ]
                writer.writerow([_safe_csv_cell(value) for value in values])
    buffer = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"bastionix_scan_{scan.id}.csv",
    )


@scanner_bp.route("/<int:scan_id>/report.pdf", methods=["GET"])
@login_required
def export_scan_pdf(scan_id):
    scan = _owned_scan(scan_id)
    if scan.status != "completed":
        return jsonify(error="Reports are available after a scan completes."), 409
    findings = VulnerabilityFinding.query.filter_by(scan_id=scan.id).all()
    buffer = generate_network_scan_pdf(scan, findings)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"bastionix_scan_{scan.id}.pdf",
    )
