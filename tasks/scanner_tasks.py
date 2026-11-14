"""Persisted scan lifecycle backed by a bounded worker pool."""

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from flask import current_app

from models import db
from models.network_scan import (
    CVEReference,
    DetectedService,
    NetworkHost,
    NetworkPort,
    NetworkScan,
    ScanAuditLog,
    VulnerabilityFinding,
)
from scanners.target_validation import validate_target
from services.network_scanner import (
    ScanCancelled,
    ScannerUnavailable,
    normalize_results,
    run_nmap_scan,
)

logger = logging.getLogger("bastionix.scanner_tasks")
ACTIVE_STATUSES = ("queued", "running")


def _utcnow():
    return datetime.now(timezone.utc)


def _audit(scan, event_type, details, ip_address=None):
    db.session.add(ScanAuditLog(
        scan_id=scan.id,
        user_id=scan.user_id,
        event_type=event_type,
        details=details[:1000],
        ip_address=ip_address,
    ))


def _failure_message(error):
    if isinstance(error, ScannerUnavailable):
        return str(error)
    if isinstance(error, TimeoutError):
        return "The scan exceeded its configured timeout."
    if isinstance(error, ValueError):
        return str(error)[:500]
    if isinstance(error, RuntimeError):
        return "Nmap scan execution failed."
    return "The scanner operation failed. Check the server logs for details."


class ScanTaskManager:
    def __init__(self, app):
        self.app = app
        self.executor = ThreadPoolExecutor(
            max_workers=app.config["SCANNER_WORKERS"],
            thread_name_prefix="bastionix-scan",
        )
        self._events = {}
        self._lock = threading.RLock()

    def submit(self, scan_id):
        with self._lock:
            event = threading.Event()
            self._events[scan_id] = event
            try:
                self.executor.submit(self._run, scan_id, event)
            except RuntimeError:
                self._events.pop(scan_id, None)
                raise

    def cancel(self, scan_id):
        with self._lock:
            event = self._events.get(scan_id)
            if event is None:
                return False
            event.set()
            return True

    def _progress(self, scan_id, phase, value):
        scan = db.session.get(NetworkScan, scan_id)
        if scan is None or scan.cancel_requested:
            return
        scan.phase = phase
        scan.progress = min(99, max(scan.progress, int(value)))
        db.session.commit()

    def _run(self, scan_id, cancel_event):
        try:
            with self.app.app_context():
                scan = db.session.get(NetworkScan, scan_id)
                if scan is None or scan.status != "queued":
                    return
                if cancel_event.is_set():
                    scan.status = "cancelled"
                    scan.phase = "cancelled"
                    scan.finished_at = _utcnow()
                    _audit(scan, "scan_cancelled", "Scan cancelled before execution.")
                    db.session.commit()
                    return
                scan.status = "running"
                scan.phase = "host_discovery_and_service_detection"
                scan.progress = 1
                scan.started_at = _utcnow()
                db.session.commit()
                _audit(scan, "scan_started", "Authorized safe-profile network scan started.")
                db.session.commit()

                approved_networks = self.app.config["SCANNER_APPROVED_NETWORKS"]
                target = validate_target(
                    scan.target,
                    approved_networks,
                    max_hosts=self.app.config["SCANNER_MAX_HOSTS"],
                    allow_loopback=self.app.config["SCANNER_ALLOW_LOOPBACK"],
                )
                addresses = list(target.addresses)
                if addresses != json.loads(scan.resolved_targets):
                    raise ValueError("Resolved target addresses changed after authorization.")

                nmap_path = self.app.config.get("NMAP_PATH")
                scan_args = (
                    addresses,
                    json.loads(scan.ports),
                    lambda completed, total: self._progress(
                        scan_id,
                        "host_discovery_and_service_detection",
                        5 + int(70 * completed / max(total, 1)),
                    ),
                    cancel_event,
                )
                raw_results = (
                    run_nmap_scan(*scan_args, nmap_path=nmap_path)
                    if nmap_path
                    else run_nmap_scan(*scan_args)
                )
                scan = db.session.get(NetworkScan, scan_id)
                scan.phase = "vulnerability_intelligence"
                scan.progress = 78
                db.session.commit()
                normalized = normalize_results(
                    raw_results,
                    lambda completed, total: self._progress(
                        scan_id,
                        "vulnerability_intelligence",
                        78 + int(20 * completed / max(total, 1)),
                    ),
                    cancel_event,
                )
                if cancel_event.is_set():
                    raise ScanCancelled()
                self._persist_results(scan_id, normalized)
        except ScanCancelled:
            with self.app.app_context():
                scan = db.session.get(NetworkScan, scan_id)
                if scan:
                    scan.status = "cancelled"
                    scan.phase = "cancelled"
                    scan.finished_at = _utcnow()
                    _audit(scan, "scan_cancelled", "Scan cancelled by the owning user.")
                    db.session.commit()
        except (ScannerUnavailable, TimeoutError, ValueError, OSError) as exc:
            logger.warning("BastionIX scan %s failed: %s", scan_id, type(exc).__name__)
            self._mark_failed(scan_id, exc)
        except Exception as exc:
            logger.exception("Unexpected BastionIX scan failure for scan %s.", scan_id)
            self._mark_failed(scan_id, exc)
        finally:
            with self._lock:
                self._events.pop(scan_id, None)

    def _persist_results(self, scan_id, hosts):
        scan = db.session.get(NetworkScan, scan_id)
        if scan is None:
            return
        for result in hosts:
            host = NetworkHost(
                scan_id=scan_id,
                address=result["address"],
                hostname=result.get("hostname"),
                state=result.get("state", "unknown"),
            )
            db.session.add(host)
            db.session.flush()
            for result_port in result.get("ports", []):
                port = NetworkPort(
                    host_id=host.id,
                    port=result_port["port"],
                    protocol=result_port["protocol"],
                    state=result_port["state"],
                    reason=result_port.get("reason"),
                )
                db.session.add(port)
                db.session.flush()
                service = DetectedService(
                    port_id=port.id,
                    name=result_port.get("name"),
                    product=result_port.get("product"),
                    version=result_port.get("version"),
                    extra_info=result_port.get("extra_info"),
                    cpe=result_port.get("cpe"),
                    confidence=result_port.get("confidence"),
                    vulnerability_intelligence_status=result_port.get(
                        "vulnerability_intelligence_status", "not_applicable"
                    ),
                )
                db.session.add(service)
                if port.state != "open":
                    continue
                db.session.add(VulnerabilityFinding(
                    scan_id=scan_id,
                    port_id=port.id,
                    classification="informational",
                    title=f"Open TCP port {port.port}",
                    description=(
                        f"TCP port {port.port} is open. Service fingerprint: "
                        f"{service.product or service.name or 'unknown'} "
                        f"{service.version or ''}".strip()
                    ),
                    severity="Informational",
                    source="Nmap service detection",
                    reference_urls="[]",
                    remediation="Review whether this service and network exposure are required; restrict access to approved clients.",
                ))
                for match in result_port.get("vulnerabilities", []):
                    reference = CVEReference.query.filter_by(cve_id=match["cve_id"]).first()
                    if reference is None:
                        reference = CVEReference(
                            cve_id=match["cve_id"],
                            description=match["description"] or "No English description provided by NVD.",
                            cvss_score=match.get("cvss_score"),
                            cvss_version=match.get("cvss_version"),
                            severity=match.get("severity", "Unknown"),
                            reference_urls=json.dumps(match.get("references", [])),
                            source="NVD",
                        )
                        db.session.add(reference)
                    db.session.add(VulnerabilityFinding(
                        scan_id=scan_id,
                        port_id=port.id,
                        cve_id=match["cve_id"],
                        classification="potential",
                        title=match["cve_id"],
                        description=match["description"] or "No English description provided by NVD.",
                        severity=match.get("severity", "Unknown"),
                        cvss_score=match.get("cvss_score"),
                        cvss_version=match.get("cvss_version"),
                        source=match.get("source", "NVD keyword match"),
                        reference_urls=json.dumps(match.get("references", [])),
                        remediation=match.get("remediation", "Review the vendor advisory and validate whether the installed build is affected."),
                    ))
        scan = db.session.get(NetworkScan, scan_id)
        scan.status = "completed"
        scan.phase = "completed"
        scan.progress = 100
        scan.finished_at = _utcnow()
        _audit(scan, "scan_completed", f"Scan completed; {len(hosts)} host result(s) recorded.")
        db.session.commit()

    def _mark_failed(self, scan_id, error):
        with self.app.app_context():
            db.session.rollback()
            scan = db.session.get(NetworkScan, scan_id)
            if scan is None:
                return
            scan.status = "failed"
            scan.phase = "failed"
            scan.error_message = _failure_message(error)
            scan.finished_at = _utcnow()
            _audit(scan, "scan_failed", f"Scan failed: {type(error).__name__}.")
            db.session.commit()


def init_scan_manager(app):
    app.extensions["scan_manager"] = ScanTaskManager(app)
