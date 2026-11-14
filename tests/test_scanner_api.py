import json
import time

import pytest
from models import db
from models.network_scan import (
    CVEReference,
    NetworkHost,
    NetworkPort,
    NetworkScan,
    ScanAuditLog,
    VulnerabilityFinding,
)
from models.user import User


def _scan_payload(target="192.168.10.8"):
    return {
        "target": target,
        "authorization_confirmed": True,
        "profile": "safe",
        "ports": [22, 443],
    }


def test_scan_start_requires_login(app):
    response = app.test_client().post("/api/scans", json=_scan_payload())
    assert response.status_code == 302


def test_scan_api_requires_authorization(authenticated_client):
    body = _scan_payload()
    body["authorization_confirmed"] = False
    response = authenticated_client.post("/api/scans", json=body)
    assert response.status_code == 400
    assert "authorization" in response.json["error"].lower()


def test_health_endpoint_is_authenticated_and_does_not_expose_paths(
    app, authenticated_client, monkeypatch
):
    import routes.network_scanner as routes

    probed_paths = []

    def fake_status(path=None):
        probed_paths.append(path)
        return {
            "status": "operational",
            "nmap": {"status": "ready", "version": "7.99"},
            "python_integration": {"status": "ready", "version": "0.7.1"},
        }

    app.config["NMAP_PATH"] = r"C:\Nmap\nmap.exe"
    monkeypatch.setattr(routes, "nmap_status", fake_status)
    response = authenticated_client.get("/api/scans/health")
    assert response.status_code == 200
    assert response.json["scanner"]["status"] == "operational"
    assert "executable" not in response.json["scanner"]
    assert probed_paths == [r"C:\Nmap\nmap.exe"]


def test_loopback_scan_requires_opt_in_and_approved_scope(
    app, authenticated_client, monkeypatch
):
    import routes.network_scanner as routes
    from scanners.target_validation import parse_approved_networks

    body = _scan_payload("127.0.0.1")
    assert authenticated_client.post("/api/scans", json=body).status_code == 400
    app.config["SCANNER_APPROVED_NETWORKS"] = parse_approved_networks("127.0.0.1/32")
    app.config["SCANNER_ALLOW_LOOPBACK"] = True
    monkeypatch.setattr(routes, "require_nmap", lambda: "nmap.exe")
    monkeypatch.setattr(app.extensions["scan_manager"], "submit", lambda _scan_id: None)
    response = authenticated_client.post("/api/scans", json=body)
    assert response.status_code == 202
    assert response.json["scan"]["target"] == "127.0.0.1"


def test_scan_start_database_failure_is_safe(
    app, authenticated_client, monkeypatch
):
    import routes.network_scanner as routes
    from sqlalchemy.exc import OperationalError

    monkeypatch.setattr(routes, "require_nmap", lambda: "nmap.exe")

    def fail_commit():
        raise OperationalError("commit", {}, Exception("C:\\private\\database.db"))

    monkeypatch.setattr(db.session, "commit", fail_commit)
    response = authenticated_client.post("/api/scans", json=_scan_payload())
    assert response.status_code == 503
    assert "private" not in response.get_data(as_text=True)
    with app.app_context():
        db.session.rollback()
        assert NetworkScan.query.count() == 0


def test_worker_rolls_back_storage_failure_and_redacts_path(app, user):
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError

    with app.app_context():
        scan = NetworkScan(
            user_id=user,
            target="192.168.10.8",
            resolved_targets='["192.168.10.8"]',
            ports="[443]",
            status="running",
            authorization_confirmed=True,
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id
        with pytest.raises(SQLAlchemyError):
            db.session.execute(text("SELECT * FROM missing_scanner_table"))
        app.extensions["scan_manager"]._mark_failed(
            scan_id, OSError(r"C:\private\database\path")
        )
        db.session.remove()
        scan = db.session.get(NetworkScan, scan_id)
        assert scan.status == "failed"
        assert "private" not in scan.error_message
        assert "database" not in scan.error_message


def test_scan_start_returns_accepted_and_persists_configuration(
    app, authenticated_client, monkeypatch
):
    import routes.network_scanner as routes

    monkeypatch.setattr(routes, "require_nmap", lambda: "nmap.exe")
    monkeypatch.setattr(
        app.extensions["scan_manager"], "submit", lambda scan_id: None
    )
    response = authenticated_client.post("/api/scans", json=_scan_payload())
    assert response.status_code == 202
    scan_id = response.json["scan"]["id"]
    with app.app_context():
        scan = db.session.get(NetworkScan, scan_id)
        assert scan.status == "queued"
        assert scan.authorization_confirmed is True
        assert json.loads(scan.resolved_targets) == ["192.168.10.8"]
        assert scan.configuration.profile == "safe"
        assert ScanAuditLog.query.filter_by(
            scan_id=scan_id, event_type="scan_authorized"
        ).count() == 1


def test_scan_start_rejects_missing_nmap_without_creating_scan(
    app, authenticated_client, monkeypatch
):
    import routes.network_scanner as routes

    from services.network_scanner import ScannerUnavailable

    def missing():
        raise ScannerUnavailable("Install Nmap.")

    monkeypatch.setattr(routes, "require_nmap", missing)
    response = authenticated_client.post("/api/scans", json=_scan_payload())
    assert response.status_code == 503
    assert "Install Nmap" in response.json["error"]
    with app.app_context():
        assert NetworkScan.query.count() == 0


def test_scan_results_are_owner_scoped(app, authenticated_client, user):
    with app.app_context():
        scan = NetworkScan(
            user_id=user,
            target="192.168.10.8",
            resolved_targets='["192.168.10.8"]',
            ports="[443]",
            authorization_confirmed=True,
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

        other = User(username="other", email="other@example.test")
        other.set_password("TestPassword-123!")
        db.session.add(other)
        db.session.commit()
        other_id = other.id

    with authenticated_client.session_transaction() as session:
        session["_user_id"] = str(other_id)
        session["_fresh"] = True
    response = authenticated_client.get(f"/api/scans/{scan_id}")
    assert response.status_code == 404
    assert response.json["error"] == "Scan or finding not found."


def test_scan_cancellation_is_owner_scoped(app, authenticated_client, user, monkeypatch):
    with app.app_context():
        scan = NetworkScan(
            user_id=user,
            target="192.168.10.8",
            resolved_targets='["192.168.10.8"]',
            ports="[443]",
            status="running",
            authorization_confirmed=True,
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id
    monkeypatch.setattr(app.extensions["scan_manager"], "cancel", lambda _id: True)
    response = authenticated_client.post(f"/api/scans/{scan_id}/cancel")
    assert response.status_code == 202
    with app.app_context():
        assert db.session.get(NetworkScan, scan_id).cancel_requested is True


def test_worker_persists_service_and_potential_cve_and_exports_reports(
    app, authenticated_client, user
):
    with app.app_context():
        scan = NetworkScan(
            user_id=user,
            target="192.168.10.8",
            resolved_targets='["192.168.10.8"]',
            ports="[443]",
            status="running",
            authorization_confirmed=True,
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id
        app.extensions["scan_manager"]._persist_results(scan_id, [{
            "address": "192.168.10.8",
            "hostname": None,
            "state": "up",
            "ports": [{
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "reason": "syn-ack",
                "name": "https",
                "product": "Example Server",
                "version": "1.2",
                "extra_info": None,
                "cpe": None,
                "vulnerabilities": [{
                    "cve_id": "CVE-2099-1234",
                    "description": "Potential test match.",
                    "severity": "High",
                    "cvss_score": 8.0,
                    "cvss_version": "3.1",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2099-1234"],
                    "source": "NVD keyword match",
                    "remediation": "Validate the vendor advisory.",
                }],
            }],
        }])
        assert CVEReference.query.count() == 1
        finding = VulnerabilityFinding.query.filter_by(
            scan_id=scan_id, cve_id="CVE-2099-1234"
        ).one()
        assert finding.classification == "potential"
        assert NetworkHost.query.filter_by(scan_id=scan_id).count() == 1
        assert NetworkPort.query.count() == 1
    details = authenticated_client.get(f"/api/scans/{scan_id}")
    assert details.status_code == 200
    assert details.json["scan"]["findings"][0]["classification"] in {
        "informational", "potential"
    }
    assert any(item["cvss_version"] == "3.1" for item in details.json["scan"]["findings"])
    history = authenticated_client.get("/api/scans")
    assert history.status_code == 200
    assert any(item["id"] == scan_id for item in history.json["scans"])
    csv_report = authenticated_client.get(f"/api/scans/{scan_id}/report.csv")
    assert csv_report.status_code == 200
    assert b"CVE-2099-1234" in csv_report.data
    pdf_report = authenticated_client.get(f"/api/scans/{scan_id}/report.pdf")
    assert pdf_report.status_code == 200
    assert pdf_report.data.startswith(b"%PDF")


def test_background_worker_completes_without_network_io(
    app, authenticated_client, monkeypatch
):
    import routes.network_scanner as routes
    import tasks.scanner_tasks as scanner_tasks

    monkeypatch.setattr(routes, "require_nmap", lambda: "nmap.exe")
    monkeypatch.setattr(scanner_tasks, "run_nmap_scan", lambda *args: {"scan": {}})
    monkeypatch.setattr(scanner_tasks, "normalize_results", lambda *args: [])
    response = authenticated_client.post("/api/scans", json=_scan_payload())
    assert response.status_code == 202
    scan_id = response.json["scan"]["id"]
    deadline = time.time() + 5
    status = "queued"
    while time.time() < deadline and status in {"queued", "running"}:
        time.sleep(0.05)
        result = authenticated_client.get(f"/api/scans/{scan_id}")
        status = result.json["scan"]["status"]
    assert status == "completed"
    assert result.json["scan"]["progress"] == 100
