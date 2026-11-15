import json
from datetime import datetime, timedelta, timezone

from models import db
from models.network_scan import (
    DetectedService,
    NetworkHost,
    NetworkPort,
    NetworkScan,
    VulnerabilityFinding,
)
from models.password_analysis import PasswordAnalysis
from models.settings import UserSettings
from models.url_analysis import URLAnalysis
from models.user import User


def _password(user_id, *, category="Strong", created_at=None):
    return PasswordAnalysis(
        user_id=user_id,
        password_length=16,
        entropy=72.0,
        strength_score=85.0,
        strength_category=category,
        created_at=created_at or datetime.now(timezone.utc),
    )


def _url(user_id, *, verdict="Safe", created_at=None):
    return URLAnalysis(
        user_id=user_id,
        url="https://example.test/",
        domain="example.test",
        verdict=verdict,
        confidence=90.0,
        threat_level="Low" if verdict == "Safe" else "High",
        created_at=created_at or datetime.now(timezone.utc),
    )


def _scan(user_id, *, created_at=None):
    return NetworkScan(
        user_id=user_id,
        target="10.0.0.10",
        resolved_targets=json.dumps(["10.0.0.10"]),
        ports=json.dumps([443]),
        profile="safe",
        authorization_confirmed=True,
        status="completed",
        progress=100,
        phase="completed",
        created_at=created_at or datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )


def test_dashboard_uses_owned_records_and_marks_missing_coverage(authenticated_client):
    response = authenticated_client.get("/dashboard?range=all")
    assert response.status_code == 200
    assert b"Insufficient data" in response.data
    assert b"0/3 data domains" in response.data


def test_dashboard_aggregates_real_records_and_network_findings(app, authenticated_client, user):
    with app.app_context():
        db.session.add_all([_password(user, category="Weak"), _url(user, verdict="Phishing")])
        scan = _scan(user)
        host = NetworkHost(address="10.0.0.10", state="up", scan=scan)
        port = NetworkPort(port=443, protocol="tcp", state="open", reason="syn-ack", host=host)
        port.service = DetectedService(name="https", product="nginx", version="1.25")
        scan.findings.append(VulnerabilityFinding(
            classification="potential",
            title="Potential service match",
            description="Version-based match requires validation.",
            severity="Critical",
            cvss_score=9.0,
            source="NVD",
            remediation="Review the vendor advisory.",
            reference_urls="[]",
            cve_id="CVE-2025-0001",
            port=port,
        ))
        db.session.add(scan)
        db.session.commit()

    response = authenticated_client.get("/dashboard?range=all")
    assert response.status_code == 200
    assert b"3/3 data domains" in response.data
    assert b"Critical findings" in response.data
    assert b"nginx" in response.data
    assert b"CVE-2025-0001" in response.data
    assert b"Potential service match" in response.data
    assert b"Assessments" in response.data


def test_dashboard_time_filter_excludes_older_records(app, authenticated_client, user):
    with app.app_context():
        db.session.add(_password(user, created_at=datetime.now(timezone.utc) - timedelta(days=40)))
        db.session.add(_password(user, category="Weak"))
        db.session.commit()
    response = authenticated_client.get("/dashboard?range=24h")
    assert response.status_code == 200
    assert b"1 weak of 1 assessed" in response.data


def test_vulnerability_and_scan_history_pages_are_owner_scoped(app, authenticated_client, user):
    with app.app_context():
        other = User(username="other-user", email="other@example.test")
        other.set_password("AnotherPassword-456!")
        db.session.add(other)
        db.session.flush()
        owned_scan = _scan(user)
        other_scan = _scan(other.id)
        owned_scan.findings.append(VulnerabilityFinding(
            classification="potential",
            title="Owned finding",
            description="Owned description",
            severity="High",
            source="NVD",
            remediation="Patch the service.",
            reference_urls="[]",
        ))
        other_scan.findings.append(VulnerabilityFinding(
            classification="potential",
            title="Private other finding",
            description="Must remain private",
            severity="Critical",
            source="NVD",
            remediation="Review.",
            reference_urls="[]",
        ))
        db.session.add_all([owned_scan, other_scan])
        db.session.commit()

    response = authenticated_client.get("/vulnerabilities?severity=high")
    assert response.status_code == 200
    assert b"Owned finding" in response.data
    assert b"Private other finding" not in response.data
    assert authenticated_client.get("/scan-history?sort=target").status_code == 200
    export = authenticated_client.get("/reports/vulnerabilities/csv")
    assert export.status_code == 200
    assert b"Owned finding" in export.data
    assert b"Private other finding" not in export.data


def test_reports_and_settings_use_existing_data_without_server_paths(app, authenticated_client, user):
    with app.app_context():
        db.session.add(_password(user))
        db.session.add(_url(user))
        db.session.add(UserSettings(user_id=user, theme="dark"))
        db.session.commit()

    reports = authenticated_client.get("/reports")
    assert reports.status_code == 200
    assert b"1 records" in reports.data
    settings = authenticated_client.get("/settings")
    assert settings.status_code == 200
    assert b"database.db" not in settings.data
    assert b"Total Users" not in settings.data


def test_redesigned_pages_render_and_scan_history_sort_is_valid(authenticated_client):
    for path in (
        "/password-checker",
        "/attack-simulation",
        "/url-checker",
        "/network-scanner",
        "/vulnerabilities",
        "/scan-history?sort=target",
        "/reports",
        "/settings",
        "/profile",
    ):
        assert authenticated_client.get(path).status_code == 200, path


def test_password_settings_change_requires_current_password(authenticated_client):
    invalid = authenticated_client.post(
        "/settings/password",
        data={
            "current_password": "wrong-password",
            "new_password": "NewSecurePassword-123!",
            "confirm_password": "NewSecurePassword-123!",
        },
    )
    assert invalid.status_code == 400
    valid = authenticated_client.post(
        "/settings/password",
        data={
            "current_password": "TestPassword-123!",
            "new_password": "NewSecurePassword-123!",
            "confirm_password": "NewSecurePassword-123!",
        },
        follow_redirects=True,
    )
    assert valid.status_code == 200
    assert b"Your password was updated." in valid.data
