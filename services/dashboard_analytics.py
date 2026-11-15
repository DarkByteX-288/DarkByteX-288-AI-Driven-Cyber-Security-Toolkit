"""Owner-scoped dashboard aggregates derived from persisted assessments."""

from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import selectinload

from models.attack_log import AttackLog
from models.network_scan import (
    DetectedService,
    NetworkHost,
    NetworkPort,
    NetworkScan,
    VulnerabilityFinding,
)
from models.password_analysis import PasswordAnalysis
from models.url_analysis import URLAnalysis


RANGE_DAYS = {"24h": 1, "7d": 7, "30d": 30, "all": None}
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
SEVERITY_RISK = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "informational": 0.1,
}


def _cutoff_for(time_range, now=None):
    days = RANGE_DAYS.get(time_range, RANGE_DAYS["7d"])
    if days is None:
        return None
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is not None:
        current = current.astimezone(timezone.utc).replace(tzinfo=None)
    return current - timedelta(days=days)


def _within_range(query, model, cutoff):
    return query.filter(model.created_at >= cutoff) if cutoff is not None else query


def _activity_timestamp(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _posture_score(password_total, weak_passwords, url_total, risky_urls,
                   completed_scans, findings):
    """Score only observed domains; the result is not a system-wide audit."""
    factors = []
    weighted_scores = []

    if password_total:
        score = 100 * (1 - weak_passwords / password_total)
        weighted_scores.append((score, 0.4))
        factors.append({
            "name": "Password assessments",
            "score": round(score),
            "detail": f"{weak_passwords} weak of {password_total} assessed",
        })

    if url_total:
        score = 100 * (1 - risky_urls / url_total)
        weighted_scores.append((score, 0.3))
        factors.append({
            "name": "URL assessments",
            "score": round(score),
            "detail": f"{risky_urls} non-safe of {url_total} analyzed",
        })

    if completed_scans:
        risk_points = sum(
            SEVERITY_RISK.get((finding.severity or "").lower(), 0)
            for finding in findings
        )
        risk_ratio = min(1.0, risk_points / completed_scans)
        score = 100 * (1 - risk_ratio)
        weighted_scores.append((score, 0.3))
        factors.append({
            "name": "Completed network scans",
            "score": round(score),
            "detail": (
                f"{len(findings)} recorded findings across "
                f"{completed_scans} completed scans"
            ),
        })

    if not weighted_scores:
        return {
            "score": None,
            "label": "Insufficient data",
            "coverage": 0,
            "factors": factors,
        }

    total_weight = sum(weight for _, weight in weighted_scores)
    score = round(sum(value * weight for value, weight in weighted_scores) / total_weight)
    coverage = len(weighted_scores)
    if coverage < 2:
        label = "Limited coverage"
    elif score < 20:
        label = "Critical"
    elif score < 40:
        label = "Needs attention"
    elif score < 60:
        label = "Moderate"
    elif score < 80:
        label = "Good"
    else:
        label = "Excellent"
    return {"score": score, "label": label, "coverage": coverage, "factors": factors}


def _recommendations(findings, risky_url, weak_password):
    recommendations = []
    for finding in findings:
        recommendations.append({
            "priority": (finding.severity or "Informational").title(),
            "title": finding.title,
            "reason": (
                f"{finding.cve_id} is a potential match."
                if finding.cve_id
                else "A finding was recorded by an authorized network assessment."
            ),
            "action": finding.remediation,
            "href": "/vulnerabilities",
        })

    if risky_url is not None:
        recommendations.append({
            "priority": "High" if risky_url.verdict == "Phishing" else "Medium",
            "title": "Review a non-safe URL assessment",
            "reason": f"{risky_url.domain or 'A URL'} was classified as {risky_url.verdict}.",
            "action": "Avoid visiting the URL or entering credentials until it is independently verified.",
            "href": "/url-checker",
        })

    if weak_password is not None:
        recommendations.append({
            "priority": "Medium",
            "title": "Review a weak password assessment",
            "reason": (
                f"A recent assessment was rated {weak_password.strength_category} "
                f"with a score of {weak_password.strength_score}/100."
            ),
            "action": "Replace the password with a unique, long passphrase and use a password manager.",
            "href": "/password-checker",
        })
    return recommendations[:6]


def get_dashboard_analytics(user_id, time_range="7d", now=None):
    """Return user-owned dashboard metrics for a validated time range."""
    if time_range not in RANGE_DAYS:
        time_range = "7d"
    cutoff = _cutoff_for(time_range, now)

    passwords = _within_range(
        PasswordAnalysis.query.filter_by(user_id=user_id), PasswordAnalysis, cutoff
    )
    urls = _within_range(
        URLAnalysis.query.filter_by(user_id=user_id), URLAnalysis, cutoff
    )
    scans = _within_range(
        NetworkScan.query.filter_by(user_id=user_id), NetworkScan, cutoff
    )
    findings_query = (
        VulnerabilityFinding.query.join(NetworkScan)
        .filter(NetworkScan.user_id == user_id)
    )
    findings_query = _within_range(findings_query, NetworkScan, cutoff)
    findings = findings_query.order_by(VulnerabilityFinding.created_at.desc()).all()

    password_total = passwords.count()
    url_total = urls.count()
    scan_total = scans.count()
    password_rows = passwords.with_entities(
        PasswordAnalysis.strength_category, func.count()
    ).group_by(PasswordAnalysis.strength_category).all()
    url_rows = urls.with_entities(URLAnalysis.verdict, func.count()).group_by(
        URLAnalysis.verdict
    ).all()
    scan_rows = scans.with_entities(NetworkScan.status, func.count()).group_by(
        NetworkScan.status
    ).all()

    password_categories = dict(password_rows)
    url_verdicts = dict(url_rows)
    scan_statuses = dict(scan_rows)
    weak_passwords = sum(
        count for category, count in password_categories.items()
        if category in {"Very Weak", "Weak"}
    )
    risky_urls = sum(
        count for verdict, count in url_verdicts.items() if verdict != "Safe"
    )
    critical_findings = sum(
        1 for finding in findings if (finding.severity or "").lower() == "critical"
    )
    completed_scans = scan_statuses.get("completed", 0)

    port_query = (
        NetworkPort.query.join(NetworkHost)
        .join(NetworkScan)
        .filter(NetworkScan.user_id == user_id, NetworkPort.state == "open")
    )
    service_query = (
        DetectedService.query.join(NetworkPort)
        .join(NetworkHost)
        .join(NetworkScan)
        .filter(NetworkScan.user_id == user_id)
    )
    affected_service_query = (
        DetectedService.query.join(NetworkPort)
        .join(
            VulnerabilityFinding,
            VulnerabilityFinding.port_id == NetworkPort.id,
        )
        .join(NetworkScan, VulnerabilityFinding.scan_id == NetworkScan.id)
        .filter(NetworkScan.user_id == user_id)
    )
    if cutoff is not None:
        port_query = port_query.filter(NetworkScan.created_at >= cutoff)
        service_query = service_query.filter(NetworkScan.created_at >= cutoff)
        affected_service_query = affected_service_query.filter(
            NetworkScan.created_at >= cutoff
        )

    known_severities = {value.lower() for value in SEVERITY_ORDER}
    severity_counts = Counter()
    for finding in findings:
        severity = (finding.severity or "informational").lower()
        severity_counts[severity if severity in known_severities else "informational"] += 1
    vulnerability_distribution = {
        severity: severity_counts.get(severity.lower(), 0)
        for severity in SEVERITY_ORDER
    }
    cve_counts = Counter(
        finding.cve_id for finding in findings if finding.cve_id
    )

    service_counts = (
        affected_service_query.with_entities(
            func.coalesce(DetectedService.product, DetectedService.name, "Unknown"),
            func.count(func.distinct(DetectedService.id)),
        )
        .group_by(func.coalesce(DetectedService.product, DetectedService.name, "Unknown"))
        .order_by(func.count(func.distinct(DetectedService.id)).desc())
        .limit(5)
        .all()
    )

    recent_passwords = passwords.order_by(
        PasswordAnalysis.created_at.desc()
    ).limit(5).all()
    recent_urls = urls.order_by(URLAnalysis.created_at.desc()).limit(5).all()
    recent_scans = (
        scans.options(
            selectinload(NetworkScan.hosts).selectinload(NetworkHost.ports),
            selectinload(NetworkScan.findings),
        )
        .order_by(NetworkScan.created_at.desc())
        .limit(5)
        .all()
    )
    activity = []
    for item in recent_passwords:
        activity.append({
            "kind": "Password assessment",
            "description": f"{item.strength_category} strength result · {item.strength_score}/100",
            "module": "Password security",
            "status": "Completed",
            "created_at": item.created_at,
            "href": "/password-checker",
        })
    for item in recent_urls:
        activity.append({
            "kind": "URL analysis",
            "description": f"{item.domain or 'URL'} classified as {item.verdict}",
            "module": "Phishing detection",
            "status": "Completed",
            "created_at": item.created_at,
            "href": "/url-checker",
        })
    for item in recent_scans:
        activity.append({
            "kind": "Network scan",
            "description": f"{item.target} · {item.status}",
            "module": "Network security",
            "status": item.status.title(),
            "created_at": item.created_at,
            "href": f"/network-scanner?scan_id={item.id}",
        })
    activity.sort(key=lambda item: _activity_timestamp(item["created_at"]), reverse=True)

    completed_findings = findings_query.filter(NetworkScan.status == "completed").all()
    average_score = passwords.with_entities(
        func.avg(PasswordAnalysis.strength_score)
    ).scalar()
    posture = _posture_score(
        password_total,
        weak_passwords,
        url_total,
        risky_urls,
        completed_scans,
        completed_findings,
    )

    latest_risky_url = urls.filter(URLAnalysis.verdict != "Safe").order_by(
        URLAnalysis.created_at.desc()
    ).first()
    latest_weak_password = passwords.filter(
        PasswordAnalysis.strength_category.in_(("Very Weak", "Weak"))
    ).order_by(PasswordAnalysis.created_at.desc()).first()
    recommendations = _recommendations(
        findings[:4], latest_risky_url, latest_weak_password
    )

    stats = {
        "total_password": password_total,
        "total_url": url_total,
        "total_assessments": password_total + url_total + scan_total,
        "total_scans": scan_total,
        "completed_scans": completed_scans,
        "failed_scans": scan_statuses.get("failed", 0),
        "open_ports": port_query.count(),
        "service_discoveries": service_query.count(),
        "total_findings": len(findings),
        "critical_findings": critical_findings,
        "weak_passwords": weak_passwords,
        "moderate_passwords": password_categories.get("Moderate", 0),
        "strong_passwords": sum(
            count for category, count in password_categories.items()
            if category in {"Strong", "Very Strong"}
        ),
        "phishing_urls": url_verdicts.get("Phishing", 0),
        "suspicious_urls": url_verdicts.get("Suspicious", 0),
        "safe_urls": url_verdicts.get("Safe", 0),
        "avg_score": round(float(average_score), 1) if average_score is not None else None,
        "security_score": posture["score"],
    }
    chart_data = {
        "category_labels": list(password_categories),
        "category_values": list(password_categories.values()),
        "verdict_labels": list(url_verdicts),
        "verdict_values": list(url_verdicts.values()),
        "scan_labels": list(scan_statuses),
        "scan_values": list(scan_statuses.values()),
        "vulnerability_labels": list(vulnerability_distribution),
        "vulnerability_values": list(vulnerability_distribution.values()),
        "cve_labels": [item[0] for item in cve_counts.most_common(5)],
        "cve_values": [item[1] for item in cve_counts.most_common(5)],
        "service_labels": [item[0] for item in service_counts],
        "service_values": [item[1] for item in service_counts],
    }
    return {
        "time_range": time_range,
        "updated_at": datetime.now(timezone.utc),
        "stats": stats,
        "chart_data": chart_data,
        "posture": posture,
        "recent_passwords": recent_passwords,
        "recent_urls": recent_urls,
        "recent_scans": recent_scans,
        "activity": activity[:10],
        "recommendations": recommendations,
    }
