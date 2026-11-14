import json

import pytest

from models import db
from models.attack_log import AttackLog
from models.password_analysis import PasswordAnalysis
from models.url_analysis import URLAnalysis
from utils.report_generator import generate_url_csv


def test_existing_authenticated_pages_remain_available(authenticated_client):
    for path in (
        "/dashboard",
        "/password-checker",
        "/url-checker",
        "/history",
        "/settings",
        "/profile",
        "/network-scanner",
    ):
        response = authenticated_client.get(path)
        assert response.status_code == 200, path


def test_password_analysis_route_persists_derived_results_only(
    app, authenticated_client, monkeypatch
):
    import routes.password_checker as route

    result = {
        "features": {
            "length": 12,
            "entropy": 42.0,
            "has_upper": True,
            "has_lower": True,
            "has_digit": True,
            "has_symbol": True,
            "is_dictionary_word": False,
            "is_keyboard_pattern": False,
            "has_repeated_chars": False,
            "has_sequential_chars": False,
            "has_common_substitution": False,
        },
        "strength_score": 80,
        "strength_category": "Strong",
        "ml_prediction": "Strong",
        "ml_confidence": 90.0,
        "estimated_crack_time_seconds": 1000,
        "estimated_crack_time_display": "16.7 minutes",
        "recommendations": ["Use a password manager."],
        "attack_simulations": [
            {
                "attack_type": "brute_force",
                "success_likelihood": "Low",
                "estimated_time_seconds": 1000,
                "estimated_time_display": "16.7 minutes",
            }
        ],
    }
    monkeypatch.setattr(route, "analyze_password", lambda _password: result)
    response = authenticated_client.post(
        "/password-checker",
        data={"password": "do-not-persist-this-secret"},
    )
    assert response.status_code == 200
    with app.app_context():
        analysis = PasswordAnalysis.query.one()
        assert analysis.password_length == 12
        assert analysis.strength_category == "Strong"
        assert not hasattr(analysis, "password")
        assert AttackLog.query.count() == 1


def test_url_analysis_route_and_user_scoped_history_remain_available(
    app, authenticated_client, monkeypatch
):
    import routes.url_checker as route

    features = {
        "domain": "example.test",
        "uses_https": True,
        "url_length": 24,
        "domain_length": 12,
        "subdomain_count": 0,
        "has_ip_address": False,
        "has_at_symbol": False,
        "has_double_slash_redirect": False,
        "is_shortened": False,
        "has_suspicious_keywords": False,
        "special_char_count": 4,
        "tld": "test",
    }
    monkeypatch.setattr(
        route,
        "analyze_url",
        lambda _url: {
            "features": features,
            "verdict": "Safe",
            "confidence": 80.0,
            "threat_level": "Low",
            "classification": "LEGITIMATE",
            "risk_score": 10,
            "risk_category": "very_low_risk",
            "ml_prediction": "Legitimate",
            "protocol_analysis": {"scheme": "https"},
            "domain_analysis": {
                "hostname": "example.test",
                "registrable_domain": "example.test",
            },
            "tls_analysis": {"status": "unavailable", "reason": "disabled"},
            "redirect_analysis": {"reason": "disabled", "chain": []},
            "threat_intelligence": {"sources": [], "reason": "not configured"},
            "evidence": {"unavailable": []},
            "reasons": [],
            "recommendations": [],
        },
    )
    response = authenticated_client.post(
        "/url-checker",
        data={"url": "https://example.test/"},
    )
    assert response.status_code == 200
    with app.app_context():
        assert URLAnalysis.query.one().verdict == "Safe"
    assert authenticated_client.get("/history?tab=url").status_code == 200


def test_logout_is_post_only_and_csv_formula_values_are_escaped(
    authenticated_client, app, user
):
    assert authenticated_client.get("/logout").status_code == 405
    assert authenticated_client.post("/logout").status_code == 302
    with app.app_context():
        row = URLAnalysis(
            user_id=user,
            url="=HYPERLINK(\"https://example.test\")",
            domain="example.test",
            verdict="Suspicious",
            confidence=0,
            threat_level="Medium",
        )
        db.session.add(row)
        db.session.commit()
        buffer = generate_url_csv([row])
        content = buffer.getvalue().decode("utf-8")
        assert "'=HYPERLINK" in content


def test_login_rejects_external_next_redirect(app, user):
    client = app.test_client()
    response = client.post(
        "/login?next=https://attacker.example",
        data={"username": "scanner-user", "password": "TestPassword-123!"},
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_production_requires_configured_secret(monkeypatch):
    from app import create_app
    from config import ProductionConfig

    monkeypatch.setattr(ProductionConfig, "SECRET_KEY", None)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app("production")


def test_bastionix_metadata_is_injected(app):
    with app.test_request_context("/"):
        from flask import render_template

        page = render_template("base.html")
        assert "BastionIX" in page
        assert "Intelligent Security. Continuous Visibility. Stronger Defense." in page
