"""Tests for URL feature extraction and layered phishing analysis."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import url_service
from services.url_features import FEATURE_NAMES, extract_features, feature_vector
from services import url_checks
from services.url_checks import _resolve_public


def test_https_detected_but_not_treated_as_legitimate_proof():
    features = extract_features("https://example.com")
    assert features["uses_https"] is True
    assert features["https"] == 1


def test_http_detected():
    features = extract_features("http://example.com")
    assert features["uses_https"] is False
    assert features["http"] == 1


def test_valid_ip_address_detected():
    features = extract_features("http://192.0.2.1/login")
    assert features["has_ip_address"] is True
    assert features["ip_address"] == 1


def test_public_domain_not_an_ip():
    assert extract_features("https://github.com")["has_ip_address"] is False


def test_at_symbol_and_redirect_detected():
    features = extract_features("http://paypal.com@malicious.example/login")
    assert features["has_at_symbol"] is True
    assert features["at_symbol_count"] == 1


def test_percent_encoded_redirect_detected():
    features = extract_features(
        "https://example.com/continue?next=https%3A%2F%2Fother.example"
    )
    assert features["encoded_url_indicator"] == 1
    assert features["redirect_indicator"] == 1


def test_shortener_detected():
    assert extract_features("https://bit.ly/abc123")["is_shortened"] is True


def test_suspicious_keywords_are_contextual_features():
    login = extract_features("https://example.com/login")
    multi_keyword = extract_features("https://example.com/login/verify/account")
    assert login["has_suspicious_keywords"] is True
    assert login["suspicious_path"] is False
    assert multi_keyword["suspicious_path"] is True


def test_complex_legitimate_query_and_long_url_remain_valid():
    url = "https://shop.example.com/account/login?return=%2Forders%3Fpage%3D2&lang=en#details"
    features = extract_features(url)
    assert features["is_valid"] is True
    assert features["query_length"] > 0
    assert features["fragment_present"] is True


@pytest.mark.parametrize(
    "url",
    [
        "https://www.example.com",
        "http://example.com",
        "https://cdn.shop.example.com/products/item?id=23&sort=popular",
        "https://login.example.com/account",
        "https://www.chase.com/digital/login",
        "https://www.harvard.edu/admissions",
        "https://www.amazon.com/orders",
    ],
)
def test_legitimate_complex_url_shapes_are_parsed(url):
    features = extract_features(url)
    assert features["is_valid"] is True
    assert features["host"]
    assert len(feature_vector(features)) == len(FEATURE_NAMES)


@pytest.mark.parametrize(
    ("url", "feature", "expected"),
    [
        ("http://192.0.2.1/login", "ip_address", 1),
        ("https://bit.ly/abc123", "shortener_indicator", 1),
        ("https://xn--pple-43d.com/login", "punycode_indicator", 1),
        (
            "https://example.com/continue?next=https%3A%2F%2Fother.example",
            "redirect_indicator",
            1,
        ),
        (
            "https://login.auth.verify.account.example.com/password",
            "subdomain_count",
            4,
        ),
    ],
)
def test_phishing_pattern_features_are_detected(url, feature, expected):
    assert extract_features(url)[feature] == expected


def test_registrable_domain_recognizes_common_uk_suffix():
    assert extract_features("https://login.example.co.uk/auth")["registrable_domain"] == "example.co.uk"


def test_punycode_is_reported():
    features = extract_features("https://xn--pple-43d.com/login")
    assert features["punycode_indicator"] == 1
    assert any("Punycode" in item for item in features["domain_indicators"])


def test_typosquatting_and_brand_impersonation_are_heuristics():
    typo = extract_features("https://paypa1-login.example/login")
    impersonation = extract_features("https://paypal.example/login")
    assert typo["typosquatting"] is True
    assert impersonation["brand_impersonation"] is True


def test_unicode_hostname_is_normalized_to_punycode():
    features = extract_features("https://аррӏе.example/login")
    assert features["is_valid"] is True
    assert features["punycode_indicator"] == 1


def test_invalid_scheme_is_unknown_not_safe(monkeypatch):
    monkeypatch.setattr(url_service, "get_url_model", lambda: None)
    result = url_service.analyze_url("javascript:alert(1)")
    assert result["classification"] == "UNKNOWN / INSUFFICIENT DATA"
    assert result["confidence"] is None
    assert result["risk_score"] is None


def test_invalid_hostname_is_rejected():
    assert extract_features("https://bad_host.example")["is_valid"] is False


def test_vector_uses_one_stable_order():
    features = extract_features("https://example.com/path?x=1")
    vector = feature_vector(features)
    assert len(vector) == len(FEATURE_NAMES)
    assert all(features[name] == value for name, value in zip(FEATURE_NAMES, vector))


def test_model_and_heuristics_are_both_represented(monkeypatch):
    class Model:
        classes_ = ["legitimate", "phishing"]

        def predict(self, frame):
            return ["phishing"]

        def predict_proba(self, frame):
            return [[0.1, 0.9]]

    monkeypatch.setattr(
        url_service,
        "get_url_model",
        lambda: {
            "model": Model(),
            "feature_names": FEATURE_NAMES,
            "calibrated": True,
            "calibration_scope": "synthetic validation distribution only",
        },
    )
    monkeypatch.setattr(
        url_service,
        "inspect_tls",
        lambda *args, **kwargs: {"status": "unavailable", "reason": "disabled"},
    )
    monkeypatch.setattr(
        url_service,
        "inspect_redirects",
        lambda *args, **kwargs: {"status": "unavailable", "reason": "disabled", "chain": []},
    )
    monkeypatch.setattr(
        url_service,
        "inspect_threat_intelligence",
        lambda *args, **kwargs: {"status": "unavailable", "sources": [], "reason": "no keys"},
    )
    result = url_service.analyze_url("https://paypa1.example/login")
    assert result["classification"] in {"SUSPICIOUS", "PHISHING"}
    assert result["risk_score"] > 0
    assert result["ml_prediction"] == "Phishing"
    assert result["evidence"]["machine_learning"]
    assert result["evidence"]["heuristic"]
    assert result["confidence"] == 90.0
    assert result["threat_intelligence"]["status"] == "unavailable"


def test_tls_and_threat_intelligence_unavailable_do_not_prove_legitimacy(monkeypatch):
    class Model:
        classes_ = ["legitimate", "phishing"]

        def predict(self, frame):
            return ["legitimate"]

        def predict_proba(self, frame):
            return [[0.55, 0.45]]

    monkeypatch.setattr(
        url_service,
        "get_url_model",
        lambda: {
            "model": Model(),
            "feature_names": FEATURE_NAMES,
            "calibrated": True,
            "calibration_scope": "synthetic validation distribution only",
        },
    )
    monkeypatch.setattr(
        url_service,
        "inspect_tls",
        lambda *args, **kwargs: {"status": "unavailable", "reason": "disabled"},
    )
    monkeypatch.setattr(
        url_service,
        "inspect_redirects",
        lambda *args, **kwargs: {"status": "unavailable", "reason": "disabled", "chain": []},
    )
    monkeypatch.setattr(
        url_service,
        "inspect_threat_intelligence",
        lambda *args, **kwargs: {"status": "unavailable", "sources": [], "reason": "no keys"},
    )
    result = url_service.analyze_url("https://example.com")
    assert result["classification"] == "UNKNOWN / INSUFFICIENT DATA"
    assert result["confidence"] == 55.0
    assert result["evidence"]["unavailable"]


def test_ssrf_guard_blocks_private_addresses():
    try:
        _resolve_public("127.0.0.1")
    except PermissionError:
        pass
    else:
        raise AssertionError("Private addresses must be blocked before network checks.")


def test_model_only_phishing_prediction_without_independent_signals_is_unknown(monkeypatch):
    class Model:
        classes_ = ["legitimate", "phishing"]

        def predict_proba(self, frame):
            return [[0.01, 0.99]]

    monkeypatch.setattr(
        url_service,
        "get_url_model",
        lambda: {
            "model": Model(),
            "feature_names": FEATURE_NAMES,
            "calibrated": True,
            "calibration_scope": "synthetic validation distribution only",
        },
    )
    monkeypatch.setattr(
        url_service,
        "inspect_tls",
        lambda *args, **kwargs: {"status": "unavailable", "reason": "disabled"},
    )
    monkeypatch.setattr(
        url_service,
        "inspect_redirects",
        lambda *args, **kwargs: {"status": "unavailable", "reason": "disabled", "chain": []},
    )
    monkeypatch.setattr(
        url_service,
        "inspect_threat_intelligence",
        lambda *args, **kwargs: {"status": "unavailable", "sources": [], "reason": "no keys"},
    )
    result = url_service.analyze_url("https://example.com")
    assert result["ml_prediction"] == "Phishing"
    assert result["classification"] == "UNKNOWN / INSUFFICIENT DATA"


def test_threat_intelligence_without_keys_is_unavailable(monkeypatch):
    for key in (
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "PHISHTANK_API_KEY",
        "URLHAUS_AUTH_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    result = url_checks.inspect_threat_intelligence("https://example.com")
    assert result["status"] == "unavailable"
    assert result["sources"] == []


def test_threat_intelligence_rate_limit_is_explicit(monkeypatch):
    from urllib.error import HTTPError

    class Opener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 429, "rate limited", {}, None)

    monkeypatch.setattr(url_checks, "build_opener", lambda *args: Opener())
    result = url_checks._provider_result("test provider", "https://provider.example/check")
    assert result["status"] == "rate_limited"
