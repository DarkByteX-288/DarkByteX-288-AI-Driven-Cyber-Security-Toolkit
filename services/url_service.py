"""Layered URL phishing analysis with explainable, non-probabilistic risk scoring."""

import logging

import pandas as pd

from ml.model_loader import get_url_model
from services.url_checks import (
    inspect_redirects,
    inspect_threat_intelligence,
    inspect_tls,
    network_checks_enabled,
)
from services.url_features import FEATURE_NAMES, extract_features, normalize_url

logger = logging.getLogger("bastionix.url_analysis")

RISK_THRESHOLDS = {
    "very_low_risk": (0, 19),
    "low_risk": (20, 39),
    "suspicious": (40, 59),
    "high_risk": (60, 79),
    "critical_likely_phishing": (80, 100),
}

_RECOMMENDATIONS = {
    "PHISHING": [
        "Do not enter credentials, payment details, or personal information on this site.",
        "Do not download files or follow redirects from this URL.",
        "Report the URL to your organization or an established anti-phishing service.",
    ],
    "SUSPICIOUS": [
        "Verify the sender and destination using a separate trusted channel.",
        "Navigate through a known bookmark instead of this link.",
        "Do not enter sensitive information until the destination is independently verified.",
    ],
    "LEGITIMATE": [
        "No strong URL-based threat indicators were found; this is not a guarantee of safety.",
        "Verify the destination before entering sensitive information.",
    ],
    "UNKNOWN / INSUFFICIENT DATA": [
        "The available evidence is insufficient to assess this URL reliably.",
        "Avoid entering sensitive information until the destination is verified independently.",
    ],
}


def _heuristic_risk(features, tls, redirects, intelligence):
    indicators = []
    score = 0

    def add(condition, points, message):
        nonlocal score
        if condition:
            score += points
            indicators.append(message)

    add(features["ip_address"], 18, "The hostname is an IP address, not a named domain.")
    add(features["at_symbol_count"] > 0, 10, "The URL contains an '@' symbol.")
    add(features["redirect_indicator"], 12, "The URL contains an embedded or parameterized redirect.")
    add(features["shortener_indicator"], 9, "The URL uses a known or synthetic-example shortener host.")
    add(features["encoded_url_indicator"], 8, "The URL contains percent-encoded or hexadecimal obfuscation.")
    add(features["suspicious_port"], 8, "The URL uses a non-standard HTTP(S) port.")
    add(features["punycode_indicator"], 12, "The hostname uses Punycode or non-ASCII characters.")
    add(features["typosquatting"], 16, "The registered-domain label resembles a known brand.")
    add(features["brand_impersonation"], 12, "A brand name appears outside its corresponding registered domain.")
    add(features["suspicious_subdomain"], 8, "The hostname has suspicious or unusually deep subdomains.")
    add(features["suspicious_tld"], 3, "The TLD is on a low-confidence heuristic watchlist.")
    add(features["has_suspicious_keywords"], 2, "The URL contains a security-sensitive keyword.")
    add(features["suspicious_path"], 8, "The URL path combines multiple credential-related terms.")
    add(features["suspicious_query"], 8, "The query includes redirect or credential-related parameters.")
    add(features["multiple_at_symbols"], 8, "The URL contains multiple '@' symbols.")
    add(features["high_entropy"], 5, "The URL has high character entropy.")
    add(features["excessive_dots"], 5, "The hostname contains an unusually high number of dots.")
    add(features["excessive_hyphens"], 4, "The hostname contains several hyphens.")
    add(features["http"], 2, "The URL uses unencrypted HTTP.")

    if tls.get("status") == "invalid":
        score += 12
        indicators.append("TLS certificate validation failed.")

    redirect_chain = redirects.get("chain", [])
    if len(redirect_chain) >= 2:
        score += 6
        indicators.append("The URL redirects across multiple destinations.")
    if redirects.get("status") == "checked" and redirects.get("final_url"):
        initial_host = features.get("host", "")
        final_features = extract_features(redirects["final_url"])
        if final_features.get("host") and final_features["host"] != initial_host:
            score += 8
            indicators.append("The URL redirects to a different hostname.")

    if intelligence.get("confirmed_malicious_sources"):
        score = 100
        indicators.append(
            "A configured threat-intelligence source reports this URL as malicious: "
            + ", ".join(intelligence["confirmed_malicious_sources"])
            + "."
        )
    return min(score, 100), indicators


def _risk_category(score):
    for category, (lower, upper) in RISK_THRESHOLDS.items():
        if lower <= score <= upper:
            return category
    return "critical_likely_phishing"


def _classification(
    score,
    heuristic_score,
    ml_prediction,
    phishing_probability,
    intelligence,
    model_available,
):
    if intelligence.get("confirmed_malicious_sources"):
        return "PHISHING"
    if score >= 80 or (
        score >= 60 and ml_prediction == "phishing" and phishing_probability >= 0.85
    ):
        return "PHISHING"
    if score >= 40 or (
        score >= 20 and heuristic_score >= 20
    ) or (
        score >= 20 and heuristic_score >= 8 and ml_prediction == "phishing"
    ):
        return "SUSPICIOUS"
    if (
        model_available
        and ml_prediction == "legitimate"
        and (1 - phishing_probability) >= 0.70
        and heuristic_score < 20
    ):
        return "LEGITIMATE"
    return "UNKNOWN / INSUFFICIENT DATA"


def _legacy_verdict(classification):
    return {
        "LEGITIMATE": ("Safe", "legitimate"),
        "SUSPICIOUS": ("Suspicious", "suspicious"),
        "PHISHING": ("Phishing", "phishing"),
        "UNKNOWN / INSUFFICIENT DATA": ("Unknown", "unknown"),
    }[classification]


def analyze_url(url):
    """Analyze the submitted URL without fetching it unless network checks are enabled."""
    features = extract_features(url)
    if not features["is_valid"]:
        classification = "UNKNOWN / INSUFFICIENT DATA"
        legacy_verdict, verdict_key = _legacy_verdict(classification)
        return {
            "features": features,
            "submitted_url": str(url or ""),
            "normalized_url": normalize_url(url or ""),
            "classification": classification,
            "verdict": legacy_verdict,
            "verdict_key": verdict_key,
            "risk_score": None,
            "risk_category": "insufficient_data",
            "confidence": None,
            "ml_prediction": "Unavailable",
            "ml_raw_prediction": None,
            "ml_phishing_probability": None,
            "model_confidence_scope": None,
            "threat_level": "Unknown",
            "protocol_analysis": {
                "scheme": "unknown",
                "https": False,
                "reason": features["validation_error"],
            },
            "domain_analysis": {
                "hostname": "",
                "registrable_domain": "",
                "indicators": [],
                "status": "unavailable",
            },
            "structural_analysis": {
                "indicators": [],
                "suspicious_keywords": [],
            },
            "tls_analysis": {"status": "unavailable", "reason": "The URL is invalid."},
            "redirect_analysis": {
                "status": "unavailable",
                "reason": "The URL is invalid.",
                "chain": [],
            },
            "threat_intelligence": {
                "status": "unavailable",
                "sources": [],
                "reason": "The URL is invalid.",
            },
            "evidence": {
                "confirmed": [],
                "heuristic": [],
                "machine_learning": [],
                "unavailable": ["URL syntax validation failed."],
            },
            "reasons": [features["validation_error"]],
            "recommendations": list(_RECOMMENDATIONS[classification]),
        }

    tls_enabled = network_checks_enabled()
    tls = inspect_tls(features["normalized_url"], enabled=tls_enabled)
    redirects = inspect_redirects(features["normalized_url"], enabled=tls_enabled)
    intelligence = inspect_threat_intelligence(features["normalized_url"])

    ml_prediction = None
    phishing_probability = None
    confidence = None
    calibration_scope = None
    model_available = False
    model_error = None
    try:
        bundle = get_url_model()
        if bundle.get("feature_names") != FEATURE_NAMES:
            raise ValueError("The installed URL model uses an incompatible feature schema.")
        if not bundle.get("calibrated"):
            raise ValueError("The installed URL model does not provide calibrated confidence.")
        model = bundle["model"]
        row = pd.DataFrame(
            [[features[name] for name in FEATURE_NAMES]],
            columns=FEATURE_NAMES,
        )
        probabilities = model.predict_proba(row)[0]
        class_probabilities = {
            str(label).lower(): float(probability)
            for label, probability in zip(model.classes_, probabilities)
        }
        phishing_probability = class_probabilities.get("phishing")
        if phishing_probability is not None:
            decision_threshold = float(bundle.get("decision_threshold", 0.5))
            ml_prediction = (
                "phishing" if phishing_probability >= decision_threshold else "legitimate"
            )
            confidence = round(max(phishing_probability, 1 - phishing_probability) * 100, 1)
            calibration_scope = bundle.get("calibration_scope")
            model_available = True
    except (
        ImportError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RuntimeError,
    ) as exc:
        model_error = type(exc).__name__
        logger.exception("URL phishing model inference failed.")

    heuristic_score, heuristic_indicators = _heuristic_risk(
        features, tls, redirects, intelligence
    )
    if phishing_probability is None:
        risk_score = heuristic_score
    else:
        risk_score = round(0.65 * heuristic_score + 0.35 * phishing_probability * 100)
    risk_score = min(100, max(0, risk_score))
    classification = _classification(
        risk_score, heuristic_score, ml_prediction, phishing_probability or 0.0,
        intelligence, model_available,
    )
    legacy_verdict, verdict_key = _legacy_verdict(classification)

    confirmed = []
    if intelligence.get("confirmed_malicious_sources"):
        confirmed.append(
            "Reported malicious by: "
            + ", ".join(intelligence["confirmed_malicious_sources"])
            + "."
        )
    ml_evidence = []
    if ml_prediction:
        ml_evidence.append(
            f"Calibrated model prediction: {ml_prediction}; "
            f"phishing score {phishing_probability * 100:.1f}% on synthetic validation."
            if phishing_probability is not None
            else f"Model prediction: {ml_prediction}."
        )
    unavailable = []
    if tls["status"] in {"unavailable", "invalid_or_unavailable", "blocked"}:
        unavailable.append(f"TLS: {tls['reason']}")
    if redirects["status"] in {"unavailable", "blocked", "limit_reached"}:
        unavailable.append(f"Redirect analysis: {redirects['reason']}")
    if intelligence["status"] in {"unavailable", "rate_limited"}:
        unavailable.append(
            intelligence.get("reason", "Threat-intelligence providers are unavailable.")
        )
    for source in intelligence.get("sources", []):
        if source.get("status") in {"unavailable", "rate_limited"}:
            unavailable.append(
                f"{source['source']}: {source.get('reason', source['status'])}"
            )
    if model_error:
        unavailable.append(f"Machine-learning model unavailable ({model_error}).")

    reasons = list(dict.fromkeys(
        confirmed + heuristic_indicators + ml_evidence
        or ["No significant URL-structure indicators were found."]
    ))
    if classification == "LEGITIMATE":
        reasons.append(
            "The URL is classified as legitimate by the synthetic-data-trained model; "
            "this is not a verified reputation or safety guarantee."
        )
    elif classification == "UNKNOWN / INSUFFICIENT DATA":
        reasons.append("Available evidence is insufficient for a reliable classification.")

    if tls.get("status") == "valid":
        reasons.append("TLS certificate chain and hostname validation succeeded at check time.")
    if redirects.get("status") == "checked":
        reasons.append(f"Redirect check completed; {redirects.get('redirect_count', 0)} redirect(s) observed.")
    reasons.extend(unavailable)

    threat_level = (
        "Critical" if risk_score >= 80 else
        "High" if risk_score >= 60 else
        "Medium" if risk_score >= 40 else
        "Low" if classification == "LEGITIMATE" else "Unknown"
    )
    return {
        "features": features,
        "submitted_url": str(url or ""),
        "normalized_url": features["normalized_url"],
        "classification": classification,
        "verdict": legacy_verdict,
        "verdict_key": verdict_key,
        "risk_score": risk_score,
        "risk_category": _risk_category(risk_score),
        "confidence": confidence,
        "ml_prediction": ml_prediction.title() if ml_prediction else "Unavailable",
        "ml_raw_prediction": ml_prediction,
        "ml_phishing_probability": (
            round(phishing_probability * 100, 1) if phishing_probability is not None else None
        ),
        "model_confidence_scope": calibration_scope,
        "threat_level": threat_level,
        "protocol_analysis": {
            "scheme": features["protocol"],
            "https": features["uses_https"],
            "reason": "HTTPS encrypts transport but does not prove that a site is legitimate.",
        },
        "domain_analysis": {
            "hostname": features["host"],
            "registrable_domain": features["registrable_domain"],
            "tld": features["tld"],
            "indicators": features["domain_indicators"],
            "brand_similarity": features["brand_similarity"],
            "status": "heuristic",
        },
        "structural_analysis": {
            "indicators": features["structural_indicators"],
            "suspicious_keywords": features["suspicious_keywords"],
            "feature_summary": {
                "url_length": features["url_length"],
                "subdomain_count": features["subdomain_count"],
                "special_char_count": features["special_char_count"],
                "encoded_character_count": features["percent_encoded_count"],
                "entropy": features["url_entropy"],
                "fragment_present": features["fragment_present"],
            },
        },
        "tls_analysis": tls,
        "redirect_analysis": redirects,
        "threat_intelligence": intelligence,
        "evidence": {
            "confirmed": confirmed,
            "heuristic": heuristic_indicators,
            "machine_learning": ml_evidence,
            "unavailable": unavailable,
        },
        "reasons": reasons,
        "recommendations": list(_RECOMMENDATIONS[classification]),
    }
