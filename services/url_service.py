"""
services/url_service.py
--------------------------
Orchestrates the phishing URL analysis pipeline: feature extraction, ML
prediction, threat-level derivation, human-readable reasons, and
recommendations. Purely lexical/structural analysis - no live network
requests are made to the target URL, so it's safe to analyze
untrusted/malicious links.
"""

from services.url_features import extract_features, feature_vector
from ml.model_loader import get_url_model

VERDICT_TO_THREAT = {
    "legitimate": "Low",
    "suspicious": "Medium",
    "phishing": "Critical",
}


def _build_reasons(features: dict) -> list:
    reasons = []
    if not features["uses_https"]:
        reasons.append("The URL does not use HTTPS encryption.")
    if features["has_ip_address"]:
        reasons.append("The domain is a raw IP address rather than a named domain.")
    if features["has_at_symbol"]:
        reasons.append("The URL contains an '@' symbol, often used to disguise the real destination.")
    if features["has_double_slash_redirect"]:
        reasons.append("The URL contains a suspicious embedded redirect pattern ('//').")
    if features["is_shortened"]:
        reasons.append("The URL uses a link-shortening service, which can hide the real destination.")
    if features["has_suspicious_keywords"]:
        reasons.append("The URL contains keywords commonly used in phishing (e.g. 'login', 'verify', 'secure').")
    if features["subdomain_count"] >= 3:
        reasons.append("The domain has an unusually high number of subdomains.")
    if features["url_length"] > 75:
        reasons.append("The URL is unusually long, which can be used to obscure its true destination.")
    if features["has_hyphen_in_domain"]:
        reasons.append("The domain contains hyphens, sometimes used to mimic legitimate brand names.")
    if features["digit_ratio_in_domain"] > 0.3:
        reasons.append("The domain contains an unusually high proportion of digits.")
    if features["tld"] in {"tk", "ml", "ga", "cf", "xyz", "top", "click", "info"}:
        reasons.append(f"The top-level domain '.{features['tld']}' is frequently associated with abuse.")
    if not reasons:
        reasons.append("No major structural red flags were detected.")
    return reasons


def _build_recommendations(verdict: str) -> list:
    if verdict == "phishing":
        return [
            "Do not enter any credentials or personal information on this site.",
            "Do not download or open any files linked from this URL.",
            "Report the URL to your organization's security team or an anti-phishing service.",
            "If you already entered credentials, change your password immediately on the legitimate site.",
        ]
    if verdict == "suspicious":
        return [
            "Verify the sender/source before clicking this link again.",
            "Navigate to the site directly via a known bookmark or search engine instead of the link.",
            "Enable multi-factor authentication on any account this link references.",
        ]
    return [
        "The URL appears structurally safe, but always verify the content before entering sensitive data.",
        "Keep your browser and security software up to date.",
    ]


def _derive_verdict(ml_label: str, confidence: float, features: dict) -> str:
    """Combine ML output with a couple of high-confidence rule overrides
    (defense in depth: don't let the model alone decide on obvious red
    flags like raw-IP hosts)."""
    if features["has_ip_address"] and features["has_suspicious_keywords"]:
        return "phishing"

    if ml_label == "phishing" and confidence >= 60:
        return "phishing"
    if ml_label == "phishing":
        return "suspicious"
    if ml_label == "legitimate" and confidence < 60:
        return "suspicious"
    return "legitimate" if ml_label == "legitimate" else "suspicious"


def analyze_url(url: str) -> dict:
    if not url or not url.strip():
        raise ValueError("URL must not be empty.")

    features = extract_features(url)

    ml_label, ml_confidence = "legitimate", 50.0
    try:
        import pandas as pd
        bundle = get_url_model()
        model = bundle["model"]
        vec_df = pd.DataFrame([feature_vector(features)], columns=bundle["feature_names"])
        pred = model.predict(vec_df)[0]
        proba = model.predict_proba(vec_df)[0]
        confidence = float(max(proba))
        ml_label, ml_confidence = pred, round(confidence * 100, 1)
    except Exception:
        ml_label, ml_confidence = "legitimate", 50.0

    verdict_key = _derive_verdict(ml_label, ml_confidence, features)
    verdict_display = {"legitimate": "Safe", "suspicious": "Suspicious", "phishing": "Phishing"}[verdict_key]
    threat_level = VERDICT_TO_THREAT[verdict_key]

    reasons = _build_reasons(features)
    recommendations = _build_recommendations(verdict_key)

    return {
        "features": features,
        "verdict": verdict_display,
        "verdict_key": verdict_key,
        "confidence": ml_confidence,
        "threat_level": threat_level,
        "reasons": reasons,
        "recommendations": recommendations,
        "ml_raw_prediction": ml_label,
    }
