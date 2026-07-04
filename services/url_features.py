"""
services/url_features.py
---------------------------
Deterministic, rule-based feature extraction for phishing URL detection.
No network requests are made - analysis is purely lexical/structural so it
is safe to run against untrusted, potentially malicious URLs.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking", "confirm",
    "signin", "webscr", "password", "suspend", "urgent", "billing",
    "paypal", "amazon", "apple", "microsoft", "support", "unlock",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "tiny.cc",
}

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc.split(":")[0]  # strip port if present


def extract_features(url: str) -> dict:
    """Extract phishing-relevant lexical/structural features from a URL string."""
    url = url.strip()
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = _extract_domain(url)
    path = parsed.path or ""

    uses_https = parsed.scheme == "https"
    url_length = len(url)
    domain_length = len(domain)
    subdomain_count = max(domain.count(".") - 1, 0) if domain else 0

    domain_no_port = domain
    has_ip_address = bool(IP_PATTERN.match(domain_no_port))

    has_at_symbol = "@" in url
    # A double-slash appearing anywhere after the scheme's own "//" suggests
    # an embedded redirect trick (e.g. http://real.com//http://fake.com)
    after_scheme = url.split("://", 1)[-1]
    has_double_slash_redirect = "//" in after_scheme

    is_shortened = domain.lower() in SHORTENER_DOMAINS

    special_chars = re.findall(r"[^a-zA-Z0-9:/.\-_]", url)
    special_char_count = len(special_chars)

    lowered_url = url.lower()
    has_suspicious_keywords = any(kw in lowered_url for kw in SUSPICIOUS_KEYWORDS)

    tld = domain.split(".")[-1] if "." in domain else ""

    has_hyphen_in_domain = "-" in domain
    digit_ratio_in_domain = (sum(c.isdigit() for c in domain) / len(domain)) if domain else 0.0

    features = {
        "uses_https": uses_https,
        "url_length": url_length,
        "domain_length": domain_length,
        "subdomain_count": subdomain_count,
        "has_ip_address": has_ip_address,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_redirect": has_double_slash_redirect,
        "is_shortened": is_shortened,
        "has_suspicious_keywords": has_suspicious_keywords,
        "special_char_count": special_char_count,
        "tld": tld,
        "has_hyphen_in_domain": has_hyphen_in_domain,
        "digit_ratio_in_domain": round(digit_ratio_in_domain, 3),
        "path_length": len(path),
        "domain": domain,
    }
    return features


def feature_vector(features: dict) -> list:
    """Fixed-order numeric vector for the ML model. Order MUST match
    ml/train_url_model.py."""
    return [
        int(features["uses_https"]),
        features["url_length"],
        features["domain_length"],
        features["subdomain_count"],
        int(features["has_ip_address"]),
        int(features["has_at_symbol"]),
        int(features["has_double_slash_redirect"]),
        int(features["is_shortened"]),
        int(features["has_suspicious_keywords"]),
        features["special_char_count"],
        int(features["has_hyphen_in_domain"]),
        features["digit_ratio_in_domain"],
        features["path_length"],
    ]


FEATURE_NAMES = [
    "uses_https", "url_length", "domain_length", "subdomain_count",
    "has_ip_address", "has_at_symbol", "has_double_slash_redirect",
    "is_shortened", "has_suspicious_keywords", "special_char_count",
    "has_hyphen_in_domain", "digit_ratio_in_domain", "path_length",
]
