"""Network-free URL parsing and deterministic phishing feature extraction."""

import ipaddress
import math
import re
from collections import Counter
from difflib import SequenceMatcher
from functools import lru_cache
from urllib.parse import unquote, urlsplit


FEATURE_NAMES = [
    "https", "http", "url_length", "hostname_length", "domain_length",
    "subdomain_count", "ip_address", "dot_count", "hyphen_count",
    "underscore_count", "slash_count", "special_char_count", "digit_count",
    "at_symbol_count", "percent_encoded_count", "question_mark_count",
    "equal_sign_count", "ampersand_count", "path_length", "query_length",
    "path_segment_count", "suspicious_keyword_count", "url_entropy",
    "suspicious_tld", "punycode_indicator", "shortener_indicator",
    "redirect_indicator", "encoded_url_indicator", "suspicious_port",
    "login_keyword", "password_keyword", "verification_keyword",
]

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "secure",
    "security", "update", "password", "wallet", "banking", "payment",
    "confirm", "authentication", "recovery", "support", "credential",
    "billing", "unlock", "suspend", "urgent", "webscr",
}
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "tiny.cc",
    "short.example", "redirect.example",
}
SUSPICIOUS_TLDS = {
    "click", "country", "gq", "kim", "link", "loan", "lol", "men", "ml",
    "mom", "party", "rest", "racing", "review", "science", "shop", "stream",
    "tk", "top", "work", "xyz", "zip",
}
BRANDS = {
    "amazon", "apple", "bankofamerica", "binance", "chase", "coinbase",
    "facebook", "google", "linkedin", "microsoft", "netflix", "paypal",
    "outlook", "telegram", "whatsapp",
}
_OFFICIAL_BRAND_DOMAINS = {
    "amazon": {"amazon.com"},
    "apple": {"apple.com"},
    "bankofamerica": {"bankofamerica.com"},
    "binance": {"binance.com"},
    "chase": {"chase.com"},
    "coinbase": {"coinbase.com"},
    "facebook": {"facebook.com"},
    "google": {"google.com"},
    "linkedin": {"linkedin.com"},
    "microsoft": {"microsoft.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
    "outlook": {"outlook.com", "live.com"},
    "telegram": {"telegram.org"},
    "whatsapp": {"whatsapp.com"},
}
_BRAND_NOISE = {
    "account", "auth", "login", "secure", "security", "signin", "support",
    "update", "user", "verify", "www",
}
_REDIRECT_PARAMETERS = {
    "continue", "dest", "destination", "forward", "goto", "next", "redirect",
    "redirect_uri", "return", "returnurl", "target", "url",
}
_KEYWORD_RE = re.compile(
    r"(?<![a-z0-9])(" + "|".join(sorted(SUSPICIOUS_KEYWORDS, key=len, reverse=True))
    + r")(?![a-z0-9])",
    re.IGNORECASE,
)
_ENCODED_RE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)
_HEX_RE = re.compile(r"(?<![a-z0-9])(?:0x[0-9a-f]{6,}|0x[0-9a-f]{2})(?![a-z0-9])", re.I)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_MULTI_LABEL_SUFFIXES = {
    "ac.uk", "co.jp", "co.nz", "co.uk", "com.au", "com.br", "com.cn",
    "com.hk", "com.sg", "edu.au", "gov.uk", "net.au", "org.au", "org.uk",
}
_URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def normalize_url(url):
    """Normalize a user-provided URL without resolving or contacting its host."""
    value = str(url).strip()
    if not _URL_SCHEME_RE.match(value):
        value = f"https://{value}"
    return value


def _valid_hostname(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        labels = host.rstrip(".").split(".")
        return bool(labels) and all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        )


def _registrable_parts(host):
    host = host.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return host, host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return host, host
    suffix = ".".join(labels[-2:])
    suffix_size = 2 if suffix in _MULTI_LABEL_SUFFIXES else 1
    if len(labels) <= suffix_size:
        return host, host
    return ".".join(labels[-suffix_size - 1:]), labels[-suffix_size - 1]


def _safe_split(url):
    normalized = normalize_url(url)
    if re.search(r"[\x00-\x20\x7f]", normalized):
        return normalized, None, "URL contains whitespace or control characters."
    try:
        parsed = urlsplit(normalized)
        if parsed.scheme.lower() not in {"http", "https"}:
            return normalized, None, "Only HTTP and HTTPS URLs can be analyzed."
        host = parsed.hostname
        if not host:
            return normalized, None, "URL does not contain a hostname."
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return normalized, None, "URL contains an invalid port."
        ascii_host = host.encode("idna").decode("ascii")
        if len(ascii_host) > 253 or not _valid_hostname(ascii_host):
            return normalized, None, "URL contains an invalid hostname."
        return normalized, parsed, None
    except (UnicodeError, ValueError):
        return normalized, None, "URL structure or hostname is invalid."


def _entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 4)


@lru_cache(maxsize=50000)
def _brand_analysis(host, registrable):
    labels = [label.lower() for label in host.split(".")]
    try:
        ipaddress.ip_address(host)
        return False, False, 0.0, []
    except ValueError:
        pass

    domain_label = registrable.rsplit(".", 1)[0].lower()
    domain_tokens = [
        token for token in re.split(r"[^a-z0-9]+", domain_label)
        if token and token not in _BRAND_NOISE
    ]
    candidates = list(domain_tokens)
    for label in labels:
        candidates.extend(
            token for token in re.split(r"[^a-z0-9]+", label)
            if token and token not in _BRAND_NOISE
        )
    compact = "".join(domain_tokens)
    closest = max(
        (SequenceMatcher(None, candidate, brand).ratio() for candidate in candidates for brand in BRANDS),
        default=0.0,
    )
    brand_terms = {
        brand for brand in BRANDS
        if any(brand in token for token in candidates)
    }
    typosquatting = any(
        0.76 <= SequenceMatcher(None, compact, brand).ratio() < 1.0
        for brand in BRANDS
    )
    spoofed = bool(
        brand_terms
        and any(
            registrable not in _OFFICIAL_BRAND_DOMAINS[brand]
            for brand in brand_terms
        )
    )
    indicators = []
    if typosquatting:
        indicators.append("The registered-domain name resembles a well-known brand.")
    if spoofed:
        indicators.append("A brand name appears in the hostname but not as its registered domain.")
    if any(label.startswith("xn--") for label in labels):
        indicators.append("The hostname contains an IDNA/Punycode label.")
    if any(not label.isascii() for label in labels):
        indicators.append("The hostname contains Unicode characters; visual homographs are possible.")
    return typosquatting, spoofed, round(closest, 3), indicators


def extract_features(url):
    """Return ML inputs plus explainable structural/domain indicators.

    Extraction is deterministic and network-free; URL strings are never fetched.
    """
    normalized, parsed, error = _safe_split(url)
    if parsed is None:
        features = {name: 0 for name in FEATURE_NAMES}
        features.update({
            "https": 0, "http": 0, "url_length": len(str(url or "")),
            "url": str(url or ""), "normalized_url": normalized, "domain": "",
            "host": "", "registrable_domain": "", "tld": "",
            "protocol": "unknown", "is_valid": False, "validation_error": error,
            "has_ip_address": False, "has_at_symbol": "@" in str(url or ""),
            "has_double_slash_redirect": False, "is_shortened": False,
            "has_suspicious_keywords": False, "has_hyphen_in_domain": False,
            "digit_ratio_in_domain": 0.0, "special_char_count": 0,
            "path_length": 0, "suspicious_keywords": [], "structural_indicators": [],
            "domain_indicators": [], "typosquatting": False,
            "brand_impersonation": False, "brand_similarity": 0.0,
            "high_entropy": False, "suspicious_query": False,
            "suspicious_path": False, "fragment_present": False,
            "multiple_at_symbols": False, "hexadecimal_obfuscation": False,
            "unicode_hostname": False, "excessive_dots": False,
            "excessive_hyphens": False, "suspicious_subdomain": False,
        })
        return features

    host = (parsed.hostname or "").rstrip(".").lower()
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        ascii_host = host.lower()
    registered, domain_label = _registrable_parts(ascii_host)
    tld = ascii_host.rsplit(".", 1)[-1] if "." in ascii_host else ""
    raw = normalized
    path = parsed.path or ""
    query = parsed.query or ""
    lower_url = raw.lower()
    keyword_matches = sorted(set(item.lower() for item in _KEYWORD_RE.findall(lower_url)))
    keyword_set = set(keyword_matches)
    query_names = {
        key.lower() for key in re.findall(r"(?:^|&)([^=&;]+)=", query)
    }
    decoded = unquote(raw)
    try:
        ipaddress.ip_address(ascii_host)
        is_ip = True
    except ValueError:
        is_ip = bool(_IPV4_RE.fullmatch(ascii_host))
    port = parsed.port
    suspicious_port = bool(port and port not in {80, 443})
    encoded_count = len(_ENCODED_RE.findall(raw))
    punycode = any(label.startswith("xn--") for label in ascii_host.split("."))
    unicode_hostname = any(not label.isascii() for label in host.split("."))
    shortener = ascii_host in SHORTENER_DOMAINS
    redirect = (
        bool(query_names & _REDIRECT_PARAMETERS)
        or "//" in path
        or bool(re.search(r"https?%3a%2f%2f", lower_url))
    )
    suspicious_query = bool(query_names & _REDIRECT_PARAMETERS) or (
        bool(query) and len(keyword_set & {"login", "password", "verify", "account"}) >= 2
    )
    suspicious_path = len(keyword_set & {
        "login", "signin", "verify", "verification", "password", "account",
        "wallet", "banking", "payment", "recovery", "credential",
    }) >= 2
    entropy = _entropy(raw)
    dot_count = ascii_host.count(".")
    hyphen_count = raw.count("-")
    digit_count = sum(character.isdigit() for character in raw)
    special_count = sum(not character.isalnum() for character in raw)
    typosquatting, brand_impersonation, similarity, domain_indicators = _brand_analysis(
        ascii_host, registered
    )
    subdomains = ascii_host.split(".")
    suffix_labels = len(registered.split("."))
    subdomain_count = max(0, len(subdomains) - suffix_labels)
    has_at = raw.count("@") > 0
    host_length = len(ascii_host)
    normalized_domain_length = len(domain_label)
    path_segments = [part for part in path.split("/") if part]
    suspicious_subdomain = bool(
        subdomain_count >= 3
        or any(label in _BRAND_NOISE for label in subdomains[:-suffix_labels])
    )
    features = {
        "https": int(parsed.scheme.lower() == "https"),
        "http": int(parsed.scheme.lower() == "http"),
        "url_length": len(raw),
        "hostname_length": host_length,
        "domain_length": normalized_domain_length,
        "subdomain_count": subdomain_count,
        "ip_address": int(is_ip),
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "underscore_count": raw.count("_"),
        "slash_count": raw.count("/"),
        "special_char_count": special_count,
        "digit_count": digit_count,
        "at_symbol_count": raw.count("@"),
        "percent_encoded_count": encoded_count,
        "question_mark_count": raw.count("?"),
        "equal_sign_count": raw.count("="),
        "ampersand_count": raw.count("&"),
        "path_length": len(path),
        "query_length": len(query),
        "path_segment_count": len(path_segments),
        "suspicious_keyword_count": len(keyword_matches),
        "url_entropy": _entropy(raw),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "punycode_indicator": int(punycode or unicode_hostname),
        "shortener_indicator": int(shortener),
        "redirect_indicator": int(redirect),
        "encoded_url_indicator": int(encoded_count > 0 or decoded != raw or bool(_HEX_RE.search(raw))),
        "suspicious_port": int(suspicious_port),
        "login_keyword": int(bool(keyword_set & {"login", "signin"})),
        "password_keyword": int("password" in keyword_set),
        "verification_keyword": int(bool(keyword_set & {"verify", "verification"})),
        "url": normalized,
        "normalized_url": normalized,
        "domain": ascii_host,
        "host": ascii_host,
        "registrable_domain": registered,
        "tld": tld,
        "protocol": parsed.scheme.lower(),
        "port": port or (443 if parsed.scheme.lower() == "https" else 80),
        "is_valid": True,
        "validation_error": None,
        "has_ip_address": is_ip,
        "has_at_symbol": has_at,
        "multiple_at_symbols": raw.count("@") > 1,
        "has_double_slash_redirect": "//" in raw.split("://", 1)[-1],
        "is_shortened": shortener,
        "has_suspicious_keywords": bool(keyword_matches),
        "suspicious_keywords": keyword_matches,
        "has_hyphen_in_domain": "-" in ascii_host,
        "digit_ratio_in_domain": round(
            sum(character.isdigit() for character in ascii_host) / max(1, len(ascii_host)), 3
        ),
        "structural_indicators": [],
        "domain_indicators": domain_indicators,
        "typosquatting": typosquatting,
        "brand_impersonation": brand_impersonation,
        "brand_similarity": similarity,
        "high_entropy": entropy >= 4.5 and len(raw) >= 30,
        "suspicious_query": suspicious_query,
        "suspicious_path": suspicious_path,
        "fragment_present": bool(parsed.fragment),
        "hexadecimal_obfuscation": bool(_HEX_RE.search(raw)),
        "unicode_hostname": unicode_hostname,
        "excessive_dots": dot_count >= 5,
        "excessive_hyphens": ascii_host.count("-") >= 3,
        "suspicious_subdomain": suspicious_subdomain,
        "has_nonstandard_port": suspicious_port,
        "uses_https": parsed.scheme.lower() == "https",
    }
    structural = []
    if parsed.scheme.lower() == "http":
        structural.append("The URL uses unencrypted HTTP.")
    if len(raw) > 120:
        structural.append("The URL is unusually long.")
    if dot_count >= 5:
        structural.append("The hostname contains an unusually high number of dots.")
    if ascii_host.count("-") >= 3:
        structural.append("The hostname contains several hyphens.")
    if special_count >= 12:
        structural.append("The URL contains many special characters.")
    if features["multiple_at_symbols"]:
        structural.append("The URL contains multiple '@' symbols.")
    elif has_at:
        structural.append("The URL contains an '@' symbol that can obscure its destination.")
    if is_ip:
        structural.append("The URL uses an IP address instead of a named host.")
    if suspicious_port:
        structural.append("The URL uses a non-standard HTTP(S) port.")
    if encoded_count:
        structural.append("The URL contains percent-encoded characters.")
    if features["encoded_url_indicator"] and not encoded_count:
        structural.append("The URL contains encoded or hexadecimal obfuscation.")
    if subdomain_count >= 3:
        structural.append("The hostname has multiple subdomain levels.")
    if suspicious_path:
        structural.append("The path combines multiple credential or account-related terms.")
    if suspicious_query:
        structural.append("The query contains redirect or credential-related parameters.")
    if features["fragment_present"]:
        structural.append("The URL includes a fragment.")
    if redirect:
        structural.append("The URL contains a redirect indicator.")
    if shortener:
        structural.append("The host is a known or synthetic-example URL shortener.")
    if features["high_entropy"]:
        structural.append("The URL has high character entropy.")
    if tld in SUSPICIOUS_TLDS:
        structural.append("The top-level domain is on a heuristic watchlist; this alone is not proof of phishing.")
    features["structural_indicators"] = structural
    return features


def feature_vector(features):
    """Return the stable numeric model vector in FEATURE_NAMES order."""
    return [features[name] for name in FEATURE_NAMES]
