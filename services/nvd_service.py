"""Bounded NVD CVE search and process-local response caching."""

import json
import logging
import math
import os
import re
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("bastionix.nvd")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT_SECONDS = 5
CACHE_TTL_SECONDS = 6 * 60 * 60
FAILURE_CACHE_TTL_SECONDS = 60
MAX_CACHE_ENTRIES = 1024
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CVSS_METRICS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
_cache = {}
_cache_lock = threading.Lock()


def classify_cvss(score, cvss_version="3.1"):
    if score is None:
        return "Unknown"
    if cvss_version not in {"2.0", "3.0", "3.1", "4.0"}:
        return "Unknown"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "Unknown"
    if not math.isfinite(score) or not 0 <= score <= 10:
        return "Unknown"
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if cvss_version == "2.0":
        return "High"
    if score < 9:
        return "High"
    return "Critical"


def _cvss(metrics):
    if not isinstance(metrics, dict):
        return None, "Unknown", None
    for key, metric_version in _CVSS_METRICS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        if not isinstance(entries, list) or not isinstance(entries[0], dict):
            continue
        data = entries[0].get("cvssData", {})
        if not isinstance(data, dict):
            continue
        try:
            score = float(data["baseScore"])
        except (KeyError, TypeError, ValueError):
            continue
        if not math.isfinite(score) or not 0 <= score <= 10:
            continue
        cvss_version = str(data.get("version") or metric_version)
        if cvss_version != metric_version:
            continue
        return score, classify_cvss(score, cvss_version), cvss_version
    return None, "Unknown", None


def _fetch(query):
    params = urlencode({"keywordSearch": query, "resultsPerPage": 20})
    headers = {"User-Agent": "BastionIX/1.0.0 defensive vulnerability intelligence"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    request = Request(f"{NVD_API}?{params}", headers=headers)
    with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        if response.status == 429:
            return {"status": "rate_limited", "findings": []}
        payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities", []), list):
        raise ValueError("NVD response has an invalid structure.")
    results = []
    for item in payload.get("vulnerabilities", []):
        if not isinstance(item, dict):
            continue
        cve = item.get("cve", {})
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not _CVE_ID.fullmatch(cve_id):
            continue
        descriptions = cve.get("descriptions", [])
        if not isinstance(descriptions, list):
            descriptions = []
        description = next(
            (
                entry.get("value", "") for entry in descriptions
                if isinstance(entry, dict) and entry.get("lang") == "en"
            ),
            "",
        )
        score, severity, cvss_version = _cvss(cve.get("metrics", {}))
        references_data = cve.get("references", [])
        if not isinstance(references_data, list):
            references_data = []
        references = [
            reference.get("url") for reference in references_data
            if isinstance(reference, dict)
            and isinstance(reference.get("url"), str)
            and reference["url"].startswith("https://")
        ][:20]
        results.append({
            "cve_id": cve_id,
            "description": description[:4000],
            "cvss_score": score,
            "cvss_version": cvss_version,
            "severity": severity,
            "references": references,
        })
    return {"status": "available", "findings": results}


def lookup_cves(product, version):
    """Return potential keyword matches; a version match is not exploitability proof."""
    product = " ".join(str(product or "").split())[:100]
    version = " ".join(str(version or "").split())[:80]
    if not product or not version or product.lower() in {"unknown", "tcpwrapped"}:
        return {"status": "unavailable", "findings": [], "reason": "A product and version are required for CVE lookup."}
    query = f"{product} {version}"
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(query)
        if cached:
            ttl = CACHE_TTL_SECONDS if cached[1]["status"] == "available" else FAILURE_CACHE_TTL_SECONDS
            if now - cached[0] < ttl:
                return cached[1]
    try:
        result = _fetch(query)
    except HTTPError as exc:
        status = "rate_limited" if exc.code == 429 else "unavailable"
        result = {"status": status, "findings": [], "reason": f"NVD returned HTTP {exc.code}."}
    except (OSError, URLError, TimeoutError, ValueError, UnicodeError) as exc:
        logger.info("NVD lookup unavailable (%s).", type(exc).__name__)
        result = {"status": "unavailable", "findings": [], "reason": f"NVD lookup unavailable ({type(exc).__name__})."}
    with _cache_lock:
        if len(_cache) >= MAX_CACHE_ENTRIES and query not in _cache:
            oldest = min(_cache, key=lambda key: _cache[key][0])
            _cache.pop(oldest, None)
        _cache[query] = (now, result)
    return result
