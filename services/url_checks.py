"""Optional, bounded network checks for URL TLS, redirects, and reputation."""

import http.client
import ipaddress
import json
import os
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

NETWORK_TIMEOUT_SECONDS = 2.5
MAX_REDIRECTS = 5
MAX_URL_LENGTH = 2048
_USER_AGENT = "BastionIX/1.0.0 (URL safety check)"


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _resolve_public(host):
    try:
        address = ipaddress.ip_address(host)
        addresses = [str(address)]
    except ValueError:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise OSError("Hostname did not resolve to an address.")
    parsed = [ipaddress.ip_address(address) for address in addresses]
    if any(not address.is_global for address in parsed):
        raise PermissionError("Network checks are blocked for non-public IP addresses.")
    return parsed[0]


def _connect(host, port, scheme):
    address = _resolve_public(host)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(NETWORK_TIMEOUT_SECONDS)
    try:
        target = (str(address), port, 0, 0) if address.version == 6 else (str(address), port)
        connection.connect(target)
        if scheme == "https":
            context = ssl.create_default_context()
            connection = context.wrap_socket(connection, server_hostname=host)
        return connection
    except Exception:
        connection.close()
        raise


def inspect_tls(url, enabled=False):
    """Validate a public HTTPS host's TLS chain and hostname, if enabled."""
    if not enabled:
        return {"status": "unavailable", "reason": "Network checks are disabled."}
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return {"status": "not_applicable", "reason": "The URL does not use HTTPS."}
        port = parsed.port or 443
        if port != 443:
            return {"status": "unavailable", "reason": "TLS checks are limited to port 443."}
        host = parsed.hostname.encode("idna").decode("ascii")
        connection = _connect(host, port, "https")
        try:
            certificate = connection.getpeercert()
        finally:
            connection.close()
        return {
            "status": "valid",
            "hostname_verified": True,
            "trust_chain_verified": True,
            "not_after": certificate.get("notAfter"),
            "reason": "The TLS certificate chain and hostname validated at check time.",
        }
    except PermissionError as exc:
        return {"status": "blocked", "reason": str(exc)}
    except ssl.SSLCertVerificationError as exc:
        return {
            "status": "invalid",
            "hostname_verified": False,
            "trust_chain_verified": False,
            "reason": f"TLS certificate verification failed ({type(exc).__name__}).",
        }
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {
            "status": "invalid_or_unavailable",
            "hostname_verified": False,
            "trust_chain_verified": False,
            "reason": f"TLS validation failed or was unavailable ({type(exc).__name__}).",
        }


def _safe_head(url):
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("Redirect URL exceeds the configured length limit.")
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Redirect target is not an HTTP(S) URL.")
    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in {80, 443}:
        raise PermissionError("Redirect checks are blocked for non-standard ports.")
    host = parsed.hostname.encode("idna").decode("ascii")
    sock = _connect(host, port, scheme)
    connection_type = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    connection = connection_type(host, port, timeout=NETWORK_TIMEOUT_SECONDS)
    connection.sock = sock
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    try:
        connection.request("HEAD", target, headers={"User-Agent": _USER_AGENT, "Connection": "close"})
        response = connection.getresponse()
        location = response.getheader("Location")
        return response.status, location
    finally:
        connection.close()


def inspect_redirects(url, enabled=False):
    """Follow only bounded HEAD redirects to validated public addresses."""
    if not enabled:
        return {"status": "unavailable", "reason": "Network checks are disabled.", "chain": []}
    current = url
    seen = {current}
    chain = []
    try:
        for _ in range(MAX_REDIRECTS + 1):
            status, location = _safe_head(current)
            if status not in {301, 302, 303, 307, 308} or not location:
                return {
                    "status": "checked",
                    "chain": chain,
                    "redirect_count": len(chain),
                    "final_url": current,
                    "reason": "Redirect chain checked using bounded HEAD requests.",
                }
            destination = urljoin(current, location)
            if len(destination) > MAX_URL_LENGTH:
                raise ValueError("Redirect target exceeds the configured length limit.")
            if destination in seen:
                raise ValueError("A redirect loop was detected.")
            seen.add(destination)
            chain.append({"status_code": status, "url": destination})
            current = destination
        return {
            "status": "limit_reached",
            "chain": chain,
            "redirect_count": len(chain),
            "reason": "The maximum redirect count was reached.",
        }
    except PermissionError as exc:
        return {"status": "blocked", "chain": chain, "reason": str(exc)}
    except (OSError, http.client.HTTPException, ValueError, ssl.SSLError) as exc:
        return {
            "status": "unavailable",
            "chain": chain,
            "reason": f"Redirect check failed or was unavailable ({type(exc).__name__}).",
        }


def _provider_result(name, check_url, headers=None, data=None, json_body=None):
    request_headers = {"User-Agent": _USER_AGENT, **(headers or {})}
    body = json.dumps(json_body).encode("utf-8") if json_body is not None else data
    if json_body is not None:
        request_headers["Content-Type"] = "application/json"
    request = Request(check_url, data=body, headers=request_headers, method="POST" if body else "GET")
    try:
        opener = build_opener(_NoRedirectHandler)
        with opener.open(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:
            if response.status == 429:
                return {"source": name, "status": "rate_limited", "malicious": None}
            result = json.loads(response.read(256 * 1024).decode("utf-8"))
        return {"source": name, "status": "checked", "response": result}
    except HTTPError as exc:
        return {
            "source": name,
            "status": "rate_limited" if exc.code == 429 else "unavailable",
            "reason": (
                "Provider rate limit reached."
                if exc.code == 429
                else f"Provider returned HTTP {exc.code}."
            ),
        }
    except (OSError, URLError, ssl.SSLError, ValueError, UnicodeError) as exc:
        return {
            "source": name,
            "status": "unavailable",
            "reason": f"Provider request failed ({type(exc).__name__}).",
        }


def _configured_provider_checks(url):
    results = []
    google_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
    if google_key:
        payload = {
            "client": {"clientId": "ai-cyber-security-toolkit", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        result = _provider_result(
            "Google Safe Browsing",
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?"
            + urlencode({"key": google_key}),
            json_body=payload,
        )
        if result.get("status") == "checked":
            result["malicious"] = bool(result.get("response", {}).get("matches"))
            result.pop("response", None)
        results.append(result)

    virus_total_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if virus_total_key:
        import base64

        encoded_url = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        result = _provider_result(
            "VirusTotal",
            f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
            headers={"x-apikey": virus_total_key},
        )
        if result.get("status") == "checked":
            stats = result.get("response", {}).get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
            result["malicious"] = int(stats.get("malicious", 0)) > 0
            result["suspicious"] = int(stats.get("suspicious", 0)) > 0
            result.pop("response", None)
        results.append(result)

    phishtank_key = os.environ.get("PHISHTANK_API_KEY")
    if phishtank_key:
        form_data = urlencode({
            "url": url, "format": "json", "app_key": phishtank_key,
        }).encode("ascii")
        result = _provider_result(
            "PhishTank",
            "https://checkurl.phishtank.com/checkurl/",
            data=form_data,
        )
        if result.get("status") == "checked":
            record = result.get("response", {}).get("results", {})
            in_database = record.get("in_database") in (True, "true", "yes")
            verified = record.get("verified") in (True, "true", "yes")
            result["malicious"] = in_database and verified
            result.pop("response", None)
        results.append(result)

    urlhaus_key = os.environ.get("URLHAUS_AUTH_KEY")
    if urlhaus_key:
        form_data = urlencode({"url": url}).encode("ascii")
        result = _provider_result(
            "URLhaus",
            "https://urlhaus-api.abuse.ch/v1/url/",
            headers={"Auth-Key": urlhaus_key},
            data=form_data,
        )
        if result.get("status") == "checked":
            result["malicious"] = result.get("response", {}).get("query_status") == "ok"
            result.pop("response", None)
        results.append(result)
    return results


def inspect_threat_intelligence(url):
    """Query only explicitly configured providers; otherwise return unavailable."""
    try:
        results = _configured_provider_checks(url)
    except (OSError, ssl.SSLError, ValueError, UnicodeError) as exc:
        return {
            "status": "unavailable",
            "sources": [],
            "reason": f"Threat-intelligence checks failed ({type(exc).__name__}).",
        }
    if not results:
        return {
            "status": "unavailable",
            "sources": [],
            "reason": "No threat-intelligence API credentials are configured.",
        }
    confirmed = [item["source"] for item in results if item.get("malicious") is True]
    if confirmed:
        status = "malicious"
    elif any(item.get("status") == "checked" for item in results):
        status = "checked"
    elif any(item.get("status") == "rate_limited" for item in results):
        status = "rate_limited"
    else:
        status = "unavailable"
    return {
        "status": status,
        "sources": results,
        "confirmed_malicious_sources": confirmed,
    }


def network_checks_enabled():
    return os.environ.get("URL_ENABLE_NETWORK_CHECKS", "false").strip().lower() in {
        "1", "true", "yes", "on",
    }
