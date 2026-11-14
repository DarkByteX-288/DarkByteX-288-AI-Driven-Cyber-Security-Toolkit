from urllib.error import HTTPError

from services import nvd_service


def test_cvss_severity_classification_boundaries():
    assert nvd_service.classify_cvss(None) == "Unknown"
    assert nvd_service.classify_cvss(0) == "None"
    assert nvd_service.classify_cvss(3.9) == "Low"
    assert nvd_service.classify_cvss(4.0) == "Medium"
    assert nvd_service.classify_cvss(7.0) == "High"
    assert nvd_service.classify_cvss(9.0) == "Critical"
    assert nvd_service.classify_cvss(9.0, "2.0") == "High"
    assert nvd_service.classify_cvss(10.1, "3.1") == "Unknown"


def test_nvd_extracts_cvss_version_and_filters_invalid_cve_ids(monkeypatch):
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            import json

            return json.dumps({
                "vulnerabilities": [
                    {"cve": {"id": "NOT-A-CVE"}},
                    {
                        "cve": {
                            "id": "CVE-2025-12345",
                            "descriptions": [{"lang": "en", "value": "Test description"}],
                            "metrics": {
                                "cvssMetricV2": [{
                                    "cvssData": {"version": "2.0", "baseScore": 9.5}
                                }]
                            },
                            "references": [{"url": "https://nvd.nist.gov/reference"}],
                        }
                    },
                ]
            }).encode()

    monkeypatch.setattr(nvd_service, "urlopen", lambda *_args, **_kwargs: Response())
    result = nvd_service._fetch("Example Product 1.0")
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["cve_id"] == "CVE-2025-12345"
    assert finding["cvss_version"] == "2.0"
    assert finding["cvss_score"] == 9.5
    assert finding["severity"] == "High"


def test_lookup_uses_cached_potential_matches(monkeypatch):
    nvd_service._cache.clear()
    calls = []

    def fake_fetch(query):
        calls.append(query)
        return {"status": "available", "findings": [{"cve_id": "CVE-2099-1234"}]}

    monkeypatch.setattr(nvd_service, "_fetch", fake_fetch)
    first = nvd_service.lookup_cves("Example Server", "1.2.3")
    second = nvd_service.lookup_cves("Example Server", "1.2.3")
    assert first["findings"][0]["cve_id"] == "CVE-2099-1234"
    assert second == first
    assert calls == ["Example Server 1.2.3"]


def test_nvd_offline_is_an_explicit_fallback(monkeypatch):
    nvd_service._cache.clear()

    def fail(_query):
        raise OSError("offline")

    monkeypatch.setattr(nvd_service, "_fetch", fail)
    result = nvd_service.lookup_cves("Example Server", "1.2")
    assert result["status"] == "unavailable"
    assert not result["findings"]
    assert "unavailable" in result["reason"]


def test_nvd_rate_limit_is_explicit_and_cached(monkeypatch):
    nvd_service._cache.clear()
    calls = []

    def rate_limited(*_args, **_kwargs):
        calls.append(True)
        raise HTTPError("https://nvd.nist.gov", 429, "rate limited", {}, None)

    monkeypatch.setattr(nvd_service, "urlopen", rate_limited)
    first = nvd_service.lookup_cves("Example Server", "1.0")
    second = nvd_service.lookup_cves("Example Server", "1.0")
    assert first["status"] == "rate_limited"
    assert second == first
    assert len(calls) == 1
