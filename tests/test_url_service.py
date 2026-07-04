"""
tests/test_url_service.py
----------------------------
Unit tests for the rule-based URL feature extraction logic.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.url_features import extract_features


def test_https_detected():
    feats = extract_features("https://example.com")
    assert feats["uses_https"] is True


def test_http_not_https():
    feats = extract_features("http://example.com")
    assert feats["uses_https"] is False


def test_ip_address_detected():
    feats = extract_features("http://192.168.1.1/login")
    assert feats["has_ip_address"] is True


def test_normal_domain_not_ip():
    feats = extract_features("https://github.com")
    assert feats["has_ip_address"] is False


def test_at_symbol_detected():
    feats = extract_features("http://paypal.com@malicious.xyz/login")
    assert feats["has_at_symbol"] is True


def test_shortener_detected():
    feats = extract_features("http://bit.ly/abc123")
    assert feats["is_shortened"] is True


def test_suspicious_keyword_detected():
    feats = extract_features("http://example.com/verify-account/login")
    assert feats["has_suspicious_keywords"] is True


def test_domain_extraction():
    feats = extract_features("https://www.example.com/path")
    assert "example.com" in feats["domain"]
