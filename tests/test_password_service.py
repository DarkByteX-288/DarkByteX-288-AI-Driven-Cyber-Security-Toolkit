"""
tests/test_password_service.py
---------------------------------
Unit tests for the rule-based password feature extraction, attack
simulation, and scoring logic (no Flask app context required).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.password_features import (
    calculate_entropy, has_sequential_chars, has_repeated_chars,
    has_keyboard_pattern, is_dictionary_word, extract_features,
)
from services.attack_simulator import humanize_seconds, brute_force_estimate
from services.recommendation_engine import generate_recommendations


def test_entropy_empty_password():
    assert calculate_entropy("") == 0.0


def test_entropy_increases_with_character_diversity():
    assert calculate_entropy("aaaaaaaa") < calculate_entropy("aA1!aA1!")


def test_sequential_chars_detected():
    assert has_sequential_chars("abcdef")
    assert has_sequential_chars("4321")
    assert not has_sequential_chars("xk2p")


def test_repeated_chars_detected():
    assert has_repeated_chars("aaa123")
    assert not has_repeated_chars("abc123")


def test_keyboard_pattern_detected():
    assert has_keyboard_pattern("qwerty123")
    assert not has_keyboard_pattern("xk2p9j")


def test_dictionary_word_detected():
    assert is_dictionary_word("password123")
    assert is_dictionary_word("Password")
    assert not is_dictionary_word("xK2!pQz9")


def test_extract_features_shape():
    feats = extract_features("Test1234!")
    expected_keys = {
        "length", "entropy", "has_upper", "has_lower", "has_digit", "has_symbol",
        "char_class_count", "is_dictionary_word", "is_keyboard_pattern",
        "has_repeated_chars", "has_sequential_chars", "has_common_substitution",
        "unique_char_ratio",
    }
    assert expected_keys.issubset(feats.keys())
    assert feats["length"] == 9
    assert feats["has_upper"] is True
    assert feats["has_digit"] is True


def test_humanize_seconds():
    assert humanize_seconds(0.5) == "instantly"
    assert "second" in humanize_seconds(30)
    assert "year" in humanize_seconds(60 * 60 * 24 * 400)


def test_brute_force_weak_password_cracks_fast():
    result = brute_force_estimate("aaaa")
    assert result["estimated_time_seconds"] < 1


def test_recommendations_flag_short_password():
    feats = extract_features("abc")
    recs = generate_recommendations(feats)
    assert any("length" in r.lower() for r in recs)


def test_recommendations_deduplicated():
    feats = extract_features("password")
    recs = generate_recommendations(feats)
    assert len(recs) == len(set(recs))
