"""
services/password_features.py
--------------------------------
Rule-based feature extraction for password strength analysis. This module
contains NO machine-learning code - it is the deterministic, explainable
half of the analysis (entropy, pattern detection, dictionary checks, etc).

IMPORTANT: this module never logs or persists the raw password anywhere.
"""

import math
import re
import string
from functools import lru_cache

# A compact but useful common-password / dictionary-word list.
# In production this would be backed by a larger corpus (e.g. rockyou.txt
# subset or SecLists) - kept small here to stay dependency-free.
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "letmein",
    "monkey", "111111", "iloveyou", "admin", "welcome", "login", "princess",
    "dragon", "football", "baseball", "sunshine", "master", "shadow",
    "superman", "trustno1", "passw0rd", "starwars", "hello", "freedom",
    "whatever", "qazwsx", "michael", "jennifer", "jordan", "hunter",
    "computer", "internet", "service", "canada", "google", "secret",
}

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

COMMON_SUBSTITUTIONS = {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"}


def calculate_entropy(password: str) -> float:
    """Shannon-style entropy estimate based on character-space size and length.

    entropy = length * log2(pool_size)
    where pool_size is the size of the character classes actually used.
    """
    if not password:
        return 0.0

    pool_size = 0
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)
    if any(c.isspace() for c in password):
        pool_size += 1
    # Any unicode/other characters not covered above
    known = set(string.ascii_letters + string.digits + string.punctuation + " ")
    if any(c not in known for c in password):
        pool_size += 32  # conservative bump for unknown alphabets

    if pool_size == 0:
        return 0.0

    return round(len(password) * math.log2(pool_size), 2)


def has_sequential_chars(password: str, run_length: int = 3) -> bool:
    """Detects ascending/descending numeric or alphabetic runs, e.g. 'abcd', '4321'."""
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        chunk = lowered[i:i + run_length]
        codes = [ord(c) for c in chunk]
        ascending = all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1))
        descending = all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1))
        if ascending or descending:
            return True
    return False


def has_repeated_chars(password: str, run_length: int = 3) -> bool:
    """Detects the same character repeated `run_length` or more times in a row."""
    for i in range(len(password) - run_length + 1):
        if len(set(password[i:i + run_length])) == 1:
            return True
    return False


def has_keyboard_pattern(password: str, run_length: int = 4) -> bool:
    """Detects physical keyboard walks like 'qwerty', 'asdf', '1234'."""
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            chunk = row[i:i + run_length]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def is_dictionary_word(password: str) -> bool:
    """Checks the password (and a de-leetspeak'd variant) against a common word list."""
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        return True
    # Strip trailing digits (e.g. "password123" -> "password")
    stripped = re.sub(r"\d+$", "", lowered)
    if stripped in COMMON_PASSWORDS:
        return True
    # De-leetspeak
    de_leeted = "".join(COMMON_SUBSTITUTIONS.get(c, c) for c in lowered)
    if de_leeted in COMMON_PASSWORDS:
        return True
    return False


def has_common_substitution(password: str) -> bool:
    """Detects leetspeak-style substitutions (e.g. p@ssw0rd)."""
    return any(sub_char in password for sub_char in COMMON_SUBSTITUTIONS)


@lru_cache(maxsize=1)
def _substitution_chars():
    return set(COMMON_SUBSTITUTIONS.keys())


def extract_features(password: str) -> dict:
    """Extract the full rule-based + statistical feature set for a password.

    Returns a dict safe to log/persist (no raw password is included).
    """
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    features = {
        "length": length,
        "entropy": calculate_entropy(password),
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "char_class_count": sum([has_upper, has_lower, has_digit, has_symbol]),
        "is_dictionary_word": is_dictionary_word(password),
        "is_keyboard_pattern": has_keyboard_pattern(password),
        "has_repeated_chars": has_repeated_chars(password),
        "has_sequential_chars": has_sequential_chars(password),
        "has_common_substitution": has_common_substitution(password),
        "unique_char_ratio": round(len(set(password)) / length, 3) if length else 0.0,
    }
    return features


def feature_vector(features: dict) -> list:
    """Convert an extracted feature dict into a fixed-order numeric vector
    suitable for the ML model. Order MUST match ml/train_password_model.py.
    """
    return [
        features["length"],
        features["entropy"],
        int(features["has_upper"]),
        int(features["has_lower"]),
        int(features["has_digit"]),
        int(features["has_symbol"]),
        features["char_class_count"],
        int(features["is_dictionary_word"]),
        int(features["is_keyboard_pattern"]),
        int(features["has_repeated_chars"]),
        int(features["has_sequential_chars"]),
        int(features["has_common_substitution"]),
        features["unique_char_ratio"],
    ]


FEATURE_NAMES = [
    "length", "entropy", "has_upper", "has_lower", "has_digit", "has_symbol",
    "char_class_count", "is_dictionary_word", "is_keyboard_pattern",
    "has_repeated_chars", "has_sequential_chars", "has_common_substitution",
    "unique_char_ratio",
]
