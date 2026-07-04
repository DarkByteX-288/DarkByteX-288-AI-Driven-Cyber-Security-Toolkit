"""
services/attack_simulator.py
-------------------------------
Simulates common password-cracking attack strategies and estimates how long
each would take against the given password's *characteristics* (never
against the actual password value itself, and no real cracking is performed).

All estimates are theoretical, based on published guess-rate assumptions for
an offline attacker with consumer-grade GPU hardware (a common teaching
assumption: ~10 billion guesses/second for fast hashes).
"""

import string

# Assumed attacker guess rate (guesses per second) - typical teaching figure
# for an offline attack against a fast, unsalted hash on modern GPU hardware.
GUESSES_PER_SECOND = 10_000_000_000

TIME_UNITS = [
    ("centuries", 60 * 60 * 24 * 365 * 100),
    ("years", 60 * 60 * 24 * 365),
    ("months", 60 * 60 * 24 * 30),
    ("days", 60 * 60 * 24),
    ("hours", 60 * 60),
    ("minutes", 60),
    ("seconds", 1),
]


def humanize_seconds(seconds: float) -> str:
    """Convert a number of seconds into a readable string using the largest
    sensible unit, e.g. '3.2 centuries', '45 minutes', 'instantly'."""
    if seconds < 1:
        return "instantly"
    for name, unit_seconds in TIME_UNITS:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if value > 1_000_000:
                return f"{value:.2e} {name}"
            return f"{value:.1f} {name}"
    return "instantly"


def _charset_size(password: str) -> int:
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    return pool or 1


def brute_force_estimate(password: str) -> dict:
    """Exhaustive keyspace search estimate: pool_size ^ length guesses."""
    pool = _charset_size(password)
    length = len(password)
    keyspace = pool ** length if length else 0
    seconds = keyspace / GUESSES_PER_SECOND if keyspace else 0
    # Average case: attacker finds it halfway through the keyspace
    avg_seconds = seconds / 2
    return {
        "attack_type": "brute_force",
        "keyspace": keyspace,
        "estimated_time_seconds": avg_seconds,
        "estimated_time_display": humanize_seconds(avg_seconds),
        "success_likelihood": _likelihood_from_seconds(avg_seconds),
    }


def dictionary_attack_estimate(is_dictionary_word: bool, is_common_variant: bool) -> dict:
    """A dictionary attack succeeds almost instantly against known words/variants,
    and is not applicable (effectively won't succeed) otherwise."""
    if is_dictionary_word:
        seconds = 0.5
        likelihood = "Very High"
    elif is_common_variant:
        seconds = 30
        likelihood = "High"
    else:
        seconds = float("inf")
        likelihood = "Very Low"
    display = humanize_seconds(seconds) if seconds != float("inf") else "not feasible with dictionary alone"
    return {
        "attack_type": "dictionary",
        "estimated_time_seconds": seconds if seconds != float("inf") else None,
        "estimated_time_display": display,
        "success_likelihood": likelihood,
    }


def hybrid_attack_estimate(is_dictionary_word: bool, has_sequential_chars: bool, has_common_substitution: bool) -> dict:
    """Hybrid = dictionary word + common mutations (append digits, leetspeak, etc)."""
    risk_factors = sum([is_dictionary_word, has_sequential_chars, has_common_substitution])
    if risk_factors >= 2:
        seconds, likelihood = 120, "High"
    elif risk_factors == 1:
        seconds, likelihood = 3600, "Medium"
    else:
        seconds, likelihood = 86400 * 30, "Low"
    return {
        "attack_type": "hybrid",
        "estimated_time_seconds": seconds,
        "estimated_time_display": humanize_seconds(seconds),
        "success_likelihood": likelihood,
    }


def pattern_attack_estimate(is_keyboard_pattern: bool, has_sequential_chars: bool, has_repeated_chars: bool) -> dict:
    """Pattern-based attacks target keyboard walks, sequences, and repeats."""
    hits = sum([is_keyboard_pattern, has_sequential_chars, has_repeated_chars])
    if hits >= 2:
        seconds, likelihood = 5, "Very High"
    elif hits == 1:
        seconds, likelihood = 60, "High"
    else:
        seconds, likelihood = 86400 * 365, "Very Low"
    return {
        "attack_type": "pattern",
        "estimated_time_seconds": seconds,
        "estimated_time_display": humanize_seconds(seconds),
        "success_likelihood": likelihood,
    }


def keyboard_walk_estimate(is_keyboard_pattern: bool) -> dict:
    seconds = 2 if is_keyboard_pattern else float("inf")
    likelihood = "Very High" if is_keyboard_pattern else "Very Low"
    display = humanize_seconds(seconds) if is_keyboard_pattern else "not applicable"
    return {
        "attack_type": "keyboard_walk",
        "estimated_time_seconds": seconds if is_keyboard_pattern else None,
        "estimated_time_display": display,
        "success_likelihood": likelihood,
    }


def password_reuse_risk(username_or_email_hint: bool = False) -> dict:
    """Password reuse cannot be verified without breach-database access; this
    returns a qualitative reminder rather than a false-precision estimate."""
    return {
        "attack_type": "password_reuse",
        "estimated_time_seconds": None,
        "estimated_time_display": "unknown - depends on external breach exposure",
        "success_likelihood": "Unknown",
        "note": "Check this password against a breach database (e.g. Have I Been Pwned) to assess reuse risk.",
    }


def _likelihood_from_seconds(seconds: float) -> str:
    if seconds < 60:
        return "Very High"
    if seconds < 3600 * 24:
        return "High"
    if seconds < 3600 * 24 * 365:
        return "Medium"
    if seconds < 3600 * 24 * 365 * 100:
        return "Low"
    return "Very Low"


def run_all_simulations(features: dict) -> list:
    """Run every attack simulation against the extracted (non-reversible)
    password features and return a list of result dicts."""
    # Reconstruct a synthetic "password-like" string purely for brute-force
    # keyspace math using length + character classes (never the real value).
    synthetic_pool = ""
    if features["has_lower"]:
        synthetic_pool += "a"
    if features["has_upper"]:
        synthetic_pool += "A"
    if features["has_digit"]:
        synthetic_pool += "1"
    if features["has_symbol"]:
        synthetic_pool += "!"
    synthetic_password = (synthetic_pool or "a") * features["length"]

    results = [
        brute_force_estimate(synthetic_password),
        dictionary_attack_estimate(features["is_dictionary_word"], features["has_common_substitution"]),
        hybrid_attack_estimate(
            features["is_dictionary_word"], features["has_sequential_chars"], features["has_common_substitution"]
        ),
        pattern_attack_estimate(
            features["is_keyboard_pattern"], features["has_sequential_chars"], features["has_repeated_chars"]
        ),
        keyboard_walk_estimate(features["is_keyboard_pattern"]),
        password_reuse_risk(),
    ]
    return results
