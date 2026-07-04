"""
services/recommendation_engine.py
------------------------------------
Generates human-readable, actionable recommendations based on the
rule-based feature set extracted from a password.
"""


def generate_recommendations(features: dict) -> list:
    recs = []

    if features["length"] < 12:
        recs.append("Increase your password length to at least 12-16 characters.")
    if not features["has_upper"]:
        recs.append("Add uppercase letters (A-Z) to increase complexity.")
    if not features["has_lower"]:
        recs.append("Add lowercase letters (a-z) to increase complexity.")
    if not features["has_digit"]:
        recs.append("Add numbers (0-9) to increase complexity.")
    if not features["has_symbol"]:
        recs.append("Add special characters (e.g. !@#$%) to increase complexity.")
    if features["is_dictionary_word"]:
        recs.append("Avoid dictionary words, names, or common passwords - they are cracked instantly.")
    if features["is_keyboard_pattern"]:
        recs.append("Avoid keyboard patterns like 'qwerty' or '12345' - these are trivially guessed.")
    if features["has_repeated_chars"]:
        recs.append("Avoid repeating the same character multiple times in a row.")
    if features["has_sequential_chars"]:
        recs.append("Avoid sequential characters such as 'abcd' or '4321'.")
    if features["has_common_substitution"]:
        recs.append("Simple substitutions like 'a' -> '@' or 'o' -> '0' are well known to crackers; don't rely on them alone.")
    if features["char_class_count"] < 3:
        recs.append("Combine at least 3 different character types (upper, lower, digit, symbol).")

    # Positive, general-purpose guidance always included
    recs.append("Consider using a random passphrase of 4-6 unrelated words (e.g. 'correct-horse-battery-staple').")
    recs.append("Use a password manager to generate and store unique, random passwords for every account.")
    recs.append("Never reuse the same password across multiple sites or services.")

    # De-duplicate while preserving order
    seen = set()
    unique_recs = []
    for r in recs:
        if r not in seen:
            unique_recs.append(r)
            seen.add(r)
    return unique_recs
