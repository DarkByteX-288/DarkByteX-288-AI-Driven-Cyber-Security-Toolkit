"""
ml/generate_password_dataset.py
----------------------------------
Generates a labeled synthetic password dataset (datasets/password_dataset.csv)
for training the strength-classification model.

No real breached-password corpora are bundled with this project; instead we
procedurally generate representative examples across the full strength
spectrum (weak dictionary words through strong random passphrases). This
keeps the project dependency-free and legally unencumbered while still
producing a model that learns sensible, generalizable decision boundaries
from the same rule-based features used at inference time.
"""

import csv
import os
import random
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.password_features import extract_features, FEATURE_NAMES, COMMON_PASSWORDS  # noqa: E402

random.seed(42)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "datasets", "password_dataset.csv")

WORDS = [
    "sunshine", "dragon", "shadow", "monkey", "tiger", "eagle", "phoenix",
    "thunder", "silver", "purple", "orange", "castle", "forest", "river",
    "mountain", "ocean", "winter", "summer", "garden", "bridge",
]


def _label_from_features(feats: dict) -> str:
    """Derive a ground-truth strength category from a heuristic score, used
    as the training label. This mirrors (but is independent from) the
    scoring service so the ML model learns a genuinely useful signal."""
    score = 0
    score += min(feats["length"] * 4, 40)
    score += min(feats["entropy"], 40)
    score += feats["char_class_count"] * 5
    if feats["is_dictionary_word"]:
        score -= 40
    if feats["is_keyboard_pattern"]:
        score -= 25
    if feats["has_repeated_chars"]:
        score -= 15
    if feats["has_sequential_chars"]:
        score -= 15
    if feats["has_common_substitution"] and feats["is_dictionary_word"]:
        score -= 10
    score = max(0, min(100, score))

    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Moderate"
    if score < 80:
        return "Strong"
    return "Very Strong"


def _random_string(length, pool):
    return "".join(random.choice(pool) for _ in range(length))


def generate_examples(n_per_category=1500):
    examples = []

    # 1. Pure dictionary words / common passwords (very weak - weak)
    for _ in range(n_per_category):
        base = random.choice(list(COMMON_PASSWORDS) + WORDS)
        variant = random.choice([
            base,
            base.capitalize(),
            base + str(random.randint(0, 999)),
            base + "!",
        ])
        examples.append(variant)

    # 2. Keyboard walks / sequences / repeats (weak)
    keyboard_bases = ["qwerty", "asdfgh", "zxcvbn", "123456", "1qaz2wsx", "qazwsx"]
    for _ in range(n_per_category):
        base = random.choice(keyboard_bases)
        variant = base + str(random.randint(0, 99)) if random.random() > 0.5 else base
        examples.append(variant)

    for _ in range(n_per_category // 2):
        c = random.choice(string.ascii_lowercase)
        examples.append(c * random.randint(6, 10))

    for _ in range(n_per_category // 2):
        start = random.randint(0, 20)
        seq = "".join(chr(ord("a") + ((start + i) % 26)) for i in range(random.randint(6, 10)))
        examples.append(seq)

    # 3. Moderate: word + digits + one symbol, medium length
    for _ in range(n_per_category):
        word = random.choice(WORDS).capitalize()
        digits = str(random.randint(10, 9999))
        symbol = random.choice("!@#$%")
        examples.append(f"{word}{digits}{symbol}")

    # 4. Strong: longer mixed-case + digits + symbols, non-dictionary
    pool_strong = string.ascii_letters + string.digits + "!@#$%^&*"
    for _ in range(n_per_category):
        length = random.randint(10, 14)
        examples.append(_random_string(length, pool_strong))

    # 5. Very strong: long fully random strings or multi-word passphrases
    pool_vstrong = string.ascii_letters + string.digits + string.punctuation
    for _ in range(n_per_category // 2):
        length = random.randint(16, 24)
        examples.append(_random_string(length, pool_vstrong))

    for _ in range(n_per_category // 2):
        chosen = random.sample(WORDS, 4)
        sep = random.choice(["-", "_", "."])
        examples.append(sep.join(chosen) + str(random.randint(0, 99)))

    random.shuffle(examples)
    return examples


def main():
    passwords = generate_examples()

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ["label"])
        for pwd in passwords:
            feats = extract_features(pwd)
            label = _label_from_features(feats)
            row = [feats[name] for name in FEATURE_NAMES] + [label]
            writer.writerow(row)

    print(f"Generated {len(passwords)} rows -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
