"""
ml/generate_url_dataset.py
------------------------------
Generates a labeled synthetic URL dataset (datasets/phishing_urls.csv) for
training the phishing-detection model.

Real-world phishing datasets (e.g. PhishTank, OpenPhish) require attribution
and periodic licensing/download agreements, so this project procedurally
generates structurally representative legitimate and phishing-style URLs
using the same lexical patterns real phishing campaigns rely on (IP
addresses, URL shorteners, suspicious keywords, excessive subdomains,
lookalike domains, etc). This keeps the project self-contained while
producing a model that learns the real, transferable lexical signal.
"""

import csv
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.url_features import extract_features, feature_vector, FEATURE_NAMES  # noqa: E402

random.seed(42)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "datasets", "phishing_urls.csv")

LEGIT_DOMAINS = [
    "github.com", "wikipedia.org", "google.com", "microsoft.com", "amazon.com",
    "stackoverflow.com", "python.org", "mozilla.org", "apple.com", "spotify.com",
    "nytimes.com", "bbc.com", "reddit.com", "linkedin.com", "dropbox.com",
    "notion.so", "figma.com", "cloudflare.com", "wordpress.org", "shopify.com",
]

LEGIT_PATHS = [
    "/", "/about", "/products", "/docs/getting-started", "/blog/2026/updates",
    "/pricing", "/contact", "/help/support", "/login", "/search?q=example",
]

PHISHY_KEYWORDS = ["login", "verify", "secure", "update", "account", "confirm", "signin", "billing", "unlock"]
BRAND_LOOKALIKES = ["paypal", "amazon", "apple", "microsoft", "netflix", "bankofamerica", "chase", "google"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd"]
SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "xyz", "top", "click", "info"]


def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))


def generate_legit_urls(n):
    urls = []
    for _ in range(n):
        domain = random.choice(LEGIT_DOMAINS)
        path = random.choice(LEGIT_PATHS)
        scheme = "https"
        sub = random.choice(["", "www.", "docs.", "shop."])
        urls.append(f"{scheme}://{sub}{domain}{path}")
    return urls


def generate_phishing_urls(n):
    urls = []
    for _ in range(n):
        style = random.choice(["ip", "shortener", "lookalike", "suspicious_tld", "long_subdomain", "at_symbol"])

        if style == "ip":
            urls.append(f"http://{random_ip()}/{random.choice(PHISHY_KEYWORDS)}/account")

        elif style == "shortener":
            shortener = random.choice(SHORTENERS)
            token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=7))
            urls.append(f"http://{shortener}/{token}")

        elif style == "lookalike":
            brand = random.choice(BRAND_LOOKALIKES)
            suffix = random.choice(["-secure", "-verify", "-login", "-support", "0"])
            tld = random.choice(["com", "net", "info", "cc"])
            urls.append(f"http://{brand}{suffix}.{tld}/{random.choice(PHISHY_KEYWORDS)}")

        elif style == "suspicious_tld":
            word = random.choice(PHISHY_KEYWORDS + BRAND_LOOKALIKES)
            tld = random.choice(SUSPICIOUS_TLDS)
            urls.append(f"http://{word}-{random.randint(1,999)}.{tld}/{random.choice(PHISHY_KEYWORDS)}")

        elif style == "long_subdomain":
            brand = random.choice(BRAND_LOOKALIKES)
            junk = "-".join(random.choices(["secure", "id", "session", "auth", "user", "verify"], k=4))
            urls.append(f"http://{junk}.{brand}.tk/{random.choice(PHISHY_KEYWORDS)}")

        else:  # at_symbol
            brand = random.choice(BRAND_LOOKALIKES)
            urls.append(f"http://{brand}.com@malicious-{random.randint(1,999)}.xyz/{random.choice(PHISHY_KEYWORDS)}")

    return urls


def main():
    legit = generate_legit_urls(2000)
    phishing = generate_phishing_urls(2000)

    rows = [(u, "legitimate") for u in legit] + [(u, "phishing") for u in phishing]
    random.shuffle(rows)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url"] + FEATURE_NAMES + ["label"])
        for url, label in rows:
            feats = extract_features(url)
            vec = feature_vector(feats)
            writer.writerow([url] + vec + [label])

    print(f"Generated {len(rows)} rows -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
