"""URL-specific dataset validation, feature derivation, and domain-aware splits."""

import ipaddress
import os
import re
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

from services.url_features import (
    FEATURE_NAMES,
    _valid_hostname,
    extract_features,
    normalize_url,
    feature_vector,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "datasets", "url_phishing_dataset_100k.csv")
ARTIFACT_DIR = os.path.join(BASE_DIR, "datasets", "url_detection_artifacts")
LABEL_MAP = {
    "0": "legitimate",
    "1": "phishing",
    "legitimate": "legitimate",
    "phishing": "phishing",
}

_MULTI_LABEL_SUFFIXES = {
    "ac.uk", "co.jp", "co.nz", "co.uk", "com.au", "com.br", "com.cn",
    "com.hk", "com.sg", "edu.au", "gov.uk", "net.au", "org.au", "org.uk",
}


def registrable_domain(url):
    """Return a practical registrable-domain grouping key without network lookups."""
    candidate = normalize_url(url)
    try:
        host = (urlsplit(candidate).hostname or "").rstrip(".").lower()
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            pass
        labels = host.split(".")
        if len(labels) < 2:
            return host
        suffix = ".".join(labels[-2:])
        if suffix in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
            return ".".join(labels[-3:])
        return suffix
    except ValueError:
        return ""


def _record_is_valid(url):
    if not isinstance(url, str) or not url.strip() or re.search(r"[\s\x00-\x1f\x7f]", url):
        return False
    candidate = normalize_url(url.strip())
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            return False
        parsed.port
        ascii_host = host.encode("idna").decode("ascii")
        return len(ascii_host) <= 253 and _valid_hostname(ascii_host)
    except (UnicodeError, ValueError):
        return False


def prepare_dataset(path=DATASET_PATH):
    """Validate labels/URLs and recompute every model feature from the URL itself."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"URL training dataset not found: {path}")

    raw = pd.read_csv(path, dtype={"url": "string"}, keep_default_na=False)
    required = {"url", "label"}
    missing_columns = required - set(raw.columns)
    if missing_columns:
        raise ValueError(f"URL dataset is missing required columns: {sorted(missing_columns)}")

    report = {
        "source_file": os.path.basename(path),
        "source_rows": int(len(raw)),
        "source_columns": list(raw.columns),
        "data_origin_counts": raw["data_origin"].value_counts().to_dict()
        if "data_origin" in raw else {},
        "attack_category_counts": raw["attack_category"].value_counts().to_dict()
        if "attack_category" in raw else {},
        "missing_values_by_column": {
            column: int(
                raw[column].isna().sum()
                + raw[column].astype(str).str.strip().eq("").sum()
            )
            for column in raw.columns
        },
    }

    raw["url"] = raw["url"].astype("string").str.strip()
    raw["normalized_label"] = raw["label"].astype(str).str.strip().str.lower().map(LABEL_MAP)
    report["missing_url_rows"] = int(raw["url"].isna().sum() + (raw["url"] == "").sum())
    report["unknown_label_rows"] = int(raw["normalized_label"].isna().sum())
    report["label_name_mismatch_rows"] = 0
    if "label_name" in raw:
        label_names = raw["label_name"].astype(str).str.strip().str.lower()
        report["label_name_mismatch_rows"] = int(
            (label_names != raw["normalized_label"]).sum()
        )
    if "attack_category" in raw:
        expected_category_label = raw["attack_category"].astype(str).map(
            lambda category: "legitimate" if category.strip().lower() == "legitimate" else "phishing"
        )
        report["category_label_mismatch_rows"] = int(
            (expected_category_label != raw["normalized_label"]).sum()
        )
    else:
        report["category_label_mismatch_rows"] = None

    provided_feature_columns = [column for column in FEATURE_NAMES if column in raw]
    report["invalid_numeric_values_by_column"] = {}
    for column in provided_feature_columns:
        values = pd.to_numeric(raw[column], errors="coerce")
        report["invalid_numeric_values_by_column"][column] = int(
            (values.isna() | ~np.isfinite(values)).sum()
        )

    valid_url = raw["url"].map(_record_is_valid)
    report["invalid_url_rows"] = int((~valid_url).sum())
    usable = raw.loc[valid_url & raw["normalized_label"].notna()].copy()

    contradictory_urls = usable.groupby("url")["normalized_label"].nunique()
    contradictory_urls = set(contradictory_urls[contradictory_urls > 1].index)
    report["contradictory_url_count"] = len(contradictory_urls)
    usable = usable.loc[~usable["url"].isin(contradictory_urls)]

    before_duplicates = len(usable)
    usable = usable.drop_duplicates(subset=["url"], keep="first")
    report["duplicate_url_rows_removed"] = int(before_duplicates - len(usable))
    report["valid_unique_rows"] = int(len(usable))
    report["label_distribution"] = usable["normalized_label"].value_counts().to_dict()

    features = usable["url"].map(extract_features)
    feature_frame = pd.DataFrame(
        [feature_vector(item) for item in features], columns=FEATURE_NAMES, index=usable.index
    )
    if not np.isfinite(feature_frame.to_numpy(dtype=float)).all():
        raise ValueError("Derived URL features contain non-finite numeric values.")

    groups = usable["url"].map(registrable_domain)
    missing_groups = groups == ""
    report["unassignable_domain_rows"] = int(missing_groups.sum())
    if missing_groups.any():
        usable = usable.loc[~missing_groups]
        feature_frame = feature_frame.loc[~missing_groups]
        groups = groups.loc[~missing_groups]

    report["unique_registrable_domains"] = int(groups.nunique())
    hosts = features.map(lambda item: item["host"])
    report["unique_hostnames"] = int(hosts.nunique())
    report["duplicate_hostname_rows"] = int(len(hosts) - hosts.nunique())
    report["duplicate_registrable_domain_rows"] = int(len(groups) - groups.nunique())
    report["largest_registrable_domain_group"] = int(groups.value_counts().max())
    registrable_label_counts = pd.DataFrame(
        {"domain_group": groups, "label": usable["normalized_label"]}
    ).groupby("domain_group")["label"].nunique()
    report["registrable_domains_with_mixed_labels"] = int(
        (registrable_label_counts > 1).sum()
    )
    report["recomputed_feature_columns"] = list(FEATURE_NAMES)
    report["provided_features_recomputed"] = True
    report["provided_feature_mismatch_counts"] = {}
    for column in FEATURE_NAMES:
        if column not in usable:
            continue
        supplied = pd.to_numeric(usable[column], errors="coerce")
        expected = feature_frame[column].astype(float)
        mismatch = supplied.isna() | ~np.isfinite(supplied) | (supplied != expected)
        report["provided_feature_mismatch_counts"][column] = int(mismatch.sum())

    prepared = feature_frame.copy()
    prepared.insert(0, "url", usable["url"].astype(str))
    prepared["label"] = usable["normalized_label"].astype(str)
    prepared["domain_group"] = groups.astype(str)
    for metadata_column in ("attack_category", "data_origin"):
        if metadata_column in usable:
            prepared[metadata_column] = usable[metadata_column].astype(str)
    return prepared.reset_index(drop=True), report


def split_dataset(frame, seed=42):
    """Assign complete domains to row-stratified 70/15/15 splits."""
    split_names = ("train", "validation", "test")
    fractions = {"train": 0.70, "validation": 0.15, "test": 0.15}
    if "attack_category" in frame:
        strata = (
            frame["label"].astype(str)
            + "|"
            + frame["attack_category"].astype(str)
        )
    else:
        strata = frame["label"].astype(str)
    split_frame = frame.assign(_split_stratum=strata)
    category_counts = (
        split_frame.groupby(["domain_group", "_split_stratum"], sort=False)
        .size()
        .unstack(fill_value=0)
    )
    label_counts = (
        frame.groupby(["domain_group", "label"], sort=False)
        .size()
        .unstack(fill_value=0)
        .add_prefix("label|")
    )
    row_counts = frame.groupby("domain_group", sort=False).size().to_frame("all_rows")
    group_counts = pd.concat([category_counts, label_counts, row_counts], axis=1).fillna(0)
    objective_weights = np.array(
        [0.1] * category_counts.shape[1]
        + [50.0] * label_counts.shape[1]
        + [50.0],
        dtype=float,
    )
    targets = {
        split: group_counts.sum(axis=0).to_numpy(dtype=float) * fractions[split]
        for split in split_names
    }
    counts = {
        split: np.zeros(group_counts.shape[1], dtype=float)
        for split in split_names
    }
    rng = np.random.default_rng(seed)
    group_names = group_counts.index.to_numpy(copy=True)
    rng.shuffle(group_names)
    group_names = sorted(
        group_names,
        key=lambda group: max(
            group_counts.loc[group].to_numpy(dtype=float)
            / np.maximum(targets["test"], 1.0)
        ),
        reverse=True,
    )
    group_assignment = {}
    for group in group_names:
        group_vector = group_counts.loc[group].to_numpy(dtype=float)
        choices = []
        for split in split_names:
            target = targets[split]
            before = (counts[split] - target) / target
            after = (counts[split] + group_vector - target) / target
            delta = float(
                np.sum(objective_weights * (np.square(after) - np.square(before)))
            )
            choices.append((delta, split))
        _, selected_split = min(choices)
        counts[selected_split] += group_vector
        group_assignment[group] = selected_split

    assigned = frame["domain_group"].map(group_assignment)
    sets = {
        name: frame.loc[assigned == name].copy()
        for name in split_names
    }
    domain_sets = {
        name: set(part["domain_group"])
        for name, part in sets.items()
    }
    if (
        domain_sets["train"] & domain_sets["validation"]
        or domain_sets["train"] & domain_sets["test"]
        or domain_sets["validation"] & domain_sets["test"]
    ):
        raise AssertionError("A registrable domain leaked across dataset splits.")
    return sets


def write_splits(splits, output_dir=ARTIFACT_DIR):
    os.makedirs(output_dir, exist_ok=True)
    persisted_columns = [
        "url", *FEATURE_NAMES, "label", "domain_group",
        "attack_category", "data_origin",
    ]
    for name, frame in splits.items():
        columns = [column for column in persisted_columns if column in frame]
        frame[columns].to_csv(os.path.join(output_dir, f"{name}.csv"), index=False)
