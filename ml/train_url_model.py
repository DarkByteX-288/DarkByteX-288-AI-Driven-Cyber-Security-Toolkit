"""Train and independently evaluate the URL phishing model.

Run from the project directory with ``python ml/train_url_model.py``.
All train/validation/test splits are grouped by registrable domain.
"""

import json
import os
import sys
import tempfile
import warnings

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import (
    GradientBoostingClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.impute import SimpleImputer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.url_dataset import ARTIFACT_DIR, DATASET_PATH, prepare_dataset, split_dataset, write_splits
from services.url_features import FEATURE_NAMES

MODEL_PATH = os.path.join(BASE_DIR, "trained_models", "url_model.pkl")
REPORT_PATH = os.path.join(ARTIFACT_DIR, "model_evaluation.json")
POSITIVE_LABEL = "phishing"
MINIMUM_VALIDATION_RECALL = 0.85


def _candidate_pipeline(estimator, use_url_text=False, scale_numeric=False):
    numeric_steps = [("imputer", SimpleImputer(strategy="median"))]
    if scale_numeric:
        numeric_steps.append(("scaler", StandardScaler(with_mean=False)))
    transformers = [
        ("numeric", Pipeline(numeric_steps), FEATURE_NAMES),
    ]
    if use_url_text:
        transformers.append(
            (
                "url_chars",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(2, 5),
                    min_df=2,
                    max_features=40000,
                    sublinear_tf=True,
                ),
                "url",
            )
        )
    return Pipeline(
        [
            ("features", ColumnTransformer(transformers, sparse_threshold=0.3)),
            ("classifier", estimator),
        ]
    )


def _build_candidates():
    candidates = {
        "random_forest": _candidate_pipeline(
            RandomForestClassifier(
                n_estimators=180,
                max_depth=18,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )
        ),
        "hist_gradient_boosting": _candidate_pipeline(
            HistGradientBoostingClassifier(
                max_iter=160,
                max_leaf_nodes=31,
                l2_regularization=1.0,
                random_state=42,
            )
        ),
        "gradient_boosting": _candidate_pipeline(
            GradientBoostingClassifier(
                n_estimators=100,
                max_depth=3,
                learning_rate=0.08,
                random_state=42,
            )
        ),
        "logistic_regression": _candidate_pipeline(
            LogisticRegression(
                max_iter=1200,
                class_weight="balanced",
                random_state=42,
            ),
            scale_numeric=True,
        ),
        "url_char_logistic_regression": _candidate_pipeline(
            LogisticRegression(
                max_iter=1500,
                class_weight="balanced",
                random_state=42,
            ),
            use_url_text=True,
            scale_numeric=True,
        ),
    }
    try:
        from xgboost import XGBClassifier

        candidates["xgboost"] = _candidate_pipeline(
            XGBClassifier(
                n_estimators=180,
                max_depth=6,
                learning_rate=0.08,
                subsample=0.85,
                colsample_bytree=0.85,
                eval_metric="logloss",
                random_state=42,
                n_jobs=-1,
            )
        )
    except ImportError:
        pass

    return candidates


def _phishing_probabilities(model, x):
    classes = list(model.classes_)
    probabilities = model.predict_proba(x)
    phishing_index = classes.index(POSITIVE_LABEL)
    return probabilities[:, phishing_index]


def _select_threshold(probabilities, labels, minimum_recall=MINIMUM_VALIDATION_RECALL):
    labels = np.asarray(labels) == POSITIVE_LABEL
    negatives = ~labels
    best = None
    for threshold in np.unique(probabilities):
        prediction = probabilities >= threshold
        true_positive = int(np.sum(prediction & labels))
        false_positive = int(np.sum(prediction & negatives))
        recall = true_positive / max(1, int(labels.sum()))
        false_positive_rate = false_positive / max(1, int(negatives.sum()))
        if recall >= minimum_recall:
            candidate = (false_positive_rate, -recall, -float(threshold))
            if best is None or candidate < best[0]:
                best = (candidate, float(threshold))
    if best is not None:
        return best[1]
    return float(np.min(probabilities))


def _metrics(model, x, y, threshold=0.5):
    phishing_probability = _phishing_probabilities(model, x)
    prediction = np.where(phishing_probability >= threshold, POSITIVE_LABEL, "legitimate")
    matrix = confusion_matrix(y, prediction, labels=["legitimate", "phishing"])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    return {
        "accuracy": float(accuracy_score(y, prediction)),
        "precision": float(precision_score(y, prediction, pos_label=POSITIVE_LABEL, zero_division=0)),
        "recall": float(recall_score(y, prediction, pos_label=POSITIVE_LABEL, zero_division=0)),
        "f1": float(f1_score(y, prediction, pos_label=POSITIVE_LABEL, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, phishing_probability)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
        "decision_threshold": float(threshold),
        "confusion_matrix": {
            "labels": ["legitimate", "phishing"],
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
    }


def _select_model(validation_metrics):
    # Minimize false positives only among candidates meeting the recall floor.
    acceptable = [
        name for name, metrics in validation_metrics.items()
        if metrics["recall"] >= MINIMUM_VALIDATION_RECALL
    ]
    candidates = acceptable or list(validation_metrics)
    return min(
        candidates,
        key=lambda name: (
            validation_metrics[name]["false_positive_rate"],
            -validation_metrics[name]["f1"],
            -validation_metrics[name]["recall"],
        ),
    )


def _write_json(path, value):
    with open(path, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)


def main():
    frame, data_report = prepare_dataset(DATASET_PATH)
    splits = split_dataset(frame)
    write_splits(splits)
    model_columns = ["url", *FEATURE_NAMES]
    x_train = splits["train"][model_columns]
    y_train = splits["train"]["label"]
    x_validation = splits["validation"][model_columns]
    y_validation = splits["validation"]["label"]
    x_test = splits["test"][model_columns]
    y_test = splits["test"]["label"]

    validation_metrics = {}
    fitted_models = {}
    for name, model in _build_candidates().items():
        model.fit(x_train, y_train)
        fitted_models[name] = model
        validation_probabilities = _phishing_probabilities(model, x_validation)
        threshold = _select_threshold(validation_probabilities, y_validation)
        validation_metrics[name] = _metrics(
            model, x_validation, y_validation, threshold=threshold
        )
        print(
            f"{name}: validation FPR={validation_metrics[name]['false_positive_rate']:.4f}, "
            f"recall={validation_metrics[name]['recall']:.4f}, "
            f"F1={validation_metrics[name]['f1']:.4f}"
        )

    selected_name = _select_model(validation_metrics)
    selected_model = fitted_models[selected_name]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=FutureWarning)
        calibrated_model = CalibratedClassifierCV(
            estimator=selected_model,
            method="sigmoid",
            cv="prefit",
        )
        calibrated_model.fit(x_validation, y_validation)
    decision_threshold = _select_threshold(
        _phishing_probabilities(calibrated_model, x_validation),
        y_validation,
    )
    test_metrics = _metrics(
        calibrated_model,
        x_test,
        y_test,
        threshold=decision_threshold,
    )

    clf = selected_model.named_steps["classifier"]
    try:
        model_feature_names = selected_model.named_steps["features"].get_feature_names_out()
    except (AttributeError, ValueError):
        model_feature_names = FEATURE_NAMES
    if hasattr(clf, "feature_importances_"):
        importances = np.asarray(clf.feature_importances_, dtype=float)
        importance_method = "native_feature_importances"
    elif hasattr(clf, "coef_"):
        importances = np.abs(np.asarray(clf.coef_)[0])
        importance_method = "absolute_logistic_coefficients"
    else:
        importances = None
        importance_method = None

    importance_rows = []
    if importances is not None:
        importance_rows = [
            {"feature": feature, "importance": float(importance)}
            for feature, importance in sorted(
                zip(model_feature_names, importances),
                key=lambda pair: pair[1],
                reverse=True,
            )
        ]
        pd.DataFrame(importance_rows).to_csv(
            os.path.join(ARTIFACT_DIR, "feature_importance.csv"), index=False
        )
    pd.DataFrame(
        [
            ["legitimate", test_metrics["confusion_matrix"]["true_negative"],
             test_metrics["confusion_matrix"]["false_positive"]],
            ["phishing", test_metrics["confusion_matrix"]["false_negative"],
             test_metrics["confusion_matrix"]["true_positive"]],
        ],
        columns=["actual_label", "predicted_legitimate", "predicted_phishing"],
    ).to_csv(os.path.join(ARTIFACT_DIR, "confusion_matrix.csv"), index=False)

    split_summary = {}
    for name, part in splits.items():
        split_summary[name] = {
            "rows": int(len(part)),
            "percentage": round(len(part) * 100 / len(frame), 2),
            "label_counts": {key: int(value) for key, value in part["label"].value_counts().items()},
            "registrable_domains": int(part["domain_group"].nunique()),
            "attack_category_counts": (
                {key: int(value) for key, value in part["attack_category"].value_counts().items()}
                if "attack_category" in part else {}
            ),
        }
    domain_sets = {
        name: set(part["domain_group"])
        for name, part in splits.items()
    }
    no_domain_overlap = not any(
        domain_sets[left] & domain_sets[right]
        for left, right in (
            ("train", "validation"),
            ("train", "test"),
            ("validation", "test"),
        )
    )
    if not no_domain_overlap:
        raise AssertionError("Training output contains domain leakage across splits.")

    evaluation = {
        "dataset": data_report,
        "dataset_limitations": [
            "All supplied records are marked synthetic or synthetic-pattern examples.",
            "No independent real-world phishing or benign corpus was provided.",
            "Reported performance measures held-out synthetic-domain generalization only.",
            "Dataset-provided model features were recomputed from URLs; categories, labels, "
            "origins, and supplied feature columns were excluded from model inputs.",
        ],
        "split_method": (
            "Deterministic, weighted stratified assignment by approximate registrable domain, "
            "label, and synthetic attack category"
        ),
        "split_domain_overlap": False,
        "splits": split_summary,
        "validation_metrics": validation_metrics,
        "selected_model": selected_name,
        "calibration": {
            "method": "sigmoid (Platt scaling)",
            "fit_on": "domain-separated validation split",
            "confidence_scope": "synthetic validation distribution; not real-world calibrated",
        },
        "decision_threshold": decision_threshold,
        "validation_minimum_recall": MINIMUM_VALIDATION_RECALL,
        "test_metrics": test_metrics,
        "feature_importance_method": importance_method,
        "feature_importance": importance_rows,
        "risk_score_thresholds": {
            "very_low_risk": [0, 19],
            "low_risk": [20, 39],
            "suspicious": [40, 59],
            "high_risk": [60, 79],
            "critical_likely_phishing": [80, 100],
        },
    }
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    _write_json(REPORT_PATH, evaluation)

    bundle = {
        "model": calibrated_model,
        "feature_names": list(FEATURE_NAMES),
        "schema_version": 2,
        "selected_model": selected_name,
        "calibrated": True,
        "calibration_method": "sigmoid",
        "calibration_scope": "synthetic validation distribution only",
        "decision_threshold": decision_threshold,
        "test_metrics": test_metrics,
        "evaluation_report": REPORT_PATH,
    }
    fd, temporary_path = tempfile.mkstemp(
        prefix="url_model_", suffix=".pkl", dir=os.path.dirname(MODEL_PATH)
    )
    os.close(fd)
    try:
        joblib.dump(bundle, temporary_path)
        os.replace(temporary_path, MODEL_PATH)
    finally:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)

    print(
        f"Selected {selected_name}; domain-disjoint test accuracy="
        f"{test_metrics['accuracy']:.4f}, FPR={test_metrics['false_positive_rate']:.4f}, "
        f"recall={test_metrics['recall']:.4f}"
    )
    print(f"Model saved to {MODEL_PATH}")
    print(f"Dataset splits and evaluation saved to {ARTIFACT_DIR}")
    return bundle


if __name__ == "__main__":
    main()
