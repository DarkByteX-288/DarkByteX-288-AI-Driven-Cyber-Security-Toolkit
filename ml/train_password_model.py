"""
ml/train_password_model.py
-----------------------------
Trains a RandomForestClassifier to predict password strength category from
the rule-based feature set, evaluates it, and saves it with Joblib.

Run: python ml/train_password_model.py
"""

import os
import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from services.password_features import FEATURE_NAMES  # noqa: E402

DATASET_PATH = os.path.join(BASE_DIR, "datasets", "password_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "trained_models", "password_model.pkl")


def main():
    if not os.path.exists(DATASET_PATH):
        print("Dataset not found, generating it first...")
        from ml.generate_password_dataset import main as gen_main
        gen_main()

    df = pd.read_csv(DATASET_PATH)

    # Convert boolean columns (read as True/False strings if re-loaded) to int
    for col in FEATURE_NAMES:
        if df[col].dtype == bool:
            df[col] = df[col].astype(int)

    X = df[FEATURE_NAMES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"\n=== Password Strength Model ===")
    print(f"Accuracy: {acc:.4f}\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred, labels=model.classes_))
    print("\nFeature Importances:")
    for name, importance in sorted(
        zip(FEATURE_NAMES, model.feature_importances_), key=lambda x: -x[1]
    ):
        print(f"  {name:25s} {importance:.4f}")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES, "accuracy": acc}, MODEL_PATH)
    print(f"\nModel saved -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
