"""
services/password_service.py
-------------------------------
Orchestrates the full password analysis pipeline:
  1. Rule-based feature extraction
  2. Heuristic strength scoring (0-100) + category
  3. ML model prediction (RandomForest)
  4. Attack simulations
  5. Recommendation generation

The raw password is used only transiently in-memory and is never returned,
logged, or persisted by this module.
"""

from services.password_features import extract_features, feature_vector
from services.recommendation_engine import generate_recommendations
from services.attack_simulator import run_all_simulations
from ml.model_loader import get_password_model

CATEGORY_COLORS = {
    "Very Weak": "#e63946",
    "Weak": "#f77f00",
    "Moderate": "#fcbf49",
    "Strong": "#43aa8b",
    "Very Strong": "#2ec4b6",
}


def _heuristic_score(features: dict) -> float:
    """0-100 heuristic strength score, independent of the ML model, used to
    display a transparent, explainable "Strength Score" alongside the ML
    prediction."""
    score = 0.0
    score += min(features["length"] * 4, 40)
    score += min(features["entropy"], 40)
    score += features["char_class_count"] * 5
    if features["is_dictionary_word"]:
        score -= 40
    if features["is_keyboard_pattern"]:
        score -= 25
    if features["has_repeated_chars"]:
        score -= 15
    if features["has_sequential_chars"]:
        score -= 15
    if features["has_common_substitution"] and features["is_dictionary_word"]:
        score -= 10
    return max(0.0, min(100.0, round(score, 1)))


def _category_from_score(score: float) -> str:
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Moderate"
    if score < 80:
        return "Strong"
    return "Very Strong"


def analyze_password(password: str) -> dict:
    """Run the complete analysis pipeline for a single password.

    Returns a dict containing everything needed to render the results page
    and persist a PasswordAnalysis row (raw password excluded).
    """
    if not password:
        raise ValueError("Password must not be empty.")

    features = extract_features(password)
    score = _heuristic_score(features)
    category = _category_from_score(score)

    # ML prediction
    ml_prediction, ml_confidence = None, None
    try:
        import pandas as pd
        bundle = get_password_model()
        model = bundle["model"]
        vec_df = pd.DataFrame([feature_vector(features)], columns=bundle["feature_names"])
        pred = model.predict(vec_df)[0]
        proba = model.predict_proba(vec_df)[0]
        confidence = float(max(proba))
        ml_prediction, ml_confidence = pred, round(confidence * 100, 1)
    except Exception:
        # If the ML model is ever unavailable, degrade gracefully to
        # heuristic-only results rather than crashing the request.
        ml_prediction, ml_confidence = None, None

    attack_results = run_all_simulations(features)
    recommendations = generate_recommendations(features)

    # Overall "estimated crack time" = the brute force estimate (worst case
    # for the attacker / best case defensively, but most broadly applicable)
    brute_force = next(a for a in attack_results if a["attack_type"] == "brute_force")

    return {
        "features": features,
        "strength_score": score,
        "strength_category": category,
        "category_color": CATEGORY_COLORS[category],
        "ml_prediction": ml_prediction,
        "ml_confidence": ml_confidence,
        "attack_simulations": attack_results,
        "estimated_crack_time_seconds": brute_force["estimated_time_seconds"],
        "estimated_crack_time_display": brute_force["estimated_time_display"],
        "recommendations": recommendations,
    }
