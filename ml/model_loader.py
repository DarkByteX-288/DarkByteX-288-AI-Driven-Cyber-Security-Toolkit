"""
ml/model_loader.py
---------------------
Lazily loads trained models from disk (trained_models/*.pkl). If a model
file is missing, it triggers dataset generation + training automatically so
the app is always runnable immediately after installation.
"""

import os
import logging
import threading

import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSWORD_MODEL_PATH = os.path.join(BASE_DIR, "trained_models", "password_model.pkl")
URL_MODEL_PATH = os.path.join(BASE_DIR, "trained_models", "url_model.pkl")

_lock = threading.Lock()
_logger = logging.getLogger("bastionix.ml")
_password_model_cache = None
_url_model_cache: dict | None = None


def _ensure_password_model():
    if not os.path.exists(PASSWORD_MODEL_PATH):
        from ml.train_password_model import main as train_main
        train_main()


def _ensure_url_model():
    if not os.path.exists(URL_MODEL_PATH):
        from ml.train_url_model import main as train_main
        train_main()


def get_password_model():
    """Returns a dict: {'model': ..., 'feature_names': [...], 'accuracy': float}"""
    global _password_model_cache
    with _lock:
        if _password_model_cache is None:
            _ensure_password_model()
            _password_model_cache = joblib.load(PASSWORD_MODEL_PATH)
    return _password_model_cache


def get_url_model():
    global _url_model_cache
    with _lock:
        from services.url_features import FEATURE_NAMES

        compatible = (
            isinstance(_url_model_cache, dict)
            and _url_model_cache.get("schema_version") == 2
            and _url_model_cache.get("feature_names") == FEATURE_NAMES
            and _url_model_cache.get("calibrated") is True
        )
        if not compatible and os.path.exists(URL_MODEL_PATH):
            try:
                candidate = joblib.load(URL_MODEL_PATH)
            except (OSError, EOFError, ValueError, ImportError, AttributeError) as exc:
                _logger.warning(
                    "Stored URL model could not be loaded; retraining it: %s",
                    type(exc).__name__,
                    exc_info=True,
                )
            else:
                compatible = (
                    isinstance(candidate, dict)
                    and candidate.get("schema_version") == 2
                    and candidate.get("feature_names") == FEATURE_NAMES
                    and candidate.get("calibrated") is True
                )
                if compatible:
                    _url_model_cache = candidate
        if not compatible:
            from ml.train_url_model import main as train_main

            train_main()
            _url_model_cache = joblib.load(URL_MODEL_PATH)
    return _url_model_cache


def retrain_password_model():
    """Force-retrain the password model (used by Settings > Retrain AI Models)."""
    global _password_model_cache
    from ml.generate_password_dataset import main as gen_main
    from ml.train_password_model import main as train_main
    with _lock:
        gen_main()
        train_main()
        _password_model_cache = joblib.load(PASSWORD_MODEL_PATH)
    return _password_model_cache


def retrain_url_model():
    """Force-retrain the URL model (used by Settings > Retrain AI Models)."""
    global _url_model_cache
    from ml.train_url_model import main as train_main
    with _lock:
        train_main()
        candidate = joblib.load(URL_MODEL_PATH)
        if not candidate.get("calibrated"):
            raise ValueError("The newly trained URL model is not calibrated.")
        _url_model_cache = candidate
    return _url_model_cache
