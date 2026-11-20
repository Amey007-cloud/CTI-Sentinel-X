from __future__ import annotations

"""Safe, optional runtime integration for the CTI Sentinel URL classifier.

The model is deliberately an additional signal. This module never changes the
legacy CTI threat score and never makes network requests to the submitted URL.
"""

import os
import threading
from pathlib import Path
from typing import Any

MODEL_ID = "cti-sentinel-url-classifier-v1"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "url_classifier.joblib"

_lock = threading.Lock()
_bundle: dict[str, Any] | None = None
_bundle_path: str | None = None


def _configured_path() -> Path:
    configured = os.getenv("CTI_MODEL_PATH", "").strip()
    if not configured:
        return DEFAULT_MODEL_PATH
    path = Path(configured).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


def _download_from_hub() -> Path | None:
    repo_id = os.getenv("HF_MODEL_REPO_ID", "").strip()
    if not repo_id:
        return None

    filename = os.getenv("HF_MODEL_FILENAME", "url_classifier.joblib").strip()
    if not filename or Path(filename).is_absolute() or ".." in Path(filename).parts:
        raise ValueError("HF_MODEL_FILENAME must be a safe repository-relative filename.")

    # A pinned commit revision is strongly recommended. The default is main so
    # that a newly published private/public repository can be tested easily.
    revision = os.getenv("HF_MODEL_REVISION", "main").strip() or "main"
    token = os.getenv("HF_TOKEN", "").strip() or None
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(
        repo_id=repo_id,
        filename=filename,
        revision=revision,
        token=token,
        repo_type="model",
    )
    return Path(path)


def _load_bundle() -> dict[str, Any]:
    global _bundle, _bundle_path
    local_path = _configured_path()
    local_exists = local_path.is_file()
    path_key = str(local_path.resolve()) if local_exists else ""

    with _lock:
        if _bundle is not None and (_bundle_path == path_key or not path_key):
            return _bundle

        artifact_path = local_path if local_exists else _download_from_hub()
        if artifact_path is None or not artifact_path.is_file():
            raise FileNotFoundError(
                "No trained URL model is installed. Set CTI_MODEL_PATH or HF_MODEL_REPO_ID after training and publishing."
            )

        # Joblib/pickle artifacts can execute code while loading. Only load a
        # model artifact from this project or a Hugging Face repository you own
        # and trust. Pin HF_MODEL_REVISION to a commit hash in deployments.
        import joblib

        loaded = joblib.load(artifact_path)
        if not isinstance(loaded, dict) or "pipeline" not in loaded:
            raise ValueError("The model artifact has an unsupported format.")
        pipeline = loaded["pipeline"]
        if not callable(getattr(pipeline, "predict_proba", None)):
            raise ValueError("The model artifact does not provide class probabilities.")

        threshold = float(loaded.get("decision_threshold", 0.5))
        if not 0.0 < threshold < 1.0:
            raise ValueError("The model artifact contains an invalid decision threshold.")

        _bundle = loaded
        _bundle_path = str(Path(artifact_path).resolve())
        return _bundle


def reset_model_cache() -> None:
    """Clear the in-process cache; primarily useful for tests and model swaps."""
    global _bundle, _bundle_path
    with _lock:
        _bundle = None
        _bundle_path = None


def model_status() -> dict[str, Any]:
    path = _configured_path()
    repo_id = os.getenv("HF_MODEL_REPO_ID", "").strip()
    if path.is_file():
        return {
            "configured": True,
            "status": "local",
            "label": "CTI Sentinel URL ML",
            "description": "Trained URL classifier available from local model storage.",
        }
    if repo_id:
        return {
            "configured": True,
            "status": "huggingface",
            "label": "CTI Sentinel URL ML",
            "description": f"URL classifier configured from Hugging Face repository {repo_id}.",
        }
    return {
        "configured": False,
        "status": "not_installed",
        "label": "CTI Sentinel URL ML",
        "description": "The optional URL classifier has not been trained or installed yet.",
    }


def predict_url(url: str) -> dict[str, Any]:
    """Return an ML-only URL signal, or a graceful unavailable state."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("A non-empty URL string is required for ML classification.")

    try:
        bundle = _load_bundle()
        pipeline = bundle["pipeline"]
        probabilities = pipeline.predict_proba([url.strip()])[0]
        classes = list(pipeline.classes_)
        if 1 not in classes:
            raise ValueError("The trained model is missing the MALICIOUS class.")
        malicious_probability = float(probabilities[classes.index(1)])
        threshold = float(bundle.get("decision_threshold", 0.5))
        prediction = "MALICIOUS" if malicious_probability >= threshold else "BENIGN"
        confidence = malicious_probability if prediction == "MALICIOUS" else 1.0 - malicious_probability
        metadata = bundle.get("metadata", {}) or {}
        return {
            "ml_status": "completed",
            "ml_prediction": prediction,
            "ml_confidence": round(confidence, 6),
            "ml_malicious_probability": round(malicious_probability, 6),
            "ml_decision_threshold": round(threshold, 6),
            "ml_model": metadata.get("model_id", MODEL_ID),
            "ml_message": "Independent URL-only model signal. Its probability score is not calibrated and is not blended into the legacy CTI threat score.",
        }
    except FileNotFoundError:
        return {
            "ml_status": "unavailable",
            "ml_prediction": None,
            "ml_confidence": None,
            "ml_malicious_probability": None,
            "ml_decision_threshold": None,
            "ml_model": MODEL_ID,
            "ml_message": "The custom URL model is not installed yet; existing CTI analysis continues unchanged.",
        }
    except Exception:
        # Keep the existing multi-source investigation available even if the
        # optional ML artifact or one of its Python dependencies is broken.
        return {
            "ml_status": "unavailable",
            "ml_prediction": None,
            "ml_confidence": None,
            "ml_malicious_probability": None,
            "ml_decision_threshold": None,
            "ml_model": MODEL_ID,
            "ml_message": "The optional URL model could not be loaded; existing CTI analysis continues unchanged.",
        }
