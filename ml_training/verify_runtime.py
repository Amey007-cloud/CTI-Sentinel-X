from __future__ import annotations

import json
from pathlib import Path

from dotenv import load_dotenv

from ml.url_classifier import model_status, predict_url

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    load_dotenv(ROOT / ".env")
    status = model_status()
    if status.get("status") != "local":
        raise SystemExit(
            "A local trained model was not found. Run scripts/train_url_model.ps1 first. "
            "This smoke test intentionally verifies the local artifact, not a remote download."
        )

    # The classifier consumes the string only; this URL is never requested.
    result = predict_url("https://example.com/account/login")
    if result.get("ml_status") != "completed":
        raise SystemExit("The model artifact exists but runtime prediction did not complete.")
    probability = result.get("ml_malicious_probability")
    if not isinstance(probability, (int, float)) or not 0.0 <= float(probability) <= 1.0:
        raise SystemExit("The model returned an invalid malicious-class score.")

    print("[PASS] Local CTI Sentinel URL model loaded and produced a valid inference result.")
    print(json.dumps({
        "model_status": status,
        "ml_status": result.get("ml_status"),
        "prediction": result.get("ml_prediction"),
        "predicted_class_score": result.get("ml_confidence"),
        "malicious_probability": probability,
        "decision_threshold": result.get("ml_decision_threshold"),
        "model_id": result.get("ml_model"),
        "note": "The sample URL was not visited. Scores are model outputs, not calibrated real-world probabilities.",
    }, indent=2))


if __name__ == "__main__":
    main()
