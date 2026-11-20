from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PREDICTIONS = ROOT / "reports" / "test_predictions_anonymized.csv"


def evaluate(path: Path) -> dict:
    frame = pd.read_csv(path)
    required = {"y_true", "malicious_probability"}
    if not required.issubset(frame.columns):
        raise ValueError(f"Prediction file must contain {sorted(required)}")
    y = frame["y_true"].astype(int).to_numpy()
    p = frame["malicious_probability"].astype(float).to_numpy()
    if len(set(y)) != 2:
        raise ValueError("Evaluation predictions must contain both classes.")
    threshold = 0.5
    if "y_pred" in frame.columns:
        pred = frame["y_pred"].astype(int).to_numpy()
    else:
        pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    result = {
        "rows": int(len(frame)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, p)),
        "pr_auc": float(average_precision_score(y, p)),
        "false_positive_rate": float(fp / max(1, fp + tn)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    print(json.dumps(result, indent=2))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Recalculate metrics from the anonymized held-out predictions.")
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    args = parser.parse_args()
    evaluate(args.predictions)


if __name__ == "__main__":
    main()
