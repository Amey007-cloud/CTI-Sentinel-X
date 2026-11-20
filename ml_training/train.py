from __future__ import annotations

import argparse
import hashlib
import json
import ipaddress
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedGroupKFold

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "data" / "processed" / "url_dataset.csv"
DEFAULT_MODEL_DIR = ROOT / "models"
DEFAULT_REPORT_DIR = ROOT / "reports"
MODEL_ID = "cti-sentinel-url-classifier-v1"
_TLD_EXTRACTOR = None


def registrable_domain(url: str) -> str:
    """Return an approximate registrable domain for group-aware splitting."""
    from urllib.parse import urlsplit
    host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    host = host.lower().strip(".")
    if not host:
        return "__unknown__"
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass
    global _TLD_EXTRACTOR
    try:
        import tldextract
        if _TLD_EXTRACTOR is None:
            _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
        extracted = _TLD_EXTRACTOR(host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
    except Exception:
        pass
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _group_split(X: np.ndarray, y: np.ndarray, groups: np.ndarray, seed: int):
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    for train_idx, holdout_idx in splitter.split(X, y, groups):
        if len(np.unique(y[train_idx])) == 2 and len(np.unique(y[holdout_idx])) == 2:
            return train_idx, holdout_idx
    raise ValueError("Could not create a group-aware split containing both classes. Add more distinct domains per class.")


def _make_vectorizer(quick: bool) -> TfidfVectorizer:
    return TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=1 if quick else 2,
        max_features=50_000 if quick else 200_000,
        sublinear_tf=True,
        lowercase=True,
        dtype=np.float32,
    )


def _candidate_models(quick: bool) -> dict[str, Any]:
    max_iter = 350 if quick else 1500
    return {
        "logistic_regression": Pipeline([
            ("tfidf", _make_vectorizer(quick)),
            ("classifier", LogisticRegression(
                C=2.0, class_weight="balanced", solver="liblinear", max_iter=max_iter,
                random_state=42,
            )),
        ]),
        "complement_nb": Pipeline([
            ("tfidf", _make_vectorizer(quick)),
            ("classifier", ComplementNB(alpha=0.35, norm=True)),
        ]),
    }


def _probability(pipeline: Any, X: np.ndarray) -> np.ndarray:
    classes = list(pipeline.classes_)
    if 1 not in classes:
        raise ValueError("A candidate model was not trained with the MALICIOUS class.")
    return pipeline.predict_proba(X)[:, classes.index(1)]


def choose_threshold(y_true: np.ndarray, probabilities: np.ndarray, max_fpr: float = 0.05) -> float:
    best_threshold = 0.5
    best_f1 = -1.0
    best_recall = -1.0
    for threshold in np.linspace(0.05, 0.95, 181):
        predicted = (probabilities >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
        fpr = fp / max(1, fp + tn)
        f1 = f1_score(y_true, predicted, zero_division=0)
        recall = recall_score(y_true, predicted, zero_division=0)
        if fpr <= max_fpr and (f1 > best_f1 or (f1 == best_f1 and recall > best_recall)):
            best_threshold, best_f1, best_recall = float(threshold), float(f1), float(recall)
    if best_f1 < 0:
        # No threshold respected the false-positive budget. Fall back to the
        # threshold with the best F1, and make that limitation visible in report.
        for threshold in np.linspace(0.05, 0.95, 181):
            f1 = f1_score(y_true, probabilities >= threshold, zero_division=0)
            if f1 > best_f1:
                best_threshold, best_f1 = float(threshold), float(f1)
    return best_threshold


def calculate_metrics(y_true: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict[str, Any]:
    predicted = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    fpr = fp / max(1, fp + tn)
    metrics = {
        "threshold": round(float(threshold), 6),
        "accuracy": round(float(accuracy_score(y_true, predicted)), 6),
        "precision": round(float(precision_score(y_true, predicted, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, predicted, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, predicted, zero_division=0)), 6),
        "false_positive_rate": round(float(fpr), 6),
        "roc_auc": round(float(roc_auc_score(y_true, probabilities)), 6),
        "pr_auc": round(float(average_precision_score(y_true, probabilities)), 6),
        "confusion_matrix": {"true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn), "true_positive": int(tp)},
        "support": {"benign": int((y_true == 0).sum()), "malicious": int((y_true == 1).sum())},
    }
    return metrics


def _write_model_card(path: Path, metadata: dict, evaluation: dict) -> None:
    source_list = ", ".join(metadata.get("dataset_sources", [])) or "Not recorded"
    test = evaluation["test_metrics"]
    body = f"""---
tags:
- cybersecurity
- phishing-detection
- url-classification
- scikit-learn
pipeline_tag: text-classification
---

# CTI Sentinel X URL Intelligence Classifier v1

A URL-only lexical classifier intended to provide an additional signal inside CTI Sentinel X. It does not visit submitted URLs, retrieve page HTML, or replace CTI enrichment providers, Qwen/Nomic models, or the existing rule-based threat score.

## Model

- Model ID: `{metadata['model_id']}`
- Algorithm selected by validation: `{metadata['selected_algorithm']}`
- Input: raw URL string only; character-level TF-IDF n-grams (3–5 characters)
- Labels: `0 = BENIGN`, `1 = MALICIOUS`
- Decision threshold: `{metadata['decision_threshold']:.4f}` (selected on validation; false-positive-rate target met: `{metadata['validation_fpr_target_met']}`)
- Training time (UTC): `{metadata['trained_at_utc']}`

## Evaluation

The held-out test set was split by registrable domain to reduce domain overlap. A temporal holdout was not possible because the benchmark sources do not provide uniform per-URL capture timestamps. These are measured results from this training run, not guarantees of real-world performance.

| Metric | Test result |
|---|---:|
| Accuracy | {test['accuracy']:.4f} |
| Precision | {test['precision']:.4f} |
| Recall | {test['recall']:.4f} |
| F1 | {test['f1']:.4f} |
| ROC-AUC | {test['roc_auc']:.4f} |
| PR-AUC | {test['pr_auc']:.4f} |
| False-positive rate | {test['false_positive_rate']:.4f} |

## Data and attribution

Sources used: {source_list}. The dataset manifest records row counts, label mapping and source attribution. The PhiUSIIL source is licensed CC BY 4.0 and must be attributed to Prasad and Chandra (UCI Machine Learning Repository, 2024; DOI: 10.1016/j.cose.2023.103545). PhishTank and URLhaus feeds are optional; users must follow their current provider terms and redistribution restrictions. Raw threat feeds are not included in this model repository.

Only the `URL` string from PhiUSIIL is used. Website-derived features such as page title, HTML, similarity scores, and DOM features are intentionally excluded because they are unavailable in CTI Sentinel's URL-only inference path.

## Intended use and limitations

Use as a triage signal for URL investigation, not as proof that a URL is safe or malicious. False positives and false negatives are possible. The evaluation data may not represent current threat populations, and phishing infrastructure changes rapidly. Do not use this model alone for blocking, incident closure, law-enforcement attribution, or other high-impact decisions. Combine it with live threat-intelligence sources and analyst review. The reported class probability is not guaranteed to be statistically calibrated; interpret it as a model score, not a measured real-world probability.

## Loading

This repository contains a joblib/scikit-learn artifact. Loading serialized Python artifacts can execute code. Load only from this trusted project repository, pin the repository revision, and use compatible scikit-learn/joblib versions.
"""
    path.write_text(body, encoding="utf-8")


def train(dataset_path: Path, model_dir: Path, report_dir: Path, quick: bool = False, max_rows: int | None = None) -> dict:
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}. Run the dataset downloader first.")
    frame = pd.read_csv(dataset_path, low_memory=False)
    required = {"url", "label"}
    if not required.issubset(frame.columns):
        raise ValueError("Training CSV must contain canonical 'url' and 'label' columns.")
    frame = frame.dropna(subset=["url", "label"]).copy()
    frame["url"] = frame["url"].astype(str).str.strip()
    frame["label"] = pd.to_numeric(frame["label"], errors="coerce")
    frame = frame[frame["label"].isin([0, 1]) & frame["url"].str.len().between(4, 8192)].copy()
    frame["label"] = frame["label"].astype(int)
    if max_rows and len(frame) > max_rows:
        total_rows = len(frame)
        sampled_parts = []
        for label_value, part in frame.groupby("label"):
            requested = max(1, int(round(max_rows * len(part) / total_rows)))
            sampled_parts.append(part.sample(n=min(len(part), requested), random_state=42))
        frame = pd.concat(sampled_parts, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
    counts = frame["label"].value_counts().to_dict()
    if counts.get(0, 0) < 50 or counts.get(1, 0) < 50:
        raise ValueError(f"Need at least 50 records per class after filtering; got {counts}.")

    X = frame["url"].to_numpy(dtype=str)
    y = frame["label"].to_numpy(dtype=int)
    groups = frame["url"].map(registrable_domain).to_numpy(dtype=str)
    outer_train_idx, test_idx = _group_split(X, y, groups, 42)
    train_idx, validation_idx = _group_split(X[outer_train_idx], y[outer_train_idx], groups[outer_train_idx], 43)
    fit_idx = outer_train_idx[train_idx]
    val_idx = outer_train_idx[validation_idx]

    candidate_results = {}
    candidate_models = _candidate_models(quick)
    best_name = None
    best_key = (-1.0, -1.0)
    best_threshold = 0.5
    for name, candidate in candidate_models.items():
        print(f"[TRAIN] Fitting {name} on {len(fit_idx):,} rows...")
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            candidate.fit(X[fit_idx], y[fit_idx])
        validation_probabilities = _probability(candidate, X[val_idx])
        threshold = choose_threshold(y[val_idx], validation_probabilities, max_fpr=0.05)
        metrics = calculate_metrics(y[val_idx], validation_probabilities, threshold)
        candidate_results[name] = {
            "validation_metrics": metrics,
            "warnings": [str(item.message) for item in captured[:5]],
        }
        selection_key = (metrics["pr_auc"], metrics["f1"])
        if selection_key > best_key:
            best_key, best_name, best_threshold = selection_key, name, threshold
        print(f"[VALIDATION] {name}: PR-AUC={metrics['pr_auc']:.4f}, F1={metrics['f1']:.4f}, FPR={metrics['false_positive_rate']:.4f}")

    final_model = _candidate_models(quick)[best_name]
    print(f"[FINAL] Refitting selected model ({best_name}) on {len(outer_train_idx):,} outer-training rows...")
    final_model.fit(X[outer_train_idx], y[outer_train_idx])
    test_probabilities = _probability(final_model, X[test_idx])
    test_metrics = calculate_metrics(y[test_idx], test_probabilities, best_threshold)

    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    dataset_sha256 = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    metadata = {
        "model_id": MODEL_ID,
        "model_version": "1.0.0",
        "selected_algorithm": best_name,
        "decision_threshold": float(best_threshold),
        "validation_false_positive_rate": candidate_results[best_name]["validation_metrics"]["false_positive_rate"],
        "validation_fpr_target_met": candidate_results[best_name]["validation_metrics"]["false_positive_rate"] <= 0.05,
        "label_mapping": {"0": "BENIGN", "1": "MALICIOUS"},
        "input_contract": "One raw URL string; no webpage retrieval or external network access.",
        "feature_extractor": "TfidfVectorizer(analyzer=char, ngram_range=(3,5))",
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_sha256": dataset_sha256,
        "dataset_rows": int(len(frame)),
        "dataset_class_counts": {"benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
        "dataset_sources": sorted({part for cell in frame["source"].dropna().astype(str).unique() for part in cell.split(";") if part}) if "source" in frame.columns else [],
        "split_strategy": "StratifiedGroupKFold with registrable-domain grouping; validation threshold is selected without test-set tuning.",
        "temporal_holdout": "Not applied because the benchmark does not provide a uniform per-URL capture timestamp across all source records.",
        "coverage_note": "When optional PhishTank/URLhaus feeds are absent, the malicious class is primarily phishing URLs from PhiUSIIL; this is not a universal malware URL benchmark.",
        "scikit_learn_version": sklearn.__version__,
        "joblib_version": joblib.__version__,
        "quick_smoke_training": bool(quick),
    }
    bundle = {
        "artifact_version": 1,
        "pipeline": final_model,
        "decision_threshold": float(best_threshold),
        "metadata": metadata,
    }
    model_path = model_dir / "url_classifier.joblib"
    joblib.dump(bundle, model_path, compress=3)
    config_path = model_dir / "config.json"
    config_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    test_report = {
        "model": metadata,
        "candidate_comparison": candidate_results,
        "selected_algorithm": best_name,
        "validation_threshold": float(best_threshold),
        "test_metrics": test_metrics,
        "test_rows": int(len(test_idx)),
        "test_unique_domains": int(len(set(groups[test_idx]))),
        "domain_overlap_between_train_and_test": int(len(set(groups[outer_train_idx]) & set(groups[test_idx]))),
        "warning": "This benchmark is not a guarantee of live-world accuracy. Review current-source coverage and false-positive samples before operational use.",
    }
    (report_dir / "evaluation.json").write_text(json.dumps(test_report, indent=2), encoding="utf-8")
    prediction_frame = pd.DataFrame({
        "url_sha256_prefix": [hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] for value in X[test_idx]],
        "registrable_domain_sha256_prefix": [hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] for value in groups[test_idx]],
        "y_true": y[test_idx],
        "malicious_probability": test_probabilities,
        "y_pred": (test_probabilities >= best_threshold).astype(int),
    })
    prediction_frame.to_csv(report_dir / "test_predictions_anonymized.csv", index=False)
    _write_model_card(model_dir / "README.md", metadata, test_report)

    print("\n[COMPLETE] Model artifact and evaluation report saved.")
    print(json.dumps(test_metrics, indent=2))
    print(f"Model: {model_path}")
    print(f"Evaluation: {report_dir / 'evaluation.json'}")
    return test_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and compare URL-only malicious URL classifiers.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--quick", action="store_true", help="Smaller vocabulary/iteration count for a smoke test; not for release evaluation.")
    parser.add_argument("--max-rows", type=int, default=None, help="Optional stratified row cap for smoke testing only.")
    args = parser.parse_args()
    train(args.dataset, args.model_dir, args.report_dir, quick=args.quick, max_rows=args.max_rows)


if __name__ == "__main__":
    main()
