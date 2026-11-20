from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from ml.url_classifier import predict_url, reset_model_cache
from ml_training.prepare_dataset import canonicalize_url, _read_phiusiil
from ml_training.train import train


def test_canonicalize_url_preserves_path_query_and_fragment():
    value = canonicalize_url("HTTPS://Example.COM/login?User=ABC#Step")
    assert value == "https://example.com/login?User=ABC#Step"


def test_phiusiil_labels_are_mapped_without_using_other_features(tmp_path: Path):
    source = tmp_path / "phiusiil.csv"
    pd.DataFrame({
        "URL": ["https://legit.example/", "http://phish.example/login"],
        "Label": [1, 0],
        "URLTitleMatchScore": [0.9, 0.1],
    }).to_csv(source, index=False)
    result = _read_phiusiil(source)
    assert result["label"].tolist() == [0, 1]
    assert result["source"].eq("PhiUSIIL-UCI").all()
    assert "URLTitleMatchScore" not in result.columns


def test_prediction_is_gracefully_unavailable_without_model(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTI_MODEL_PATH", str(tmp_path / "missing.joblib"))
    monkeypatch.delenv("HF_MODEL_REPO_ID", raising=False)
    reset_model_cache()
    result = predict_url("https://example.com/")
    assert result["ml_status"] == "unavailable"
    assert result["ml_prediction"] is None
    reset_model_cache()


def test_runtime_prediction_from_trusted_joblib_artifact(monkeypatch, tmp_path: Path):
    urls = [
        "https://shop-example.com/products/123",
        "https://news-example.org/articles/latest",
        "https://university-example.edu/admissions",
        "https://bank-example.com/customer/help",
        "http://secure-login-verify.bad-domain.net/account/update",
        "http://free-gift-prize.bad-domain.org/login/confirm",
        "https://account-locked.bad-domain.com/verify/password",
        "http://billing-alert.bad-domain.net/secure/signin",
    ]
    labels = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 4))),
        ("classifier", LogisticRegression(max_iter=300, random_state=1)),
    ])
    pipeline.fit(urls, labels)
    artifact = tmp_path / "url_classifier.joblib"
    joblib.dump({
        "pipeline": pipeline, "decision_threshold": 0.5,
        "metadata": {"model_id": "cti-sentinel-test-model"},
    }, artifact)
    monkeypatch.setenv("CTI_MODEL_PATH", str(artifact))
    monkeypatch.delenv("HF_MODEL_REPO_ID", raising=False)
    reset_model_cache()
    result = predict_url("http://secure-login-verify.bad-domain.net/account/update")
    assert result["ml_status"] == "completed"
    assert result["ml_model"] == "cti-sentinel-test-model"
    assert 0.0 <= result["ml_malicious_probability"] <= 1.0
    assert result["ml_prediction"] in {"BENIGN", "MALICIOUS"}
    assert result["ml_confidence"] >= 0.5
    reset_model_cache()


def test_group_aware_training_smoke_run(tmp_path: Path):
    rows = []
    for i in range(35):
        for j in range(3):
            rows.append({
                "url": f"https://store{i:03d}-good.com/product/{j}?item={i}",
                "label": 0, "source": "synthetic-test",
            })
    for i in range(35):
        for j in range(3):
            rows.append({
                "url": f"http://login{i:03d}-verify.net/account/{j}?token={i}",
                "label": 1, "source": "synthetic-test",
            })
    dataset = tmp_path / "dataset.csv"
    pd.DataFrame(rows).to_csv(dataset, index=False)
    model_dir, report_dir = tmp_path / "models", tmp_path / "reports"
    result = train(dataset, model_dir, report_dir, quick=True)
    assert (model_dir / "url_classifier.joblib").is_file()
    assert (model_dir / "README.md").is_file()
    assert result["test_rows"] > 0
    assert result["domain_overlap_between_train_and_test"] == 0
    saved = json.loads((report_dir / "evaluation.json").read_text(encoding="utf-8"))
    assert saved["test_metrics"]["support"]["malicious"] > 0


def test_dataset_preparation_deduplicates_and_excludes_label_conflicts(monkeypatch, tmp_path: Path):
    import ml_training.prepare_dataset as prep

    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    raw_dir.mkdir()
    phiusiil_rows = []
    for i in range(60):
        phiusiil_rows.append({"URL": f"https://legit-{i:03d}.com/home", "Label": 1})
        phiusiil_rows.append({"URL": f"http://phish-{i:03d}.net/login", "Label": 0})
    # This URL will receive disagreeing labels from the two sources and must be dropped.
    phiusiil_rows.append({"URL": "http://conflict-example.net/login", "Label": 1})
    pd.DataFrame(phiusiil_rows).to_csv(raw_dir / "phiusiil.csv", index=False)
    pd.DataFrame({
        "phish_id": [987654],
        "url": ["http://conflict-example.net/login"],
        "verified": ["yes"],
        "online": ["yes"],
        "verification_time": ["2026-11-20T00:00:00+00:00"],
    }).to_csv(raw_dir / "phishtank.csv", index=False)

    monkeypatch.setattr(prep, "RAW_DIR", raw_dir)
    monkeypatch.setattr(prep, "PROCESSED_DIR", processed_dir)
    monkeypatch.setattr(prep, "PHIUSIIL_FILE", raw_dir / "phiusiil.csv")
    monkeypatch.setattr(prep, "PHISHTANK_FILE", raw_dir / "phishtank.csv")
    monkeypatch.setattr(prep, "URLHAUS_FILE", raw_dir / "missing-urlhaus.csv")
    monkeypatch.setattr(prep, "OUTPUT_FILE", processed_dir / "dataset.csv")
    monkeypatch.setattr(prep, "MANIFEST_FILE", processed_dir / "manifest.json")

    manifest = prep.prepare_dataset()
    prepared = pd.read_csv(processed_dir / "dataset.csv")
    assert "http://conflict-example.net/login" not in set(prepared["url"])
    assert len(prepared) == 120
    assert set(prepared["label"].unique()) == {0, 1}
    assert manifest["conflicting_url_rows_removed"] == 2
    assert manifest["class_counts"] == {"BENIGN": 60, "MALICIOUS": 60}
