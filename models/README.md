---
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

- Model ID: `cti-sentinel-url-classifier-v1`
- Algorithm selected by validation: `logistic_regression`
- Input: raw URL string only; character-level TF-IDF n-grams (3–5 characters)
- Labels: `0 = BENIGN`, `1 = MALICIOUS`
- Decision threshold: `0.1950` (selected on validation; false-positive-rate target met: `True`)
- Training time (UTC): `2026-11-20T16:22:08.295602+00:00`

## Evaluation

The held-out test set was split by registrable domain to reduce domain overlap. A temporal holdout was not possible because the benchmark sources do not provide uniform per-URL capture timestamps. These are measured results from this training run, not guarantees of real-world performance.

| Metric | Test result |
|---|---:|
| Accuracy | 0.9963 |
| Precision | 0.9992 |
| Recall | 0.9913 |
| F1 | 0.9952 |
| ROC-AUC | 0.9976 |
| PR-AUC | 0.9979 |
| False-positive rate | 0.0005 |

## Data and attribution

Sources used: PhiUSIIL-UCI. The dataset manifest records row counts, label mapping and source attribution. The PhiUSIIL source is licensed CC BY 4.0 and must be attributed to Prasad and Chandra (UCI Machine Learning Repository, 2024; DOI: 10.1016/j.cose.2023.103545). PhishTank and URLhaus feeds are optional; users must follow their current provider terms and redistribution restrictions. Raw threat feeds are not included in this model repository.

Only the `URL` string from PhiUSIIL is used. Website-derived features such as page title, HTML, similarity scores, and DOM features are intentionally excluded because they are unavailable in CTI Sentinel's URL-only inference path.

## Intended use and limitations

Use as a triage signal for URL investigation, not as proof that a URL is safe or malicious. False positives and false negatives are possible. The evaluation data may not represent current threat populations, and phishing infrastructure changes rapidly. Do not use this model alone for blocking, incident closure, law-enforcement attribution, or other high-impact decisions. Combine it with live threat-intelligence sources and analyst review. The reported class probability is not guaranteed to be statistically calibrated; interpret it as a model score, not a measured real-world probability.

## Loading

This repository contains a joblib/scikit-learn artifact. Loading serialized Python artifacts can execute code. Load only from this trusted project repository, pin the repository revision, and use compatible scikit-learn/joblib versions.
