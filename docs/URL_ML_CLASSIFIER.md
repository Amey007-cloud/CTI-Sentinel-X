# CTI Sentinel X — URL ML Classifier

## Role in the platform

The URL classifier is an optional, additional lexical-model signal. The existing Flask CTI workflow, MongoDB persistence, VirusTotal/MISP/URLhaus/ThreatFox/OTX/CTI Digest integrations, file analysis, Cuckoo3, FastAPI assistant, Qwen2.5 3B and Nomic Embed Text remain separate and unchanged. The classifier is called only from URL analysis. It does not analyze IPs or file hashes.

The classifier's output is stored alongside the URL intelligence record as `ml_prediction`, `ml_confidence`, `ml_malicious_probability`, `ml_decision_threshold`, `ml_model` and `ml_status`. It is intentionally **not** blended into `threat_score` or `threat_level`; those remain driven by the existing provider-based scoring function. If the model file, Hugging Face repository or ML dependency is unavailable, the response indicates `ml_status=unavailable` and the existing CTI analysis continues. The model never visits or opens the URL.

## Training data policy

The initial benchmark is the PhiUSIIL Phishing URL dataset from UCI (235,795 examples; 134,850 legitimate and 100,945 phishing; CC BY 4.0). UCI defines Label 1 as legitimate and Label 0 as phishing; the preparation script maps these to our canonical labels `0=BENIGN`, `1=MALICIOUS`. The PhiUSIIL file contains website-derived fields, but this project deliberately extracts **only the raw `URL` field**. This avoids training on page/HTML features that are unavailable in the live URL-only inference route.

Optional live feeds augment malicious examples: verified online phishing URLs from PhishTank and recent malware URLs from URLhaus. Without those optional feeds, the malicious class is primarily phishing URLs from PhiUSIIL; this first model should not be described as a universal malware-URL detector. Configure `PHISHTANK_APP_KEY` and `URLHAUS_AUTH_KEY` locally. The downloader uses descriptive User-Agent headers, does not visit threat URLs, and stores raw downloads under `data/raw/`. Review the provider's current terms, rate limits, attribution and redistribution conditions before publication. Raw feeds and processed datasets are excluded from Git/Docker contexts by default.

The preparation stage canonicalizes URL scheme/host, removes exact duplicate URLs and excludes URLs whose source labels conflict. It writes a manifest recording counts, label mapping and source attribution.

## Install and run on Windows PowerShell

Run from the project root. Python 3.11 or 3.12 is recommended for the training environment.

```powershell
python -m venv .venv-ml
.\.venv-ml\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-ml-training.txt
```

Add any provider keys to the ignored local `.env` file only (never paste them into source code or commit them). Then download and prepare data:

```powershell
python -m ml_training.download_datasets
```

To use only the UCI benchmark without the optional feeds:

```powershell
python -m ml_training.download_datasets --skip-phishtank --skip-urlhaus
```

Train and compare the Logistic Regression and Complement Naive Bayes pipelines:

```powershell
python -m ml_training.train
```

Or run the bundled PowerShell helper, which creates the isolated environment, installs all training/download dependencies, downloads the benchmark and runs training in one go:

```powershell
.\scripts\train_url_model.ps1
```

After training, verify that the local model artifact loads and returns an inference result (the sample URL is not visited):

```powershell
.\scripts\verify_url_model.ps1
```

A quick synthetic-data smoke test is built into the automated test suite; `--quick` on `train` reduces vocabulary/iterations and must not be used for a release model.

Review `reports/evaluation.json`, `reports/test_predictions_anonymized.csv`, `models/config.json` and `models/README.md`. The holdout split is grouped by registrable domain to reduce domain leakage. A temporal holdout is not applied because the benchmark sources do not provide uniform per-URL capture timestamps. A validation split selects the operating threshold under a target 5% false-positive-rate constraint; the test split is held back for final measurement. Metrics include precision, recall, F1, ROC-AUC, PR-AUC, false-positive rate and confusion matrix. The raw `predict_proba` output is a model score and is not guaranteed to be statistically calibrated. No score or metric is prefilled or claimed before a real training run.

## Runtime integration

The Flask frontend image installs `requirements-ml.txt`; the FastAPI/RAG image does not need these packages. Configure either a local artifact at `CTI_MODEL_PATH` or a Hugging Face repository using `HF_MODEL_REPO_ID`, `HF_MODEL_FILENAME` and `HF_MODEL_REVISION`. Prefer pinning `HF_MODEL_REVISION` to an immutable commit hash. `HF_TOKEN` is needed only for private repositories and must stay secret.

When no model is installed, `/api/analyze` still works as before and returns an `ml_status` of `unavailable`. After installation, URL results include the model prediction and confidence card in the Investigate UI and the fields are persisted in `url_intelligence` and report history. IP/hash/file workflows do not invoke this model.

## Hugging Face publishing

The publishing script uploads only the model artifact, configuration, model card and evaluation JSON; it never uploads raw or processed source datasets, credentials, or full prediction records. It creates a private model repository by default. Use `--public` only after checking dataset/provider terms, model metrics, sample false positives/negatives and the model card.

```powershell
$env:HF_TOKEN = "hf_..."
python -m ml_training.publish_to_hf --repo-id YOUR_HF_USERNAME/cti-sentinel-url-classifier
```

The joblib artifact is a serialized Python object and must be loaded only from a repository you own and trust. Pin the Hugging Face commit hash in deployment configuration and keep scikit-learn/joblib versions compatible with the artifact.

## Limitations

This is a URL lexical classifier, not a full browser/website analysis model. It can miss newly registered malicious domains, shorteners and compromised legitimate sites; it can also flag benign URLs with unusual strings. Benchmark data may be stale or source-biased. A BENIGN prediction is not a safety guarantee. The model probability is not a calibrated estimate of real-world compromise likelihood. Use live CTI provider results and analyst review for decisions.
