# CTI Sentinel X — ML Upgrade Build and Test Status

## Implemented

- Added an optional URL-only classifier runtime that returns an additional ML signal without changing the legacy CTI `threat_score` or `threat_level`.
- Added a reproducible PhiUSIIL download, URL canonicalization, source-provenance manifest, conflict removal and dataset-preparation pipeline.
- Added candidate comparison (character n-gram TF-IDF + Logistic Regression and Complement Naive Bayes), registrable-domain grouped validation/test splits, validation-only threshold selection and held-out evaluation.
- Added model card/config generation, local inference verification and a private-by-default Hugging Face publisher.
- Added dashboard, investigate and report UI display for the URL model output.
- Preserved the existing Qwen2.5 3B, Nomic Embed Text, RAG assistant, external threat-intelligence integrations, file triage and legacy scoring pipeline.
- Added Git/Docker exclusions for `.env`, recovery backups, raw/processed datasets, local serialized models and generated evaluation/prediction files.

## Automated checks completed in the build environment

- `python -m pytest -q`: **16 passed**.
- `python -m compileall -q .`: passed.
- `node --check` across `static/js/*.js`: passed.
- Docker Compose YAML parsed and the expected model mount/environment settings were verified.

The test suite includes a small synthetic-data training smoke test and a runtime integration test proving that the ML result is persisted while the legacy score remains unchanged. Synthetic test data is not the release training dataset and its results are not model-performance claims.

## Still required on the Windows project machine

- Run the provided PowerShell test helper in the recovered project folder.
- Download the real UCI benchmark and any optional provider feeds permitted by their current terms.
- Train on the real prepared dataset and review the generated holdout evaluation, especially false positives, false negatives, precision, recall, PR-AUC, domain leakage and whether the validation FPR target was met.
- Verify local inference and rebuild/recreate the Flask frontend container to load the locally generated model artifact.
- Only after reviewing results and provider terms, publish the trained model to Hugging Face. The publisher defaults to a private repository.

No real-dataset training, final model metrics, GitHub push, Docker Hub push or Hugging Face publication is claimed as complete by this build package.
