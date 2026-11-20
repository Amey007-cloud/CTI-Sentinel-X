CTI SENTINEL X — ML UPGRADE PATCH

This is an overlay patch for the recovered CTI_Sentinel_X_Recovered project folder.

1. Make sure Docker Desktop is running and stop the CTI Sentinel containers safely with `docker compose stop` (do not use `down -v`).
2. Extract this ZIP directly into the existing CTI_Sentinel_X_Recovered folder. Allow overwriting of the included source files.
3. Do not delete or replace your existing `.env` or `recovery_backup` folder. Neither is included in this patch.
4. Open PowerShell in the project folder and run `PowerShell -ExecutionPolicy Bypass -File .\scripts\test_ml.ps1`.
5. Run `PowerShell -ExecutionPolicy Bypass -File .\scripts\train_url_model.ps1` to download the real benchmark and train.
6. Review `reports\evaluation.json` and `models\README.md`; then run `PowerShell -ExecutionPolicy Bypass -File .\scripts\verify_url_model.ps1`.
7. Rebuild the Flask container with `docker compose up -d --build frontend`.

The real UCI download and full training must run on your Windows machine with internet access. The ZIP does not contain a pre-trained artifact or fabricated metrics. The ML classifier is an additional URL-only signal; existing threat scoring, RAG, Qwen/Nomic, integrations and file workflows remain in place.
