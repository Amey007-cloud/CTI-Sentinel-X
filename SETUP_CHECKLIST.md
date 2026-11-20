# Final Assessment Demonstration Checklist

1. Run `python setup_and_run.py` and confirm MongoDB, FastAPI and Flask containers become healthy.
2. Open `http://localhost:5000` and demonstrate the dashboard, dynamic metrics and platform lifecycle overview.
3. Open Threat Matrix. Filter Windows/Linux/macOS/Android/iOS and each of `ANTICIPATED`, `ACTIVE`, `EVOLVING`, `RESOLVED`.
4. Open a threat card, inspect recommended controls and update its lifecycle state with a reason. Show the audit trail record in MongoDB.
5. Open Investigate. Analyze a safe public indicator or seeded demo entry and show provider correlation and persistent report.
6. Open Knowledge Base and verify platform defensive baseline documents are indexed in MongoDB.
7. Run `python scripts/ingest_sample_data.py`; confirm each document in the multiple-document request has a non-zero chunk count.
8. For real LLM output, configure Ollama or OpenAI. Ask Copilot a platform-specific question and show actual source excerpts/URLs, model provider, embedding provider and latency.
9. Refresh Copilot and demonstrate that the same conversation is restored from MongoDB using its session ID.
10. Optionally run `python agent/scan_host.py` or `python agent/scan_host.py --watch --interval 900`; show the read-only host scan record.
11. Create a remediation plan, approve it and record verification notes. State clearly that the app does not execute commands.
12. Open `http://localhost:8000/docs`; demonstrate `/health`, `/ingest`, `/chat`, `/sessions`, `/metrics`, `/host/scan` and `/remediations`.
13. Show `docker compose ps`, the report library and relevant MongoDB collections/indexes.

Synthetic records are training data, not live threat intelligence. Provider calls require authorized API keys. If no LLM is available, the application explicitly uses offline evidence mode; do not call that an LLM response.
