# Final Assessment Demonstration Guide

This is a presenter-oriented walkthrough for a 8–12 minute demonstration. Use the live system output rather than claiming checks that were not run.

## Before the demonstration

1. Start Docker Desktop.
2. From the project root, run `python setup_and_run.py`.
3. Confirm `docker compose ps` shows `mongo`, `backend`, `frontend` as healthy.
4. Open `http://localhost:5000` and `http://localhost:8000/docs`.
5. For model-backed inference, start Ollama on the Windows host and ensure the configured models are present:
   - `qwen2.5:3b`
   - `nomic-embed-text`
6. Confirm the AI health endpoint and inspect the provider name returned for an actual chat request. If the model is not available, the app falls back to offline evidence mode and labels it.

## Demo flow

### 1. Command center
Explain that the dashboard combines existing CTI Sentinel investigation data with platform lifecycle data. Show dashboard metric cards, threat distribution, platform cards, source integration statuses and recent reports. Synthetic records are visibly marked.

### 2. Threat Matrix
Filter the matrix by Windows and `ACTIVE`, then Linux and `EVOLVING`. Open a threat card and inspect its source, severity, score and defensive recommendations. Change its lifecycle state only after entering an audit reason. The API writes both the threat document's bounded `status_history` and a separate audit event.

### 3. IOC / file investigation
Use a safe public test indicator or a known demo entry. Avoid submitting private/internal indicators to external providers without authorization. Explain that provider errors are isolated and each observation is stored. A small harmless text file can demonstrate hashing and static metadata; do not upload malware to the local host. Cuckoo3 is optional and must be isolated.

### 4. Knowledge ingestion and RAG
Open Knowledge Base. The application automatically seeds curated baseline documents if the knowledge database is empty. Run:
```powershell
python scripts/ingest_sample_data.py
```
This sends several documents in one request and verifies non-zero chunk counts per document. The ingestion logic keeps the `chunk_text()` function name distinct from the chunk loop variable, avoiding the multi-document name-shadowing bug described in Appendix A.

### 5. AI Copilot
Select Windows or Linux and ask a question requiring indexed information, such as:
> For a Linux vulnerability triage, which package and platform details should I collect before deciding whether a patch applies?

Show the response provider, embedding provider, latency and retrieved source cards. Click an actual source URL where configured. If the LLM is unavailable, the system displays `offline-evidence-mode` and a deterministic evidence summary; do not describe this as an LLM answer.

### 6. Conversation memory
Refresh Copilot or reopen the page with the same browser profile. The session ID remains in local storage, and messages are read back from MongoDB's `sessions` collection. Start a new conversation to create a separate session.

### 7. Host posture
Run `python agent/scan_host.py` from the host being assessed. The scanner only reads version and defensive posture signals. Optionally run `python agent/scan_host.py --watch --interval 900` to collect periodic snapshots; press Ctrl+C to stop.

### 8. Human-approved remediation
Create a remediation plan from a validated finding. Show the `PENDING_APPROVAL` state, approve it, then record operator verification notes to mark it `COMPLETED`. Explain that the application records authorization and evidence; it does not run commands or modify the host.

### 9. MongoDB / API evidence
Open FastAPI Swagger at `/docs`. Demonstrate `/health`, `/ingest`, `/chat`, `/sessions`, `/metrics`, `/host/scan` and `/remediations`. If asked, show relevant collections:
- `threats`, `iocs`, `reports`, `analysis_reports`
- `knowledge_documents`, `knowledge_chunks`
- `sessions`, `chat_sessions`, `chat_metrics`
- `host_scans`, `remediation_plans`, `audit_events`, `rate_limits`

## Explain the important architectural choices

- MongoDB stores the operational CTI records, RAG document metadata, chunk vectors, conversation memory, monitoring metrics and audit records.
- A chunk and a chat message are separate documents so they can be independently indexed and queried.
- Each message is stored by `session_id` and timestamp; the application does not keep durable conversation history only in process memory.
- Atlas Vector Search is configurable; local mode provides cosine retrieval on compatible stored vectors.
- Docker Compose networking uses `backend` and `mongo` service DNS names, not container-local `localhost`.
- Rate-limit records are automatically deleted by MongoDB TTL index.
- The system is defensive and evidence-first; the scanner and approval workflow do not execute remediation.

## Demonstration honesty

- Demo threat scenarios are synthetic; they are not live CVE alerts.
- Live enrichment is only available for configured providers and the credentials/quotas they require.
- A fallback embedding is feature hashing, not a semantic embedding model.
- Offline evidence mode is not an LLM/SLM response.
- Cuckoo3 requires a separately installed isolated environment.
- Do not claim production internet security controls that are not part of this local assessment build.
