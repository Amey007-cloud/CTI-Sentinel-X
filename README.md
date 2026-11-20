# CTI Sentinel X — MongoDB Final Assessment

**Evidence-grounded threat intelligence, platform posture and RAG copilot.**

CTI Sentinel X evolves the Lab 7 CTI Sentinel workbench into the final MongoDB assessment. It provides a responsive analyst dashboard, multi-source IOC investigation, file triage, a platform-specific threat lifecycle matrix, MongoDB-backed knowledge ingestion and retrieval, an LLM/SLM chat copilot, persistent chat memory, read-only host posture monitoring, human-approved remediation records, reporting and a three-service Docker Compose deployment.

> **Academic/demo scope:** demo threat records are explicitly labelled synthetic. Live provider enrichment requires the relevant authorized API credentials. The application can answer from retrieved evidence in a clearly labelled offline mode when an LLM is unavailable; offline mode is not an LLM. Use Ollama or OpenAI for model-backed responses. The included Compose profile is for a local academic demonstration, not direct public-internet deployment.

## 1. Application capabilities

### Operations dashboard
- Live MongoDB-backed counts, charts, active threat queue, platform cards, source integration status and report shortcuts.
- Platform focus: Windows, Linux, macOS, Android and iOS.
- Four lifecycle states: `ANTICIPATED`, `ACTIVE`, `EVOLVING`, `RESOLVED`.

### IOC and file investigation
- URL, IP, domain, MD5, SHA-1 and SHA-256 investigation.
- Optional provider enrichment through VirusTotal, MISP, ThreatFox, URLhaus, AlienVault OTX, MalwareBazaar and Malpedia.
- Provider failures are isolated so one failed source does not cancel the investigation.
- File triage records hashes, file size, MIME/magic type, entropy and printable strings. Uploaded files are not executed.
- Optional Cuckoo3 submission is supported only when a separate isolated sandbox is configured.

### Threat matrix and lifecycle audit
- Filter by platform, lifecycle state and severity; search threat name, indicator and description.
- Inspect evidence and recommended defensive steps.
- Analyst lifecycle transitions persist in MongoDB and append an audit event. A reason is required for every transition.

### Sentinel AI Copilot (RAG)
- FastAPI `/chat`, `/ingest`, `/health`, session, metrics, host scan and remediation endpoints.
- Ingest trusted advisories, incident runbooks and analyst documentation.
- Word-based chunking with overlap, embeddings and per-chunk metadata stored in MongoDB.
- Retrieval uses Atlas Vector Search when configured, otherwise local cosine similarity against stored vectors.
- Ollama or OpenAI can provide LLM responses. Ollama or OpenAI can provide embeddings. If the provider is unreachable, deterministic feature-hash embeddings and an evidence-only response are used and identified as fallbacks; this fallback is not semantic model inference.
- Responses return source title, URL, platform, excerpt and relevance score.
- Messages are separate MongoDB documents keyed by `session_id`, so history survives backend restarts.

### Host posture and remediation workflow
- Optional local scanner for Windows, Linux and macOS.
- One-shot inventory: `python agent/scan_host.py`
- Periodic read-only watch: `python agent/scan_host.py --watch --interval 900`
- The scanner records OS/security posture signals; it does not exploit vulnerabilities, execute AI-generated commands, install updates or change configuration.
- Analysts can draft, approve and record completion evidence for defensive remediation plans. Approval records authorization only; the operator performs the change separately.

### Reports and monitoring
- Persisted analysis reports and investigation history.
- FastAPI health and metrics: provider configuration, document/chunk counts, session counts, request count, average and p95 latency.
- MongoDB indexes for threat, knowledge, session, audit, metric and TTL rate-limit access patterns.
- Docker health checks for MongoDB, API and web services.

## 2. Architecture

```text
Browser ──> Flask Web UI :5000
                 │
                 ├── PyMongo ─────────────┐
                 │                         │
                 └── HTTP proxy ──> FastAPI :8000
                                      │    │
                                      │    ├── Ollama / OpenAI (optional)
                                      │    │
                                      └────┴────> MongoDB :27017
                                                   │
                       CTI operational collections│
                       knowledge_documents         │
                       knowledge_chunks             │
                       sessions / chat_sessions    │
                       chat_metrics / rate_limits  │
                       host_scans / remediation    │
                       audit_events                │
```

Docker Compose starts three services: `mongo`, `backend` and `frontend`. In the recovered local deployment, Flask and FastAPI intentionally connect to the existing Windows-host MongoDB through `host.docker.internal:27017` so the original `cti_sentinel` data remains available. The Compose `mongo` service remains separately available on host port `27018`; it is not the database used by the app containers in this configuration. Flask reaches FastAPI using `CHAT_API_URL=http://backend:8000`; the browser reaches Flask at `http://localhost:5000`. Keep the Windows MongoDB service running while using this recovered-data configuration.

## 3. Quick start on Windows

Requirements: Docker Desktop running; Python 3.11+ for bootstrap/helper scripts; internet access for first image and Python dependency downloads.

1. Open PowerShell in the project root.
2. Create a fresh local `.env` and start the stack:

```powershell
python setup_and_run.py
```

Or:

```powershell
.\start.ps1
```

The bootstrapper creates `.env` with freshly generated local credentials if it does not exist. Existing `.env` files are preserved. Do not share or commit `.env`.

3. Open:
- Web application: http://localhost:5000
- FastAPI / Swagger: http://localhost:8000/docs
- API health: http://localhost:8000/health
- MongoDB host endpoint: `mongodb://localhost:27018`

4. Check service health:

```powershell
docker compose ps
docker compose logs -f backend frontend
```

Stop the stack without deleting data:

```powershell
.\stop.ps1
```

To remove containers but preserve named volumes, `docker compose down` is safe. **Do not use `docker compose down -v` unless you intentionally want to delete the project's persisted database and uploaded data.**

## 4. Configure an actual LLM / SLM

The default model selection is Ollama. Install Ollama on Windows, then open a separate terminal and pull the configured models:

```powershell
ollama pull qwen2.5:3b
ollama pull nomic-embed-text
```

Ensure Ollama is running. The Compose backend defaults to `http://host.docker.internal:11434`, which is the Docker Desktop route to the Windows host. Restart the backend after model setup:

```powershell
docker compose restart backend
```

Alternatively configure OpenAI in `.env`:

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=your-key
OPENAI_MODEL=gpt-4o-mini
EMBEDDING_PROVIDER=openai
OPENAI_EMBED_MODEL=text-embedding-3-small
```

Then run:

```powershell
docker compose up -d --build backend
```

Never put API keys in code, HTML, JavaScript, screenshots or Git. A provider failure is disclosed in the response metadata and results in evidence-only fallback rather than a fabricated model response.

## 5. Validate multi-document RAG ingestion

The API seeds a curated defensive knowledge base at first startup. To exercise the Appendix A multi-document ingestion path, run:

```powershell
python scripts/ingest_sample_data.py
```

The script posts multiple documents in one request and checks that each document produces a non-zero chunk count. This specifically guards against the classic `chunk_text` name-shadowing bug described in the assessment instructions.

Ask the Copilot a platform-specific question (for example: “What exact information should I collect before assessing a Windows security advisory?”). Open the returned source trail and confirm citations match the indexed documents.

## 6. Suggested final-assessment demonstration

Use `SETUP_CHECKLIST.md` and `docs/DEMO_GUIDE.md` as the full walkthrough. Recommended order:

1. Show Docker service health and the MongoDB operational database.
2. Show dashboard totals and the platform lifecycle cards.
3. Filter the Threat Matrix by platform and lifecycle; update one record and show the audit trail.
4. Investigate a safe public IP/domain/hash or use a seeded demo indicator.
5. Ingest the sample documents and show per-document chunk counts.
6. Ask the AI Copilot a platform-specific question; show retrieved evidence, source URLs, provider and latency.
7. Refresh the page and reopen the same chat session to demonstrate MongoDB persistence.
8. Run the optional read-only host scan and show its MongoDB record.
9. Create a remediation plan, approve it and record manually verified completion notes.
10. Show `/docs`, `/health`, MongoDB collections and the report library.

Synthetic records are training data, not live intelligence. Verify vendor bulletins, affected versions and the host's actual asset inventory before taking action.

## 7. Repository layout

```text
CTI_Sentinel_Final_Project/
├── app.py, wsgi.py, run.py
├── assistant_api/       # FastAPI RAG, embeddings, LLM, chat memory, API
├── database/            # MongoDB connection, validators, indexes
├── services/            # CTI providers, file triage, Cuckoo adapter, dashboard
├── templates/ static/   # Responsive Flask UI, styles and interactions
├── agent/               # Read-only Windows/Linux/macOS posture scanner
├── scripts/             # seeding, multi-doc RAG ingestion, environment prep
├── labs/ lab_7_1/ lab_7_2/ # retained Lab 7 evidence and scripts
├── docs/                # architecture, security, exercise mapping, demo guide
├── tests/               # unit tests
├── Dockerfile.api Dockerfile.web docker-compose.yml
└── .env.example
```

## 8. GitHub submission

The assessment requires a **private GitHub repository**. Follow `GITHUB_SUBMISSION.md`. Before pushing, verify `.env`, local uploads, reports and database data are excluded. Add the faculty member as a collaborator during the required remonstration window and submit a PDF containing the private repository URL.

## 9. Security and production limitations

The included stack is a local academic demonstration. Before any external exposure, add HTTPS/TLS, authentication/SSO, role-based access, CSRF protection for browser mutations, user-specific rate limits/quotas, private networking, secrets manager, security headers, audit retention, backups and restore testing, dependency/container scanning and an approved change-management integration. Never expose the development MongoDB listener or FastAPI docs publicly without access controls.

See `docs/SECURITY.md` for additional safe-operation boundaries.


## Optional custom URL intelligence model

CTI Sentinel X now includes a reproducible URL-only ML training pipeline and an optional runtime classifier. It adds a separate model prediction to URL investigations without replacing VirusTotal, MISP, URLhaus, ThreatFox, OTX, CTI Digest, Cuckoo3, the existing threat score, the FastAPI assistant, Qwen2.5 or Nomic embeddings. The custom classifier is intentionally not marked as ready until a real dataset download, training run and held-out evaluation have completed.

See [`docs/URL_ML_CLASSIFIER.md`](docs/URL_ML_CLASSIFIER.md) for dataset acquisition, training, evaluation and Hugging Face publishing steps.


## 4. Optional custom URL ML classifier

CTI Sentinel X includes an independent URL-only machine-learning signal. It uses character n-gram TF-IDF features and compares Logistic Regression with Complement Naive Bayes. It does not replace Qwen2.5 3B, Nomic Embed Text, RAG, external intelligence integrations or the existing rule-based CTI score. If no trained artifact is present, URL investigations continue normally and the ML panel reports `unavailable`.

See [`docs/URL_ML_CLASSIFIER.md`](docs/URL_ML_CLASSIFIER.md) for the reproducible dataset download, preparation, training, evaluation and optional Hugging Face publication workflow. Do not publish raw threat feeds, local database backups, `.env` or model artifacts to GitHub. Review measured holdout metrics and source terms before making the Hugging Face model public.

Build/test state and the remaining Windows acceptance steps are recorded in [`docs/BUILD_AND_TEST_STATUS.md`](docs/BUILD_AND_TEST_STATUS.md).
