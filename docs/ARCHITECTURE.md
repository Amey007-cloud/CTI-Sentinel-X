# Architecture and Data Model

## Service boundaries

| Service | Responsibility | Persistent state |
|---|---|---|
| Flask web frontend | Existing CTI Sentinel dashboard, IOC/file investigations, report library, knowledge/posture UI and server-side API proxy | Reads/writes CTI collections through PyMongo; proxies AI requests to FastAPI |
| FastAPI assistant | Document ingestion, embeddings, RAG retrieval, LLM calls, message history, posture and remediation APIs | `knowledge_documents`, `knowledge_chunks`, `sessions`, `chat_sessions`, `chat_metrics`, `host_scans`, `remediation_plans`, `audit_events`, `rate_limits` |
| MongoDB | Operational CTI store, knowledge/vector store, conversation memory and audit/metrics store | Named Compose volume |
| Ollama/OpenAI | Optional language and embedding model providers | External/local model service; no API secret is persisted in MongoDB |

## RAG flow

1. An analyst uploads or pastes an approved advisory/runbook.
2. The backend validates the platform, identifies a stable `doc_id`, chunks content into overlapping word windows and computes an embedding for every chunk.
3. `knowledge_documents` stores source metadata and `knowledge_chunks` stores text, vector, source, platform, chunk index and embedding provider.
4. A question is embedded with the same provider. Atlas mode attempts `$vectorSearch`; local mode scores compatible vectors with cosine similarity.
5. The backend adds matching threat records and the most recent conversation messages to a grounded prompt.
6. The selected LLM returns a response; unavailable providers cause a clearly labelled offline evidence response.
7. User and assistant messages are inserted as separate documents in `sessions`, keyed by `session_id` and indexed by timestamp. This avoids unbounded session-document growth.
8. The API returns source title, platform, relevance score, excerpt and source URL to the UI.

## Collections and indexes

| Collection | Purpose | Selected index pattern |
|---|---|---|
| `threats` | Threat records and lifecycle | `(status, threat_level)`, `last_seen`, unique `indicator` |
| `iocs` | Indicator registry | unique `(type, value)`, `threat_level`, `last_seen` |
| `sources` | Provider catalogue | unique `name` |
| `reports`, `analysis_reports` | Static reports and persistent investigations | source/date, indicator/date, status/date |
| `file_samples` | Hash and file metadata | unique SHA-256, SHA-1 and MD5 |
| `knowledge_documents` | Ingested document metadata | unique `doc_id`, `(platform, updated_at)` |
| `knowledge_chunks` | RAG content and embedding vectors | unique `(doc_id, chunk_index)`, `(platform, embedding_provider)` |
| `sessions` | One message per document | `(session_id, timestamp)` |
| `chat_sessions` | Session metadata | unique `session_id`, `last_active` |
| `chat_metrics` | Request latency/provider/retrieval metrics | `timestamp` |
| `host_scans` | Read-only host posture snapshots | `(hostname, scanned_at)` |
| `remediation_plans` | Approval workflow state | `(status, created_at)` |
| `audit_events` | Administrative and analyst events | `timestamp` |
| `rate_limits` | Short-lived request counters | TTL index on `expires_at` |

## Data modelling decisions

- Threats and investigations are independently queryable documents; references such as IOC IDs and source IDs avoid repeatedly embedding large evidence records.
- A small, bounded recent-threat summary is retained in the existing Lab 7 model where appropriate; complete report and IOC evidence remains in referenced collections.
- Chat messages are separate documents to support pagination, retention and indexed chronological retrieval. Session metadata is stored separately.
- Every RAG chunk repeats the minimal source metadata needed for filtering and citations; the authoritative document metadata remains in `knowledge_documents`.
- Synthetic sample records have `is_demo=true` and `origin=synthetic_demo` so they cannot be mistaken for live feed findings.

## Deployment topology and container addressing

The browser uses `localhost:5000`. Flask reaches FastAPI at `backend:8000` using the Compose service name; FastAPI reaches MongoDB at `mongo:27017`. The MongoDB host port is `27018` to reduce collision risk with earlier lab containers. Docker named volumes persist MongoDB data and uploaded report assets.
