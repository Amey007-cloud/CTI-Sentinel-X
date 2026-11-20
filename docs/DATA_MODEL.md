# MongoDB Data Model and Query Design

The application keeps the inherited CTI Sentinel collections and adds collections required by the final assessment. Indexes and validators are initialized idempotently by `database/schema.py` and `assistant_api/core.py`.

| Collection | Purpose | Important fields / pattern |
|---|---|---|
| `threats` | Threat intelligence and lifecycle state | `indicator`, `platform`, `status`, `threat_level`, `threat_score`, `sources`, `recommended_actions`; indexes on status/severity, last-seen, tier and unique indicator |
| `iocs` | Normalized indicators | type/value unique key, threat level and last-seen indexes |
| `sources` | Source/provider catalogue | unique provider name |
| `misp_events`, `threat_correlations`, `source_observations` | Cross-source observations/correlation | source IDs, indicators, event metadata |
| `url_intelligence`, `ip_intelligence`, `hash_intelligence` | Typed enrichment records | unique URL/IP/hash |
| `reports`, `analysis_reports`, `analysis_history` | Persistent reports and investigation history | source/date, indicator/date, kind/status and submitted-time indexes |
| `file_samples`, `sandbox_tasks` | File metadata and optional sandbox jobs | unique file hashes and sandbox task IDs |
| `security_solutions` | Defensive controls and recommendations | category and solution identifier |
| `knowledge_documents` | One metadata document per ingested source | unique `doc_id`, title, platform, source URL, origin, content hash, chunk count |
| `knowledge_chunks` | One record per text chunk | `doc_id`, `chunk_index`, source title, platform, text, embedding, embedding provider; unique `(doc_id, chunk_index)` |
| `sessions` | One message per MongoDB document | `session_id`, role, content, timestamp, platform, source citations |
| `chat_sessions` | Small session summary record | unique `session_id`, title, platform, created/last-active, message count |
| `chat_metrics` | Request telemetry | session, latency, provider, retrieval mode, source count and timestamp |
| `host_scans` | Read-only local host inventory snapshots | hostname, platform, OS version, checks and scanned time |
| `remediation_plans` | Human approval / verification workflow | plan ID, status, rationale, steps, approval and completion notes |
| `audit_events` | Append-oriented operational audit | event, actor, timestamp, references and reason |
| `rate_limits` | Short-lived request counters | key, count, expires_at with TTL index |

## Embedded versus referenced records

A session's messages are not stored as an ever-growing array. Each message is an independent document indexed by `(session_id, timestamp)`. This enables chronological pagination, independent retention and multi-instance backend operation without rewriting a large parent document.

A knowledge source is represented by one metadata document and multiple referenced chunk documents. Each chunk repeats the minimal source metadata required for platform filtering and citations. The vector is stored beside the text that it represents.

Threat lifecycle transitions update the current `status` while retaining a bounded 50-entry history in `status_history`. A corresponding separate event is written to `audit_events`. This preserves current-state queries and a durable audit trail.

## Vector retrieval modes

- `VECTOR_SEARCH_MODE=atlas`: calls MongoDB Atlas `$vectorSearch` against an index configured on `knowledge_chunks.embedding`.
- `VECTOR_SEARCH_MODE=local`: loads compatible vectors from MongoDB and ranks them by cosine similarity. This supports local MongoDB containers without an Atlas vector index.
- Embedding provider is stored on every chunk. Retrieval restricts comparison to the matching provider to prevent mixing vectors with incompatible dimensions.
- If Ollama/OpenAI embeddings are unavailable during local demo setup, deterministic feature hashing is used and clearly named `local-hashing-fallback`. It is not semantic model embedding.

## Schema and index principles

- Compound indexes align with common filters and sort patterns.
- Unique indexes prevent duplicate document and indicator keys.
- JSON Schema validators use moderate validation so legacy Lab 7 records can coexist with new fields.
- TTL indexing expires short-lived rate-limit counters automatically.
- Indexes are created idempotently during service startup.
