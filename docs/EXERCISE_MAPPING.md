# Course Concept Traceability

The final-assessment handout explicitly identifies the following exercise groups as inputs to this capstone: Exercise 2 (cloud setup and connection), Exercises 4–6 (queries, aggregation and indexing), Exercise 12 (security and environment variables), Exercise 13 (Docker Compose), Exercise 14 (production monitoring) and Exercise 17 (vector search and RAG). The handout also calls out rate limiting from Exercise 15 in its production-hardening checklist. The mappings below describe where those ideas are applied in CTI Sentinel X.

| Course concept referenced by the final-assessment handout | Implementation in CTI Sentinel X |
|---|---|
| Exercise 2 — cloud setup and connection | `MONGO_URI` supports local Compose MongoDB or an authorized MongoDB Atlas connection; connection ping is exposed through health endpoints. |
| Exercises 4–6 — queries, aggregation and indexing | Filtered threat/IOC queries, dashboard aggregation pipelines, status/platform breakdowns, source/date compound indexes and session-history indexes. |
| Exercise 12 — security and environment variables | API keys and connection settings are environment-driven; `.env` is ignored by Git; no API key is hard-coded. |
| Exercise 13 — containerized deployment | Three-service Docker Compose stack: MongoDB, FastAPI assistant backend and Flask frontend. Service-name addressing avoids the container-localhost issue. |
| Exercise 14 — production monitoring | `/health`, `/api/health`, chat latency/provider metrics, integration status, Docker health checks and operational logs. |
| Exercise 15 — rate limiting | MongoDB-backed per-minute chat request counter with a TTL index to expire short-lived counters. |
| Exercise 17 — vector search and RAG | Multi-document ingestion, word chunking with overlap, embeddings, MongoDB vector persistence, Atlas Vector Search option/local cosine fallback, citations and conversation memory. |

Additional MongoDB concepts retained or applied from the earlier CTI Sentinel labs and the wider course work:

- Schema validation and collection/index initialization in `database/schema.py`.
- CRUD, projections and normalization in the existing indicator, report, IOC and source services.
- Embedded-versus-referenced modelling in the original Lab 7 schema notes and the final knowledge/session data model.
- Aggregation-based analytics for threat lifecycle and platform views.
- Working-set analysis scripts and documentation retained under `labs/`, `lab_7_1/` and `lab_7_2/`.
- Durable conversation memory using individual message documents keyed by `session_id`.
- Multi-database design comparisons from later comparative exercises inform the design rationale, while MongoDB remains the operational database required by this final assessment.

This traceability document intentionally does not invent exercise titles for numbers not expressly identified in the uploaded final-assessment instructions.
