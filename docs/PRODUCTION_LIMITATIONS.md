# Production Readiness Boundaries

CTI Sentinel X is designed as a functional local academic assessment system. The following controls are implemented in this project:

- API and UI are separated into Flask and FastAPI services.
- MongoDB collections, indexes and TTL rate-limit index are initialized on startup.
- `.env` holds private credentials; the sample repository ignores `.env`.
- Rate limiting is implemented for chat requests.
- Assistant prompts treat retrieved text as untrusted evidence and prohibit claims of execution.
- Provider failures are isolated or disclosed; offline response mode is labelled.
- Docker health checks, connection pools and graceful MongoDB client close are configured.
- Read-only host scanning and manual approval/verification records are provided.
- Uploaded files are hashed/inspected but never executed by the web application.

Before Internet-facing deployment, add or independently validate:

1. HTTPS/TLS at a trusted reverse proxy and secure internal service transport.
2. Authentication, MFA/SSO, role-based authorization and per-user ownership checks for sessions/reports.
3. CSRF protection for browser-side state-changing actions and strict security headers/CSP.
4. User-specific quotas and rate limiting at the reverse proxy/API gateway, not only source-IP counters.
5. Secret manager/KMS integration, database least-privilege credentials and credential rotation.
6. Network segmentation, restricted MongoDB exposure, private provider egress and firewall policy.
7. Backup schedules, point-in-time recovery where needed, restore drills and retention policies.
8. Dependency and container image vulnerability scans, signed images and software bill of materials.
9. Formal audit retention, operator attribution, change approval and incident-response integration.
10. Load, concurrency, failover, disaster-recovery and security testing on production-like infrastructure.

Do not expose the included local Compose ports or development API documentation publicly without these controls.
