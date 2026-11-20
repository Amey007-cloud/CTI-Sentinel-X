# Security and Safe-Operation Notes

## Secrets and credentials

- Copy `.env.example` to `.env` and change the local MongoDB password and Flask secret before use.
- `.env` is ignored by Git. Never put provider keys in JavaScript, HTML, screenshots, logs or source control.
- The Compose MongoDB root account is a convenient local assessment setup. For a shared/production deployment, create a least-privileged application user and keep administrative credentials out of the app containers.

## AI boundaries

- Retrieved documents are passed as evidence, not trusted instructions. The system prompt explicitly guards against prompt injection in retrieved text.
- The assistant is defensive and evidence-first. It must distinguish retrieved facts from general guidance and disclose gaps.
- A citation is a retrieved source reference, not an endorsement that the source is authoritative or current. Analysts must verify official vendor advisories and affected-version scope.
- The local hashing embedding fallback is labelled and must not be represented as semantic vector embeddings.
- A configured LLM provider may be unavailable; the system clearly labels offline evidence mode rather than fabricating a model response.

## File handling

- The legacy file-analysis feature hashes and inspects uploads. The application does not execute submitted files.
- Cuckoo3 integration is optional and must point to an isolated analysis environment with disposable guests and network controls.
- The knowledge ingestion file endpoint accepts UTF-8 text formats only; do not upload executables or confidential content without authorization.

## Host posture and remediation

- `agent/scan_host.py` performs read-only inventory/configuration checks on the local Windows, Linux or macOS host.
- The scanner sends a limited JSON inventory result to the application. It does not install updates, modify settings or run AI-created commands.
- Remediation approval stores human approval state. Completion records operator-supplied verification notes. No remediation is automatically run by the application.

## Production hardening before external exposure

Add HTTPS/TLS, authentication/SSO, role-based authorization, CSRF protections for browser mutations, per-user quotas, private networking, secrets management, audit retention, backups and restore drills, dependency scanning, container image scanning and a formal change-management integration. The included Compose stack is intended for a local academic demonstration, not direct Internet exposure.
