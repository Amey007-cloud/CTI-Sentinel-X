# Deployment Notes

## Local Docker Compose topology

Compose defines:

- `mongo`: MongoDB 7 with a persistent named volume, bound to `127.0.0.1:27018`, and a health check. It is retained as a separate project-local database service.
- `backend`: FastAPI on port 8000, depends on the Compose MongoDB health check, and serves `/health`.
- `frontend`: Flask/Gunicorn web UI on port 5000, depends on backend health, and uses persistent named volumes for uploads/reports.

### Recovered-data connection routing

This recovered deployment intentionally points both application containers to the existing MongoDB server running on the Windows host (`mongodb://host.docker.internal:27017/`) so that the original coursework data is retained and accessible. The databases are separate:

- Flask frontend: `cti_sentinel`
- FastAPI/RAG backend: `cti_sentinel_final`

The Compose `mongo` service on host port `27018` is **not** the database used by the app containers in this recovery configuration. Do not change these two application connection targets or delete Compose volumes unless you intentionally redesign the database topology. Keep the Windows MongoDB service running while using this configuration.

Internal service routes:
- Flask → FastAPI: `http://backend:8000` (`CHAT_API_URL`)
- Browser → Flask: `http://localhost:5000`
- Windows-host Ollama → API container: `http://host.docker.internal:11434`
- App containers → recovered host MongoDB: `mongodb://host.docker.internal:27017/`

Inside a container, `localhost` refers to that same container. Use `host.docker.internal` to reach the Windows host and Compose DNS names only for container-to-container connections.

## Credentials

Run `python scripts/prepare_env.py` or `python setup_and_run.py` before starting Compose. The helper creates `.env` with local MongoDB Compose and Flask credentials if it does not exist. The app containers in the recovered-data configuration use the host MongoDB without those Compose credentials; the Compose `mongo` service still uses them. Existing `.env` is preserved. Keep this file private and out of source control.

Changing `MONGO_ROOT_PASSWORD` after the Compose MongoDB volume has already been initialized does not rotate the credentials stored in that database. Use a deliberate MongoDB user/password rotation procedure if you need to change an existing deployment.

## Useful commands

```powershell
docker compose ps
docker compose logs -f mongo backend frontend
docker compose restart backend
docker compose stop
```

`docker compose stop` stops containers without deleting persistent data. `docker compose down` preserves named volumes. `docker compose down -v` deletes the project's persistent MongoDB and uploads; avoid it unless intentionally resetting the Compose data. It does not back up the separate Windows-host MongoDB.

## Atlas option

For a deliberate migration to Atlas, update both application connection variables (`MONGO_URI` for backend and frontend) to an authorized Atlas connection string. Configure `VECTOR_SEARCH_MODE=atlas` plus a vector index named by `VECTOR_INDEX_NAME` on `knowledge_chunks.embedding`. Atlas Vector Search needs vector field dimensions to match the configured embedding model. Re-ingest documents after changing embedding model/provider so document and query vectors remain compatible. Do not run two different MongoDB targets unintentionally.
