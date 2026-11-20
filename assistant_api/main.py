from __future__ import annotations

import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from pymongo import MongoClient, DESCENDING

from assistant_api.core import (
    build_chat_reply, ensure_indexes, json_safe, provider_status,
    upsert_documents, utcnow, PLATFORMS, STATUSES,
)
from assistant_api.seed_knowledge import SEED_DOCUMENTS

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "cti_sentinel_final")
client: Optional[MongoClient] = None

def get_db():
    if client is None:
        raise RuntimeError("MongoDB client is not initialized")
    return client[MONGO_DB]

@asynccontextmanager
async def lifespan(app: FastAPI):
    global client
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000, connectTimeoutMS=8000,
                         maxPoolSize=60, minPoolSize=2, retryWrites=True)
    client.admin.command("ping")
    db = get_db()
    required_fields = {
        "knowledge_documents": ["doc_id", "title", "platform", "content_hash"],
        "knowledge_chunks": ["doc_id", "source_title", "text", "embedding", "embedding_provider"],
        "sessions": ["session_id", "role", "content", "timestamp"],
        "chat_sessions": ["session_id", "created_at", "last_active"],
        "host_scans": ["scan_id", "hostname", "platform", "checks", "scanned_at"],
        "remediation_plans": ["plan_id", "title", "status", "steps", "created_at"],
        "audit_events": ["event", "timestamp", "actor"],
        "rate_limits": ["key", "count", "expires_at"],
    }
    existing = set(db.list_collection_names())
    for name, required in required_fields.items():
        if name not in existing:
            db.create_collection(name, validator={"$jsonSchema": {"bsonType": "object", "required": required, "additionalProperties": True}}, validationLevel="moderate", validationAction="warn")
    ensure_indexes(db)
    if db.knowledge_documents.count_documents({}) == 0:
        result = upsert_documents(db, SEED_DOCUMENTS, chunk_size=180)
        print(f"[CTI AI] Seeded knowledge base: {result}")
    print(f"[CTI AI] Connected to MongoDB database '{MONGO_DB}'")
    yield
    if client is not None:
        client.close()
        client = None

app = FastAPI(
    title="CTI Sentinel Intelligence API",
    description="Evidence-grounded RAG assistant, persistent chat memory, knowledge ingestion and host posture workflow.",
    version="2.0.0",
    lifespan=lifespan,
)

class ChatRequest(BaseModel):
    session_id: Optional[str] = Field(default=None, max_length=80)
    message: str = Field(min_length=2, max_length=6000)
    platform: str = "ALL"
    top_k: int = Field(default=4, ge=1, le=8)

class IngestDocument(BaseModel):
    doc_id: Optional[str] = None
    title: str = Field(min_length=2, max_length=200)
    content: str = Field(min_length=10, max_length=1_000_000)
    platform: str = "ALL"
    source_url: Optional[str] = ""
    origin: Optional[str] = "analyst_ingest"

class IngestRequest(BaseModel):
    documents: list[IngestDocument] = Field(min_length=1, max_length=50)
    chunk_size: int = Field(default=220, ge=40, le=1200)
    replace_existing: bool = True

class HostScanRequest(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = Field(min_length=1, max_length=160)
    platform: str
    os_version: str = "Unknown"
    scanner_version: str = "1.0.0"
    checks: list[dict] = Field(default_factory=list, max_length=100)
    scanned_at: Optional[datetime] = None

class RemediationRequest(BaseModel):
    title: str = Field(min_length=3, max_length=180)
    platform: str = "ALL"
    threat_ref: Optional[str] = ""
    priority: str = "MEDIUM"
    rationale: str = Field(min_length=5, max_length=4000)
    steps: list[str] = Field(min_length=1, max_length=20)

async def _rate_limit(request: Request, db, limit: int = 40):
    key = request.client.host if request.client else "unknown"
    now = utcnow()
    window = now.replace(second=0, microsecond=0)
    record_key = f"chat:{key}:{window.isoformat()}"
    db.rate_limits.update_one(
        {"key": record_key},
        {"$setOnInsert": {"key": record_key, "expires_at": window + timedelta(minutes=2)},
         "$inc": {"count": 1}}, upsert=True,
    )
    current = db.rate_limits.find_one({"key": record_key}, {"count": 1}) or {"count": 0}
    if current.get("count", 0) > limit:
        raise HTTPException(status_code=429, detail="Rate limit reached. Wait one minute and retry.")

@app.get("/health")
async def health():
    try:
        db = get_db()
        db.command("ping")
        return {"status": "healthy", "mongo": "connected", "database": MONGO_DB,
                "knowledge_documents": db.knowledge_documents.count_documents({}),
                "knowledge_chunks": db.knowledge_chunks.count_documents({}),
                "providers": provider_status(), "timestamp": utcnow().isoformat()}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"MongoDB unavailable: {exc}")

@app.post("/chat")
async def chat(payload: ChatRequest, request: Request):
    db = get_db()
    await _rate_limit(request, db)
    platform = payload.platform.upper()
    if platform not in PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unsupported platform. Choose from {sorted(PLATFORMS)}")
    session_id = payload.session_id or str(uuid.uuid4())
    try:
        return json_safe(build_chat_reply(db, session_id, payload.message.strip(), platform, payload.top_k))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Assistant request failed safely: {exc}")

@app.post("/ingest")
async def ingest(payload: IngestRequest):
    db = get_db()
    documents = [item.model_dump() for item in payload.documents]
    for doc in documents:
        doc["platform"] = str(doc.get("platform") or "ALL").upper()
        if doc["platform"] not in PLATFORMS:
            raise HTTPException(status_code=400, detail=f"Invalid platform: {doc['platform']}")
    try:
        result = upsert_documents(db, documents, payload.chunk_size, payload.replace_existing)
        db.audit_events.insert_one({"event": "knowledge_ingest", "details": result,
                                    "timestamp": utcnow(), "actor": "analyst"})
        return {"ok": True, **result, "message": f"Ingested {result['chunks_created']} chunks from {result['documents_processed']} document(s)."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {exc}")

@app.get("/knowledge")
async def knowledge():
    db = get_db()
    rows = list(db.knowledge_documents.find({}, {"_id": 0}).sort("updated_at", DESCENDING).limit(200))
    return {"documents": json_safe(rows), "total": db.knowledge_documents.count_documents({}),
            "chunks": db.knowledge_chunks.count_documents({})}

@app.get("/sessions")
async def sessions(limit: int = 30):
    db = get_db()
    rows = list(db.chat_sessions.find({}, {"_id": 0}).sort("last_active", DESCENDING).limit(max(1, min(limit, 100))))
    return {"sessions": json_safe(rows)}

@app.get("/sessions/{session_id}")
async def session_history(session_id: str, limit: int = 100):
    db = get_db()
    rows = list(db.sessions.find({"session_id": session_id}, {"_id": 0}).sort("timestamp", DESCENDING).limit(max(1, min(limit, 250))))
    rows.reverse()
    return {"session_id": session_id, "messages": json_safe(rows)}

@app.delete("/sessions/{session_id}")
async def delete_session(session_id: str):
    db = get_db()
    db.sessions.delete_many({"session_id": session_id})
    db.chat_sessions.delete_one({"session_id": session_id})
    db.audit_events.insert_one({"event": "chat_session_deleted", "session_id": session_id,
                                "timestamp": utcnow(), "actor": "analyst"})
    return {"ok": True, "session_id": session_id}

@app.get("/metrics")
async def metrics():
    db = get_db()
    since = utcnow() - timedelta(hours=24)
    rows = list(db.chat_metrics.find({"timestamp": {"$gte": since}}, {"latency_ms": 1, "provider": 1, "_id": 0}))
    latency = sorted(float(r.get("latency_ms", 0)) for r in rows)
    p95 = latency[min(len(latency)-1, int(len(latency)*.95))] if latency else 0
    return {"knowledge_documents": db.knowledge_documents.count_documents({}),
            "knowledge_chunks": db.knowledge_chunks.count_documents({}),
            "sessions": db.chat_sessions.count_documents({}), "messages": db.sessions.count_documents({}),
            "host_scans": db.host_scans.count_documents({}), "remediation_plans": db.remediation_plans.count_documents({}),
            "requests_24h": len(rows), "avg_latency_ms": round(sum(latency)/len(latency), 1) if latency else 0,
            "p95_latency_ms": round(p95, 1), "providers": provider_status()}

@app.post("/host/scan")
async def save_host_scan(payload: HostScanRequest):
    db = get_db()
    platform = payload.platform.upper()
    if platform not in PLATFORMS - {"ALL"}:
        raise HTTPException(status_code=400, detail="Unsupported host platform.")
    record = payload.model_dump()
    record["platform"] = platform
    record["scanned_at"] = payload.scanned_at or utcnow()
    record["created_at"] = utcnow()
    db.host_scans.insert_one(record)
    db.audit_events.insert_one({"event": "host_posture_scan", "scan_id": payload.scan_id,
                                "hostname": payload.hostname, "platform": platform,
                                "timestamp": utcnow(), "actor": "local_read_only_agent"})
    return {"ok": True, "scan_id": payload.scan_id, "check_count": len(payload.checks)}

@app.get("/host/scans/latest")
async def latest_host_scans(limit: int = 20):
    db = get_db()
    rows = list(db.host_scans.find({}, {"_id": 0}).sort("scanned_at", DESCENDING).limit(max(1, min(limit, 50))))
    return {"scans": json_safe(rows)}

@app.post("/remediations")
async def create_remediation(payload: RemediationRequest):
    db = get_db()
    platform = payload.platform.upper()
    if platform not in PLATFORMS:
        raise HTTPException(status_code=400, detail="Unsupported platform.")
    record = payload.model_dump()
    record.update({"plan_id": str(uuid.uuid4()), "platform": platform, "status": "PENDING_APPROVAL",
                   "created_at": utcnow(), "approved_at": None, "completed_at": None,
                   "execution_mode": "HUMAN_CONTROLLED_RUNBOOK"})
    result = db.remediation_plans.insert_one(record)
    db.audit_events.insert_one({"event": "remediation_plan_created", "plan_id": record["plan_id"],
                                "timestamp": utcnow(), "actor": "analyst"})
    return {"ok": True, "plan_id": record["plan_id"], "status": record["status"]}

@app.get("/remediations")
async def remediation_list(limit: int = 50):
    db = get_db()
    rows = list(db.remediation_plans.find({}, {"_id": 0}).sort("created_at", DESCENDING).limit(max(1, min(limit, 100))))
    return {"remediations": json_safe(rows)}

@app.post("/remediations/{plan_id}/approve")
async def approve_remediation(plan_id: str):
    db = get_db()
    plan = db.remediation_plans.find_one({"plan_id": plan_id})
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not found.")
    if plan.get("status") not in {"PENDING_APPROVAL", "APPROVED"}:
        raise HTTPException(status_code=409, detail="Only pending plans can be approved.")
    db.remediation_plans.update_one({"plan_id": plan_id}, {"$set": {"status": "APPROVED", "approved_at": utcnow(), "approved_by": "analyst"}})
    db.audit_events.insert_one({"event": "remediation_plan_approved", "plan_id": plan_id, "timestamp": utcnow(), "actor": "analyst"})
    return {"ok": True, "status": "APPROVED", "note": "Approval records human authorization; it does not execute system commands."}

@app.post("/remediations/{plan_id}/complete")
async def complete_remediation(plan_id: str, request: Request):
    body = await request.json()
    notes = str(body.get("notes", "Verified manually by operator."))[:2000]
    db = get_db()
    plan = db.remediation_plans.find_one({"plan_id": plan_id})
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not found.")
    if plan.get("status") != "APPROVED":
        raise HTTPException(status_code=409, detail="Approve the plan before recording completion.")
    db.remediation_plans.update_one({"plan_id": plan_id}, {"$set": {"status": "COMPLETED", "completed_at": utcnow(), "completion_notes": notes}})
    db.audit_events.insert_one({"event": "remediation_plan_completed", "plan_id": plan_id, "timestamp": utcnow(), "actor": "analyst", "notes": notes})
    return {"ok": True, "status": "COMPLETED"}
