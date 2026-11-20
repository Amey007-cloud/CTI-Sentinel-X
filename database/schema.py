from __future__ import annotations

import sys
from pathlib import Path
PROJECT_ROOT=Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path: sys.path.insert(0,str(PROJECT_ROOT))

from pymongo.errors import CollectionInvalid, OperationFailure
from database.connection import get_database

COLLECTIONS=[
    "threats","iocs","sources","reports","misp_events","security_solutions","threat_correlations",
    "url_intelligence","ip_intelligence","hash_intelligence","analysis_history","working_set_docs",
    "analysis_reports","file_samples","sandbox_tasks","source_observations",
    "knowledge_documents","knowledge_chunks","sessions","chat_sessions","chat_metrics",
    "host_scans","remediation_plans","audit_events","rate_limits",
]

def validator(required_fields):
    return {"$jsonSchema":{"bsonType":"object","required":required_fields,"additionalProperties":True}}

VALIDATORS={
    "threats":validator(["name","classification","status"]),
    "iocs":validator(["type","value","threat_level"]),
    "sources":validator(["name","type"]),
    "reports":validator(["title","format","source_id"]),
    "misp_events":validator(["event_id","info"]),
    "security_solutions":validator(["name","category"]),
    "threat_correlations":validator(["indicator","sources"]),
    "url_intelligence":validator(["url"]),
    "ip_intelligence":validator(["ip"]),
    "hash_intelligence":validator(["hash"]),
    "knowledge_documents":validator(["doc_id","title","platform","content_hash"]),
    "knowledge_chunks":validator(["doc_id","source_title","text","embedding","embedding_provider"]),
    "sessions":validator(["session_id","role","content","timestamp"]),
    "chat_sessions":validator(["session_id","created_at","last_active"]),
    "host_scans":validator(["scan_id","hostname","platform","checks","scanned_at"]),
    "remediation_plans":validator(["plan_id","title","status","steps","created_at"]),
    "audit_events":validator(["event","timestamp","actor"]),
    "rate_limits":validator(["key","count","expires_at"]),
    "analysis_reports":validator(["kind","indicator","status"]),
    "file_samples":validator(["sha256","filename"]),
    "sandbox_tasks":validator(["analysis_id","status"]),
}

def create_collection_if_missing(db,name):
    if name in db.list_collection_names(): return
    try:
        kwargs={}
        if name in VALIDATORS: kwargs={"validator":VALIDATORS[name],"validationLevel":"moderate","validationAction":"warn"}
        db.create_collection(name,**kwargs); print(f"[OK] Created collection: {name}")
    except CollectionInvalid: pass

def create_indexes(db):
    specs={
        "threats":[([("status",1),("threat_level",1)],"idx_threat_status_level"),([("last_seen",-1)],"idx_threat_last_seen"),([("classification.tier",1)],"idx_threat_tier"),([("ioc_ids",1)],"idx_threat_iocs"),([("indicator",1)],"uq_threat_indicator",True)],
        "iocs":[([("type",1),("value",1)],"uq_ioc_type_value",True),([("threat_level",1)],"idx_ioc_level"),([("last_seen",-1)],"idx_ioc_last_seen")],
        "sources":[([("name",1)],"uq_source_name",True)],
        "reports":[([("source_id",1)],"idx_report_source"),([("publication_date",-1)],"idx_report_date"),([("sha256",1)],"uq_report_sha256",True)],
        "misp_events":[([("event_id",1)],"uq_misp_event",True),([("attributes.value",1)],"idx_misp_attribute_value")],
        "security_solutions":[([("solution_id",1)],"uq_solution_id",True),([("category",1)],"idx_solution_category")],
        "threat_correlations":[([("indicator",1)],"idx_correlation_indicator"),([("created_at",-1)],"idx_correlation_created")],
        "url_intelligence":[([("url",1)],"uq_url",True)],
        "ip_intelligence":[([("ip",1)],"uq_ip",True)],
        "hash_intelligence":[([("hash",1)],"uq_hash",True)],
        "analysis_history":[([("indicator",1),("timestamp",-1)],"idx_analysis_indicator_time")],
        "analysis_reports":[([("submitted_at",-1)],"idx_analysis_submitted"),([("indicator",1),("submitted_at",-1)],"idx_analysis_indicator"),([("kind",1),("status",1)],"idx_analysis_status")],
        "file_samples":[([("sha256",1)],"uq_file_sha256",True),([("sha1",1)],"idx_file_sha1"),([("md5",1)],"idx_file_md5")],
        "sandbox_tasks":[([("analysis_id",1)],"uq_sandbox_analysis",True),([("status",1)],"idx_sandbox_status")],
        "source_observations":[([("analysis_id",1),("source",1)],"uq_source_observation",True),([("indicator",1)],"idx_source_indicator")],
        "knowledge_documents":[([("doc_id",1)],"uq_knowledge_doc",True),([("platform",1),("updated_at",-1)],"idx_knowledge_platform")],
        "knowledge_chunks":[([("doc_id",1),("chunk_index",1)],"uq_knowledge_chunk",True),([("platform",1),("embedding_provider",1)],"idx_knowledge_platform_provider")],
        "sessions":[([("session_id",1),("timestamp",-1)],"idx_sessions_history")],
        "chat_sessions":[([("session_id",1)],"uq_chat_session",True),([("last_active",-1)],"idx_chat_session_recent")],
        "chat_metrics":[([("timestamp",-1)],"idx_chat_metrics_time")],
        "host_scans":[([("hostname",1),("scanned_at",-1)],"idx_host_scan_recent")],
        "remediation_plans":[([("status",1),("created_at",-1)],"idx_remediation_status")],
        "audit_events":[([("timestamp",-1)],"idx_audit_time")],
        "rate_limits":[([("expires_at",1)],"ttl_rate_limit",False)],
    }
    for collection,items in specs.items():
        for item in items:
            fields,name,*rest=item
            kwargs={"name":name}
            if rest: kwargs["unique"]=rest[0]
            if name == "ttl_rate_limit": kwargs["expireAfterSeconds"] = 0
            try: db[collection].create_index(fields,**kwargs)
            except OperationFailure as exc:
                print(f"[WARN] Index {collection}/{name}: {exc}")

def initialize_database():
    db=get_database()
    for name in COLLECTIONS:create_collection_if_missing(db,name)
    create_indexes(db)
    print("[OK] Database schema and indexes initialized.")
    return db

def main():
    try:
        db=initialize_database(); print(f"[OK] Database ready: {db.name}")
    except OperationFailure as exc:
        print(f"[ERROR] MongoDB operation failed: {exc}"); raise

if __name__=="__main__": main()
