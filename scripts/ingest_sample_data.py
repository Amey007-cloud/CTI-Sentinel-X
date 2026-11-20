"""Exercise the multi-document ingestion path through the FastAPI endpoint."""
from __future__ import annotations
import os, sys
from pathlib import Path
import requests

BACKEND = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
SAMPLE_DOCS = [
    {"doc_id":"appendix-demo-nosql-v1","title":"NoSQL Database Families","platform":"ALL","origin":"course_sample","content":"NoSQL databases include document, key-value, wide-column and graph families. MongoDB is a document database with flexible BSON documents and aggregation. Key-value stores are often used for caching and session state. Wide-column databases can support high write throughput with query-driven denormalization. Graph databases model entities and their relationships for multi-hop traversal."},
    {"doc_id":"appendix-demo-mongodb-crud-v1","title":"MongoDB CRUD Operations","platform":"ALL","origin":"course_sample","content":"PyMongo insert_one and insert_many create documents. find retrieves documents with filters and projections. Comparison operators include $gt, $lt and $in; logical operators include $or and $and. update_one and update_many modify documents with operators such as $set, $inc and $push. delete_one and delete_many remove selected documents. Indexes should align with the equality, sort and range patterns used by queries."},
    {"doc_id":"appendix-demo-aggregation-v1","title":"MongoDB Aggregation Framework","platform":"ALL","origin":"course_sample","content":"The MongoDB aggregation framework processes documents through pipeline stages. $match filters records, $group computes metrics such as sum and average, $project reshapes output, $unwind expands arrays and $lookup joins related collections. $facet can execute multiple sub-pipelines. Query patterns and compound indexes should be evaluated with explain plans and realistic data volumes."},
    {"doc_id":"appendix-demo-replica-v1","title":"Replica Sets and Failover","platform":"ALL","origin":"course_sample","content":"A MongoDB replica set provides high availability through replication. The primary accepts writes and secondaries replicate the operation log. If a primary becomes unavailable, an election can promote an eligible secondary. Write concern controls acknowledgement and durability expectations; read preference controls read routing. Production operations should include backup verification, restore exercises and monitoring of replication lag."},
    {"doc_id":"appendix-demo-rag-v1","title":"Vector Search and Retrieval Augmented Generation","platform":"ALL","origin":"course_sample","content":"Retrieval augmented generation chunks trusted documents, computes embeddings, stores chunk text and vectors, retrieves relevant evidence for a question and supplies that context to a language model. MongoDB Atlas Vector Search uses a vector index and vectorSearch aggregation stage. A local MongoDB demonstration can use brute-force cosine similarity when Atlas vector search is not available. Responses should cite retrieved source documents and state evidence limitations."},
    {"doc_id":"appendix-demo-security-v1","title":"Threat Intelligence Analyst Decision Rules","platform":"ALL","origin":"course_sample","content":"A threat intelligence analyst should distinguish anticipated, active, evolving and resolved states. A single IOC match is not enough to confirm compromise. Validate indicator freshness, confidence, source provenance, product version and affected asset scope. Prefer official vendor advisories and trusted CERT sources. Stage defensive patches, preserve evidence, document approvals and verify the outcome. Never run unreviewed commands from an AI response."},
]

def main():
    print(f"Sending {len(SAMPLE_DOCS)} documents to {BACKEND}/ingest")
    try:
        response = requests.post(f"{BACKEND}/ingest", json={"documents":SAMPLE_DOCS,"chunk_size":90,"replace_existing":True}, timeout=180)
        response.raise_for_status(); data=response.json()
    except Exception as exc:
        print(f"[ERROR] Ingestion failed: {exc}"); return 1
    print(data.get("message", "Ingestion completed."))
    failures=[]
    for doc in data.get("per_document", []):
        status="PASS" if doc.get("chunks_created", 0)>0 else "FAIL"
        print(f"[{status}] {doc.get('title')}: {doc.get('chunks_created')} chunks")
        if status=="FAIL": failures.append(doc.get("title"))
    if failures:
        print("[ERROR] One or more documents did not produce chunks:", failures); return 2
    print("[PASS] Multi-document ingestion path validated.")
    return 0

if __name__=="__main__": raise SystemExit(main())
