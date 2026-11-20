from __future__ import annotations

from datetime import datetime, timezone, timedelta
from bson import ObjectId
from database.connection import get_database


def jsonable(value):
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items() if k != "_id"}
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, ObjectId):
        return str(value)
    return value


def stats():
    db = get_database()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=72)
    return {
        "threats": db.threats.count_documents({}),
        "active": db.threats.count_documents({"status": "ACTIVE", "last_seen": {"$gte": cutoff}}),
        "critical": db.threats.count_documents({"threat_level": "CRITICAL"}),
        "high": db.threats.count_documents({"threat_level": "HIGH"}),
        "iocs": db.iocs.count_documents({}),
        "reports": db.reports.count_documents({}) + db.analysis_reports.count_documents({}),
        "sources": db.sources.count_documents({}),
        "misp_matches": db.threat_correlations.count_documents({"source_count": {"$gt": 0}, "sources": "MISP"}),
        "url_intelligence": db.url_intelligence.count_documents({}),
        "ip_intelligence": db.ip_intelligence.count_documents({}),
        "hash_intelligence": db.hash_intelligence.count_documents({}),
        "file_analyses": db.analysis_reports.count_documents({"kind": "file_analysis"}),
        "sandbox_completed": db.sandbox_tasks.count_documents({"status": "completed"}),
    }


def active_threats(limit=12):
    db = get_database()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=72)
    cursor = db.threats.find({"status": "ACTIVE", "last_seen": {"$gte": cutoff}}, {"name":1,"indicator":1,"indicator_type":1,"threat_level":1,"threat_score":1,"classification":1,"sources":1,"last_seen":1}).sort("threat_score", -1).limit(limit)
    return [jsonable(x) for x in cursor]


def threat_distribution():
    db = get_database()
    rows = db.threats.aggregate([{"$group":{"_id":"$threat_level","count":{"$sum":1}}},{"$sort":{"count":-1}}])
    return [{"level": x["_id"] or "UNKNOWN", "count": x["count"]} for x in rows]


def type_distribution():
    db = get_database()
    rows = db.threats.aggregate([{"$group":{"_id":"$indicator_type","count":{"$sum":1}}},{"$sort":{"count":-1}}])
    return [{"type": x["_id"] or "unknown", "count": x["count"]} for x in rows]


def recent_reports(limit=10):
    db = get_database()
    static = list(db.reports.find({}, {"title":1,"source_id":1,"publication_date":1,"sha256":1,"threat_level":1}).sort("publication_date", -1).limit(limit))
    analyses = list(db.analysis_reports.find({}, {"analysis_id":1,"title":1,"indicator":1,"indicator_type":1,"submitted_at":1,"completed_at":1,"threat_level":1,"threat_score":1,"kind":1}).sort("submitted_at", -1).limit(limit))
    rows = []
    for x in static:
        x["kind"] = "security_report"
        x["report_id"] = str(x.get("_id"))
        rows.append(jsonable(x))
    for x in analyses:
        x["kind"] = x.get("kind", "analysis")
        x["report_id"] = str(x.get("_id"))
        x["title"] = x.get("title") or f"Analysis — {x.get('indicator', 'unknown')}"
        x["publication_date"] = x.get("submitted_at")
        rows.append(jsonable(x))
    rows.sort(key=lambda x: x.get("publication_date") or "", reverse=True)
    return rows[:limit]


def all_reports(limit=100, query=""):
    db = get_database()
    static = list(db.reports.find({}, {"title":1,"publication_date":1,"sha256":1,"threat_level":1,"format":1}).sort("publication_date", -1).limit(limit))
    analyses = list(db.analysis_reports.find({}, {"analysis_id":1,"indicator":1,"indicator_type":1,"submitted_at":1,"completed_at":1,"threat_level":1,"threat_score":1,"kind":1,"filename":1}).sort("submitted_at", -1).limit(limit))
    rows = []
    q = query.lower().strip()
    for x in static:
        title = x.get("title", "")
        if q and q not in title.lower() and q not in str(x.get("sha256", "")).lower():
            continue
        x["kind"] = "security_report"; x["report_id"] = str(x.get("_id")); x["publication_date"] = x.get("publication_date")
        rows.append(jsonable(x))
    for x in analyses:
        hay = f"{x.get('indicator','')} {x.get('filename','')}".lower()
        if q and q not in hay:
            continue
        x["report_id"] = str(x.get("_id")); x["title"] = f"Analysis — {x.get('indicator','unknown')}"; x["publication_date"] = x.get("submitted_at")
        rows.append(jsonable(x))
    rows.sort(key=lambda x: x.get("publication_date") or "", reverse=True)
    return rows[:limit]
