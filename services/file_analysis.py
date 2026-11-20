from __future__ import annotations

import hashlib
import math
import mimetypes
import re
import uuid
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

from services.external import analyze_hash
from services.normalization import document_sha256
from database.connection import get_database

MAGIC = {
    b"MZ": "Windows PE executable",
    b"%PDF": "PDF document",
    b"PK\x03\x04": "ZIP/Office/OpenXML archive",
    b"\x7fELF": "ELF executable",
    b"\xd0\xcf\x11\xe0": "OLE Compound Document",
    b"\xca\xfe\xba\xbe": "Mach-O / Java class signature",
    b"\x50\x4b\x05\x06": "ZIP archive",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)


def _strings(data: bytes, minimum: int = 6, limit: int = 100) -> list[str]:
    found = re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)
    return [x.decode("utf-8", "replace") for x in found[:limit]]


def _magic(data: bytes) -> str:
    for signature, name in MAGIC.items():
        if data.startswith(signature):
            return name
    return "Unknown / generic binary"


def inspect_file(path: Path, original_name: str) -> dict:
    data = path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    mime = mimetypes.guess_type(original_name)[0] or "application/octet-stream"
    return {
        "filename": original_name,
        "size": len(data),
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "mime_type": mime,
        "magic_type": _magic(data[:16]),
        "entropy": _entropy(data),
        "strings": _strings(data),
        "extension": Path(original_name).suffix.lower(),
    }


def create_file_analysis(path: Path, original_name: str, submit_to_sandbox: bool = False) -> dict:
    db = get_database()
    metadata = inspect_file(path, original_name)
    enrichment = analyze_hash(metadata["sha256"])
    analysis_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    report = {
        "analysis_id": analysis_id,
        "kind": "file_analysis",
        "indicator": metadata["sha256"],
        "indicator_type": "file",
        "filename": original_name,
        "status": "completed",
        "submitted_at": now,
        "completed_at": now,
        "file": metadata,
        "cti": enrichment,
        "threat_score": enrichment.get("threat_score", 0),
        "threat_level": enrichment.get("threat_level", "CLEAN"),
        "sources": enrichment.get("sources", []),
        "sandbox": {"status": "not_requested"},
        "behavior": {},
        "mitre_attack": [],
        "errors": enrichment.get("errors", []),
    }
    db.file_samples.update_one({"sha256": metadata["sha256"]}, {"$set": {**metadata, "updated_at": now}}, upsert=True)
    inserted = db.analysis_reports.insert_one(report)
    report["_id"] = inserted.inserted_id
    if submit_to_sandbox:
        from services.cuckoo import submit_file
        task = submit_file(path, metadata, analysis_id)
        db.analysis_reports.update_one({"_id": inserted.inserted_id}, {"$set": {"sandbox": task}})
        report["sandbox"] = task
    return report
