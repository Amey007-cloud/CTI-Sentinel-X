from __future__ import annotations
import hashlib
from datetime import datetime,timezone
from pathlib import Path
from database.connection import get_database
from database.schema import initialize_database

def main():
    initialize_database(); db=get_database()
    folder=Path(__file__).resolve().parent.parent/"data"/"reports"
    source=db.sources.find_one({"name":"Annual Security Reports"})
    if not source: raise RuntimeError("Run python run.py first.")
    count=0
    for path in folder.glob("*.md"):
        text=path.read_text(encoding="utf-8")
        digest=hashlib.sha256(text.encode()).hexdigest()
        doc={"title":path.stem,"source_id":source["_id"],
             "publication_date":datetime.now(timezone.utc),"format":"markdown",
             "sha256":digest,"threat_level":"INFORMATIONAL",
             "markdown_content":text,"filename":path.name,
             "updated_at":datetime.now(timezone.utc)}
        db.reports.update_one({"sha256":digest},{"$set":doc},upsert=True); count+=1
    print(f"[OK] Ingested {count} Markdown report(s).")

if __name__=="__main__": main()
