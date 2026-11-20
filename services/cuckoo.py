from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from database.connection import get_database
from services.scoring import classify_score


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _base() -> str:
    return _env("CUCKOO_API_URL").rstrip("/")


def _headers() -> dict:
    token = _env("CUCKOO_API_TOKEN")
    if not token:
        return {}
    scheme = _env("CUCKOO_AUTH_SCHEME", "token")
    return {"Authorization": f"{scheme} {token}"}


def status() -> dict:
    base = _base()
    if not base:
        return {"configured": False, "reachable": False, "message": "CUCKOO_API_URL is not configured."}
    try:
        path = _env("CUCKOO_STATUS_PATH", "/analyses/")
        r = requests.get(f"{base}{path}", headers=_headers(), params={"limit": 1}, timeout=8)
        return {"configured": True, "reachable": r.ok, "http_status": r.status_code, "data": r.json() if r.content else {}, "message": "" if r.ok else r.text[:300]}
    except requests.RequestException as exc:
        return {"configured": True, "reachable": False, "message": str(exc)}


def submit_file(path: Path, metadata: dict, analysis_id: str) -> dict:
    base = _base(); now = datetime.now(timezone.utc)
    if not base:
        return {"status":"not_configured","task_id":None,"analysis_id":analysis_id,"message":"Cuckoo3 is not configured."}
    submit_path = _env("CUCKOO_SUBMIT_PATH", "/submit/file")
    try:
        with path.open("rb") as fh:
            data={}
            settings=_env("CUCKOO_SETTINGS_JSON")
            if settings: data["settings"]=settings
            response=requests.post(
                f"{base}{submit_path}", headers=_headers(),
                files={"file":(metadata["filename"],fh,metadata["mime_type"])},
                data=data, timeout=30,
            )
        response.raise_for_status(); body=response.json(); cuckoo_analysis_id=body.get("analysis_id") or body.get("id")
        task={"status":"submitted" if cuckoo_analysis_id else "failed","task_id":None,"cuckoo_analysis_id":cuckoo_analysis_id,"analysis_id":analysis_id,"submitted_at":now,"message":"" if cuckoo_analysis_id else "Cuckoo3 returned no analysis_id."}
        get_database().sandbox_tasks.update_one({"analysis_id":analysis_id},{"$set":task},upsert=True)
        return task
    except requests.RequestException as exc:
        task={"status":"error","task_id":None,"analysis_id":analysis_id,"submitted_at":now,"message":f"Cuckoo3 submission failed: {exc}"}
        get_database().sandbox_tasks.update_one({"analysis_id":analysis_id},{"$set":task},upsert=True); return task


def _cuckoo3_analysis(analysis_id):
    path=_env("CUCKOO_ANALYSIS_PATH","/analysis/{analysis_id}").replace("{analysis_id}",str(analysis_id))
    r=requests.get(f"{_base()}{path}",headers=_headers(),timeout=15)
    if r.status_code in {404,420}: return None,"not_ready"
    r.raise_for_status(); return r.json(),None


def _cuckoo3_post(analysis_id,task_id):
    path=_env("CUCKOO_POST_PATH","/analysis/{analysis_id}/task/{task_id}/post").replace("{analysis_id}",str(analysis_id)).replace("{task_id}",str(task_id))
    r=requests.get(f"{_base()}{path}",headers=_headers(),timeout=30)
    if r.status_code in {404,420}: return None,"not_ready"
    r.raise_for_status(); return r.json(),None


def _legacy_report(task_id):
    path=_env("CUCKOO_LEGACY_REPORT_PATH","/tasks/report/{task_id}").replace("{task_id}",str(task_id))
    r=requests.get(f"{_base()}{path}",headers=_headers(),timeout=20)
    if r.status_code in {404,420}: return None,"not_ready"
    r.raise_for_status(); return r.json(),None


def _score_behavior(report:dict)->tuple[int,list[str]]:
    signatures=report.get("signatures") or []
    score=min(70,sum(int(s.get("score",1) or 1) for s in signatures if isinstance(s,dict)))
    network=report.get("network") or {}
    if network.get("host") or network.get("hosts") or network.get("dns"): score+=10
    behavior=report.get("behavior") or {}
    processes=behavior.get("processes") or []
    if processes: score+=min(10,len(processes))
    names=[s.get("name") or s.get("description") or "signature" for s in signatures[:30] if isinstance(s,dict)]
    return min(score,100),names


def normalize_report(report:dict)->dict:
    score,names=_score_behavior(report)
    behavior=report.get("behavior") or {}
    network=report.get("network") or {}
    return {
        "raw":report,
        "signatures":report.get("signatures",[])[:50] if isinstance(report.get("signatures"),list) else [],
        "signature_names":names,
        "processes":behavior.get("processes",[])[:100] if isinstance(behavior.get("processes"),list) else [],
        "network":network,
        "dns":network.get("dns",[]),
        "http":network.get("http",[]),
        "hosts":network.get("host",network.get("hosts",[])),
        "files":(behavior.get("summary") or {}).get("files",[]),
        "registry":(behavior.get("summary") or {}).get("keys",[]),
        "score":score,
        "threat_level":classify_score(score),
        "mitre":report.get("ttps",[]),
    }


def poll_worker_once()->int:
    db=get_database(); updated=0
    for task in db.sandbox_tasks.find({"status":{"$in":["submitted","running"]}}).limit(20):
        analysis_id=task.get("cuckoo_analysis_id") or task.get("task_id")
        if not analysis_id: continue
        try:
            # Cuckoo3 native API: /analysis/{analysis_id}, then /task/{task_id}/post.
            analysis,state=_cuckoo3_analysis(analysis_id)
            if analysis:
                state_name=str(analysis.get("state","")).lower()
                tasks=analysis.get("tasks") or []
                task_id=(tasks[0].get("id") if tasks and isinstance(tasks[0],dict) else None)
                if state_name in {"finished","reported","completed"} and task_id:
                    post,post_state=_cuckoo3_post(analysis_id,task_id)
                    if post:
                        normalized=normalize_report(post)
                        db.sandbox_tasks.update_one({"_id":task["_id"]},{"$set":{"status":"completed","task_id":task_id,"completed_at":datetime.now(timezone.utc),"report":normalized}})
                        db.analysis_reports.update_one({"analysis_id":task.get("analysis_id")},{"$set":{"sandbox":{"status":"completed","task_id":task_id,"cuckoo_analysis_id":analysis_id},"behavior":normalized,"mitre_attack":normalized.get("mitre",[]),"sandbox_completed_at":datetime.now(timezone.utc)},"$max":{"threat_score":normalized.get("score",0)}})
                        updated+=1; continue
                db.sandbox_tasks.update_one({"_id":task["_id"]},{"$set":{"status":"running" if state_name not in {"failed","error"} else "error","task_id":task_id,"last_checked_at":datetime.now(timezone.utc),"cuckoo_state":state_name}})
                continue
            # Optional legacy Cuckoo endpoint support.
            legacy_report,legacy_state=_legacy_report(task.get("task_id")) if task.get("task_id") else (None,"not_ready")
            if legacy_report:
                normalized=normalize_report(legacy_report)
                db.sandbox_tasks.update_one({"_id":task["_id"]},{"$set":{"status":"completed","completed_at":datetime.now(timezone.utc),"report":normalized}})
                db.analysis_reports.update_one({"analysis_id":task.get("analysis_id")},{"$set":{"sandbox":{"status":"completed","task_id":task.get("task_id")},"behavior":normalized,"mitre_attack":normalized.get("mitre",[])}})
                updated+=1
        except Exception as exc:
            db.sandbox_tasks.update_one({"_id":task["_id"]},{"$set":{"status":"error","error":str(exc),"last_checked_at":datetime.now(timezone.utc)}})
    return updated

_worker_started=False; _worker_lock=threading.Lock()
def start_worker():
    global _worker_started
    with _worker_lock:
        if _worker_started or not _base(): return
        _worker_started=True
        def loop():
            while True:
                try: poll_worker_once()
                except Exception: pass
                time.sleep(int(_env("CUCKOO_POLL_SECONDS","8")))
        threading.Thread(target=loop,name="cti-cuckoo-worker",daemon=True).start()
