from __future__ import annotations

import os
import sys
import tempfile
import uuid
import requests
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parent
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))

from bson import ObjectId
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

load_dotenv(ROOT/".env")
from database.connection import get_database, ping_database
from database.schema import initialize_database
from services.dashboard import active_threats, all_reports, jsonable, recent_reports, stats, threat_distribution, type_distribution
from services.external import analyze_hash, analyze_ip, analyze_url, integration_status
from services.file_analysis import create_file_analysis
from services.normalization import detect_indicator, normalize_domain, normalize_url, validate_hash
from services.cuckoo import start_worker, status as cuckoo_status

app=Flask(__name__,template_folder="templates",static_folder="static")
app.secret_key=os.getenv("FLASK_SECRET_KEY", "local-dev-only-change-this-secret")
app.config["JSON_SORT_KEYS"]=False
CHAT_API_URL=os.getenv("CHAT_API_URL", "http://localhost:8000").rstrip("/")
app.config["MAX_CONTENT_LENGTH"]=int(os.getenv("MAX_UPLOAD_MB","50"))*1024*1024


def startup():
    initialize_database()
    db=get_database()
    if not db.threats.find_one():
        from scripts.seed_cti_data import seed_demo_data
        seed_demo_data()
    from scripts.seed_final_project import seed_platform_threats
    seed_platform_threats()
    if os.getenv("CUCKOO_API_URL"):
        start_worker()


def _save_report(result:dict, kind:str="indicator_analysis") -> dict:
    db=get_database(); now=datetime.now(timezone.utc)
    report={
        "analysis_id":result.get("analysis_id") or str(uuid.uuid4()),
        "kind":kind,
        "indicator":result.get("indicator",""),
        "indicator_type":result.get("indicator_type","indicator"),
        "title":result.get("title") or f"Analysis — {result.get('indicator','Unknown')}",
        "status":result.get("status","completed"),
        "submitted_at":result.get("submitted_at",now),
        "completed_at":result.get("completed_at",now),
        "threat_score":int(result.get("threat_score",0) or 0),
        "threat_level":result.get("threat_level","UNKNOWN"),
        "sources":result.get("sources",[]),
        "result":result,
        "updated_at":now,
    }
    if kind=="file_analysis":
        report.update({"filename":result.get("filename"),"file":result.get("file",{}),"sandbox":result.get("sandbox",{}),"behavior":result.get("behavior",{}),"mitre_attack":result.get("mitre_attack",[])})
    existing=db.analysis_reports.find_one({"analysis_id":report["analysis_id"]})
    if existing:
        db.analysis_reports.update_one({"_id":existing["_id"]},{"$set":report}); report["_id"]=existing["_id"]
    else:
        report["_id"]=db.analysis_reports.insert_one(report).inserted_id
    return report

@app.get("/")
def dashboard(): return render_template("dashboard.html")
@app.get("/investigate")
def investigate(): return render_template("investigate.html")
@app.get("/threats")
def threats(): return render_template("threats.html")
@app.get("/reports")
def reports(): return render_template("reports.html")
@app.get("/reports/<report_id>")
def report_detail(report_id): return render_template("report_detail.html",report_id=report_id)

@app.get("/api/health")
def api_health():
    return jsonify({"status":"ok" if ping_database() else "error","database":get_database().name,"timestamp":datetime.now(timezone.utc).isoformat(),"cuckoo":cuckoo_status()})

@app.get("/api/dashboard")
def api_dashboard():
    db=get_database()
    return jsonify({"stats":stats(),"threat_distribution":threat_distribution(),"type_distribution":type_distribution(),"active_threats":active_threats(10),"recent_reports":recent_reports(8),"solutions":jsonable(list(db.security_solutions.find({}, {"_id":0}).limit(12))),"integrations":integration_status()})
@app.get("/api/dashboard/stats")
def api_stats(): return jsonify(stats())
@app.get("/api/dashboard/threat-distribution")
def api_threat_distribution(): return jsonify(threat_distribution())
@app.get("/api/dashboard/type-distribution")
def api_type_distribution(): return jsonify(type_distribution())
@app.get("/api/threats/active")
def api_active_threats(): return jsonify(active_threats(50))
@app.get("/api/reports/recent")
def api_recent_reports(): return jsonify(recent_reports(20))
@app.get("/api/reports")
def api_reports(): return jsonify(all_reports(min(int(request.args.get("limit",100)),200),request.args.get("q","")))
@app.get("/api/integrations")
def api_integrations(): return jsonify(integration_status())
@app.get("/api/cuckoo/status")
def api_cuckoo_status(): return jsonify(cuckoo_status())

@app.get("/api/history")
def api_history():
    rows=get_database().analysis_history.find({}, {"_id":0}).sort("timestamp",-1).limit(50)
    return jsonify(jsonable(list(rows)))
@app.get("/api/solutions")
def api_solutions(): return jsonify(jsonable(list(get_database().security_solutions.find({}, {"_id":0}).limit(50))))

@app.post("/api/analyze")
def api_analyze():
    body=request.get_json(silent=True) or {}; value=str(body.get("indicator","")).strip()
    if not value:return jsonify({"error":"Indicator is required."}),400
    indicator_type=detect_indicator(value)
    try:
        if indicator_type=="url": result=analyze_url(normalize_url(value),bool(body.get("deep_scan")))
        elif indicator_type=="ip": result=analyze_ip(value,bool(body.get("refresh")))
        elif indicator_type in {"sha256","sha1","md5"}: result=analyze_hash(validate_hash(value))
        else:
            value=normalize_domain(value); db=get_database(); ioc=db.iocs.find_one({"type":"domain","value":value}); threat=db.threats.find_one({"indicator":value})
            result={"indicator":value,"indicator_type":"domain","mode":"mongodb","status":"completed","threat_level":(threat or {}).get("threat_level","UNKNOWN"),"threat_score":(threat or {}).get("threat_score",0),"sources":["MongoDB"] if threat else [],"ioc":jsonable(ioc) if ioc else None,"threat":jsonable(threat) if threat else None,"message":"Domain correlation is available from MongoDB; configure OTX/MISP/ThreatFox for live enrichment."}
        report=_save_report(result)
        get_database().analysis_history.insert_one({"indicator":value,"indicator_type":indicator_type,"result":result,"sources":result.get("sources",[]),"report_id":report["_id"],"timestamp":datetime.now(timezone.utc)})
        result["report_id"]=str(report["_id"]); result["analysis_id"]=report["analysis_id"]
        return jsonify(jsonable(result))
    except ValueError as exc:return jsonify({"error":str(exc)}),400
    except Exception as exc:
        app.logger.exception("Analysis failed")
        return jsonify({"error":f"Analysis failed safely: {exc}"}),500

@app.post("/api/analyze/file")
def api_analyze_file():
    upload=request.files.get("file")
    if not upload or not upload.filename:return jsonify({"error":"Select a file first."}),400
    filename=secure_filename(upload.filename) or "sample.bin"
    upload_root=ROOT/"data"/"uploads"; upload_root.mkdir(parents=True,exist_ok=True)
    temp_path=upload_root/f"{uuid.uuid4().hex}_{filename}"
    try:
        upload.save(temp_path)
        submit=bool(request.form.get("sandbox","true").lower() in {"1","true","yes","on"})
        report=create_file_analysis(temp_path,filename,submit)
        result=report.copy(); result["report_id"]=str(report["_id"]); result.pop("_id",None)
        get_database().analysis_history.insert_one({"indicator":result["indicator"],"indicator_type":"file","result":result,"sources":result.get("sources",[]),"report_id":report["_id"],"timestamp":datetime.now(timezone.utc)})
        return jsonify(jsonable(result))
    except ValueError as exc:return jsonify({"error":str(exc)}),400
    except Exception as exc:
        app.logger.exception("File analysis failed")
        return jsonify({"error":f"File analysis failed safely: {exc}"}),500
    finally:
        try: temp_path.unlink(missing_ok=True)
        except Exception: pass

@app.get("/api/report/<report_id>")
def api_report(report_id):
    try: oid=ObjectId(report_id)
    except Exception:return jsonify({"error":"Invalid report ID."}),400
    doc=get_database().analysis_reports.find_one({"_id":oid})
    if doc:return jsonify(jsonable(doc))
    doc=get_database().reports.find_one({"_id":oid})
    if doc:return jsonify(jsonable(doc))
    return jsonify({"error":"Report not found."}),404

@app.get("/api/threat/<path:indicator>")
def api_threat(indicator):
    db=get_database(); threat=db.threats.find_one({"indicator":indicator})
    if not threat:return jsonify({"error":"Threat not found."}),404
    solutions=list(db.security_solutions.find({"solution_id":{"$in":threat.get("recommended_solution_ids",[])}},{"_id":0}))
    iocs=list(db.iocs.find({"_id":{"$in":threat.get("ioc_ids",[])}},{"_id":0}))
    return jsonify({"threat":jsonable(threat),"solutions":jsonable(solutions),"iocs":jsonable(iocs)})

@app.post("/api/threat/<path:indicator>/lifecycle")
def update_threat_lifecycle(indicator):
    """Record an analyst-approved lifecycle transition and preserve its audit trail."""
    body=request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error":"JSON body must be an object."}),400
    new_status=str(body.get("status","")).upper().strip()
    reason=str(body.get("reason","")).strip()[:1000]
    allowed={"ANTICIPATED","ACTIVE","EVOLVING","RESOLVED"}
    if new_status not in allowed:
        return jsonify({"error":"Status must be ANTICIPATED, ACTIVE, EVOLVING or RESOLVED."}),400
    if len(reason)<8:
        return jsonify({"error":"Provide an audit reason of at least 8 characters."}),400
    db=get_database()
    threat=db.threats.find_one({"indicator":indicator})
    if not threat:
        return jsonify({"error":"Threat not found."}),404
    previous=str(threat.get("status","UNKNOWN")).upper()
    now=datetime.now(timezone.utc)
    transition={"from":previous,"to":new_status,"reason":reason,"changed_at":now,"actor":"analyst"}
    db.threats.update_one(
        {"_id":threat["_id"]},
        {"$set":{"status":new_status,"status_updated_at":now,"status_note":reason},
         "$push":{"status_history":{"$each":[transition],"$slice":-50}}}
    )
    db.audit_events.insert_one({"event":"threat_lifecycle_transition","indicator":indicator,
                                "from":previous,"to":new_status,"reason":reason,
                                "timestamp":now,"actor":"analyst"})
    return jsonify({"ok":True,"indicator":indicator,"previous_status":previous,
                    "status":new_status,"changed_at":now.isoformat()})

@app.get("/copilot")
def copilot(): return render_template("copilot.html")

@app.get("/knowledge")
def knowledge_page(): return render_template("knowledge.html")

@app.get("/posture")
def posture_page(): return render_template("posture.html")

@app.get("/api/platform-threats")
def api_platform_threats():
    db=get_database(); platform=str(request.args.get("platform","ALL")).upper(); status=str(request.args.get("status","ALL")).upper(); level=str(request.args.get("level","ALL")).upper()
    criteria={}
    if platform not in {"ALL","WINDOWS","LINUX","MACOS","ANDROID","IOS"}: return jsonify({"error":"Unsupported platform."}),400
    if platform!="ALL": criteria["platform"]={"$in":[platform,"ALL"]}
    if status!="ALL": criteria["status"]=status
    if level!="ALL": criteria["threat_level"]=level
    rows=list(db.threats.find(criteria,{"_id":0,"name":1,"indicator":1,"indicator_type":1,"platform":1,"status":1,"threat_level":1,"threat_score":1,"description":1,"sources":1,"recommended_actions":1,"last_seen":1,"is_demo":1}).sort("threat_score",-1).limit(200))
    return jsonify(jsonable(rows))

@app.get("/api/platform-summary")
def api_platform_summary():
    db=get_database()
    rows=list(db.threats.aggregate([{"$group":{"_id":{"platform":"$platform","status":"$status"},"count":{"$sum":1}}}]))
    states=["ANTICIPATED","ACTIVE","EVOLVING","RESOLVED"]
    platforms=["WINDOWS","LINUX","MACOS","ANDROID","IOS"]
    result={p:{s:0 for s in states} for p in platforms+["ALL"]}
    totals={s:0 for s in states}
    all_scope={s:0 for s in states}
    for row in rows:
        key=row.get("_id") or {}; platform=key.get("platform") or "ALL"; status=key.get("status") or "ACTIVE"
        count=int(row.get("count",0))
        if status not in states: continue
        totals[status]+=count
        if platform=="ALL": all_scope[status]+=count
        elif platform in platforms: result[platform][status]+=count
    result["ALL"]=totals
    for platform in platforms:
        for status in states:
            result[platform][status]+=all_scope[status]
    return jsonify(result)

def _proxy_assistant(path, method="GET", payload=None, timeout=90):
    try:
        response=requests.request(method, f"{CHAT_API_URL}/{path.lstrip('/')}", json=payload, timeout=timeout)
        try: body=response.json()
        except ValueError: body={"detail":response.text[:2000]}
        return jsonify(body), response.status_code
    except requests.RequestException as exc:
        return jsonify({"error":f"AI service is not reachable: {exc}","detail":"Check the backend service and CHAT_API_URL."}),503

@app.get("/api/assistant/health")
def assistant_health(): return _proxy_assistant("health", timeout=6)
@app.post("/api/assistant/chat")
def assistant_chat(): return _proxy_assistant("chat", "POST", request.get_json(silent=True) or {}, timeout=120)
@app.post("/api/assistant/ingest")
def assistant_ingest(): return _proxy_assistant("ingest", "POST", request.get_json(silent=True) or {}, timeout=180)
@app.get("/api/assistant/knowledge")
def assistant_knowledge(): return _proxy_assistant("knowledge")
@app.get("/api/assistant/sessions")
def assistant_sessions(): return _proxy_assistant("sessions?limit="+str(request.args.get("limit",30)))
@app.get("/api/assistant/sessions/<session_id>")
def assistant_session(session_id): return _proxy_assistant("sessions/"+quote(session_id,safe=""))
@app.delete("/api/assistant/sessions/<session_id>")
def assistant_delete_session(session_id): return _proxy_assistant("sessions/"+quote(session_id,safe=""),"DELETE")
@app.get("/api/assistant/metrics")
def assistant_metrics(): return _proxy_assistant("metrics")
@app.get("/api/assistant/host-scans")
def assistant_host_scans(): return _proxy_assistant("host/scans/latest")
@app.post("/api/assistant/host-scan")
def assistant_save_host_scan(): return _proxy_assistant("host/scan","POST",request.get_json(silent=True) or {})
@app.get("/api/assistant/remediations")
def assistant_remediations(): return _proxy_assistant("remediations")
@app.post("/api/assistant/remediations")
def assistant_create_remediation(): return _proxy_assistant("remediations","POST",request.get_json(silent=True) or {})
@app.post("/api/assistant/remediations/<plan_id>/approve")
def assistant_approve_remediation(plan_id): return _proxy_assistant("remediations/"+quote(plan_id,safe="")+"/approve","POST",{})
@app.post("/api/assistant/remediations/<plan_id>/complete")
def assistant_complete_remediation(plan_id): return _proxy_assistant("remediations/"+quote(plan_id,safe="")+"/complete","POST",request.get_json(silent=True) or {})

@app.post("/api/assistant/ingest-file")
def assistant_ingest_file():
    upload=request.files.get("file")
    if not upload or not upload.filename: return jsonify({"error":"Select a document first."}),400
    suffix=Path(upload.filename).suffix.lower()
    if suffix not in {".txt",".md",".csv",".json",".log"}: return jsonify({"error":"Supported formats: TXT, MD, CSV, JSON and LOG."}),400
    raw=upload.read(4*1024*1024+1)
    if len(raw)>4*1024*1024: return jsonify({"error":"Document exceeds the 4 MB limit."}),413
    try: content=raw.decode("utf-8-sig")
    except UnicodeDecodeError: return jsonify({"error":"Document must be UTF-8 text."}),400
    payload={"documents":[{"title":request.form.get("title") or upload.filename,"content":content,"platform":request.form.get("platform","ALL"),"source_url":request.form.get("source_url",""),"origin":"analyst_upload"}],"chunk_size":int(request.form.get("chunk_size",220)),"replace_existing":True}
    return _proxy_assistant("ingest","POST",payload,timeout=180)

if __name__=="__main__":
    startup(); app.run(host=os.getenv("FLASK_HOST","127.0.0.1"),port=int(os.getenv("FLASK_PORT","5000")),debug=os.getenv("FLASK_DEBUG","0")=="1")
