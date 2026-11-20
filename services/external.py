from __future__ import annotations

import base64
import os
import re
from datetime import datetime, timezone
from typing import Any, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

from database.connection import get_database
from services.scoring import calculate_score, classify_score

VT_BASE = "https://www.virustotal.com/api/v3"
MB_BASE = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_BASE = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1/"
OTX_BASE = "https://otx.alienvault.com/api/v1"
MALPEDIA_BASE = "https://malpedia.caad.fkie.fraunhofer.de/api"
CTI_DIGEST_URL = os.getenv("CTI_DIGEST_URL", "https://ctidigest.com/").strip()
TIMEOUT = int(os.getenv("EXTERNAL_API_TIMEOUT", "15"))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _vt_key() -> str:
    return _env("VIRUSTOTAL_API_KEY")


def _misp_config():
    return _env("MISP_URL").rstrip("/"), _env("MISP_API_KEY"), _env("MISP_VERIFY_SSL").lower() != "false"


def _mb_key() -> str:
    return _env("MALWAREBAZAAR_API_KEY")


def _threatfox_key() -> str:
    return _env("THREATFOX_API_KEY")


def _urlhaus_key() -> str:
    return _env("URLHAUS_API_KEY")


def _otx_key() -> str:
    return _env("OTX_API_KEY")


def _malpedia_key() -> str:
    return _env("MALPEDIA_API_TOKEN")


def _safe_call(name: str, fn: Callable[[], dict]) -> dict:
    try:
        result = fn()
        if not isinstance(result, dict):
            result = {"data": result}
        result.setdefault("source", name)
        result.setdefault("status", "success")
        result.setdefault("error", None)
        return result
    except Exception as exc:
        return {"source": name, "status": "error", "error": str(exc), "match": False, "results": []}


def integration_status() -> dict:
    return {
        "mongodb": {"configured": True, "label": "MongoDB", "description": "Primary CTI data store"},
        "virustotal": {"configured": bool(_vt_key()), "label": "VirusTotal", "description": "URL, IP and hash reputation"},
        "misp": {"configured": bool(_misp_config()[0] and _misp_config()[1]), "label": "MISP", "description": "Threat-intelligence events and correlation"},
        "malwarebazaar": {"configured": bool(_mb_key()), "label": "MalwareBazaar", "description": "Malware hash and family intelligence"},
        "threatfox": {"configured": bool(_threatfox_key()), "label": "ThreatFox", "description": "Malware IOC and C2 intelligence"},
        "urlhaus": {"configured": bool(_urlhaus_key()), "label": "URLhaus", "description": "Malware distribution URL intelligence"},
        "otx": {"configured": bool(_otx_key()), "label": "AlienVault OTX", "description": "Community IOC reputation and pulses"},
        "malpedia": {"configured": bool(_malpedia_key()), "label": "Malpedia", "description": "Malware family and sample metadata"},
        "ctidigest": {"configured": bool(CTI_DIGEST_URL), "label": "CTI Digest", "description": "Open-source CTI news and IOC intelligence"},
        "cuckoo": {"configured": bool(_env("CUCKOO_API_URL")), "label": "Cuckoo3", "description": "Dynamic sandbox analysis"},
        "url_classifier": _url_classifier_status(),
    }


def _url_classifier_status() -> dict:
    try:
        from ml.url_classifier import model_status
        return model_status()
    except Exception:
        return {
            "configured": False, "status": "unavailable",
            "label": "CTI Sentinel URL ML",
            "description": "Optional URL ML classifier is not available; existing CTI analysis is unaffected.",
        }


def _request(method: str, url: str, **kwargs):
    kwargs.setdefault("timeout", TIMEOUT)
    response = requests.request(method, url, **kwargs)
    response.raise_for_status()
    return response


def _vt_headers() -> dict:
    return {"x-apikey": _vt_key(), "accept": "application/json"}


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode().rstrip("=")


def _vt_get(path: str):
    if not _vt_key():
        return None, "VirusTotal API key is not configured."
    try:
        response = _request("GET", f"{VT_BASE}{path}", headers=_vt_headers())
        return response.json(), None
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return None, "Indicator not found in VirusTotal."
        if exc.response is not None and exc.response.status_code == 429:
            return None, "VirusTotal rate limit reached."
        return None, f"VirusTotal HTTP error: {exc}"
    except requests.RequestException as exc:
        return None, f"VirusTotal request failed: {exc}"


def _vt_post(path: str, **kwargs):
    if not _vt_key():
        return None, "VirusTotal API key is not configured."
    try:
        response = _request("POST", f"{VT_BASE}{path}", headers=_vt_headers(), **kwargs)
        return response.json(), None
    except requests.HTTPError as exc:
        return None, f"VirusTotal HTTP error: {exc}"
    except requests.RequestException as exc:
        return None, f"VirusTotal request failed: {exc}"


def _vt_stats(data: dict[str, Any]) -> dict[str, Any]:
    attrs = data.get("data", {}).get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}
    engines = []
    for engine, result in list(results.items())[:40]:
        engines.append({
            "engine": engine,
            "category": result.get("category"),
            "result": result.get("result"),
            "method": result.get("method"),
        })
    return {
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "timeout": int(stats.get("timeout", 0)),
        "total_engines": sum(int(v or 0) for v in stats.values()),
        "reputation": attrs.get("reputation"),
        "country": attrs.get("country"),
        "continent": attrs.get("continent"),
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner"),
        "network": attrs.get("network"),
        "network_location": attrs.get("network_location"),
        "categories": attrs.get("categories", {}),
        "tags": attrs.get("tags", []),
        "title": attrs.get("title"),
        "jarm": attrs.get("jarm"),
        "registrar": attrs.get("registrar"),
        "first_submission_date": attrs.get("first_submission_date"),
        "last_submission_date": attrs.get("last_submission_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "last_analysis_results": engines,
    }


def _vt_wait_analysis(analysis_id: str, timeout: int = 45) -> tuple[dict | None, str | None]:
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        data, error = _vt_get(f"/analyses/{analysis_id}")
        if error:
            return None, error
        status = ((data or {}).get("data", {}).get("attributes", {}) or {}).get("status", "").lower()
        if status in {"completed", "failed"}:
            return data, None if status == "completed" else f"VirusTotal analysis ended with status: {status}"
        time.sleep(2)
    return None, "VirusTotal analysis timed out before completion."


def _vt_scan_url(url: str) -> tuple[dict | None, str | None]:
    body, error = _vt_post("/urls", data={"url": url})
    if error:
        return None, error
    analysis_id = ((body or {}).get("data", {}) or {}).get("id")
    if not analysis_id:
        return None, "VirusTotal did not return an analysis ID for the URL."
    return _vt_wait_analysis(analysis_id)


def _misp_lookup(indicator: str) -> dict:
    base, key, verify = _misp_config()
    if not base or not key:
        return {"configured": False, "match": False, "count": 0, "results": [], "message": "MISP is not configured."}
    try:
        response = _request(
            "POST", f"{base}/attributes/restSearch",
            json={"returnFormat": "json", "value": indicator, "limit": 20},
            headers={"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
            verify=verify,
        )
        body = response.json()
        attrs = body.get("response", {}).get("Attribute", []) or []
        results = []
        for attr in attrs[:20]:
            event = attr.get("Event", {}) or {}
            results.append({
                "event_id": str(attr.get("event_id", event.get("id", ""))),
                "event_info": event.get("info", ""),
                "type": attr.get("type"),
                "category": attr.get("category"),
                "value": attr.get("value"),
                "timestamp": attr.get("timestamp"),
                "tags": attr.get("Tag", []),
            })
        return {"configured": True, "match": bool(results), "count": len(results), "results": results, "message": ""}
    except requests.RequestException as exc:
        return {"configured": True, "match": False, "count": 0, "results": [], "message": f"MISP request failed: {exc}"}


def _malwarebazaar_lookup(file_hash: str) -> dict:
    key = _mb_key()
    if not key:
        return {"configured": False, "match": False, "results": [], "message": "MalwareBazaar Auth-Key is not configured."}
    try:
        response = _request("POST", MB_BASE, data={"query": "get_info", "hash": file_hash.lower()}, headers={"Auth-Key": key})
        body = response.json()
        if body.get("query_status") == "hash_not_found":
            return {"configured": True, "match": False, "results": [], "message": "Hash not found in MalwareBazaar."}
        data = body.get("data", [])
        if isinstance(data, dict):
            data = [data]
        return {"configured": True, "match": bool(data), "results": data[:10], "message": ""}
    except requests.RequestException as exc:
        return {"configured": True, "match": False, "results": [], "message": f"MalwareBazaar request failed: {exc}"}


def _threatfox_lookup(indicator: str, indicator_type: str) -> dict:
    key = _threatfox_key()
    if not key:
        return {"configured": False, "match": False, "results": [], "message": "ThreatFox Auth-Key is not configured."}
    try:
        payload = {"query": "search_ioc", "search_term": indicator, "exact_match": True}
        if indicator_type in {"sha256", "sha1", "md5", "file_hash"}:
            payload = {"query": "search_hash", "hash": indicator}
        response = _request("POST", THREATFOX_BASE, json=payload, headers={"Auth-Key": key, "Content-Type": "application/json"})
        body = response.json()
        data = body.get("data", []) or []
        return {"configured": True, "match": bool(data), "results": data[:20], "message": body.get("query_status", "")}
    except requests.RequestException as exc:
        return {"configured": True, "match": False, "results": [], "message": f"ThreatFox request failed: {exc}"}


def _urlhaus_lookup(url: str) -> dict:
    key = _urlhaus_key()
    if not key:
        return {"configured": False, "match": False, "results": [], "message": "URLhaus Auth-Key is not configured."}
    try:
        response = _request("POST", f"{URLHAUS_BASE}url/", data={"url": url}, headers={"Auth-Key": key})
        body = response.json()
        match = body.get("query_status") not in {"no_results", "invalid_url"} and bool(body.get("id") or body.get("url") or body.get("payloads"))
        return {"configured": True, "match": match, "results": [body] if body else [], "message": body.get("query_status", "")}
    except requests.RequestException as exc:
        return {"configured": True, "match": False, "results": [], "message": f"URLhaus request failed: {exc}"}


def _otx_lookup(indicator: str, indicator_type: str) -> dict:
    key = _otx_key()
    if not key:
        return {"configured": False, "match": False, "results": [], "message": "AlienVault OTX API key is not configured."}
    mapping = {"ip": "IPv4", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file", "file_hash": "file"}
    kind = mapping.get(indicator_type, "domain")
    try:
        response = _request("GET", f"{OTX_BASE}/indicators/{kind}/{indicator}/general", headers={"X-OTX-API-KEY": key})
        body = response.json()
        pulses = body.get("pulse_info", {}).get("pulses", []) or []
        return {"configured": True, "match": bool(pulses), "results": pulses[:20], "pulse_count": len(pulses), "message": ""}
    except requests.RequestException as exc:
        return {"configured": True, "match": False, "results": [], "message": f"OTX request failed: {exc}"}


def _malpedia_lookup(file_hash: str) -> dict:
    key = _malpedia_key()
    if not key or len(file_hash) not in {32, 64}:
        return {"configured": bool(key), "match": False, "results": [], "message": "Malpedia token is not configured or hash format is unsupported."}
    try:
        response = _request("GET", f"{MALPEDIA_BASE}/get/sample/{file_hash}/info", headers={"Authorization": f"apitoken {key}"})
        body = response.json()
        return {"configured": True, "match": bool(body), "results": [body] if body else [], "message": ""}
    except requests.RequestException as exc:
        return {"configured": True, "match": False, "results": [], "message": f"Malpedia request failed: {exc}"}


def _ctidigest_lookup(indicator: str) -> dict:
    # CTI Digest exposes a public web intelligence feed rather than a stable
    # public IOC REST API. We therefore perform a conservative exact-string
    # search against the public page and never fabricate a match.
    if not CTI_DIGEST_URL:
        return {"configured": False, "match": False, "results": [], "message": "CTI Digest URL is not configured."}
    try:
        response = _request("GET", CTI_DIGEST_URL, headers={"User-Agent": "CTI-Sentinel/2.0"})
        text = response.text
        needle = indicator.lower()
        match = needle in text.lower()
        return {
            "configured": True,
            "match": match,
            "results": [{"source": CTI_DIGEST_URL, "exact_string_match": match}] if match else [],
            "message": "Public CTI Digest feed checked." if not match else "Exact indicator text found on CTI Digest public page.",
        }
    except requests.RequestException as exc:
        return {"configured": True, "match": False, "results": [], "message": f"CTI Digest request failed: {exc}"}


def _parallel_sources(specs: dict[str, Callable[[], dict]]) -> dict:
    results = {}
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(specs)))) as pool:
        futures = {pool.submit(fn): name for name, fn in specs.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                results[name] = {"configured": True, "match": False, "results": [], "status": "error", "message": str(exc)}
    return results


def _persist_analysis(collection: str, key: str, document: dict):
    db = get_database()
    value = document.get(key) or document.get("indicator")
    if value is None:
        raise ValueError(f"Cannot persist analysis: missing '{key}' and 'indicator'.")
    doc = dict(document)
    doc[key] = value
    db[collection].update_one({key: value}, {"$set": doc}, upsert=True)


def _persist_correlation(indicator: str, indicator_type: str, sources: dict, score: int):
    db = get_database()
    matched = [name for name, result in sources.items() if result.get("match")]
    db.threat_correlations.update_one(
        {"indicator": indicator},
        {"$set": {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "sources": matched,
            "source_results": sources,
            "source_count": len(matched),
            "confidence": round(min(0.99, 0.40 + len(matched) * 0.08 + score / 500), 3),
            "created_at": now_utc(),
        }},
        upsert=True,
    )


def analyze_url(url: str, deep_scan: bool = False) -> dict:
    db = get_database()
    cached = db.url_intelligence.find_one({"url": url})
    errors = []
    vt, vt_error = _vt_get(f"/urls/{_vt_url_id(url)}")
    if vt_error and "not found" not in vt_error.lower():
        errors.append(vt_error)
    if not vt and deep_scan and _vt_key():
        vt, scan_error = _vt_scan_url(url)
        if scan_error:
            errors.append(scan_error)
        if vt:
            # The scan response is an analysis object; retrieve the final URL report.
            vt, report_error = _vt_get(f"/urls/{_vt_url_id(url)}")
            if report_error:
                errors.append(report_error)

    vt_data = _vt_stats(vt) if vt else {}
    sources = _parallel_sources({
        "VirusTotal": lambda: {"configured": bool(_vt_key()), "match": bool(vt), "results": [vt_data] if vt else [], "message": vt_error or ""},
        "MISP": lambda: _misp_lookup(url),
        "URLhaus": lambda: _urlhaus_lookup(url),
        "ThreatFox": lambda: _threatfox_lookup(url, "url"),
        "OTX": lambda: _otx_lookup(url, "url"),
        "CTI Digest": lambda: _ctidigest_lookup(url),
    })
    matched = [k for k, v in sources.items() if v.get("match")]
    score = calculate_score(
        malicious=vt_data.get("malicious", 0),
        suspicious=vt_data.get("suspicious", 0),
        misp_match=sources["MISP"].get("match", False),
        multi_source=len(matched) >= 2,
    )
    result = {
        "indicator": url, "indicator_type": "url", "mode": "live" if matched else ("cached" if cached else "not_found"),
        "status": "completed", "sources": matched or (["MongoDB"] if cached else []),
        "source_results": sources, "virustotal": vt_data,
        "misp": sources["MISP"], "threat_score": score if matched else int((cached or {}).get("threat_score", 0)),
        "threat_level": classify_score(score if matched else int((cached or {}).get("threat_score", 0))),
        "analyzed_at": now_utc(), "errors": errors,
        "message": "Live multi-source URL intelligence." if matched else "No live provider match was found.",
    }
    # Add the optional URL-only ML layer as a separate signal. Never blend it
    # into the existing provider-derived threat_score, and never let an ML
    # dependency/model failure interrupt the established CTI workflow.
    try:
        from ml.url_classifier import predict_url
        result.update(predict_url(url))
    except Exception:
        result.update({
            "ml_status": "unavailable", "ml_prediction": None,
            "ml_confidence": None, "ml_malicious_probability": None,
            "ml_decision_threshold": None, "ml_model": "cti-sentinel-url-classifier-v1",
            "ml_message": "The optional URL model is unavailable; existing CTI analysis continues unchanged.",
        })

    _persist_analysis("url_intelligence", "url", result)
    _persist_correlation(url, "url", sources, result["threat_score"])
    return result


def analyze_ip(ip: str, refresh: bool = False) -> dict:
    db = get_database()
    cached = db.ip_intelligence.find_one({"ip": ip})
    errors = []
    vt, vt_error = _vt_get(f"/ip_addresses/{ip}")
    if vt_error and "not found" not in vt_error.lower():
        errors.append(vt_error)
    if refresh and _vt_key():
        scan, scan_error = _vt_post(f"/ip_addresses/{ip}/analyse")
        if scan_error:
            errors.append(scan_error)
        elif scan:
            vt, report_error = _vt_get(f"/ip_addresses/{ip}")
            if report_error:
                errors.append(report_error)
    vt_data = _vt_stats(vt) if vt else {}
    sources = _parallel_sources({
        "VirusTotal": lambda: {"configured": bool(_vt_key()), "match": bool(vt), "results": [vt_data] if vt else [], "message": vt_error or ""},
        "MISP": lambda: _misp_lookup(ip),
        "ThreatFox": lambda: _threatfox_lookup(ip, "ip"),
        "OTX": lambda: _otx_lookup(ip, "ip"),
        "CTI Digest": lambda: _ctidigest_lookup(ip),
    })
    matched = [k for k, v in sources.items() if v.get("match")]
    score = calculate_score(
        malicious=vt_data.get("malicious", 0), suspicious=vt_data.get("suspicious", 0),
        misp_match=sources["MISP"].get("match", False), multi_source=len(matched) >= 2,
    )
    result = {
        "indicator": ip, "indicator_type": "ip", "mode": "live" if matched else ("cached" if cached else "not_found"),
        "status": "completed", "sources": matched or (["MongoDB"] if cached else []),
        "source_results": sources, "virustotal": vt_data, "misp": sources["MISP"],
        "threat_score": score if matched else int((cached or {}).get("threat_score", 0)),
        "threat_level": classify_score(score if matched else int((cached or {}).get("threat_score", 0))),
        "analyzed_at": now_utc(), "errors": errors,
        "message": "Live multi-source IP intelligence." if matched else "No live provider match was found.",
    }
    _persist_analysis("ip_intelligence", "ip", result)
    _persist_correlation(ip, "ip", sources, result["threat_score"])
    return result


def analyze_hash(file_hash: str) -> dict:
    db = get_database()
    file_hash = file_hash.lower()
    cached = db.hash_intelligence.find_one({"hash": file_hash})
    mb = _malwarebazaar_lookup(file_hash)
    misp = _misp_lookup(file_hash)
    threatfox = _threatfox_lookup(file_hash, "file_hash")
    otx = _otx_lookup(file_hash, "file_hash")
    malpedia = _malpedia_lookup(file_hash)
    ctidigest = _ctidigest_lookup(file_hash)
    first = mb["results"][0] if mb.get("results") else {}
    sources = _parallel_sources({
        "MalwareBazaar": lambda: mb, "MISP": lambda: misp, "ThreatFox": lambda: threatfox,
        "OTX": lambda: otx, "Malpedia": lambda: malpedia, "CTI Digest": lambda: ctidigest,
    })
    matched = [k for k, v in sources.items() if v.get("match")]
    score = calculate_score(
        misp_match=misp.get("match", False), malwarebazaar_match=mb.get("match", False),
        known_family=bool(first.get("signature")), multi_source=len(matched) >= 2,
    )
    if not matched and cached:
        score = int(cached.get("threat_score", 0))
    result = {
        "indicator": file_hash, "indicator_type": "file_hash", "mode": "live" if matched else ("cached" if cached else "not_found"),
        "status": "completed", "sources": matched or (["MongoDB"] if cached else []),
        "hash": file_hash, "sha256": first.get("sha256_hash") or (file_hash if len(file_hash) == 64 else None),
        "sha1": first.get("sha1_hash") or (file_hash if len(file_hash) == 40 else None),
        "md5": first.get("md5_hash") or (file_hash if len(file_hash) == 32 else None),
        "first_seen": first.get("first_seen"), "last_seen": first.get("last_seen"),
        "file_name": first.get("file_name"), "file_type": first.get("file_type"),
        "file_type_mime": first.get("file_type_mime"), "file_size": first.get("file_size"),
        "signature": first.get("signature"), "tags": first.get("tags", []),
        "source_results": sources, "malwarebazaar": mb, "misp": misp,
        "threat_score": score, "threat_level": classify_score(score), "analyzed_at": now_utc(),
        "file_upload": False, "full_file_analysis": False, "errors": [],
        "message": "Live multi-source hash intelligence." if matched else "No live provider match was found.",
    }
    _persist_analysis("hash_intelligence", "hash", result)
    _persist_correlation(file_hash, "file_hash", sources, score)
    return result
