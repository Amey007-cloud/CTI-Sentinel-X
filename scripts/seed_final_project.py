from __future__ import annotations

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from database.connection import get_database


def seed_platform_threats() -> int:
    db = get_database()
    now = datetime.now(timezone.utc)
    examples = [
        {"indicator":"DEMO-WIN-2026-001","indicator_type":"advisory","name":"Windows endpoint hardening gap — demo scenario","platform":"WINDOWS","status":"ACTIVE","threat_level":"HIGH","threat_score":82,"description":"Synthetic training record representing an endpoint with delayed security updates and an exposed remote administration surface. This is not a live CVE or verified campaign.","sources":["CTI Sentinel Demo Dataset"],"recommended_actions":["Confirm Windows build and installed update level against Microsoft Security Response Center guidance.","Restrict remote administration to approved management networks and enforce MFA.","Apply vendor security updates through staged change control and verify patch installation."],"classification":{"tier":1,"tier_name":"Endpoint exposure"},"cves":[],"first_seen":now-timedelta(days=3),"last_seen":now-timedelta(hours=1)},
        {"indicator":"DEMO-LNX-2026-002","indicator_type":"configuration","name":"Linux SSH exposure review — demo scenario","platform":"LINUX","status":"EVOLVING","threat_level":"HIGH","threat_score":76,"description":"Synthetic training record for a Linux fleet where SSH exposure and package support status require reassessment. Not a real vulnerability advisory.","sources":["CTI Sentinel Demo Dataset"],"recommended_actions":["Identify distribution, release, kernel and package versions.","Restrict SSH access, disable password authentication where operationally approved, and review sudo membership.","Compare packages with the distribution security tracker and stage the vendor update."],"classification":{"tier":2,"tier_name":"Configuration drift"},"cves":[],"first_seen":now-timedelta(days=5),"last_seen":now-timedelta(hours=4)},
        {"indicator":"DEMO-MAC-2026-003","indicator_type":"posture","name":"macOS update and FileVault posture — demo scenario","platform":"MACOS","status":"ANTICIPATED","threat_level":"MEDIUM","threat_score":61,"description":"Synthetic anticipated-risk record for devices whose OS build and FileVault posture have not been checked recently.","sources":["CTI Sentinel Demo Dataset"],"recommended_actions":["Inventory exact macOS build and check Apple security releases.","Verify FileVault, firewall and MDM compliance status.","Schedule supported updates and verify device compliance after restart."],"classification":{"tier":3,"tier_name":"Preventive posture"},"cves":[],"first_seen":now-timedelta(days=1),"last_seen":now-timedelta(hours=10)},
        {"indicator":"DEMO-AND-2026-004","indicator_type":"posture","name":"Android security patch review — demo scenario","platform":"ANDROID","status":"ACTIVE","threat_level":"MEDIUM","threat_score":69,"description":"Synthetic training record for an Android device fleet with mixed security patch levels. Exact device model and build must be confirmed.","sources":["CTI Sentinel Demo Dataset"],"recommended_actions":["Capture model, build number and Android security patch level.","Compare the device build with Android Security Bulletin and manufacturer notices.","Apply supported OTA updates and review app permissions and device management posture."],"classification":{"tier":2,"tier_name":"Mobile posture"},"cves":[],"first_seen":now-timedelta(days=4),"last_seen":now-timedelta(hours=2)},
        {"indicator":"DEMO-IOS-2026-005","indicator_type":"posture","name":"iOS configuration profile review — demo scenario","platform":"IOS","status":"RESOLVED","threat_level":"LOW","threat_score":23,"description":"Synthetic resolved training record. A test configuration profile was reviewed and removed through an approved management workflow; retain evidence for audit.","sources":["CTI Sentinel Demo Dataset"],"recommended_actions":["Verify the profile removal on managed devices.","Review MDM compliance and Apple security update status.","Keep the resolution evidence and monitor for recurrence."],"classification":{"tier":4,"tier_name":"Closed with verification"},"cves":[],"first_seen":now-timedelta(days=8),"last_seen":now-timedelta(days=1)},
        {"indicator":"DEMO-ALL-2026-006","indicator_type":"campaign","name":"Cross-platform ransomware readiness exercise","platform":"ALL","status":"EVOLVING","threat_level":"CRITICAL","threat_score":91,"description":"Synthetic tabletop exercise for ransomware readiness across endpoint platforms. This is a scenario, not an observed active campaign.","sources":["CTI Sentinel Demo Dataset"],"recommended_actions":["Validate immutable and offline backups with a restore test.","Confirm endpoint isolation and incident escalation procedures.","Review identity controls, MFA, privileged access and recovery communications."],"classification":{"tier":1,"tier_name":"Enterprise readiness"},"cves":[],"first_seen":now-timedelta(days=2),"last_seen":now-timedelta(minutes=30)},
    ]
    count = 0
    for item in examples:
        item.update({"is_demo": True, "origin": "synthetic_demo", "updated_at": now})
        db.threats.update_one({"indicator": item["indicator"]}, {"$setOnInsert": {**item, "created_at": now}}, upsert=True)
        count += 1
    return count

if __name__ == "__main__":
    print(f"[PASS] Seeded/updated {seed_platform_threats()} platform threat scenarios (synthetic demo data).")
