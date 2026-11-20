from __future__ import annotations

# Supports direct execution:
# python scripts\seed_cti_data.py
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timedelta, timezone
from hashlib import sha256

from database.connection import get_database
from database.schema import initialize_database


UTC = timezone.utc


def seed_demo_data():
    db = initialize_database()
    now = datetime.now(UTC)

    sources = [
        {
            "name": "CTI Digest",
            "type": "threat_intelligence_platform",
            "url": "https://ctidigest.com/",
            "description": "Open-source CTI news and IOC source.",
            "active": True,
        },
        {
            "name": "VirusTotal",
            "type": "external_ioc_reputation",
            "url": "https://www.virustotal.com/",
            "description": "URL/IP reputation integration.",
            "active": True,
        },
        {
            "name": "MISP",
            "type": "threat_intelligence_correlation",
            "url": "https://www.misp-project.org/",
            "description": "Threat intelligence events and correlation.",
            "active": True,
        },
        {
            "name": "Abuse.ch MalwareBazaar",
            "type": "hash_intelligence",
            "url": "https://bazaar.abuse.ch/",
            "description": "Hash-based malware intelligence.",
            "active": True,
        },
        {"name":"ThreatFox","type":"malware_ioc_intelligence","url":"https://threatfox.abuse.ch/","description":"Malware IOC and C2 intelligence.","active":True},
        {"name":"URLhaus","type":"malware_url_intelligence","url":"https://urlhaus.abuse.ch/","description":"Malware distribution URL intelligence.","active":True},
        {"name":"AlienVault OTX","type":"community_cti","url":"https://otx.alienvault.com/","description":"Community IOC reputation and pulses.","active":True},
        {"name":"Malpedia","type":"malware_family_intelligence","url":"https://malpedia.caad.fkie.fraunhofer.de/","description":"Malware family and sample metadata.","active":True},
        {"name":"Cuckoo3","type":"dynamic_malware_analysis","url":"https://github.com/cert-ee/cuckoo3","description":"Isolated dynamic sandbox analysis.","active":True},
        {
            "name": "Annual Security Reports",
            "type": "security_reports",
            "url": "https://github.com/jacobdjwilson/awesome-annual-security-reports",
            "description": "Curated annual cybersecurity reports.",
            "active": True,
        },
    ]

    for source in sources:
        db.sources.update_one(
            {"name": source["name"]},
            {"$set": source},
            upsert=True,
        )

    source_ids = {
        source["name"]: db.sources.find_one(
            {"name": source["name"]}
        )["_id"]
        for source in sources
    }

    solutions = [
        {
            "solution_id": "dns-filtering",
            "name": "DNS Filtering",
            "category": "Network Security",
            "protects_against": [
                "Malicious domains",
                "Phishing URLs",
                "C2 infrastructure",
            ],
        },
        {
            "solution_id": "edr",
            "name": "EDR",
            "category": "Endpoint Security",
            "protects_against": [
                "Malware",
                "Ransomware",
                "Malicious hashes",
            ],
        },
        {
            "solution_id": "siem",
            "name": "SIEM",
            "category": "Security Monitoring",
            "protects_against": [
                "Correlated threats",
                "Security events",
                "Threat hunting",
            ],
        },
        {
            "solution_id": "soar",
            "name": "SOAR",
            "category": "Security Automation",
            "protects_against": [
                "Incident response",
                "IOC enrichment",
                "Automated triage",
            ],
        },
        {
            "solution_id": "firewall",
            "name": "Firewall / IP Blocking",
            "category": "Network Security",
            "protects_against": [
                "Malicious IPs",
                "Suspicious connections",
            ],
        },
        {
            "solution_id": "email-security",
            "name": "Email Security",
            "category": "Email Security",
            "protects_against": [
                "Phishing",
                "Malicious links",
                "Credential theft",
            ],
        },
        {
            "solution_id": "xdr",
            "name": "XDR",
            "category": "Extended Detection",
            "protects_against": [
                "Cross-domain threats",
                "Multi-stage campaigns",
            ],
        },
        {
            "solution_id": "threat-intel",
            "name": "Threat Intelligence",
            "category": "Intelligence",
            "protects_against": [
                "IOC discovery",
                "Threat correlation",
                "Threat hunting",
            ],
        },
    ]

    for solution in solutions:
        db.security_solutions.update_one(
            {"solution_id": solution["solution_id"]},
            {"$set": solution},
            upsert=True,
        )

    reports = [
        {
            "title": "CTI Sentinel Demonstration Report — Phishing Campaigns",
            "source_id": source_ids["CTI Digest"],
            "publication_date": now - timedelta(days=1),
            "format": "markdown",
            "sha256": sha256(
                b"cti-sentinel-phishing-demo"
            ).hexdigest(),
            "threat_level": "HIGH",
            "markdown_content": """# Phishing Campaign Demonstration

## Summary

This is a **safe synthetic report** used for MongoDB Lab 7.1.

## Intelligence

- Indicator type: URL
- Classification: Credential theft campaign
- Tier: 1 / top-level campaign
- Status: Active for demonstration

## Defensive recommendations

- DNS filtering
- Email security
- SIEM correlation
- Threat-intelligence monitoring
""",
        },
        {
            "title": "CTI Sentinel Demonstration Report — Malware Hash Intelligence",
            "source_id": source_ids["Annual Security Reports"],
            "publication_date": now - timedelta(days=3),
            "format": "markdown",
            "sha256": sha256(
                b"cti-sentinel-malware-demo"
            ).hexdigest(),
            "threat_level": "CRITICAL",
            "markdown_content": """# Malware Hash Intelligence

## Scope

This report demonstrates hash-only file intelligence.

The dashboard stores the hash and associated metadata rather than uploading or executing files.

## Data model

`SHA256 -> MalwareBazaar/MISP -> MongoDB -> Threat classification`
""",
        },
    ]

    report_ids = []

    for report in reports:
        existing = db.reports.find_one(
            {"sha256": report["sha256"]}
        )

        if existing:
            report_ids.append(existing["_id"])
        else:
            report_ids.append(
                db.reports.insert_one(report).inserted_id
            )

    iocs = [
        {
            "type": "ip",
            "value": "192.0.2.10",
            "threat_level": "HIGH",
            "first_seen": now - timedelta(days=2),
            "last_seen": now - timedelta(hours=4),
            "sources": ["MISP", "VirusTotal"],
            "confidence": 0.91,
        },
        {
            "type": "ip",
            "value": "198.51.100.23",
            "threat_level": "MEDIUM",
            "first_seen": now - timedelta(days=5),
            "last_seen": now - timedelta(hours=30),
            "sources": ["MISP"],
            "confidence": 0.72,
        },
        {
            "type": "url",
            "value": "https://phishing.example.test/login",
            "threat_level": "CRITICAL",
            "first_seen": now - timedelta(days=1),
            "last_seen": now - timedelta(hours=2),
            "sources": ["VirusTotal", "MISP"],
            "confidence": 0.96,
        },
        {
            "type": "domain",
            "value": "malware.example.test",
            "threat_level": "HIGH",
            "first_seen": now - timedelta(days=4),
            "last_seen": now - timedelta(hours=12),
            "sources": ["CTI Digest", "MISP"],
            "confidence": 0.86,
        },
        {
            "type": "sha256",
            "value": "a" * 64,
            "threat_level": "CRITICAL",
            "first_seen": now - timedelta(days=2),
            "last_seen": now - timedelta(hours=1),
            "sources": ["MalwareBazaar", "MISP"],
            "confidence": 0.98,
        },
        {
            "type": "sha256",
            "value": "b" * 64,
            "threat_level": "HIGH",
            "first_seen": now - timedelta(days=7),
            "last_seen": now - timedelta(days=1),
            "sources": ["MalwareBazaar"],
            "confidence": 0.88,
        },
    ]

    for ioc in iocs:
        db.iocs.update_one(
            {
                "type": ioc["type"],
                "value": ioc["value"],
            },
            {"$set": ioc},
            upsert=True,
        )

    threats = [
        (
            "Credential Theft Campaign",
            "https://phishing.example.test/login",
            "url",
            88,
            "CRITICAL",
            1,
            "phishing_campaign",
            ["phishing", "credential-theft", "web"],
            [
                "dns-filtering",
                "email-security",
                "siem",
                "threat-intel",
            ],
            2,
        ),
        (
            "Suspicious Network Infrastructure",
            "192.0.2.10",
            "ip",
            71,
            "HIGH",
            3,
            "malicious_infrastructure",
            ["network", "ip", "command-and-control"],
            [
                "firewall",
                "siem",
                "xdr",
                "threat-intel",
            ],
            4,
        ),
        (
            "Known Malware Hash",
            "a" * 64,
            "sha256",
            96,
            "CRITICAL",
            4,
            "malware_artifact",
            ["malware", "hash", "endpoint"],
            [
                "edr",
                "xdr",
                "siem",
                "threat-intel",
            ],
            1,
        ),
        (
            "Malicious Domain Intelligence",
            "malware.example.test",
            "domain",
            62,
            "HIGH",
            3,
            "malicious_domain",
            ["domain", "web", "network"],
            [
                "dns-filtering",
                "firewall",
                "threat-intel",
            ],
            12,
        ),
        (
            "Previously Observed IP",
            "198.51.100.23",
            "ip",
            43,
            "MEDIUM",
            3,
            "suspicious_infrastructure",
            ["ip", "monitoring"],
            [
                "siem",
                "threat-intel",
            ],
            30,
        ),
        (
            "Historical Malware Hash",
            "b" * 64,
            "sha256",
            58,
            "HIGH",
            4,
            "malware_artifact",
            ["malware", "hash"],
            [
                "edr",
                "siem",
            ],
            720,
        ),
    ]

    tier_names = {
        1: "TOP_LEVEL_THREAT",
        2: "CAMPAIGN_OR_ACTOR",
        3: "INFRASTRUCTURE",
        4: "ARTIFACT",
    }

    for (
        name,
        indicator,
        indicator_type,
        score,
        level,
        tier,
        category,
        tags,
        solution_ids,
        hours_ago,
    ) in threats:
        ioc = db.iocs.find_one(
            {"value": indicator}
        )

        last_seen = now - timedelta(hours=hours_ago)

        document = {
            "name": name,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "description": (
                f"Demonstration threat record for {name}."
            ),
            "classification": {
                "tier": tier,
                "tier_name": tier_names[tier],
                "category": category,
                "confidence": 0.90,
            },
            "tags": tags,
            "source_ids": [
                source_ids["CTI Digest"],
                source_ids["MISP"],
            ],
            "report_ids": report_ids[:1],
            "ioc_ids": (
                [ioc["_id"]]
                if ioc
                else []
            ),
            "threat_score": score,
            "threat_level": level,
            "status": (
                "ACTIVE"
                if hours_ago <= 72
                else "HISTORICAL"
            ),
            "first_seen": now - timedelta(days=7),
            "last_seen": last_seen,
            "recommended_solution_ids": solution_ids,
            "updated_at": now,
        }

        db.threats.update_one(
            {"indicator": indicator},
            {"$set": document},
            upsert=True,
        )

    misp_events = [
        {
            "event_id": "DEMO-1001",
            "info": "Synthetic phishing campaign event for academic demonstration",
            "threat_level": 3,
            "analysis": 2,
            "attributes": [
                {
                    "type": "url",
                    "value": "https://phishing.example.test/login",
                },
                {
                    "type": "ip-dst",
                    "value": "192.0.2.10",
                },
            ],
            "tags": ["phishing", "credential-theft"],
        },
        {
            "event_id": "DEMO-1002",
            "info": "Synthetic malware hash event",
            "threat_level": 4,
            "analysis": 2,
            "attributes": [
                {
                    "type": "sha256",
                    "value": "a" * 64,
                }
            ],
            "tags": ["malware"],
        },
    ]

    for event in misp_events:
        db.misp_events.update_one(
            {"event_id": event["event_id"]},
            {"$set": event},
            upsert=True,
        )

    db.url_intelligence.update_one(
        {"url": "https://phishing.example.test/login"},
        {
            "$set": {
                "url": "https://phishing.example.test/login",
                "source": "Demo/MongoDB",
                "virustotal": {
                    "malicious": 8,
                    "suspicious": 2,
                    "harmless": 50,
                    "undetected": 5,
                },
                "misp": {
                    "configured": False,
                    "match": True,
                    "results": [
                        {"event_id": "DEMO-1001"}
                    ],
                },
                "threat_score": 88,
                "threat_level": "CRITICAL",
                "analyzed_at": now,
            }
        },
        upsert=True,
    )

    db.ip_intelligence.update_one(
        {"ip": "192.0.2.10"},
        {
            "$set": {
                "ip": "192.0.2.10",
                "source": "Demo/MongoDB",
                "virustotal": {
                    "malicious": 7,
                    "suspicious": 2,
                    "harmless": 50,
                    "undetected": 10,
                    "country": "XX",
                    "asn": 64500,
                    "as_owner": "Demo Network",
                },
                "misp": {
                    "configured": False,
                    "match": True,
                    "results": [
                        {"event_id": "DEMO-1001"}
                    ],
                },
                "threat_score": 71,
                "threat_level": "HIGH",
                "analyzed_at": now,
            }
        },
        upsert=True,
    )

    db.hash_intelligence.update_one(
        {"hash": "a" * 64},
        {
            "$set": {
                "hash": "a" * 64,
                "source": "Demo/MongoDB",
                "sha256": "a" * 64,
                "first_seen": (
                    now - timedelta(days=2)
                ).isoformat(),
                "last_seen": (
                    now - timedelta(hours=1)
                ).isoformat(),
                "signature": "DemoRAT",
                "tags": ["malware", "rat"],
                "malwarebazaar": {
                    "match": True,
                    "results": [
                        {"signature": "DemoRAT"}
                    ],
                },
                "misp": {
                    "configured": False,
                    "match": True,
                    "results": [
                        {"event_id": "DEMO-1002"}
                    ],
                },
                "threat_score": 96,
                "threat_level": "CRITICAL",
                "analyzed_at": now,
            }
        },
        upsert=True,
    )


    # Cross-source correlation records used by the dashboard.
    correlations = [
        {
            "indicator": "https://phishing.example.test/login",
            "indicator_type": "url",
            "virustotal_match": True,
            "misp_match": True,
            "malwarebazaar_match": False,
            "sources": ["VirusTotal", "MISP"],
            "confidence": 0.96,
            "created_at": now,
        },
        {
            "indicator": "192.0.2.10",
            "indicator_type": "ip",
            "virustotal_match": True,
            "misp_match": True,
            "malwarebazaar_match": False,
            "sources": ["VirusTotal", "MISP"],
            "confidence": 0.91,
            "created_at": now,
        },
        {
            "indicator": "a" * 64,
            "indicator_type": "sha256",
            "virustotal_match": False,
            "misp_match": True,
            "malwarebazaar_match": True,
            "sources": ["MISP", "MalwareBazaar"],
            "confidence": 0.98,
            "created_at": now,
        },
    ]

    for correlation in correlations:
        db.threat_correlations.update_one(
            {
                "indicator": correlation["indicator"]
            },
            {"$set": correlation},
            upsert=True,
        )

    print("[OK] CTI Sentinel demo data seeded.")


if __name__ == "__main__":
    seed_demo_data()
