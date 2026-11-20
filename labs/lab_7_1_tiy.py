from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import json
from datetime import datetime, timezone

from database.connection import get_database


OUTPUT_DIR = PROJECT_ROOT / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def main():
    db = get_database()

    embedded_design = {
        "name": "Embedded IOC Redesign",
        "classification": {
            "tier": 1,
            "category": "phishing_campaign",
            "confidence": 0.95,
        },
        "iocs": [
            {
                "type": "url",
                "value": "https://phishing.example.test/login",
                "threat_level": "CRITICAL",
            },
            {
                "type": "ip",
                "value": "192.0.2.10",
                "threat_level": "HIGH",
            },
        ],
    }

    original_design = {
        "threat": {
            "ioc_ids": [
                "IOC-URL-001",
                "IOC-IP-001",
            ]
        },
        "iocs": [
            {
                "id": "IOC-URL-001",
                "type": "url",
            },
            {
                "id": "IOC-IP-001",
                "type": "ip",
            },
        ],
    }

    faster = [
        "Get a threat and its small IOC metadata in one document read.",
        "Render a threat detail card without an additional IOC lookup.",
    ]

    harder = [
        "Find every threat containing a specific IOC.",
        "Update one IOC globally when it is duplicated.",
        "Prevent duplicate IOC records across many threats.",
        "Maintain consistency when an IOC classification changes.",
    ]

    payload = {
        "activity": "7.1 Try-It-Yourself",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "redesigned_relationship": "threat -> iocs",
        "original_design": original_design,
        "embedded_design": embedded_design,
        "queries_that_become_faster": faster,
        "queries_that_become_harder": harder,
        "conclusion": (
            "Embedding improves locality for bounded threat-specific "
            "metadata. Referencing remains preferable for reusable, "
            "high-cardinality IOCs."
        ),
    }

    output_file = (
        OUTPUT_DIR
        / "lab_7_1_tiy_embedded_redesign.json"
    )

    output_file.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )

    # Recreate the TIY collection safely.
    if "threats_embedded_tiy" in db.list_collection_names():
        db.threats_embedded_tiy.drop()

    db.create_collection("threats_embedded_tiy")
    db.threats_embedded_tiy.insert_one(
        embedded_design
    )

    print("[OK] Created collection: threats_embedded_tiy")
    print("[OK] Output:", output_file)


if __name__ == "__main__":
    main()
