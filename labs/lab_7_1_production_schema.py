from __future__ import annotations

# Supports:
# python labs\lab_7_1_production_schema.py
# python -m labs.lab_7_1_production_schema
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import json
from datetime import datetime, timezone

from database.connection import get_database
from database.schema import initialize_database


OUTPUT_DIR = PROJECT_ROOT / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def analyze_relationships():
    return {
        "embedded": [
            {
                "path": "threats.classification",
                "reason": (
                    "Small bounded metadata belongs directly to the threat "
                    "and is normally read together with it."
                ),
                "embedded_alternative": (
                    "Keep tier, category and confidence in the threat document."
                ),
            },
            {
                "path": "threats.tags",
                "reason": (
                    "Small threat-specific metadata is naturally represented "
                    "as an array inside the threat document."
                ),
                "embedded_alternative": (
                    "Keep tags as an array in the threat document."
                ),
            },
        ],
        "referenced": [
            {
                "path": "threats.ioc_ids -> iocs",
                "reason": (
                    "IOCs are reusable, potentially high-cardinality objects "
                    "that may belong to multiple threats."
                ),
                "embedded_alternative": (
                    "Embed IOC objects in every threat. This improves locality "
                    "but duplicates data and makes global IOC updates harder."
                ),
            },
            {
                "path": "threats.source_ids -> sources",
                "reason": (
                    "Sources are shared across many threats and should not "
                    "be duplicated in every threat."
                ),
                "embedded_alternative": (
                    "Copy source metadata into every threat, increasing "
                    "duplication and update cost."
                ),
            },
            {
                "path": "threats.report_ids -> reports",
                "reason": (
                    "One report can describe many threats and may contain "
                    "larger Markdown content."
                ),
                "embedded_alternative": (
                    "Embed report content into threats, increasing document "
                    "size and duplication."
                ),
            },
        ],
    }


def bson_analysis(db):
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "limit_bytes": 16 * 1024 * 1024,
        "collections": {},
    }

    collection_names = [
        "threats",
        "iocs",
        "sources",
        "reports",
        "misp_events",
        "security_solutions",
    ]

    for name in collection_names:
        pipeline = [
            {
                "$project": {
                    "size_bytes": {
                        "$bsonSize": "$$ROOT"
                    }
                }
            },
            {
                "$group": {
                    "_id": None,
                    "count": {"$sum": 1},
                    "avg": {"$avg": "$size_bytes"},
                    "min": {"$min": "$size_bytes"},
                    "max": {"$max": "$size_bytes"},
                    "near_16mb": {
                        "$sum": {
                            "$cond": [
                                {
                                    "$gte": [
                                        "$size_bytes",
                                        int(15.5 * 1024 * 1024),
                                    ]
                                },
                                1,
                                0,
                            ]
                        }
                    },
                }
            },
        ]

        row = next(db[name].aggregate(pipeline), None)

        if not row:
            result["collections"][name] = {
                "count": 0,
                "average_bytes": 0,
                "min_bytes": 0,
                "max_bytes": 0,
                "near_16mb_count": 0,
                "max_percent_of_limit": 0,
            }
            continue

        max_bytes = row["max"]

        result["collections"][name] = {
            "count": row["count"],
            "average_bytes": round(row["avg"], 2),
            "min_bytes": row["min"],
            "max_bytes": max_bytes,
            "near_16mb_count": row["near_16mb"],
            "max_percent_of_limit": round(
                max_bytes / (16 * 1024 * 1024) * 100,
                4,
            ),
        }

    return result


def main():
    db = initialize_database()

    relationships = analyze_relationships()
    bson = bson_analysis(db)

    passed = all(
        item["max_bytes"] < 16 * 1024 * 1024
        for item in bson["collections"].values()
        if item["count"]
    )

    payload = {
        "lab": "7.1",
        "relationships": relationships,
        "bson_size_analysis": bson,
        "16mb_verification": {
            "passed": passed,
            "rule": (
                "All analyzed documents remain below MongoDB's "
                "16 MiB BSON document limit."
            ),
        },
    }

    output_file = (
        OUTPUT_DIR / "lab_7_1_schema_analysis.json"
    )

    output_file.write_text(
        json.dumps(
            payload,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    print("=" * 72)
    print("LAB 7.1 — PRODUCTION SCHEMA ANALYSIS")
    print("=" * 72)

    print("\nEMBEDDED RELATIONSHIPS")

    for item in relationships["embedded"]:
        print(
            f"  - {item['path']}: "
            f"{item['reason']}"
        )

    print("\nREFERENCED RELATIONSHIPS")

    for item in relationships["referenced"]:
        print(
            f"  - {item['path']}: "
            f"{item['reason']}"
        )

    print("\nBSON SIZE")

    for name, item in bson["collections"].items():
        print(
            f"  {name:22} "
            f"count={item['count']:5} "
            f"avg={item['average_bytes']:10.2f} "
            f"max={item['max_bytes']:10}"
        )

    print(
        "\n[OK] 16 MiB verification:",
        passed,
    )

    print("[OK] Output:", output_file)


if __name__ == "__main__":
    main()
