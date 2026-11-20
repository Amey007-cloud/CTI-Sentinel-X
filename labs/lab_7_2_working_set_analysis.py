import sys
import random
import time
from pathlib import Path
from datetime import datetime, timezone

from bson import BSON

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from database.connection import get_database


COLLECTION_NAME = "lab_7_2_working_set"
DOCUMENT_COUNT = 100_000
TARGET_DOCUMENT_SIZE = 2 * 1024  # approximately 2 KB


def cache_snapshot(db):
    """
    Read WiredTiger cache statistics using MongoDB serverStatus().
    """
    status = db.command("serverStatus")
    wired_tiger = status.get("wiredTiger", {})
    cache = wired_tiger.get("cache", {})

    pages_requested = cache.get("pages requested from the cache", 0)
    pages_read = cache.get("pages read into cache", 0)

    if pages_requested:
        hit_ratio = (
            (pages_requested - pages_read)
            / pages_requested
            * 100
        )
    else:
        hit_ratio = 0.0

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "maximum_bytes_configured": cache.get(
            "maximum bytes configured", 0
        ),
        "bytes_currently_in_cache": cache.get(
            "bytes currently in the cache", 0
        ),
        "cache_fill_percent": round(
            (
                cache.get("bytes currently in the cache", 0)
                / cache.get("maximum bytes configured", 1)
            )
            * 100,
            2
        ),
        "bytes_read_into_cache": cache.get(
            "bytes read into cache", 0
        ),
        "pages_read_into_cache": pages_read,
        "pages_requested_from_cache": pages_requested,
        "cache_hit_ratio_percent": round(hit_ratio, 2),
    }


def create_2kb_document(index):
    """
    Create a document approximately 2 KB in BSON size.
    """
    base_document = {
        "document_id": index,
        "sequence": index,
        "category": "cybersecurity-report",
        "created_at": datetime.now(timezone.utc),
        "description": (
            "Working-set analysis document for MongoDB WiredTiger "
            "cache experimentation. "
        ),
    }

    # Add deterministic padding and adjust until BSON is close to 2 KB.
    target_payload_size = 1800

    base_document["payload"] = "X" * target_payload_size

    return base_document


def measure_document_size(document):
    """
    Measure actual BSON size in bytes.
    """
    return len(BSON.encode(document))


def prepare_working_set(db):
    """
    Create and populate the 100,000-document working-set collection.
    """
    collection = db[COLLECTION_NAME]

    collection.drop()

    print("=" * 72)
    print("LAB 7.2 — WORKING SET ANALYSIS")
    print("=" * 72)

    print(f"Target documents : {DOCUMENT_COUNT:,}")
    print(f"Target size/doc  : approximately {TARGET_DOCUMENT_SIZE:,} bytes")
    print()

    batch = []
    sample_sizes = []

    for index in range(DOCUMENT_COUNT):
        document = create_2kb_document(index)

        if index < 10:
            sample_sizes.append(measure_document_size(document))

        batch.append(document)

        if len(batch) == 1000:
            collection.insert_many(batch, ordered=False)
            batch.clear()

            if (index + 1) % 10_000 == 0:
                print(
                    f"[INSERT] {index + 1:,}/{DOCUMENT_COUNT:,}"
                )

    if batch:
        collection.insert_many(batch, ordered=False)

    collection.create_index("document_id")

    count = collection.count_documents({})

    print()
    print(f"[OK] Documents inserted: {count:,}")

    if sample_sizes:
        average_sample_size = sum(sample_sizes) / len(sample_sizes)

        print(
            f"[OK] Average sampled BSON size: "
            f"{average_sample_size:,.2f} bytes"
        )

    estimated_size_mb = (
        count * TARGET_DOCUMENT_SIZE
    ) / (1024 * 1024)

    print(
        f"[INFO] Approximate logical working set: "
        f"{estimated_size_mb:.2f} MB"
    )

    return collection


def run_random_reads(collection, db, duration_seconds=30):
    """
    Run random reads across the entire 100,000-document collection
    and observe WiredTiger cache metrics.
    """
    print()
    print("=" * 72)
    print("RANDOM READ CACHE OBSERVATION")
    print("=" * 72)

    start_time = time.time()
    read_count = 0
    previous_snapshot = None

    while time.time() - start_time < duration_seconds:

        random_id = random.randint(
            0,
            DOCUMENT_COUNT - 1
        )

        collection.find_one(
            {"document_id": random_id}
        )

        read_count += 1

        # Take a cache snapshot every 5 seconds.
        if read_count % 500 == 0:

            snapshot = cache_snapshot(db)

            print(
                f"[{snapshot['timestamp']}] "
                f"Cache={snapshot['cache_fill_percent']:.2f}% "
                f"HitRatio={snapshot['cache_hit_ratio_percent']:.2f}% "
                f"Reads={read_count:,}"
            )

            if previous_snapshot:
                delta = (
                    snapshot["cache_hit_ratio_percent"]
                    - previous_snapshot[
                        "cache_hit_ratio_percent"
                    ]
                )

                print(
                    f"    Hit ratio delta: "
                    f"{delta:+.2f} percentage points"
                )

            previous_snapshot = snapshot

    print()
    print(
        f"[OK] Random reads completed: {read_count:,}"
    )


def main():
    db = get_database()

    collection = prepare_working_set(db)

    initial_cache = cache_snapshot(db)

    print()
    print("INITIAL WIREDTIGER CACHE")
    print(initial_cache)

    run_random_reads(
        collection,
        db,
        duration_seconds=30
    )

    final_cache = cache_snapshot(db)

    print()
    print("FINAL WIREDTIGER CACHE")
    print(final_cache)

    print()
    print("=" * 72)
    print("LAB 7.2 WORKING SET ANALYSIS COMPLETE")
    print("=" * 72)


if __name__ == "__main__":
    main()