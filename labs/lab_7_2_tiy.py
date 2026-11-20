import sys
import argparse
import time
from pathlib import Path
from datetime import datetime, timezone

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from database.connection import get_database

DEFAULT_GITHUB_API = (
    "https://api.github.com/repos/"
    "jacobdjwilson/awesome-annual-security-reports/git/trees/main?recursive=1"
)


def cache_snapshot():
    status = get_database().command("serverStatus")
    cache = status.get("wiredTiger", {}).get("cache", {})
    maximum = cache.get("maximum bytes configured", 0)
    current = cache.get("bytes currently in the cache", 0)
    pages_read = cache.get("pages read into cache", 0)
    pages_requested = cache.get("pages requested from the cache", 0)
    hit_ratio = (
        ((pages_requested - pages_read) / pages_requested * 100)
        if pages_requested else None
    )
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cache_current_bytes": current,
        "cache_max_bytes": maximum,
        "cache_fill_percent": round(current / maximum * 100, 2) if maximum else 0,
        "pages_read_into_cache": pages_read,
        "pages_requested_from_cache": pages_requested,
        "cache_hit_ratio_percent": round(hit_ratio, 2) if hit_ratio is not None else None,
        "bytes_read_into_cache": cache.get("bytes read into cache", 0),
    }


def local_report_keys(db):
    keys = set()
    for report in db.reports.find({}, {"sha256": 1, "filename": 1, "title": 1, "source_url": 1}):
        for field in ("sha256", "filename", "source_url", "title"):
            value = report.get(field)
            if value:
                keys.add(str(value).strip().lower())
    return keys


def browse_new_reports(db, source_url: str, timeout: int = 15):
    """
    Browse the public annual-security-report repository and find
    security report Markdown files that are not represented by the
    local MongoDB report set.

    Only files inside:
        Markdown Conversions/

    are treated as security reports.

    Repository configuration/documentation files such as:
        .github/
        AGENTS.md
        CONTRIBUTING.md
        README.md

    are ignored.
    """

    local = local_report_keys(db)

    try:
        response = requests.get(
            source_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "CTI-Sentinel-Lab7",
            },
            timeout=timeout,
        )

        response.raise_for_status()

        payload = response.json()
        tree = payload.get("tree", [])

        candidates = []

        for item in tree:
            path = str(item.get("path", ""))

            # Only GitHub files, not directories
            if item.get("type") != "blob":
                continue

            # Only Markdown files
            if not path.lower().endswith(".md"):
                continue

            # Only actual converted security reports
            if not path.startswith("Markdown Conversions/"):
                continue

            normalized = path.lower()
            filename = path.rsplit("/", 1)[-1].lower()

            # Skip reports already represented in MongoDB
            if normalized in local or filename in local:
                continue

            candidates.append(path)

        # Sort for deterministic output and limit the display
        # so the terminal is not flooded with hundreds of entries.
        candidates = sorted(set(candidates))

        return candidates[:20], None

    except requests.RequestException as exc:
        return [], f"External report source unavailable: {exc}"


def run(interval=10, cycles=0, source_url=DEFAULT_GITHUB_API):
    db = get_database()
    previous = None
    cycle = 0

    print("=" * 72)
    print("LAB 7.2 TRY-IT-YOURSELF — REPORT + WIREDTIGER CACHE MONITOR")
    print("=" * 72)
    print("Report source:", source_url)
    print("Press Ctrl+C to stop.")

    try:
        while True:
            cycle += 1
            snapshot = cache_snapshot()
            new_reports, source_error = browse_new_reports(db, source_url)

            print(
                f"\n[{snapshot['timestamp']}] "
                f"Cache={snapshot['cache_fill_percent']:.2f}% "
                f"HitRatio={snapshot['cache_hit_ratio_percent']}% "
                f"Current={snapshot['cache_current_bytes']:,} "
                f"ReadInto={snapshot['bytes_read_into_cache']:,}"
            )

            if previous:
                current = snapshot["cache_hit_ratio_percent"]
                old = previous["cache_hit_ratio_percent"]
                delta = None if current is None or old is None else round(current - old, 2)
                print("Hit ratio delta:", delta, "percentage points")

            if source_error:
                print("Report source:", source_error)
            elif new_reports:
                print("New report files not represented in MongoDB:")
                for path in new_reports:
                    print("  +", path)
            else:
                print("No newer/untracked report files detected in the source tree.")

            previous = snapshot
            if cycles and cycle >= cycles:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[STOP] Monitor stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=10)
    parser.add_argument("--cycles", type=int, default=0)
    parser.add_argument("--source-url", default=DEFAULT_GITHUB_API)
    args = parser.parse_args()
    run(args.interval, args.cycles, args.source_url)
