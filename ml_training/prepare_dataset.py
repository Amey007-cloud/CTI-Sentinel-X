from __future__ import annotations

import argparse
import json
import re
import ipaddress
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"
PHIUSIIL_FILE = RAW_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
PHISHTANK_FILE = RAW_DIR / "phishtank_online.csv"
URLHAUS_FILE = RAW_DIR / "urlhaus_recent.csv"
OUTPUT_FILE = PROCESSED_DIR / "url_dataset.csv"
MANIFEST_FILE = PROCESSED_DIR / "dataset_manifest.json"


def canonicalize_url(value: object) -> str | None:
    """Canonicalize URL syntax without visiting the URL or changing its path."""
    if value is None or pd.isna(value):
        return None
    raw = re.sub(r"[\x00-\x20\x7f]", "", str(value).strip())
    if not raw or len(raw) > 8192:
        return None
    if raw.startswith("//"):
        raw = "https:" + raw
    elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        if not host:
            return None
        # Preserve path/query case and content, but normalize the scheme and
        # host. Do not discard fragments: URL obfuscation may use them.
        try:
            address = ipaddress.ip_address(host)
            host = address.compressed.lower()
            if address.version == 6:
                host = f"[{host}]"
        except ValueError:
            host = host.encode("idna").decode("ascii").lower()
        port = f":{parts.port}" if parts.port else ""
        userinfo = ""
        if parts.username is not None:
            userinfo = parts.username
            if parts.password is not None:
                userinfo += f":{parts.password}"
            userinfo += "@"
        netloc = f"{userinfo}{host}{port}"
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, parts.fragment))
    except (UnicodeError, ValueError):
        return None


def _read_phiusiil(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=["url", "label", "source", "source_record_id", "collection_timestamp"])
    frame = pd.read_csv(path, low_memory=False)
    columns = {str(column).strip().lower(): column for column in frame.columns}
    if "url" not in columns or "label" not in columns:
        raise ValueError("PhiUSIIL CSV must contain URL and Label columns.")
    raw_labels = pd.to_numeric(frame[columns["label"]], errors="coerce")
    # UCI's documented mapping: 1=legitimate and 0=phishing. Our canonical
    # binary mapping is 0=BENIGN and 1=MALICIOUS.
    labels = raw_labels.map({1: 0, 0: 1})
    result = pd.DataFrame({
        "url": frame[columns["url"]],
        "label": labels,
        "source": "PhiUSIIL-UCI",
        "source_record_id": range(1, len(frame) + 1),
        "collection_timestamp": "",
    })
    return result.dropna(subset=["label"])


def _read_phishtank(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=["url", "label", "source", "source_record_id", "collection_timestamp"])
    frame = pd.read_csv(path, low_memory=False)
    columns = {str(column).strip().lower(): column for column in frame.columns}
    if "url" not in columns:
        raise ValueError("PhishTank CSV does not contain a url column.")
    if "verified" in columns:
        frame = frame[frame[columns["verified"]].astype(str).str.lower().eq("yes")]
    if "online" in columns:
        frame = frame[frame[columns["online"]].astype(str).str.lower().eq("yes")]
    record_id = frame[columns["phish_id"]] if "phish_id" in columns else range(1, len(frame) + 1)
    timestamp = frame[columns["verification_time"]] if "verification_time" in columns else ""
    return pd.DataFrame({
        "url": frame[columns["url"]], "label": 1, "source": "PhishTank",
        "source_record_id": record_id, "collection_timestamp": timestamp,
    })


def _read_urlhaus(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=["url", "label", "source", "source_record_id", "collection_timestamp"])
    frame = pd.read_csv(path, comment="#", low_memory=False, on_bad_lines="skip")
    columns = {str(column).strip().lower(): column for column in frame.columns}
    if "url" not in columns:
        raise ValueError("URLhaus CSV does not contain a url column.")
    record_id = frame[columns["id"]] if "id" in columns else range(1, len(frame) + 1)
    timestamp = frame[columns["dateadded"]] if "dateadded" in columns else ""
    if "url_status" in columns:
        # Preserve the provider's active/recent sample; both are malicious
        # observations in the exported URLhaus feed.
        valid = frame[columns["url_status"]].astype(str).str.lower().isin({"online", "offline"})
        frame = frame[valid]
        record_id = frame[columns["id"]] if "id" in columns else range(1, len(frame) + 1)
        timestamp = frame[columns["dateadded"]] if "dateadded" in columns else ""
    return pd.DataFrame({
        "url": frame[columns["url"]], "label": 1, "source": "URLhaus",
        "source_record_id": record_id, "collection_timestamp": timestamp,
    })


def prepare_dataset() -> dict:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    frames = [
        _read_phiusiil(PHIUSIIL_FILE),
        _read_phishtank(PHISHTANK_FILE),
        _read_urlhaus(URLHAUS_FILE),
    ]
    frames = [frame for frame in frames if not frame.empty]
    if not frames:
        raise FileNotFoundError("No supported raw dataset was found. Run python -m ml_training.download_datasets first.")

    data = pd.concat(frames, ignore_index=True)
    source_row_counts = {str(name): int(count) for name, count in data.groupby("source").size().items()}
    data["url"] = data["url"].map(canonicalize_url)
    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    data = data.dropna(subset=["url", "label"])
    data = data[data["label"].isin([0, 1])].copy()
    data["label"] = data["label"].astype("int8")
    before_dedup = int(len(data))

    # Conflicting labels are excluded rather than silently allowing one source
    # to overwrite another. This is especially important when a formerly
    # benign dataset URL later appears in a live malicious feed.
    unique_label_count = data.groupby("url")["label"].nunique()
    conflicting_urls = set(unique_label_count[unique_label_count > 1].index)
    conflict_rows = int(data["url"].isin(conflicting_urls).sum())
    data = data[~data["url"].isin(conflicting_urls)].copy()
    data["source_record_id"] = data["source_record_id"].astype(str)
    data = data.groupby(["url", "label"], as_index=False, sort=False).agg({
        "source": lambda values: ";".join(sorted(set(str(value) for value in values if str(value)))),
        "source_record_id": lambda values: ";".join(sorted(set(str(value) for value in values if str(value)))[:10]),
        "collection_timestamp": lambda values: ";".join(sorted(set(str(value) for value in values if str(value) and str(value) != "nan"))[:5]),
    })
    data = data.sort_values("url", kind="stable").reset_index(drop=True)

    class_counts = {"BENIGN": int((data["label"] == 0).sum()), "MALICIOUS": int((data["label"] == 1).sum())}
    if min(class_counts.values()) < 50:
        raise ValueError(f"Dataset is too small or missing a class: {class_counts}. At least 50 samples per class are required.")

    data["source_record_id"] = data["source_record_id"].astype(str)
    data.to_csv(OUTPUT_FILE, index=False)
    sources = sorted({part for cell in data["source"].dropna().astype(str) for part in cell.split(";") if part})
    raw_source_files = {}
    for source_name, source_path in [("PhiUSIIL-UCI", PHIUSIIL_FILE), ("PhishTank", PHISHTANK_FILE), ("URLhaus", URLHAUS_FILE)]:
        if source_path.is_file():
            digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
            raw_source_files[source_name] = {
                "filename": source_path.name,
                "size_bytes": int(source_path.stat().st_size),
                "sha256": digest,
            }
    try:
        output_label = str(OUTPUT_FILE.relative_to(ROOT))
    except ValueError:
        output_label = str(OUTPUT_FILE)
    manifest = {
        "dataset_name": "CTI Sentinel X URL Intelligence Dataset",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "output_file": output_label,
        "rows_before_deduplication": before_dedup,
        "rows_after_deduplication": int(len(data)),
        "duplicate_or_conflicting_rows_removed": int(before_dedup - len(data)),
        "conflicting_url_rows_removed": conflict_rows,
        "class_counts": class_counts,
        "sources_used": sources,
        "source_row_counts_before_deduplication": source_row_counts,
        "raw_source_files": raw_source_files,
        "source_timestamp_range": {
            "minimum": min([stamp for cell in data["collection_timestamp"].dropna().astype(str) for stamp in cell.split(";") if stamp and stamp.lower() != "nan"], default=None),
            "maximum": max([stamp for cell in data["collection_timestamp"].dropna().astype(str) for stamp in cell.split(";") if stamp and stamp.lower() != "nan"], default=None),
        },
        "label_mapping": {"0": "BENIGN", "1": "MALICIOUS"},
        "feature_policy": "Only the raw URL string is used by the classifier. Website HTML, page content and PhiUSIIL-derived website features are excluded.",
        "source_coverage": {
            "PhiUSIIL-UCI": "Phishing versus legitimate URLs; this is the baseline malicious-class coverage.",
            "PhishTank": "Verified phishing URLs when the optional authenticated feed is enabled.",
            "URLhaus": "Malware-distribution URLs when the optional authenticated feed is enabled.",
        },
        "source_attribution": {
            "PhiUSIIL-UCI": "Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website). UCI Machine Learning Repository. DOI: 10.1016/j.cose.2023.103545. CC BY 4.0.",
            "PhishTank": "PhishTank verified online phishing feed. Follow current developer terms, rate limits, attribution and application-key requirements.",
            "URLhaus": "abuse.ch URLhaus recent malware URL export. Follow current Auth-Key, fair-use and redistribution terms.",
        },
        "important_note": "Raw feeds are not redistributed by this project. Verify each source's current terms before publishing derived datasets or model artifacts.",
    }
    MANIFEST_FILE.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize, label and deduplicate downloaded URL datasets.")
    parser.parse_args()
    prepare_dataset()


if __name__ == "__main__":
    main()
