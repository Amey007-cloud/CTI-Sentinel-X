from __future__ import annotations

import argparse
import os
import zipfile
from pathlib import Path
from urllib.parse import quote

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
UCI_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil%2Bphishing%2Burl%2Bdataset.zip"
USER_AGENT = "CTI-Sentinel-X-Research/1.0 (academic URL-classification dataset acquisition)"


def _download(url: str, destination: Path, headers: dict[str, str] | None = None, force: bool = False) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_size > 1024 and not force:
        print(f"[SKIP] Already downloaded: {destination.name}")
        return
    temporary = destination.with_suffix(destination.suffix + ".part")
    request_headers = {"User-Agent": USER_AGENT, **(headers or {})}
    with requests.get(url, headers=request_headers, timeout=(20, 180), stream=True) as response:
        response.raise_for_status()
        with temporary.open("wb") as output:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    output.write(chunk)
    if temporary.stat().st_size < 1024:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"Download from {url} was unexpectedly small; refusing to use it.")
    temporary.replace(destination)
    print(f"[OK] Downloaded {destination.name} ({destination.stat().st_size:,} bytes)")


def download_phiusiil(force: bool = False) -> None:
    archive = RAW_DIR / "phiusiil_dataset.zip"
    csv_path = RAW_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
    if csv_path.exists() and csv_path.stat().st_size > 1024 and not force:
        print("[SKIP] PhiUSIIL CSV already extracted.")
        return
    _download(UCI_URL, archive, force=force)
    with zipfile.ZipFile(archive) as package:
        member = next((name for name in package.namelist() if name.lower().endswith(".csv")), None)
        if not member:
            raise RuntimeError("The UCI download did not contain a CSV file.")
        with package.open(member) as source, csv_path.open("wb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
    if csv_path.stat().st_size < 1024:
        raise RuntimeError("The extracted PhiUSIIL CSV is unexpectedly small.")
    print(f"[OK] Extracted {csv_path.name} ({csv_path.stat().st_size:,} bytes)")


def download_phishtank(app_key: str, force: bool = False) -> None:
    if not app_key:
        print("[SKIP] PHISHTANK_APP_KEY is not set; live PhishTank feed not downloaded.")
        return
    url = f"https://data.phishtank.com/data/{quote(app_key, safe='')}/online-valid.csv"
    _download(url, RAW_DIR / "phishtank_online.csv", force=force)


def download_urlhaus(auth_key: str, force: bool = False) -> None:
    if not auth_key:
        print("[SKIP] URLHAUS_AUTH_KEY is not set; live URLhaus feed not downloaded.")
        return
    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{quote(auth_key, safe='')}/recent.csv"
    _download(url, RAW_DIR / "urlhaus_recent.csv", force=force)


def main() -> None:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description="Download the public benchmark and optional live threat feeds.")
    parser.add_argument("--force", action="store_true", help="Redownload even if local raw files already exist.")
    parser.add_argument("--skip-phishtank", action="store_true")
    parser.add_argument("--skip-urlhaus", action="store_true")
    args = parser.parse_args()

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    download_phiusiil(force=args.force)
    if not args.skip_phishtank:
        download_phishtank(os.getenv("PHISHTANK_APP_KEY", "").strip(), force=args.force)
    if not args.skip_urlhaus:
        download_urlhaus(os.getenv("URLHAUS_AUTH_KEY", "").strip(), force=args.force)

    from ml_training.prepare_dataset import prepare_dataset
    prepare_dataset()


if __name__ == "__main__":
    main()
