from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models"


def publish(repo_id: str, private: bool = False) -> str:
    token = os.getenv("HF_TOKEN", "").strip()
    if not token:
        raise RuntimeError("HF_TOKEN is missing. Store it locally in .env or set it in the shell; never commit it.")
    required = [MODEL_DIR / "url_classifier.joblib", MODEL_DIR / "config.json", MODEL_DIR / "README.md"]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError("Train the model first; missing: " + ", ".join(missing))

    from huggingface_hub import HfApi
    api = HfApi(token=token)
    api.create_repo(repo_id=repo_id, repo_type="model", private=private, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cti-sentinel-hf-") as temp_dir:
        stage = Path(temp_dir)
        for source in required:
            shutil.copy2(source, stage / source.name)
        evaluation = ROOT / "reports" / "evaluation.json"
        if evaluation.is_file():
            shutil.copy2(evaluation, stage / "evaluation.json")
        # Deliberately excludes data/raw, data/processed and any API credentials.
        api.upload_folder(
            folder_path=str(stage),
            repo_id=repo_id,
            repo_type="model",
            commit_message="Publish CTI Sentinel X URL classifier v1",
        )
    info = api.repo_info(repo_id=repo_id, repo_type="model")
    print(f"[PUBLISHED] https://huggingface.co/{repo_id}")
    print(f"[REVISION] {info.sha}")
    return info.sha


def main() -> None:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description="Publish only the trained model, config and model card to Hugging Face.")
    parser.add_argument("--repo-id", default=os.getenv("HF_MODEL_REPO_ID", "").strip())
    parser.add_argument("--public", action="store_true", help="Create a public model repository. Default is private.")
    args = parser.parse_args()
    if not args.repo_id or "/" not in args.repo_id:
        raise SystemExit("Provide --repo-id as USERNAME/cti-sentinel-url-classifier.")
    publish(args.repo_id, private=not args.public)


if __name__ == "__main__":
    main()
