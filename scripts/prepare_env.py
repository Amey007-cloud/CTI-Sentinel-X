"""Create a first-run .env with fresh local-only credentials."""
from __future__ import annotations

import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / ".env.example"
TARGET = ROOT / ".env"


def main() -> int:
    if not TARGET.exists():
        text = SAMPLE.read_text(encoding="utf-8")
        text = text.replace("replace-with-generated-password", secrets.token_urlsafe(28))
        text = text.replace("replace-with-generated-flask-secret", secrets.token_urlsafe(48))
        TARGET.write_text(text, encoding="utf-8")
        print("[PASS] Created .env with fresh local credentials. Values were not printed.")
    else:
        text = TARGET.read_text(encoding="utf-8")
        if "replace-with-generated-password" in text or "replace-with-generated-flask-secret" in text:
            print("[ERROR] .env still contains placeholder credentials.")
            print("Delete .env and run this script again, or replace the placeholders manually.")
            return 2
        print("[PASS] Existing .env preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
