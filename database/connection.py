from __future__ import annotations

# This makes BOTH of these work:
#   python database\connection.py
#   python -m database.connection
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import os
from typing import Optional
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

load_dotenv(PROJECT_ROOT / ".env")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017").strip()
DATABASE_NAME = os.getenv("MONGO_DATABASE", "cti_sentinel").strip()

_client: Optional[MongoClient] = None


def get_client() -> MongoClient:
    global _client

    if _client is None:
        _client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=15000,
            maxPoolSize=50,
            minPoolSize=2,
            retryWrites=True,
        )

    return _client


def get_database() -> Database:
    return get_client()[DATABASE_NAME]


def get_collection(name: str) -> Collection:
    if not name:
        raise ValueError("Collection name cannot be empty.")

    return get_database()[name]


def ping_database() -> bool:
    try:
        get_client().admin.command("ping")
        return True
    except PyMongoError as exc:
        print(f"[ERROR] MongoDB connection failed: {exc}")
        return False


def server_info() -> dict:
    try:
        return get_client().server_info()
    except PyMongoError:
        return {}


def close_connection() -> None:
    global _client

    if _client is not None:
        _client.close()
        _client = None


def main() -> None:
    print(f"MongoDB URI: {MONGO_URI}")
    print(f"Database: {DATABASE_NAME}")

    if ping_database():
        print("[OK] MongoDB connection successful.")
        print(f"[OK] MongoDB version: {server_info().get('version', 'unknown')}")
    else:
        print("[ERROR] MongoDB connection failed.")

    close_connection()


if __name__ == "__main__":
    main()
