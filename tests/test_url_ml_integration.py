from __future__ import annotations

from typing import Any

import importlib
import sys
import types

try:
    import services.external as external
except ModuleNotFoundError as exc:
    # The light-weight verification container may omit the optional MongoDB
    # driver. Stub only the connection accessor; the test supplies its own DB.
    if exc.name != "pymongo":
        raise
    connection_stub = types.ModuleType("database.connection")
    connection_stub.get_database = lambda: None
    sys.modules["database.connection"] = connection_stub
    external = importlib.import_module("services.external")


class FakeCollection:
    def __init__(self, existing: dict[str, Any] | None = None):
        self.existing = existing
        self.updated = []

    def find_one(self, query):
        return self.existing

    def update_one(self, query, update, upsert=False):
        self.updated.append((query, update, upsert))


class FakeDatabase:
    def __init__(self):
        self.url_intelligence = FakeCollection()
        self.threat_correlations = FakeCollection()

    def __getitem__(self, name):
        return getattr(self, name)


def test_url_ml_signal_is_added_without_changing_legacy_cti_score(monkeypatch):
    database = FakeDatabase()
    monkeypatch.setattr(external, "get_database", lambda: database)
    monkeypatch.setattr(external, "_vt_get", lambda path: ({"data": {}}, None))
    monkeypatch.setattr(external, "_vt_stats", lambda value: {"malicious": 3, "suspicious": 1})
    monkeypatch.setattr(
        external,
        "_parallel_sources",
        lambda specs: {
            "VirusTotal": {"match": True, "status": "success", "message": "test match"},
            "MISP": {"match": False, "status": "success", "message": ""},
            "URLhaus": {"match": False, "status": "success", "message": ""},
            "ThreatFox": {"match": False, "status": "success", "message": ""},
            "OTX": {"match": False, "status": "success", "message": ""},
            "CTI Digest": {"match": False, "status": "success", "message": ""},
        },
    )
    monkeypatch.setattr(external, "calculate_score", lambda **kwargs: 47)
    monkeypatch.setattr(external, "classify_score", lambda value: "MEDIUM")

    import ml.url_classifier as classifier

    monkeypatch.setattr(
        classifier,
        "predict_url",
        lambda url: {
            "ml_status": "completed",
            "ml_prediction": "MALICIOUS",
            "ml_confidence": 0.91,
            "ml_malicious_probability": 0.91,
            "ml_decision_threshold": 0.63,
            "ml_model": "cti-sentinel-test-model",
            "ml_message": "test model signal",
        },
    )

    result = external.analyze_url("https://suspicious.example/login")

    assert result["ml_status"] == "completed"
    assert result["ml_prediction"] == "MALICIOUS"
    assert result["threat_score"] == 47
    assert result["threat_level"] == "MEDIUM"
    assert database.url_intelligence.updated
    persisted = database.url_intelligence.updated[-1][1]["$set"]
    assert persisted["ml_model"] == "cti-sentinel-test-model"
    assert persisted["threat_score"] == 47
