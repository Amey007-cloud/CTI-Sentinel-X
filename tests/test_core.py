from assistant_api import core


def test_chunk_text_handles_multiple_documents_without_name_shadowing():
    docs = [
        "first document has enough words " * 20,
        "second document also has enough words " * 20,
    ]
    chunks_by_doc = [core.chunk_text(doc, 40) for doc in docs]
    assert len(chunks_by_doc) == 2
    assert all(chunks for chunks in chunks_by_doc)
    assert all(isinstance(chunk, str) for chunks in chunks_by_doc for chunk in chunks)
    # Overlap preserves a boundary window between adjacent chunks.
    words = " ".join(docs[0].split())
    assert chunks_by_doc[0][0].split()[-13:] == chunks_by_doc[0][1].split()[:13]


def test_chunk_text_empty_and_bounds():
    assert core.chunk_text("") == []
    assert core.chunk_text("one two three", 40) == ["one two three"]


def test_hash_embedding_is_normalized_and_deterministic():
    a = core._hash_embedding("windows endpoint security patch")
    b = core._hash_embedding("windows endpoint security patch")
    assert a == b
    assert len(a) == 384
    assert abs(sum(x*x for x in a) ** 0.5 - 1.0) < 1e-8


def test_cosine_similarity_and_dimension_mismatch():
    assert abs(core.cosine_similarity([1, 0, 0], [1, 0, 0]) - 1.0) < 1e-9
    assert abs(core.cosine_similarity([1, 0], [0, 1])) < 1e-9
    assert core.cosine_similarity([1, 0], [1, 0, 0]) == 0.0


class FakeCollection:
    def __init__(self):
        self.rows = []

    def find_one(self, query):
        return next((r for r in self.rows if all(r.get(k) == v for k, v in query.items())), None)

    def delete_many(self, query):
        self.rows = [r for r in self.rows if not all(r.get(k) == v for k, v in query.items())]

    def insert_many(self, rows):
        self.rows.extend(dict(row) for row in rows)

    def update_one(self, query, update, upsert=False):
        row = self.find_one(query)
        if row is None and upsert:
            row = dict(update.get("$setOnInsert", {}))
            self.rows.append(row)
        if row is not None:
            row.update(update.get("$set", {}))


class FakeDatabase:
    def __init__(self):
        self.knowledge_documents = FakeCollection()
        self.knowledge_chunks = FakeCollection()


def test_multi_document_ingestion_creates_chunks_and_is_idempotent(monkeypatch):
    monkeypatch.setattr(
        core,
        "embed_text",
        lambda text: (core._hash_embedding(text), "local-hashing-fallback"),
    )
    db = FakeDatabase()
    documents = [
        {"doc_id": "doc-one", "title": "Windows baseline", "platform": "WINDOWS",
         "content": "Windows patch verification and endpoint protection. " * 30},
        {"doc_id": "doc-two", "title": "Linux baseline", "platform": "LINUX",
         "content": "Linux package tracking and SSH hardening. " * 30},
    ]
    first = core.upsert_documents(db, documents, chunk_size=40)
    assert first["documents_processed"] == 2
    assert first["chunks_created"] > 0
    assert len(first["per_document"]) == 2
    assert all(item["chunks_created"] > 0 for item in first["per_document"])
    assert {r["source_title"] for r in db.knowledge_chunks.rows} == {
        "Windows baseline", "Linux baseline"
    }

    second = core.upsert_documents(db, documents, chunk_size=40)
    assert second["documents_processed"] == 0
    assert second["chunks_created"] == 0
    assert all(item["skipped"] for item in second["per_document"])


def test_multi_document_ingestion_can_append_new_chunks_without_overwriting(monkeypatch):
    monkeypatch.setattr(
        core,
        "embed_text",
        lambda text: (core._hash_embedding(text), "local-hashing-fallback"),
    )
    db = FakeDatabase()
    first_doc = {"doc_id": "append-doc", "title": "Append test", "platform": "ALL",
                 "content": "original evidence " * 70}
    second_doc = {"doc_id": "append-doc", "title": "Append test", "platform": "ALL",
                  "content": "additional evidence " * 70}
    first = core.upsert_documents(db, [first_doc], chunk_size=40)
    before = first["chunks_created"]
    second = core.upsert_documents(db, [second_doc], chunk_size=40, replace_existing=False)
    assert second["chunks_created"] > 0
    assert len(db.knowledge_chunks.rows) == before + second["chunks_created"]
    indexes = [row["chunk_index"] for row in db.knowledge_chunks.rows]
    assert len(indexes) == len(set(indexes))
    metadata = db.knowledge_documents.find_one({"doc_id": "append-doc"})
    assert metadata["chunk_count"] == len(db.knowledge_chunks.rows)
