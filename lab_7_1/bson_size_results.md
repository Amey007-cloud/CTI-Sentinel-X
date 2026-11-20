# Lab 7.1 — BSON Size Results

Run:

```powershell
python labs\lab_7_1_production_schema.py
```

The executable result is saved to:

`outputs/lab_7_1_schema_analysis.json`

The JSON contains document count, average BSON size, minimum size, maximum size, and the maximum percentage of the 16 MiB limit for each analyzed collection.

No fixed result is hard-coded in this document; the measurement is generated from the MongoDB instance used during the lab run.
