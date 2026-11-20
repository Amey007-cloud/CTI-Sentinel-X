# Lab 7.1 — Analyze a Production Schema

## Objective
Examine the production-style CTI schema and identify embedding and referencing decisions.

## Data model
The application uses MongoDB collections including `threats`, `iocs`, `sources`, `reports`, `security_solutions`, and intelligence correlation collections.

### Embedded data
Small, bounded, threat-specific metadata such as classification and tags is embedded because it is normally read with the threat and does not need independent lifecycle management.

### Referenced data
- `threats.ioc_ids -> iocs`: IOCs are reusable and can be associated with multiple threats.
- `threats.source_ids -> sources`: sources are shared across many threat records.
- `threats.report_ids -> reports`: reports can describe multiple threats and may contain larger Markdown content.

Embedding those referenced objects would duplicate data and make global updates/searches harder.

## BSON size experiment
Run:

```powershell
python labs\lab_7_1_production_schema.py
```

The script uses the MongoDB `$bsonSize` aggregation expression and writes:

`outputs/lab_7_1_schema_analysis.json`

The script verifies that analyzed documents remain below MongoDB's 16 MiB BSON document limit.

## Try It Yourself
Run:

```powershell
python labs\lab_7_1_tiy.py
```

This redesigns threat-to-IOC data as an embedded structure. It demonstrates that threat detail reads become more local, while global IOC search, update consistency, and deduplication become harder.
