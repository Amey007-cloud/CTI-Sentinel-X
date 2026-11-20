# Lab 7.1 — Embedding vs Referencing Decisions

| Relationship | Design | Reason |
|---|---|---|
| Threat → classification/tags | Embedded | Small bounded metadata read with the threat |
| Threat → IOC | Referenced | Reusable, potentially high-cardinality IOC data |
| Threat → source | Referenced | Sources are shared by many threats |
| Threat → report | Referenced | Reports can be shared and contain larger Markdown content |

For each referenced relationship, the embedded alternative would copy the related object into the threat document. That can reduce joins/application-side lookups but increases duplication and update cost.

See `labs/lab_7_1_production_schema.py` for the executable BSON-size analysis.
