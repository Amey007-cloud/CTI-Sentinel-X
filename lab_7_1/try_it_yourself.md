# Lab 7.1 — Try It Yourself

## Redesign
The original design references IOCs using identifiers. The alternative embeds bounded IOC metadata directly in a threat document.

### Queries that become faster
- Fetch a threat and display its bounded IOC metadata in one document read.
- Render a threat-detail view without resolving separate IOC documents.

### Queries that become harder
- Find every threat containing a particular IOC.
- Update one IOC globally when it is duplicated across threats.
- Maintain uniqueness and consistency across duplicated IOC values.

Conclusion: embedding improves locality for bounded, threat-specific data; referencing remains preferable for reusable high-cardinality IOCs.
