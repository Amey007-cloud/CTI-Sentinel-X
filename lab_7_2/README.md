# Lab 7.2 — Working Set Analysis

## Objective
Estimate the working set and evaluate WiredTiger cache behavior.

### 100,000-document workload
Run:

```powershell
python labs\lab_7_2_working_set_analysis.py --seed
```

The default workload inserts 100,000 documents with an approximately 1,900-byte payload plus MongoDB document metadata, targeting an overall logical size near 200 MB.

### Random reads
Run:

```powershell
python labs\lab_7_2_working_set_analysis.py --reads 5000
```

The script samples random documents across the collection and reports WiredTiger cache metrics before and after the workload.

### Cache monitoring TIY
Run:

```powershell
python labs\lab_7_2_tiy.py --interval 10
```

The monitor reports cache fill and a calculated page-based cache hit ratio every 10 seconds and checks the configured annual security-report source for report entries that are not already represented in MongoDB.
