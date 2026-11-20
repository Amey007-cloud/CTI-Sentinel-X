# Lab 7.2 — Working Set Analysis

The target workload is:

`100,000 × approximately 2 KB ≈ 200 MB`

The exact BSON/storage footprint can differ because MongoDB adds document metadata and storage overhead. Therefore the executable script measures actual collection count and WiredTiger cache statistics.

Run:

```powershell
python labs\lab_7_2_working_set_analysis.py --seed
python labs\lab_7_2_working_set_analysis.py --reads 5000
```

Record the observed cache fill, hit ratio, elapsed time, reads/sec, and bytes read into cache in the lab notebook/report.
