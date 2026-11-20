# Lab 7.2 — WiredTiger Cache Monitoring

The monitoring script reads `db.serverStatus()` and the WiredTiger cache metrics, including:

- maximum configured cache bytes
- bytes currently in cache
- cache fill percentage
- pages read into cache
- pages requested from cache
- calculated page hit ratio
- bytes read into cache

Run every 10 seconds with:

```powershell
python labs\lab_7_2_tiy.py --interval 10
```

Stop with `Ctrl+C`.
