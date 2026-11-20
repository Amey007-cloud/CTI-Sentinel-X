from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))

def main():
    import flask, pymongo, requests, dotenv
    import app
    expected={
        '/', '/investigate', '/threats', '/reports', '/reports/<report_id>',
        '/api/health','/api/dashboard','/api/integrations','/api/analyze','/api/analyze/file','/api/reports','/api/report/<report_id>','/api/cuckoo/status','/api/platform-threats','/api/platform-summary', '/api/threat/<path:indicator>/lifecycle', '/api/assistant/chat', '/api/assistant/ingest', '/api/assistant/host-scan', '/api/assistant/remediations'
    }
    actual={rule.rule for rule in app.app.url_map.iter_rules()}
    missing=expected-actual
    if missing: raise SystemExit(f'Missing routes: {sorted(missing)}')
    print('[OK] Python dependencies import successfully.')
    print('[OK] Flask application imported successfully.')
    print('[OK] Required routes are registered.')
    print('[OK] Project verification passed.')
if __name__=='__main__': main()
