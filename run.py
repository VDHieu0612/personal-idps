import os
import sys
import uvicorn

# Force UTF-8 encoding for standard output on Windows
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

if __name__ == "__main__":
    print("=" * 60)
    print("  [AEGISGUARD] Personal IDS/IPS System & Security Dashboard")
    print("  [*] Starting FastAPI Engine & Serving React Dashboard...")
    print("  [*] Access Dashboard at: http://localhost:8000")
    print("  [*] OpenAPI Documentation at: http://localhost:8000/docs")
    print("=" * 60)
    
    uvicorn.run("engine.main:app", host="0.0.0.0", port=8000, reload=False)
