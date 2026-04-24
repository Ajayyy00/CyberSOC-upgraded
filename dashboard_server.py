#!/usr/bin/env python3
"""
CyberSOC Dashboard Server
=========================
Wraps the existing FastAPI app with:
  - CORS middleware (required when dashboard is served separately)
  - Static file serving for the dashboard at /dashboard/

Usage:
    python dashboard_server.py
    python dashboard_server.py --port 8000

Then open:  http://localhost:8000/dashboard/
"""

import argparse
import os
import sys

# Ensure MetaRound2 root is on sys.path
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from server.app import app
except ImportError as e:
    print(f"[ERROR] Could not import CyberSOCEnv app: {e}")
    print("Make sure you have the openenv package installed.")
    sys.exit(1)

from fastapi.middleware.cors import CORSMiddleware

# ── CORS (allow all origins for local demo) ─────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static dashboard files at /dashboard/ ───────────────────────────────────
dashboard_dir = os.path.join(ROOT, "dashboard")
if os.path.isdir(dashboard_dir):
    try:
        from fastapi.staticfiles import StaticFiles
        app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")
        _STATIC_OK = True
    except ImportError:
        _STATIC_OK = False
        print("[WARN] aiofiles not installed — static file serving disabled.")
        print("       Install with: pip install aiofiles")
else:
    _STATIC_OK = False
    print(f"[WARN] Dashboard directory not found: {dashboard_dir}")


def main():
    parser = argparse.ArgumentParser(description="CyberSOC Dashboard Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print("[ERROR] uvicorn not installed. Run: pip install uvicorn")
        sys.exit(1)

    print()
    print("╔══════════════════════════════════════════════╗")
    print("║   🛡️  CyberSOC Command Center                ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║   API Server : http://localhost:{args.port:<5}        ║")
    if _STATIC_OK:
        print(f"║   Dashboard  : http://localhost:{args.port}/dashboard/ ║")
    else:
        print("║   Dashboard  : open dashboard/index.html    ║")
    print("╚══════════════════════════════════════════════╝")
    print()

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
