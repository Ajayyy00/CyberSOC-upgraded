"""
Minimal static file server for the CyberSOC Demo HF Space.

Serves the dashboard/ directory on port 7860.
The BACKEND_URL environment variable is injected into
dashboard/js/config.js at startup by start.sh before this
process is launched.
"""

import os
import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="CyberSOC Demo Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return RedirectResponse(url="/index.html")


@app.get("/health")
def health():
    return {"status": "ok", "service": "cybersoc-demo"}


# Serve everything in the dashboard/ folder
_dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard")
app.mount("/", StaticFiles(directory=_dashboard_dir, html=True), name="static")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7860)
