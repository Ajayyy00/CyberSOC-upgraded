#!/bin/sh
# CyberSOC container startup script
#
# Environment variables (set in HF Space settings):
#   BACKEND_URL          — URL of the CyberSOC trainer Space, e.g.
#                          https://ajay00747-cybersoc-trainer.hf.space
#                          Leave unset for same-origin (full-stack mode).
#   SERVE_DASHBOARD_ONLY — Set to "1" for the Demo space (static files only).
#                          Leave unset or "0" for the Trainer space (full API).
#
# Demo Space settings:
#   BACKEND_URL          = https://ajay00747-cybersoc-trainer.hf.space
#   SERVE_DASHBOARD_ONLY = 1
#
# Trainer Space settings:
#   (no extra env vars required)

set -e

# ── Inject backend URL into config.js ────────────────────────────────────────
CONFIG_JS="/app/dashboard/js/config.js"
if [ -n "${BACKEND_URL}" ]; then
    printf "window.CYBERSOC_BACKEND_URL = '%s';\n" "${BACKEND_URL}" > "${CONFIG_JS}"
    echo "[startup] Demo mode — backend URL: ${BACKEND_URL}"
else
    printf "window.CYBERSOC_BACKEND_URL = '';\n" > "${CONFIG_JS}"
    echo "[startup] Full-stack mode — backend on same origin"
fi

# ── Launch the correct server ─────────────────────────────────────────────────
if [ "${SERVE_DASHBOARD_ONLY:-0}" = "1" ]; then
    echo "[startup] Serving dashboard only (serve_demo.py) on port 7860"
    exec python /app/serve_demo.py
else
    echo "[startup] Serving full stack (dashboard_server.py) on port 7860"
    exec uvicorn dashboard_server:app --host 0.0.0.0 --port 7860
fi
