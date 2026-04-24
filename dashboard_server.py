#!/usr/bin/env python3
"""
CyberSOC Dashboard Server
=========================
Wraps the existing FastAPI app with:
  - CORS middleware
  - Static file serving for the dashboard at /dashboard/
  - Stateful /demo/reset and /demo/step endpoints

WHY /demo/* endpoints?
  OpenEnv's built-in /reset and /step HTTP handlers are STATELESS — each
  request creates a brand-new environment instance, runs a single call, then
  destroys it. That design is fine for ephemeral smoke-tests but breaks any
  multi-step dashboard session (the env has never been reset when /step is
  called on the second request).

  The /demo/* layer keeps one CyberSOCEnvironment instance alive in memory
  for the lifetime of the server process. The dashboard talks exclusively to
  /demo/reset and /demo/step, which use the persistent instance.

Usage:
    python dashboard_server.py
    python dashboard_server.py --port 8000

Then open:  http://localhost:8000/dashboard/
"""

import argparse
import os
import sys
import threading
from typing import Any, Dict, Optional

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

from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

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


@app.get("/")
def root_redirect():
    return RedirectResponse(url="/dashboard/")


# ── Stateful Demo Session ────────────────────────────────────────────────────
# Keeps ONE live CyberSOCEnvironment instance in memory between /demo/reset
# and /demo/step calls, bypassing the stateless OpenEnv HTTP layer.

try:
    from server.play_environment import CyberSOCEnvironment
    _ENV_AVAILABLE = True
except ImportError:
    _ENV_AVAILABLE = False
    print("[WARN] CyberSOCEnvironment could not be imported. /demo/* endpoints disabled.")

_demo_env: Optional[Any] = None        # The persistent env instance
_demo_lock = threading.Lock()          # Thread-safety for concurrent requests


class DemoResetRequest(BaseModel):
    task_id: str = "hard"


class DemoStepRequest(BaseModel):
    # Accept any action dict — mirrors SOCActionWrapper fields
    type: str
    # Allow all other action-specific fields
    model_config = {"extra": "allow"}


def _obs_to_dict(obs) -> Dict[str, Any]:
    """Convert a SOCObservation (Pydantic or dataclass) to a JSON-safe dict."""
    if hasattr(obs, "model_dump"):
        return obs.model_dump()
    if hasattr(obs, "__dict__"):
        return obs.__dict__
    return dict(obs)


@app.post("/demo/reset")
async def demo_reset(request: DemoResetRequest):
    """
    Stateful reset: creates (or re-creates) the live CyberSOCEnvironment
    and calls reset() with the chosen task_id.  The instance is kept alive
    so that subsequent /demo/step calls can continue the same episode.
    """
    global _demo_env

    if not _ENV_AVAILABLE:
        raise HTTPException(503, "CyberSOCEnvironment not available")

    with _demo_lock:
        # Close any previous instance
        if _demo_env is not None:
            try:
                _demo_env.close()
            except Exception:
                pass

        _demo_env = CyberSOCEnvironment()
        obs = _demo_env.reset(task_id=request.task_id)

    obs_dict = _obs_to_dict(obs)
    return JSONResponse({"observation": obs_dict, "reward": None, "done": False})


@app.post("/demo/step")
async def demo_step(request: DemoStepRequest):
    """
    Stateful step: sends the action to the persistent environment instance
    that was created by the most recent /demo/reset call.
    """
    global _demo_env

    if not _ENV_AVAILABLE:
        raise HTTPException(503, "CyberSOCEnvironment not available")

    if _demo_env is None:
        raise HTTPException(400, "No active episode — call /demo/reset first")

    # Reconstruct a SOCActionWrapper from the incoming dict
    try:
        from models import SOCActionWrapper
        action_dict = request.model_dump()
        action = SOCActionWrapper.model_validate(action_dict)
    except Exception as e:
        raise HTTPException(422, f"Invalid action: {e}")

    with _demo_lock:
        try:
            result = _demo_env.step(action)
        except Exception as e:
            raise HTTPException(500, f"Step failed: {e}")

    # result may be (obs, reward, done, info) tuple or a StepResult object
    if isinstance(result, tuple):
        obs, reward, done = result[0], result[1], result[2]
    else:
        obs = result.observation if hasattr(result, "observation") else result
        reward = getattr(result, "reward", None)
        done = getattr(result, "done", False)

    obs_dict = _obs_to_dict(obs)
    return JSONResponse({"observation": obs_dict, "reward": reward, "done": bool(done)})


@app.get("/demo/state")
async def demo_state():
    """Return basic state of the current demo session."""
    if _demo_env is None:
        return JSONResponse({"active": False})
    try:
        state = _demo_env.get_state() if hasattr(_demo_env, "get_state") else {}
        state_dict = _obs_to_dict(state) if state else {}
        return JSONResponse({"active": True, **state_dict})
    except Exception:
        return JSONResponse({"active": True})


# ── CLI entry-point ──────────────────────────────────────────────────────────
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
