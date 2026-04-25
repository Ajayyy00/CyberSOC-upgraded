#!/usr/bin/env python3
"""
CyberSOC Dashboard Server
=========================
Wraps the existing FastAPI app with:
  - CORS middleware
  - Static file serving for the dashboard at /dashboard/
  - Multi-tenant WebSocket sessions at /ws/{session_id}

Multi-tenant design
-------------------
Each browser tab generates a unique session_id (UUID stored in sessionStorage)
and maintains a persistent WebSocket connection to /ws/{session_id}.  The server
keeps one CyberSOCEnvironment instance per session_id in a plain dict guarded by
a threading.Lock.  Environment instances are torn down automatically when the
WebSocket closes.

This replaces the old single-global /demo/reset + /demo/step REST hack, which
only supported one concurrent user and leaked state between sessions.

WebSocket message protocol
--------------------------
Client -> server:
    {"type": "reset",  "task_id": "hard"}
    {"type": "step",   <action fields — same as SOCActionWrapper>}
    {"type": "ping"}

Server -> client:
    {"type": "reset_ok",  "observation": {...}, "reward": 0.0, "done": false}
    {"type": "step_ok",   "observation": {...}, "reward": 0.5, "done": false}
    {"type": "error",     "message": "..."}
    {"type": "pong"}

Usage
-----
    python dashboard_server.py            # default port 8000
    python dashboard_server.py --port 9000

Then open: http://localhost:8000/dashboard/
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import threading
from typing import Any, Dict

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from server.app import app
except ImportError as e:
    print(f"[ERROR] Could not import CyberSOCEnv app: {e}")
    print("Make sure you have the openenv package installed.")
    sys.exit(1)

from fastapi import WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Core API Server Only ──────────────────────────────────────────

@app.get("/")
def read_root():
    return {"status": "CyberSOC API is running! Use /reset and /step for OpenEnv, or connect via WebSocket."}


# ── Multi-tenant session store ────────────────────────────────────────────────
try:
    from server.play_environment import CyberSOCEnvironment
    _ENV_AVAILABLE = True
except ImportError:
    _ENV_AVAILABLE = False
    print("[WARN] CyberSOCEnvironment not available — WebSocket sessions disabled.")

# session_id -> CyberSOCEnvironment instance
_sessions: Dict[str, Any] = {}
# threading.Lock is safe here: held only for dict reads/writes (microseconds),
# never across an await, so it never blocks the event loop.
_sessions_lock = threading.Lock()


def _obs_to_dict(obs: Any) -> Dict[str, Any]:
    """Serialise a SOCObservation to a JSON-safe dict."""
    if hasattr(obs, "model_dump"):
        return obs.model_dump()
    if hasattr(obs, "__dict__"):
        return obs.__dict__
    return dict(obs)


async def _run(fn, *args, **kwargs):
    """Run a synchronous blocking call off the event loop in the thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws/{session_id}")
async def ws_session(websocket: WebSocket, session_id: str):
    """
    Persistent, session-keyed WebSocket handler.

    Each browser tab connects here with its own session_id.  The handler
    maintains one CyberSOCEnvironment for the lifetime of the connection and
    cleans it up on disconnect — no shared mutable state between sessions.
    """
    if not _ENV_AVAILABLE:
        await websocket.close(code=1011, reason="CyberSOCEnvironment not available")
        return

    await websocket.accept()

    try:
        while True:
            try:
                msg: Dict[str, Any] = await websocket.receive_json()
            except Exception:
                break  # malformed JSON or connection gone

            msg_type: str = msg.get("type", "")

            # ── reset ────────────────────────────────────────────────────────
            if msg_type == "reset":
                task_id: str = msg.get("task_id", "hard")
                try:
                    # Swap out old env atomically
                    with _sessions_lock:
                        old = _sessions.pop(session_id, None)

                    # Close old env outside the lock (blocking -> executor)
                    if old is not None and hasattr(old, "close"):
                        try:
                            await _run(old.close)
                        except Exception:
                            pass

                    env = CyberSOCEnvironment()
                    with _sessions_lock:
                        _sessions[session_id] = env

                    obs = await _run(env.reset, task_id=task_id)
                    await websocket.send_json({
                        "type": "reset_ok",
                        "observation": _obs_to_dict(obs),
                        "reward": 0.0,
                        "done": False,
                    })
                except Exception as exc:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Reset failed: {exc}",
                    })

            # ── step ─────────────────────────────────────────────────────────
            elif msg_type == "step":
                with _sessions_lock:
                    env = _sessions.get(session_id)

                if env is None:
                    await websocket.send_json({
                        "type": "error",
                        "message": "No active session — send a reset message first",
                    })
                    continue

                try:
                    from models import SOCActionWrapper, RedActionWrapper, RED_ACTION_TYPES  # noqa: PLC0415
                    action_fields = {k: v for k, v in msg.items() if k != "type"}
                    action_type_str = action_fields.get("type", "")

                    # Route to Red or Blue wrapper based on action type
                    if action_type_str in RED_ACTION_TYPES:
                        action = RedActionWrapper.model_validate(action_fields)
                    else:
                        action = SOCActionWrapper.model_validate(action_fields)

                    obs = await _run(env.step, action)
                    await websocket.send_json({
                        "type": "step_ok",
                        "observation": _obs_to_dict(obs),
                        "reward": float(obs.reward) if hasattr(obs, "reward") else 0.0,
                        "done": bool(obs.done) if hasattr(obs, "done") else False,
                    })
                except Exception as exc:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Step failed: {exc}",
                    })

            # ── ping (keepalive) ──────────────────────────────────────────────
            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            else:
                await websocket.send_json({
                    "type": "error",
                    "message": (
                        f"Unknown message type '{msg_type}'. "
                        "Expected: reset | step | ping"
                    ),
                })

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        # Always clean up on disconnect regardless of how we exited
        with _sessions_lock:
            env = _sessions.pop(session_id, None)
        if env is not None and hasattr(env, "close"):
            try:
                await _run(env.close)
            except Exception:
                pass


# ── CLI entry-point ───────────────────────────────────────────────────────────
def main() -> None:
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
    print("╔══════════════════════════════════════════════════════╗")
    print("║   CyberSOC Command Center                            ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║   API      : http://localhost:{args.port:<5}                  ║")
    print(f"║   WebSocket: ws://localhost:{args.port}/ws/<session_id>   ║")
    if _STATIC_OK:
        print(f"║   Dashboard: http://localhost:{args.port}/dashboard/         ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
