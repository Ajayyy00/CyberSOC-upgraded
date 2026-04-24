# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
FastAPI application for the CyberSOCEnv Environment.

Endpoints:
    - POST /reset: Reset the environment (pass task_id in body)
    - POST /step: Execute an action
    - GET /state: Get current environment state
    - GET /schema: Get action/observation schemas
    - WS /ws: WebSocket endpoint for persistent sessions

Usage:
    # Development (with auto-reload):
    uvicorn server.app:app --reload --host 0.0.0.0 --port 8000

    # Production:
    uvicorn server.app:app --host 0.0.0.0 --port 8000 --workers 4
"""

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:  # pragma: no cover
    raise ImportError(
        "openenv is required. Install with: pip install 'openenv-core[core]'"
    ) from e

try:
    from ..models import SOCObservation, SOCActionWrapper
    from .play_environment import CyberSOCEnvironment
except (ImportError, ModuleNotFoundError):
    from models import SOCObservation, SOCActionWrapper
    from server.play_environment import CyberSOCEnvironment


# Create the app with the CyberSOCEnv environment
app = create_app(
    CyberSOCEnvironment,
    SOCActionWrapper,
    SOCObservation,
    env_name="cybersocenv",
    max_concurrent_envs=16,
)

# CORS middleware — allows the dashboard frontend to communicate with the server
from starlette.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from fastapi.responses import JSONResponse

@app.get("/health")
async def health():
    """Lightweight liveness probe used by the dashboard to check server reachability.
    Returns only status — never returns episode state, so the dashboard
    cannot accidentally render stale data from a previous session.
    """
    return JSONResponse({"status": "ok", "service": "cybersocenv"})


def main(host: str = "0.0.0.0", port: int = 8000):
    """Entry point for direct execution.

    Usage:
        python -m play.server.app
        python -m play.server.app --port 8001
    """
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
