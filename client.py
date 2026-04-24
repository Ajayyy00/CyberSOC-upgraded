# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""CyberSOCEnv Client — connects to the SOC environment server."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult

from .models import (
    SOCObservation,
    SOCActionWrapper,
    SOCState,
    Alert,
    Severity,
    ThreatType,
    NetworkTopology,
    ForensicsResult,
    TimelineEntry,
)


class CyberSOCClient(
    EnvClient[SOCActionWrapper, SOCObservation, SOCState]
):
    """
    Client for the CyberSOCEnv environment.

    Connects via WebSocket to the SOC environment server for
    low-latency, persistent-session interaction.

    Example:
        >>> with CyberSOCClient(base_url="http://localhost:8000") as client:
        ...     result = client.reset()
        ...     print(result.observation.alert_queue)
        ...
        ...     from play.models import QueryHost
        ...     result = client.step(SOCActionWrapper(type="query_host", hostname="WS-001"))
        ...     print(result.observation.host_forensics)
    """

    def _step_payload(self, action: SOCActionWrapper) -> Dict:
        """Convert SOCActionWrapper to JSON payload for step message."""
        return action.model_dump(exclude_none=True)

    def _parse_result(self, payload: Dict) -> StepResult[SOCObservation]:
        """Parse server response into StepResult[SOCObservation]."""
        obs_data = payload.get("observation", {})

        # Parse alerts
        alerts = [Alert(**a) for a in obs_data.get("alert_queue", [])]

        # Parse network topology
        topo_data = obs_data.get("network_topology", {})
        topology = NetworkTopology(**topo_data) if topo_data else NetworkTopology()

        # Parse forensics (may be None)
        forensics_data = obs_data.get("host_forensics")
        forensics = ForensicsResult(**forensics_data) if forensics_data else None

        # Parse timeline
        timeline = [TimelineEntry(**t) for t in obs_data.get("timeline", [])]

        observation = SOCObservation(
            episode_id=obs_data.get("episode_id", ""),
            alert_queue=alerts,
            network_topology=topology,
            host_forensics=forensics,
            timeline=timeline,
            business_impact_score=obs_data.get("business_impact_score", 0.0),
            step_count=obs_data.get("step_count", 0),
            active_threats=obs_data.get("active_threats", []),
            max_steps=obs_data.get("max_steps", 30),
            task_id=obs_data.get("task_id", "easy"),
            total_reward=obs_data.get("total_reward", 0.0),
            final_score=obs_data.get("final_score"),
            grade_breakdown=obs_data.get("grade_breakdown"),
            done=payload.get("done", False),
            reward=payload.get("reward"),
        )

        result = StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )
        # Attach episode_id directly on the result for easy RL loop access
        result.episode_id = observation.episode_id  # type: ignore[attr-defined]
        return result

    def _parse_state(self, payload: Dict) -> SOCState:
        """Parse server response into SOCState."""
        return SOCState(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
            task_id=payload.get("task_id", "easy"),
            total_reward=payload.get("total_reward", 0.0),
            business_impact=payload.get("business_impact", 0.0),
        )
