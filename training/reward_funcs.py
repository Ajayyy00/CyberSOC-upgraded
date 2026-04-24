"""TRL-compatible reward functions for GRPO training on CyberSOCEnv.

Usage:
    from training.reward_funcs import make_soc_reward_funcs

    reward_fns = make_soc_reward_funcs("http://localhost:8000")
    # reward_fns is a list of 10 callables — one per grading dimension.
    # Pass them directly to trl.GRPOTrainer(reward_funcs=reward_fns).

Each reward function matches the TRL GRPO signature::

    def reward_fn(completions: List[str], **kwargs) -> List[float]: ...

Completions should be JSON strings encoding a list of SOC action dicts, e.g.::

    '[{"type": "query_host", "hostname": "WS-042"},
      {"type": "run_forensics", "hostname": "WS-042"},
      {"type": "submit_containment_plan", "plan": [...], "executive_summary": "..."}]'

The function resets the environment, replays all actions, and returns the
requested dimension's score from the terminal grade_breakdown.  Non-parseable
completions return 0.0.
"""

from __future__ import annotations

import json
from typing import Callable, List, Optional

try:
    import requests as _requests
except ImportError:  # pragma: no cover
    _requests = None  # type: ignore[assignment]


DIMENSION_NAMES: List[str] = [
    "threat_containment",
    "ioc_blocking",
    "forensic_investigation",
    "siem_correlation",
    "threat_intel_usage",
    "vuln_root_cause",
    "business_impact",
    "step_efficiency",
    "plan_coverage",
    "plan_evidence_quality",
]


def _execute_completion(
    env_url: str,
    completion: str,
    task_id: str = "hard",
    timeout: int = 30,
) -> Optional[dict]:
    """Parse a completion and replay it against the live env server.

    Returns the final observation dict on success, or None on any failure
    (parse error, network error, server error).
    """
    if _requests is None:
        raise RuntimeError("requests library is required: pip install requests")

    # Parse the completion as a JSON list of action dicts
    try:
        actions = json.loads(completion)
        if not isinstance(actions, list):
            return None
    except (json.JSONDecodeError, ValueError):
        return None

    try:
        # Reset the environment for a fresh episode
        resp = _requests.post(
            f"{env_url}/reset",
            json={"task_id": task_id},
            timeout=timeout,
        )
        resp.raise_for_status()
        obs = resp.json()

        # Replay each action
        for action in actions:
            if not isinstance(action, dict) or "type" not in action:
                continue
            resp = _requests.post(f"{env_url}/step", json=action, timeout=timeout)
            if not resp.ok:
                break
            obs = resp.json()
            obs_data = obs.get("observation", obs)
            if obs_data.get("done", False):
                break

        return obs.get("observation", obs)

    except Exception:
        return None


def _make_dimension_reward_fn(env_url: str, dimension: str) -> Callable:
    """Return a single TRL GRPO reward function for one grading dimension."""

    def reward_fn(completions: List[str], **kwargs) -> List[float]:
        """TRL GRPO reward function for the ``{dim}`` dimension.

        Args:
            completions: Batch of model completions (JSON action-list strings).
            **kwargs: Extra keyword arguments passed by TRL (ignored).

        Returns:
            List of floats in [0, 1], one score per completion.
        """
        scores: List[float] = []
        for completion in completions:
            obs = _execute_completion(env_url, completion)
            if obs is None:
                scores.append(0.0)
                continue
            # Prefer terminal grade_breakdown; fall back to per-step reward_dimensions
            breakdown: dict = obs.get("grade_breakdown") or obs.get("reward_dimensions") or {}
            scores.append(float(breakdown.get(dimension, 0.0)))
        return scores

    reward_fn.__name__ = f"soc_{dimension}"
    reward_fn.__doc__ = reward_fn.__doc__.replace("{dim}", dimension)  # type: ignore[union-attr]
    return reward_fn


def make_soc_reward_funcs(env_url: str) -> List[Callable]:
    """Return 10 TRL GRPO reward functions, one per grading dimension.

    The functions are ordered to match ``DIMENSION_NAMES``:
      0  threat_containment     (weight 0.20)
      1  ioc_blocking           (weight 0.12)
      2  forensic_investigation (weight 0.10)
      3  siem_correlation       (weight 0.08)
      4  threat_intel_usage     (weight 0.08)
      5  vuln_root_cause        (weight 0.08)
      6  business_impact        (weight 0.10)
      7  step_efficiency        (weight 0.07)
      8  plan_coverage          (weight 0.10)
      9  plan_evidence_quality  (weight 0.07)

    Args:
        env_url: Base URL of the running CyberSOCEnv FastAPI server,
                 e.g. ``"http://localhost:8000"``.

    Returns:
        List of 10 callables matching the TRL GRPO signature
        ``reward_fn(completions, **kwargs) -> List[float]``.

    Example::

        from trl import GRPOTrainer, GRPOConfig
        from training.reward_funcs import make_soc_reward_funcs

        reward_fns = make_soc_reward_funcs("http://localhost:8000")
        trainer = GRPOTrainer(
            model=model,
            reward_funcs=reward_fns,
            args=GRPOConfig(...),
        )
    """
    return [_make_dimension_reward_fn(env_url, dim) for dim in DIMENSION_NAMES]
