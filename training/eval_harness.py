"""Evaluation harness for Blue-vs-Red checkpoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List

from models import SOCActionWrapper
from server.play_environment import CyberSOCEnvironment


PolicyFn = Callable[[Dict[str, Any]], Dict[str, Any]]


@dataclass
class EvalResult:
    episodes: int
    blue_win_rate: float
    avg_blue_score: float
    per_episode_scores: List[float]


def run_head_to_head_eval(
    blue_policy: PolicyFn,
    red_policy: Any,
    task_ids: List[str],
    episodes_per_task: int = 50,
) -> EvalResult:
    """Evaluate blue against a frozen red policy across task IDs."""
    scores: List[float] = []
    wins = 0
    total = 0

    for task_id in task_ids:
        for _ in range(episodes_per_task):
            env = CyberSOCEnvironment(adaptive=True, neural_red_policy=red_policy)
            obs = env.reset(task_id=task_id)

            while not obs.done:
                action_dict = blue_policy(obs.model_dump())
                obs = env.step(SOCActionWrapper(**action_dict))

            score = float(obs.final_score or 0.0)
            scores.append(score)
            wins += int(score >= 0.5)
            total += 1

    avg_score = sum(scores) / max(1, len(scores))
    return EvalResult(
        episodes=total,
        blue_win_rate=wins / max(1, total),
        avg_blue_score=avg_score,
        per_episode_scores=scores,
    )


def must_beat_all_archive(win_rates: Dict[str, float], threshold: float = 0.55) -> bool:
    return all(rate >= threshold for rate in win_rates.values())
