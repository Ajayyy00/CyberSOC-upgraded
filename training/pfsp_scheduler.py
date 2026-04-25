"""PFSP temperature scheduling and weighted opponent sampling."""

from __future__ import annotations

from typing import Dict, Iterable, Tuple


def temperature_for_iteration(
    iteration: int,
    total_iterations: int,
    start_temp: float = 0.5,
    end_temp: float = 2.0,
) -> float:
    if total_iterations <= 1:
        return end_temp
    ratio = max(0.0, min(1.0, iteration / float(total_iterations - 1)))
    return start_temp + (end_temp - start_temp) * ratio


def pfsp_weights(
    win_rates: Dict[str, float],
    temperature: float,
) -> Dict[str, float]:
    """Compute PFSP weights = (1 - blue_win_rate) ** temperature."""
    weights: Dict[str, float] = {}
    for name, win_rate in win_rates.items():
        clipped = max(0.0, min(1.0, float(win_rate)))
        weights[name] = max(1e-6, (1.0 - clipped) ** temperature)
    return weights


def normalize_weights(raw_weights: Dict[str, float]) -> Dict[str, float]:
    total = sum(raw_weights.values())
    if total <= 0:
        n = max(1, len(raw_weights))
        return {k: 1.0 / n for k in raw_weights}
    return {k: v / total for k, v in raw_weights.items()}


def rank_hard_opponents(win_rates: Dict[str, float]) -> Iterable[Tuple[str, float]]:
    """Yield opponents ordered from hardest (lowest win-rate) to easiest."""
    return sorted(win_rates.items(), key=lambda kv: kv[1])
