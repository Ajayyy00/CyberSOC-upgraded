"""
Collect imitation data from deterministic red-team decisions (Day 1 warm-start).

Runs scripted Blue rollouts across generated scenarios while the env's embedded
deterministic Red policy fires on each Blue step (adaptive=True path).  Each
(red_observation → red_action) pair is written as JSONL to disk for offline SFT.

Usage:
    python -m training.collect_sft [--output PATH] [--num-tasks N] [--task-prefix PREFIX]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from models import SOCActionWrapper
from server.play_environment import CyberSOCEnvironment
from server.tasks import get_task


# ---------------------------------------------------------------------------
# Scripted Blue rollout (triggers Red dynamics each step)
# ---------------------------------------------------------------------------

def _scripted_blue_actions(task_def: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate deterministic Blue containment actions from task requirements."""
    reqs = task_def.get("containment_requirements", {}) or {}
    actions: List[Dict[str, Any]] = []

    for host in reqs.get("must_forensics", []):
        actions.append({"type": "run_forensics", "hostname": host})

    for proc in reqs.get("must_kill", []):
        actions.append({
            "type": "kill_process",
            "hostname": proc["hostname"],
            "process_name": proc["process"],
        })

    for ioc in reqs.get("must_block_iocs", []):
        if len(ioc) >= 32 and "." not in ioc:
            ioc_type = "hash"
        elif ioc.count(".") == 3:
            ioc_type = "ip"
        else:
            ioc_type = "domain"
        actions.append({"type": "block_ioc", "ioc_type": ioc_type, "ioc_value": ioc})

    # Final plan submission
    actions.append({
        "type": "submit_containment_plan",
        "plan": [
            {
                "threat_id": t.get("threat_id", "UNKNOWN"),
                "actions_taken": ["run_forensics", "kill_process", "block_ioc"],
                "root_cause": t.get("threat_type", "unknown"),
                "confidence": 0.8,
            }
            for t in task_def.get("attack_chain", [])
        ],
        "executive_summary": "Automated containment sequence completed.",
    })
    return actions


# ---------------------------------------------------------------------------
# Dataset collection
# ---------------------------------------------------------------------------

def collect_red_imitation_dataset(
    output_path: Path,
    num_tasks: int = 1000,
    task_prefix: str = "gen_",
) -> int:
    """Run Blue rollouts and capture deterministic Red decisions as JSONL.

    Args:
        output_path: Destination file (.jsonl).
        num_tasks: Number of procedurally generated scenarios to iterate over.
        task_prefix: Prefix for generated task IDs (default "gen_").

    Returns:
        Total number of (observation, action) records written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    records: List[Dict[str, Any]] = []

    def _logger(record: Dict[str, Any]) -> None:
        # Filter out pass_turn-only episodes to keep the dataset action-rich
        if record.get("action", {}).get("type") != "pass_turn":
            records.append(record)

    # adaptive=True activates the deterministic fallback Red policy inside the env
    env = CyberSOCEnvironment(adaptive=True, red_team_logger=_logger)

    for idx in range(1, num_tasks + 1):
        task_id = f"{task_prefix}{idx:04d}"
        try:
            task_def = get_task(task_id)
        except Exception:
            continue

        try:
            env.reset(task_id=task_id)
        except Exception:
            continue

        for action in _scripted_blue_actions(task_def):
            try:
                obs = env.step(SOCActionWrapper(**action))
            except Exception:
                break
            if obs.done:
                break

        if idx % 100 == 0:
            print(f"  [{idx}/{num_tasks}] {len(records)} records so far")

    with output_path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    return len(records)


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect deterministic Red-team SFT imitation data"
    )
    parser.add_argument(
        "--output",
        default="training/data/red_imitation.jsonl",
        help="Output JSONL path",
    )
    parser.add_argument(
        "--num-tasks",
        type=int,
        default=1000,
        help="Number of generated scenarios to run",
    )
    parser.add_argument(
        "--task-prefix",
        default="gen_",
        help="Prefix for generated task IDs (e.g. 'gen_' → gen_0001..gen_1000)",
    )
    args = parser.parse_args()

    total = collect_red_imitation_dataset(
        output_path=Path(args.output),
        num_tasks=args.num_tasks,
        task_prefix=args.task_prefix,
    )
    print(f"Saved {total} red decision examples to {args.output}")


if __name__ == "__main__":
    main()
