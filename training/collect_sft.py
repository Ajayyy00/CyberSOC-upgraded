"""
Collect imitation data from deterministic red-team decisions.

This script runs generated scenarios and stores red decision tuples as JSONL:
{"observation": {...}, "action": {...}}
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from models import SOCActionWrapper
from server.play_environment import CyberSOCEnvironment
from server.tasks import get_task


def _scripted_blue_actions(task_id: str) -> List[Dict[str, Any]]:
    """Simple deterministic blue rollout to trigger red dynamics each step."""
    task_def = get_task(task_id)
    reqs = task_def.get("containment_requirements", {}) or {}
    actions: List[Dict[str, Any]] = []

    for host in reqs.get("must_forensics", []):
        actions.append({"type": "run_forensics", "hostname": host})

    for proc in reqs.get("must_kill", []):
        actions.append(
            {
                "type": "kill_process",
                "hostname": proc["hostname"],
                "process_name": proc["process"],
            }
        )

    for ioc in reqs.get("must_block_iocs", []):
        ioc_type = "hash" if len(ioc) >= 32 and "." not in ioc else ("ip" if ioc.count(".") == 3 else "domain")
        actions.append({"type": "block_ioc", "ioc_type": ioc_type, "ioc_value": ioc})

    actions.append(
        {
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
        }
    )
    return actions


def collect_red_imitation_dataset(
    output_path: Path,
    num_tasks: int = 1000,
    task_prefix: str = "gen_",
) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    records: List[Dict[str, Any]] = []

    def _logger(record: Dict[str, Any]) -> None:
        records.append(record)

    env = CyberSOCEnvironment(adaptive=True, red_team_logger=_logger)

    for idx in range(1, num_tasks + 1):
        task_id = f"{task_prefix}{idx:04d}"
        env.reset(task_id=task_id)
        for action in _scripted_blue_actions(task_id):
            obs = env.step(SOCActionWrapper(**action))
            if obs.done:
                break

    with output_path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    return len(records)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect deterministic red-team SFT data")
    parser.add_argument(
        "--output",
        default="training/data/red_imitation.jsonl",
        help="Output JSONL path",
    )
    parser.add_argument("--num-tasks", type=int, default=1000, help="Number of generated scenarios")
    parser.add_argument("--task-prefix", default="gen_", help="Task ID prefix")
    args = parser.parse_args()

    total = collect_red_imitation_dataset(
        output_path=Path(args.output),
        num_tasks=args.num_tasks,
        task_prefix=args.task_prefix,
    )
    print(f"Saved {total} red decision examples to {args.output}")


if __name__ == "__main__":
    main()
