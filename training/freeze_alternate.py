"""Freeze-alternate orchestration for Blue/Red GRPO training."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Dict, Optional

try:
    from .agent_archive import AgentArchive
    from .pfsp_scheduler import temperature_for_iteration
except ImportError:
    from agent_archive import AgentArchive
    from pfsp_scheduler import temperature_for_iteration


def _run_train_command(command: str) -> None:
    completed = subprocess.run(command, shell=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"Training command failed: {command}")


def _format_cmd(
    base_cmd: str,
    role: str,
    output_dir: str,
    frozen_opponent: Optional[str],
    episodes: int,
) -> str:
    cmd = [
        base_cmd,
        f"--train-role {role}",
        f"--output-dir {output_dir}",
        f"--episodes {episodes}",
    ]
    if frozen_opponent:
        cmd.append(f"--frozen-opponent {frozen_opponent}")
    return " ".join(cmd)


def run_freeze_alternate(
    iterations: int,
    train_blue_episodes: int,
    train_red_episodes: int,
    base_train_cmd: str,
    archive_path: str,
) -> Dict[str, str]:
    archive = AgentArchive(archive_path)
    latest_blue = archive.latest("blue")
    latest_red = archive.latest("red")

    for it in range(1, iterations + 1):
        blue_version = f"blue_v{it}"
        blue_ckpt = f"checkpoints/{blue_version}"
        cmd_blue = _format_cmd(
            base_cmd=base_train_cmd,
            role="blue",
            output_dir=blue_ckpt,
            frozen_opponent=latest_red.checkpoint_path if latest_red else None,
            episodes=train_blue_episodes,
        )
        _run_train_command(cmd_blue)
        archive.add("blue", blue_version, blue_ckpt, iteration=it, metadata={})
        latest_blue = archive.latest("blue")

        red_version = f"red_v{it}"
        red_ckpt = f"checkpoints/{red_version}"
        cmd_red = _format_cmd(
            base_cmd=base_train_cmd,
            role="red",
            output_dir=red_ckpt,
            frozen_opponent=latest_blue.checkpoint_path if latest_blue else None,
            episodes=train_red_episodes,
        )
        _run_train_command(cmd_red)
        archive.add("red", red_version, red_ckpt, iteration=it, metadata={})
        latest_red = archive.latest("red")

    return {
        "latest_blue": latest_blue.checkpoint_path if latest_blue else "",
        "latest_red": latest_red.checkpoint_path if latest_red else "",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze-alternate Blue/Red training orchestrator")
    parser.add_argument("--iterations", type=int, default=2)
    parser.add_argument("--blue-episodes", type=int, default=500)
    parser.add_argument("--red-episodes", type=int, default=300)
    parser.add_argument("--train-cmd", default="python -m training.train_grpo")
    parser.add_argument("--archive-path", default="training/archive/index.json")
    parser.add_argument("--show-temp-for", type=int, default=0, help="Print PFSP temp schedule for N iterations")
    args = parser.parse_args()

    if args.show_temp_for > 0:
        schedule = {
            f"iter_{i + 1}": temperature_for_iteration(i, args.show_temp_for)
            for i in range(args.show_temp_for)
        }
        print(json.dumps(schedule, indent=2))
        return

    outputs = run_freeze_alternate(
        iterations=args.iterations,
        train_blue_episodes=args.blue_episodes,
        train_red_episodes=args.red_episodes,
        base_train_cmd=args.train_cmd,
        archive_path=args.archive_path,
    )
    print(json.dumps(outputs, indent=2))


if __name__ == "__main__":
    main()
