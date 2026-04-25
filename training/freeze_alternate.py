"""Freeze-alternate orchestration for Blue/Red GRPO training.

Iteration loop:
  1. Train Blue N episodes vs a PFSP-sampled frozen Red.
  2. Run eval: update blue_win_rate metadata in the archive for each Red.
  3. must_beat_all gate: Blue must beat every archived Red at ≥ threshold.
  4. Train Red M episodes vs the latest frozen Blue.
  5. Archive both checkpoints; advance iteration.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Dict, Optional

try:
    from .agent_archive import AgentArchive
    from .pfsp_scheduler import temperature_for_iteration
except ImportError:
    from agent_archive import AgentArchive
    from pfsp_scheduler import temperature_for_iteration


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(command: str) -> None:
    completed = subprocess.run(command, shell=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"Training command failed (exit {completed.returncode}): {command}")


def _format_cmd(
    base_cmd: str,
    role: str,
    output_dir: str,
    frozen_opponent: Optional[str],
    episodes: int,
) -> str:
    parts = [
        base_cmd,
        f"--train-role {role}",
        f"--output-dir {output_dir}",
        f"--episodes {episodes}",
    ]
    if frozen_opponent:
        parts.append(f"--frozen-opponent {frozen_opponent}")
    return " ".join(parts)


def _run_eval_update(
    eval_cmd: str,
    blue_ckpt: str,
    archive: AgentArchive,
) -> None:
    """Run the eval harness script and parse its JSON output to update archive metadata.

    The eval command must write a JSON object mapping red_version → blue_win_rate
    to stdout and exit 0. Example output:
        {"red_v1": 0.62, "red_v2": 0.51}

    This is optional: if eval_cmd is empty, metadata is not updated.
    """
    if not eval_cmd:
        return

    cmd = f"{eval_cmd} --blue-checkpoint {blue_ckpt}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[eval] WARNING: eval command failed — skipping gate update\n{result.stderr}")
        return

    try:
        win_rates: Dict[str, float] = json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        print(f"[eval] WARNING: could not parse eval output: {result.stdout[:200]}")
        return

    for agent in archive.list_role("red"):
        rate = win_rates.get(agent.version)
        if rate is not None:
            agent.metadata["blue_win_rate"] = float(rate)
    archive.save()
    print(f"[eval] updated win rates: {win_rates}")


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def run_freeze_alternate(
    iterations: int,
    train_blue_episodes: int,
    train_red_episodes: int,
    base_train_cmd: str,
    archive_path: str,
    eval_cmd: str = "",
    graduation_threshold: float = 0.55,
    pfsp_start_temp: float = 0.5,
    pfsp_end_temp: float = 2.0,
    skip_gate: bool = False,
) -> Dict[str, str]:
    """Run N freeze-alternate iterations.

    Args:
        iterations: Number of Blue/Red training rounds.
        train_blue_episodes: Steps per Blue training round.
        train_red_episodes: Steps per Red training round.
        base_train_cmd: Base training command (e.g. ``python -m training.train_grpo``).
        archive_path: Path to the archive index JSON.
        eval_cmd: Optional command to evaluate Blue vs all archived Reds and
            emit JSON win rates. When empty, gate check is skipped.
        graduation_threshold: Blue must achieve this win rate vs every archived
            Red before Red is trained (the ``must_beat_all`` gate).
        pfsp_start_temp: PFSP temperature at iteration 0 (broad sampling).
        pfsp_end_temp: PFSP temperature at iteration N-1 (focus on hardest).
        skip_gate: Skip the must_beat_all graduation check (CI/smoke use).

    Returns:
        Dict with ``latest_blue`` and ``latest_red`` checkpoint paths.
    """
    archive = AgentArchive(archive_path)
    latest_blue = archive.latest("blue")
    latest_red = archive.latest("red")

    for it in range(1, iterations + 1):
        temperature = temperature_for_iteration(
            it - 1, iterations, pfsp_start_temp, pfsp_end_temp
        )
        print(f"\n{'=' * 60}")
        print(f"  Iteration {it}/{iterations}  |  PFSP temp = {temperature:.2f}")
        print(f"{'=' * 60}")

        # ── 1. Train Blue vs PFSP-sampled frozen Red ──────────────────────────
        # Use PFSP sampling (temperature-weighted by difficulty) to pick opponent
        pfsp_red = archive.sample_pfsp("red", temperature=temperature) if archive.list_role("red") else None
        frozen_red_ckpt = pfsp_red.checkpoint_path if pfsp_red else (
            latest_red.checkpoint_path if latest_red else None
        )
        if pfsp_red and pfsp_red != latest_red:
            print(f"[blue] PFSP opponent: {pfsp_red.version} (blue_win_rate={pfsp_red.metadata.get('blue_win_rate', '?')})")

        blue_version = f"blue_v{it}"
        blue_ckpt = f"checkpoints/{blue_version}"
        cmd_blue = _format_cmd(
            base_cmd=base_train_cmd,
            role="blue",
            output_dir=blue_ckpt,
            frozen_opponent=frozen_red_ckpt,
            episodes=train_blue_episodes,
        )
        print(f"[blue] training {blue_version} ({train_blue_episodes} eps) ...")
        _run(cmd_blue)
        archive.add("blue", blue_version, blue_ckpt, iteration=it, metadata={})
        latest_blue = archive.latest("blue")

        # ── 2. Eval + must_beat_all graduation gate ───────────────────────────
        _run_eval_update(eval_cmd, blue_ckpt, archive)

        if not skip_gate and archive.list_role("red"):
            if not archive.must_beat_all(threshold=graduation_threshold):
                reds_below = [
                    f"{r.version}={r.metadata.get('blue_win_rate', '?')}"
                    for r in archive.list_role("red")
                    if float(r.metadata.get("blue_win_rate", 0.0)) < graduation_threshold
                ]
                print(
                    f"[gate] FAILED — Blue did not beat all archived Reds "
                    f"(threshold={graduation_threshold}): {reds_below}"
                )
                print("[gate] Skipping Red training this iteration.")
                continue
            print(f"[gate] PASSED — Blue beats all archived Reds at ≥{graduation_threshold}")

        # ── 3. Train Red vs latest frozen Blue ────────────────────────────────
        red_version = f"red_v{it}"
        red_ckpt = f"checkpoints/{red_version}"
        cmd_red = _format_cmd(
            base_cmd=base_train_cmd,
            role="red",
            output_dir=red_ckpt,
            frozen_opponent=latest_blue.checkpoint_path if latest_blue else None,
            episodes=train_red_episodes,
        )
        print(f"[red] training {red_version} ({train_red_episodes} eps) ...")
        _run(cmd_red)
        # Initialise win rate at 0.5 — will be updated by next eval round
        archive.add("red", red_version, red_ckpt, iteration=it, metadata={"blue_win_rate": 0.5})
        latest_red = archive.latest("red")

    return {
        "latest_blue": latest_blue.checkpoint_path if latest_blue else "",
        "latest_red": latest_red.checkpoint_path if latest_red else "",
    }


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze-alternate Blue/Red training orchestrator")
    parser.add_argument("--iterations",    type=int,   default=2)
    parser.add_argument("--blue-episodes", type=int,   default=500)
    parser.add_argument("--red-episodes",  type=int,   default=300)
    parser.add_argument("--train-cmd",     default="python -m training.train_grpo")
    parser.add_argument("--archive-path",  default="training/archive/index.json")
    parser.add_argument("--eval-cmd",      default="", help="Command that emits JSON win rates to stdout")
    parser.add_argument("--threshold",     type=float, default=0.55, help="must_beat_all threshold")
    parser.add_argument("--pfsp-start-temp", type=float, default=0.5)
    parser.add_argument("--pfsp-end-temp",   type=float, default=2.0)
    parser.add_argument("--skip-gate",     action="store_true", help="Skip graduation gate (CI/smoke)")
    parser.add_argument(
        "--show-temp-for",
        type=int,
        default=0,
        help="Print PFSP temperature schedule for N iterations and exit",
    )
    args = parser.parse_args()

    if args.show_temp_for > 0:
        schedule = {
            f"iter_{i + 1}": round(
                temperature_for_iteration(i, args.show_temp_for, args.pfsp_start_temp, args.pfsp_end_temp), 3
            )
            for i in range(args.show_temp_for)
        }
        print(json.dumps(schedule, indent=2))
        sys.exit(0)

    outputs = run_freeze_alternate(
        iterations=args.iterations,
        train_blue_episodes=args.blue_episodes,
        train_red_episodes=args.red_episodes,
        base_train_cmd=args.train_cmd,
        archive_path=args.archive_path,
        eval_cmd=args.eval_cmd,
        graduation_threshold=args.threshold,
        pfsp_start_temp=args.pfsp_start_temp,
        pfsp_end_temp=args.pfsp_end_temp,
        skip_gate=args.skip_gate,
    )
    print(json.dumps(outputs, indent=2))


if __name__ == "__main__":
    main()
