#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
CyberSOCEnv Baseline Inference Script.

HACKATHON RULES:
  - File must be named inference.py in the project root
  - Must use OpenAI Client for all LLM calls
  - Must emit structured stdout logs: [START], [STEP], [END]
  - Runtime < 20 minutes
  - Must work on vcpu=2, memory=8gb

Environment Variables:
    API_BASE_URL  - The API endpoint for the LLM
    MODEL_NAME    - The model identifier to use for inference
    HF_TOKEN      - Your Hugging Face / API key
"""

import asyncio
import json
import os
import textwrap
from typing import Any, Dict, List, Optional

from openai import OpenAI

from models import SOCActionWrapper, SOCObservation
from server.play_environment import CyberSOCEnvironment

# =============================================================================
# Configuration (from environment variables)
# =============================================================================

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

BENCHMARK = "cybersocenv"
TASKS = ["easy", "medium", "hard"]
MAX_STEPS = {"easy": 15, "medium": 25, "hard": 30}
TEMPERATURE = 0.1
MAX_TOKENS = 1024

# Scoring: normalize rewards to [0, 1]
MAX_POSSIBLE_REWARD = 2.0  # Approximate max reward per episode
SUCCESS_SCORE_THRESHOLD = 0.3

# =============================================================================
# System Prompt
# =============================================================================

SYSTEM_PROMPT = textwrap.dedent("""
    You are an expert Cybersecurity SOC (Security Operations Center) Analyst AI.
    You are responding to security incidents on a 500-node enterprise network.

    Your goal: Investigate alerts, contain all threats, and submit a containment plan — while minimizing business downtime.

    Available Actions (respond with exactly ONE JSON object per turn):

    1. Query a host: {"type": "query_host", "hostname": "<HOST>"}
    2. Isolate a segment (causes downtime): {"type": "isolate_segment", "subnet": "<SUBNET>", "reason": "<WHY>"}
    3. Block an IOC: {"type": "block_ioc", "ioc_value": "<VALUE>", "ioc_type": "ip|domain|hash"}
    4. Run forensics: {"type": "run_forensics", "hostname": "<HOST>"}
    5. Kill a process: {"type": "kill_process", "hostname": "<HOST>", "process_name": "<PROC>"}
    6. Submit containment plan (ends episode): {"type": "submit_containment_plan", "plan": [{"threat_id": "<ID>", "actions_taken": [...], "root_cause": "<CAUSE>", "confidence": 0.0-1.0}], "executive_summary": "<SUMMARY>"}

    Rules:
    - Respond with ONLY a valid JSON object. No markdown, no explanation.
    - Investigate before acting. Query hosts and run forensics to gather evidence.
    - Block IOCs (IPs, domains, hashes) found in alerts and forensics.
    - Kill malicious processes found via forensics.
    - Avoid unnecessary subnet isolation — it increases business impact.
    - Submit the containment plan once you've contained all threats.
    - You have a limited number of steps. Be efficient.
""").strip()


# =============================================================================
# Logging Helpers (EXACT hackathon format — lowercase booleans, null errors)
# =============================================================================

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


# =============================================================================
# Observation Formatting for LLM
# =============================================================================

def format_observation(obs: SOCObservation) -> str:
    """Format observation into readable text for the LLM."""
    parts = []

    # Alert queue
    if obs.alert_queue:
        parts.append(f"## Active Alerts ({len(obs.alert_queue)}):")
        for a in obs.alert_queue:
            parts.append(
                f"  - [{a.severity.value.upper()}] {a.alert_id} "
                f"on {a.source_host} ({a.subnet}): {a.description}"
            )
            if a.ioc_indicators:
                parts.append(f"    IOCs: {', '.join(a.ioc_indicators)}")

    # Network topology
    topo = obs.network_topology
    parts.append(f"\n## Network Status:")
    parts.append(f"  Compromised: {topo.compromised_count} | "
                 f"Isolated: {topo.isolated_count} | "
                 f"Online: {topo.online_count}")

    # Forensics
    if obs.host_forensics:
        f = obs.host_forensics
        parts.append(f"\n## Forensics Result ({f.hostname}):")
        parts.append(f"  Compromised: {f.is_compromised}")
        parts.append(f"  Malicious processes: {f.malicious_processes}")
        parts.append(f"  Suspicious files: {f.suspicious_files}")
        parts.append(f"  Network connections: {f.network_connections}")
        parts.append(f"  Memory artifacts: {f.memory_artifacts}")

    # Active threats
    parts.append(f"\n## Active Threats: {obs.active_threats if obs.active_threats else 'None (all contained!)'}")
    parts.append(f"## Business Impact: {obs.business_impact_score:.2f}")
    parts.append(f"## Step: {obs.step_count} / {obs.max_steps}")

    # Timeline (last 5)
    if obs.timeline:
        parts.append(f"\n## Recent Actions:")
        for t in obs.timeline[-5:]:
            parts.append(f"  Step {t.step}: {t.action_type} -> {t.target} (reward={t.reward:.2f})")

    return "\n".join(parts)


def parse_llm_action(content: str) -> Dict[str, Any]:
    """Parse the LLM's response into a valid action dict."""
    content = content.strip()
    if content.startswith("```"):
        lines = content.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        content = "\n".join(lines).strip()

    try:
        action = json.loads(content)
        if isinstance(action, dict) and "type" in action:
            return action
    except json.JSONDecodeError:
        pass

    # Try to find JSON in the response
    for start in range(len(content)):
        if content[start] == "{":
            for end in range(len(content), start, -1):
                if content[end - 1] == "}":
                    try:
                        action = json.loads(content[start:end])
                        if isinstance(action, dict) and "type" in action:
                            return action
                    except json.JSONDecodeError:
                        continue

    raise ValueError(f"Could not parse action from LLM response: {content[:200]}")


def get_model_action(
    client: OpenAI,
    step: int,
    obs: SOCObservation,
    task_id: str,
    history: List[str],
) -> str:
    """Get the next action from the LLM."""
    obs_text = format_observation(obs)

    if step == 1:
        user_content = (
            f"## Incident Briefing (Task: {task_id.upper()})\n\n"
            f"{obs_text}\n\n"
            f"Analyze the alerts and begin your investigation. Respond with a single JSON action."
        )
    else:
        user_content = (
            f"## Observation after your action:\n\n"
            f"{obs_text}\n\n"
            f"Continue your investigation. Respond with a single JSON action."
        )

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
            stream=False,
        )
        text = (completion.choices[0].message.content or "").strip()
        return text if text else '{"type": "query_host", "hostname": "WS-001"}'
    except Exception as exc:
        if "429" in str(exc) or "RateLimit" in str(exc):
            raise  # Let the batch runner handle rate limits
        print(f"[DEBUG] Model request failed: {exc}", flush=True)
        return '{"type": "query_host", "hostname": "WS-001"}'


# =============================================================================
# Episode Runner
# =============================================================================

async def run_episode(client: OpenAI, task_id: str) -> tuple:
    """Run a single episode. Returns (success, steps, score, rewards)."""
    env = CyberSOCEnvironment()
    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)

    try:
        # Reset environment
        obs = env.reset(task_id=task_id)

        max_steps = MAX_STEPS.get(task_id, 30)

        for step in range(1, max_steps + 1):
            if obs.done:
                break

            # Get action from LLM
            llm_response = get_model_action(client, step, obs, task_id, history)

            # Parse and execute
            error = None
            action_str = "unknown"
            reward = 0.0

            try:
                action_dict = parse_llm_action(llm_response)
                action_str = action_dict.get("type", "unknown")
                action = SOCActionWrapper(**action_dict)
                obs = env.step(action)
                reward = obs.reward or 0.0
                done = obs.done
            except Exception as exc:
                error = str(exc)[:200]
                done = False
                reward = 0.0

            rewards.append(reward)
            steps_taken = step

            log_step(step=step, action=action_str, reward=reward, done=done, error=error)

            history.append(f"Step {step}: {action_str} -> reward {reward:+.2f}")

            if done:
                break

        # Calculate score from final_score if available, else normalize rewards
        if obs.final_score is not None:
            score = obs.final_score
        else:
            score = sum(rewards) / MAX_POSSIBLE_REWARD if MAX_POSSIBLE_REWARD > 0 else 0.0

        score = min(max(score, 0.0), 1.0)  # clamp to [0, 1]
        success = score >= SUCCESS_SCORE_THRESHOLD

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

    return success, steps_taken, score, rewards


# =============================================================================
# Main
# =============================================================================

async def main() -> None:
    """Run baseline inference across all tasks."""
    client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)

    total_scores = {}
    for task_id in TASKS:
        success, steps, score, rewards = await run_episode(client, task_id)
        total_scores[task_id] = score

    # Print summary
    avg = sum(total_scores.values()) / len(total_scores) if total_scores else 0.0
    print(f"\n# Summary: avg_score={avg:.3f}", flush=True)
    for tid, s in total_scores.items():
        print(f"#   {tid}: {s:.3f}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
