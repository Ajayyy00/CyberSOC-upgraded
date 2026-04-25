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
    API_BASE_URL      - The API endpoint for the LLM
    MODEL_NAME        - Blue Team model identifier
    RED_MODEL_NAME    - Red Team model identifier (defaults to MODEL_NAME)
    HF_TOKEN          - Your Hugging Face / API key
    FSP_MODE          - Set to "true" to enable Fictitious Self-Play (Blue+Red alternate)
"""

import asyncio
import json
import os
import textwrap
from typing import Any, Dict, List, Optional

from openai import OpenAI

from models import SOCActionWrapper, RedActionWrapper, SOCObservation
from server.play_environment import CyberSOCEnvironment

# =============================================================================
# Configuration (from environment variables)
# =============================================================================

API_BASE_URL   = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME     = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
RED_MODEL_NAME = os.getenv("RED_MODEL_NAME", MODEL_NAME)   # defaults to same model
HF_TOKEN       = os.getenv("HF_TOKEN")
FSP_MODE       = os.getenv("FSP_MODE", "false").lower() == "true"

BENCHMARK = "cybersocenv"
TASKS     = ["easy", "medium", "hard"]
MAX_STEPS = {"easy": 15, "medium": 25, "hard": 30}

TEMPERATURE = 0.1
MAX_TOKENS  = 1024

MAX_POSSIBLE_REWARD    = 2.0
SUCCESS_SCORE_THRESHOLD = 0.3

# =============================================================================
# Blue Team System Prompt
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
# Red Team System Prompt (FSP mode)
# =============================================================================

RED_SYSTEM_PROMPT = textwrap.dedent("""
    You are an adversarial Red Team AI in a cybersecurity simulation.
    You have already gained an initial foothold on the network and must expand your attack
    while evading the Blue Team SOC analyst who is trying to contain you.

    Your goal: spread to new hosts, deploy payloads to maximize business impact, and evade
    detection — all before the Blue Team shuts you down.

    Available Actions (respond with exactly ONE JSON object per turn):

    1. Lateral pivot to a new host:
       {"type": "lateral_pivot", "source_host": "<COMPROMISED_HOST>", "target_host": "<TARGET>"}

    2. Deploy a payload on a host you control:
       {"type": "deploy_payload", "hostname": "<HOST>", "payload_type": "ransomware|exfiltration|c2"}

    3. Evade detection on a host you control:
       {"type": "evade_detection", "hostname": "<HOST>", "technique": "migrate_pid|clear_logs"}

    4. Stay stealthy (do nothing this turn):
       {"type": "pass_turn"}

    Rules:
    - Respond with ONLY a valid JSON object. No markdown, no explanation.
    - You can only pivot FROM a host listed in compromised_hosts.
    - You cannot pivot TO an isolated host — Blue has cut that path.
    - Use evade_detection when Blue runs forensics on your hosts.
    - Use pass_turn when staying hidden is more valuable than acting.
    - Ransomware causes the most business damage; use it on high-value hosts.
""").strip()

# =============================================================================
# Logging Helpers (EXACT hackathon format)
# =============================================================================

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val  = str(done).lower()
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
# Observation Formatting
# =============================================================================

def format_observation(obs: SOCObservation) -> str:
    """Format Blue Team observation into readable text for the LLM."""
    parts = []

    if obs.alert_queue:
        parts.append(f"## Active Alerts ({len(obs.alert_queue)}):")
        for a in obs.alert_queue:
            parts.append(
                f"  - [{a.severity.value.upper()}] {a.alert_id} "
                f"on {a.source_host} ({a.subnet}): {a.description}"
            )
            if a.ioc_indicators:
                parts.append(f"    IOCs: {', '.join(a.ioc_indicators)}")

    topo = obs.network_topology
    parts.append(f"\n## Network Status:")
    parts.append(
        f"  Compromised: {topo.compromised_count} | "
        f"Isolated: {topo.isolated_count} | "
        f"Online: {topo.online_count}"
    )

    if obs.host_forensics:
        f = obs.host_forensics
        parts.append(f"\n## Forensics Result ({f.hostname}):")
        parts.append(f"  Compromised: {f.is_compromised}")
        parts.append(f"  Malicious processes: {f.malicious_processes}")
        parts.append(f"  Suspicious files: {f.suspicious_files}")
        parts.append(f"  Network connections: {f.network_connections}")
        parts.append(f"  Memory artifacts: {f.memory_artifacts}")

    parts.append(f"\n## Active Threats: {obs.active_threats if obs.active_threats else 'None (all contained!)'}")
    parts.append(f"## Business Impact: {obs.business_impact_score:.2f}")
    parts.append(f"## Step: {obs.step_count} / {obs.max_steps}")

    if obs.timeline:
        parts.append(f"\n## Recent Actions:")
        for t in obs.timeline[-5:]:
            if not t.action_type.startswith("red:"):
                parts.append(f"  Step {t.step}: {t.action_type} -> {t.target} (reward={t.reward:.2f})")

    return "\n".join(parts)


def format_red_observation(red_obs: Dict[str, Any]) -> str:
    """Format Red Team observation into readable text for the Red LLM."""
    parts = []

    parts.append(f"## Round: {red_obs.get('round', '?')}")

    compromised = red_obs.get("compromised_hosts", [])
    parts.append(f"\n## Your Compromised Hosts ({len(compromised)}):")
    for h in compromised:
        parts.append(f"  - {h}")

    blue_actions = red_obs.get("blue_actions_detected", [])
    if blue_actions:
        parts.append("\n## Blue Team's Last Action (detected):")
        for ba in blue_actions:
            parts.append(f"  Step {ba['step']}: {ba['action']} -> {ba['target']}")
    else:
        parts.append("\n## Blue Team's Last Action: (none detected yet)")

    parts.append(f"\n## Active Threats Still Live: {red_obs.get('active_threats', [])}")
    parts.append(f"## Business Impact So Far: {red_obs.get('business_impact', 0.0):.2f}")

    return "\n".join(parts)


# =============================================================================
# LLM Action Parsing
# =============================================================================

def parse_llm_action(content: str) -> Dict[str, Any]:
    """Parse the LLM's response into a valid action dict."""
    content = content.strip()
    if content.startswith("```"):
        lines = [l for l in content.split("\n") if not l.strip().startswith("```")]
        content = "\n".join(lines).strip()

    try:
        action = json.loads(content)
        if isinstance(action, dict) and "type" in action:
            return action
    except json.JSONDecodeError:
        pass

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


# =============================================================================
# LLM Callers
# =============================================================================

def get_model_action(
    client: OpenAI,
    step: int,
    obs: SOCObservation,
    task_id: str,
    history: List[str],
) -> str:
    """Get the next Blue Team action from the LLM."""
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
                {"role": "user",   "content": user_content},
            ],
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
            stream=False,
        )
        text = (completion.choices[0].message.content or "").strip()
        return text if text else '{"type": "query_host", "hostname": "WS-001"}'
    except Exception as exc:
        if "429" in str(exc) or "RateLimit" in str(exc):
            raise
        print(f"[DEBUG] Blue model request failed: {exc}", flush=True)
        return '{"type": "query_host", "hostname": "WS-001"}'


def get_red_model_action(
    client: OpenAI,
    step: int,
    red_obs: Dict[str, Any],
    task_id: str,
) -> str:
    """Get the next Red Team action from the Red LLM."""
    obs_text = format_red_observation(red_obs)

    compromised = red_obs.get("compromised_hosts", [])
    if not compromised:
        return '{"type": "pass_turn"}'

    if step == 1:
        user_content = (
            f"## Mission Briefing (Task: {task_id.upper()})\n\n"
            f"{obs_text}\n\n"
            f"You have initial footholds. Plan your next move. Respond with a single JSON action."
        )
    else:
        user_content = (
            f"## Situation Update:\n\n"
            f"{obs_text}\n\n"
            f"Choose your next Red Team action. Respond with a single JSON action."
        )

    try:
        completion = client.chat.completions.create(
            model=RED_MODEL_NAME,
            messages=[
                {"role": "system", "content": RED_SYSTEM_PROMPT},
                {"role": "user",   "content": user_content},
            ],
            temperature=TEMPERATURE,
            max_tokens=512,
            stream=False,
        )
        text = (completion.choices[0].message.content or "").strip()
        return text if text else '{"type": "pass_turn"}'
    except Exception as exc:
        if "429" in str(exc) or "RateLimit" in str(exc):
            raise
        print(f"[DEBUG] Red model request failed: {exc}", flush=True)
        return '{"type": "pass_turn"}'


# =============================================================================
# Episode Runner
# =============================================================================

async def run_episode(
    blue_client: OpenAI,
    task_id: str,
    red_client: Optional[OpenAI] = None,
    fsp: bool = False,
) -> tuple:
    """Run a single episode. Returns (success, steps, score, rewards).

    Args:
        blue_client: OpenAI client for the Blue Team LLM.
        task_id:     Task difficulty ('easy', 'medium', 'hard').
        red_client:  OpenAI client for the Red Team LLM (FSP mode only).
                     Falls back to blue_client when None.
        fsp:         When True, enables Fictitious Self-Play (Blue + Red alternate).
    """
    if red_client is None:
        red_client = blue_client

    env = CyberSOCEnvironment(fsp_mode=fsp)
    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0
    score  = 0.0
    success = False

    log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)

    try:
        obs = env.reset(task_id=task_id)
        max_steps = MAX_STEPS.get(task_id, 30)

        for step in range(1, max_steps + 1):
            if obs.done:
                break

            # ── Blue Turn ────────────────────────────────────────────────────
            blue_response = get_model_action(blue_client, step, obs, task_id, history)

            error      = None
            action_str = "unknown"
            reward     = 0.0
            done       = False

            try:
                action_dict = parse_llm_action(blue_response)
                action_str  = action_dict.get("type", "unknown")
                blue_action = SOCActionWrapper(**action_dict)
                obs         = env.step(blue_action)
                reward      = obs.reward or 0.0
                done        = obs.done
            except Exception as exc:
                error = str(exc)[:200]
                done  = False

            rewards.append(reward)
            steps_taken = step
            log_step(step=step, action=action_str, reward=reward, done=done, error=error)
            history.append(f"Step {step} [Blue]: {action_str} -> reward {reward:+.2f}")

            if done:
                break

            # ── Red Turn (FSP mode only) ──────────────────────────────────────
            if fsp and getattr(obs, "active_turn", "blue") == "red":
                red_obs_data = obs.red_observation or {}
                red_response = get_red_model_action(red_client, step, red_obs_data, task_id)

                try:
                    red_dict   = parse_llm_action(red_response)
                    red_action = RedActionWrapper(**red_dict)
                    obs        = env.step(red_action)
                    done       = obs.done
                except Exception as exc:
                    print(f"[DEBUG] Red action failed: {exc}", flush=True)
                    # Fall back to PassTurn to close the round
                    try:
                        obs  = env.step(RedActionWrapper(type="pass_turn"))
                        done = obs.done
                    except Exception:
                        pass

                history.append(
                    f"Step {step} [Red]: {red_dict.get('type', 'pass_turn')}"
                )

                if done:
                    break

        # Final score
        if obs.final_score is not None:
            score = obs.final_score
        else:
            score = sum(rewards) / MAX_POSSIBLE_REWARD if MAX_POSSIBLE_REWARD > 0 else 0.0
        score   = min(max(score, 0.0), 1.0)
        success = score >= SUCCESS_SCORE_THRESHOLD

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

    return success, steps_taken, score, rewards


# =============================================================================
# Main
# =============================================================================

async def main() -> None:
    """Run baseline inference across all tasks."""
    blue_client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
    red_client  = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN) if FSP_MODE else None

    total_scores: Dict[str, float] = {}
    for task_id in TASKS:
        success, steps, score, rewards = await run_episode(
            blue_client=blue_client,
            task_id=task_id,
            red_client=red_client,
            fsp=FSP_MODE,
        )
        total_scores[task_id] = score

    avg = sum(total_scores.values()) / len(total_scores) if total_scores else 0.0
    print(f"\n# Summary: avg_score={avg:.3f}", flush=True)
    for tid, s in total_scores.items():
        print(f"#   {tid}: {s:.3f}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
