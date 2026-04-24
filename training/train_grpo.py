#!/usr/bin/env python3
"""
CyberSOC GRPO Training — HuggingFace Compute Edition
=====================================================
Trains a 7B LLM to act as a SOC analyst using Group Relative Policy Optimization
against the live CyberSOCEnv FastAPI environment.

Recommended GPU: A10G (24 GB) or A100 (40 GB)
Typical runtime: ~2-4 hours for 300 steps on A10G

Quick start (from MetaRound2/ directory):
    pip install -r requirements-training.txt
    HF_TOKEN=<your_token> python -m training.train_grpo

Custom run:
    python -m training.train_grpo \\
        --model unsloth/Qwen2.5-14B-Instruct \\
        --steps 500 \\
        --tasks medium,hard \\
        --hub-id your-username/soc-analyst-7b
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
import time
from typing import Any, Dict, List, Optional

import requests

try:
    from .config import TrainingConfig
    from .reward_funcs import _execute_completion, DIMENSION_NAMES
except ImportError:
    from config import TrainingConfig
    from reward_funcs import _execute_completion, DIMENSION_NAMES


# ═══════════════════════════════════════════════════════════════════════════
# 1. Environment Server Management
# ═══════════════════════════════════════════════════════════════════════════

class EnvServer:
    """Starts and monitors the CyberSOCEnv FastAPI server as a subprocess."""

    def __init__(self, cfg: TrainingConfig):
        self.cfg = cfg
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        cmd = [
            sys.executable, "-m", "uvicorn",
            "server:app",
            "--host", self.cfg.env_host,
            "--port", str(self.cfg.env_port),
            "--log-level", "warning",
        ]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        print(f"[server] PID {self._proc.pid} starting on :{self.cfg.env_port} ...")
        self._wait_healthy()

    def _wait_healthy(self) -> None:
        deadline = time.time() + self.cfg.server_startup_timeout
        while time.time() < deadline:
            try:
                r = requests.post(
                    f"{self.cfg.env_url}/reset",
                    json={"task_id": "easy"},
                    timeout=3,
                )
                if r.status_code == 200:
                    print("[server] ✓ healthy")
                    return
            except Exception:
                pass
            time.sleep(1)
        stderr = self._proc.stderr.read().decode() if self._proc else ""
        raise RuntimeError(f"Env server failed to start.\n{stderr}")

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            print("[server] stopped")


# ═══════════════════════════════════════════════════════════════════════════
# 2. Prompt Formatting
# ═══════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = textwrap.dedent("""
    You are an expert SOC (Security Operations Center) analyst responding to a live
    cybersecurity incident. Given the current environment state, output a complete JSON
    array of investigation and containment actions, ending with submit_containment_plan.

    AVAILABLE ACTIONS — use exact field names:
      {"type": "correlate_alerts",          "alert_ids": ["ID1", "ID2"]}
      {"type": "query_host",                "hostname": "HOSTNAME"}
      {"type": "run_forensics",             "hostname": "HOSTNAME"}
      {"type": "enrich_ioc",               "ioc_value": "VALUE", "ioc_type": "ip|domain|hash|filename"}
      {"type": "scan_host_vulnerabilities", "hostname": "HOSTNAME"}
      {"type": "block_ioc",                "ioc_value": "VALUE", "ioc_type": "ip|domain|hash"}
      {"type": "kill_process",             "hostname": "HOSTNAME", "process_name": "PROCESS"}
      {"type": "isolate_segment",          "subnet": "SUBNET", "reason": "REASON"}
      {"type": "trigger_playbook",         "playbook_name": "NAME", "target": "HOSTNAME"}
      {"type": "submit_containment_plan",  "plan": [
          {"threat_id": "T-ID", "actions_taken": ["action1"], "root_cause": "...", "confidence": 0.9}
        ], "executive_summary": "TEXT"}

    PLAYBOOK NAMES: ransomware_containment | c2_disruption | lateral_movement_lockdown |
                    phishing_response | data_exfil_stop

    STRATEGY (evidence-gated — actions only score if prior evidence justifies them):
    1. TRIAGE: correlate_alerts on related alerts (shared hosts or IOC indicators)
    2. INVESTIGATE: query_host then run_forensics on every alert source host
    3. ENRICH: enrich_ioc only on IOCs seen in alert ioc_indicators or forensics results
    4. SCAN: scan_host_vulnerabilities on confirmed-compromised hosts
    5. CONTAIN: kill malicious processes found in forensics; block relevant IOCs
    6. ISOLATE: isolate_segment only for subnets containing confirmed-compromised hosts
    7. REPORT: submit_containment_plan as the FINAL action — include every threat_id

    GRADED ON 10 dimensions:
      threat_containment (20%) · ioc_blocking (12%) · forensic_investigation (10%)
      siem_correlation (8%) · threat_intel_usage (8%) · vuln_root_cause (8%)
      business_impact (10%) · step_efficiency (7%) · plan_coverage (10%) · plan_evidence_quality (7%)

    Output ONLY a valid JSON array. No markdown fences, no explanation.
""").strip()


def _format_alerts(alerts: List[Dict]) -> str:
    lines = []
    for a in alerts:
        iocs = ", ".join(a.get("ioc_indicators", []))
        line = (
            f"  [{a.get('severity','?').upper()}] {a.get('alert_id','?')} | "
            f"{a.get('source_host','?')} | {a.get('threat_type','?')} | "
            f"{a.get('description','')[:90]}"
        )
        if iocs:
            line += f"\n    IOCs: {iocs}"
        lines.append(line)
    return "\n".join(lines)


def format_observation(obs: Dict[str, Any], task_id: str) -> str:
    """Convert a SOC observation dict into a structured LLM user-turn prompt."""
    alerts   = obs.get("alert_queue", [])
    topo     = obs.get("network_topology", {})
    threats  = obs.get("active_threats", [])
    playbooks = obs.get("available_playbooks", [])
    subnets  = " | ".join(f"{k}:{v}" for k, v in topo.get("subnets", {}).items())

    return "\n".join([
        f"TASK DIFFICULTY : {task_id.upper()}",
        f"MAX STEPS       : {obs.get('max_steps', 30)}",
        "",
        f"ALERT QUEUE ({len(alerts)} alerts):",
        _format_alerts(alerts),
        "",
        "NETWORK TOPOLOGY:",
        f"  Hosts: {topo.get('total_hosts','?')} total | "
        f"{topo.get('compromised_count', 0)} compromised | "
        f"{topo.get('isolated_count', 0)} isolated",
        f"  Subnets: {subnets}",
        "",
        f"ACTIVE THREAT IDs : {', '.join(threats) if threats else 'unknown — check alerts'}",
        f"AVAILABLE PLAYBOOKS: {', '.join(playbooks)}",
        "",
        "Generate your complete action sequence as a JSON array:",
    ])


def build_chat_prompt(obs: Dict[str, Any], task_id: str, tokenizer) -> str:
    """Apply the tokenizer's chat template to produce the final prompt string."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": format_observation(obs, task_id)},
    ]
    return tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True
    )


# ═══════════════════════════════════════════════════════════════════════════
# 3. Dataset Builder
# ═══════════════════════════════════════════════════════════════════════════

def build_dataset(cfg: TrainingConfig, tokenizer) -> "Dataset":  # type: ignore[name-defined]
    """
    Build training dataset by calling /reset for each task × prompts_per_task.
    Each row: {"prompt": <chat-formatted string>, "task_id": <str>}
    """
    from datasets import Dataset  # noqa: PLC0415

    rows: List[Dict[str, str]] = []
    for task_id in cfg.task_ids:
        for i in range(cfg.prompts_per_task):
            try:
                r = requests.post(
                    f"{cfg.env_url}/reset",
                    json={"task_id": task_id},
                    timeout=15,
                )
                r.raise_for_status()
                obs = r.json().get("observation", r.json())
                prompt = build_chat_prompt(obs, task_id, tokenizer)
                rows.append({"prompt": prompt, "task_id": task_id})
                print(f"  [{task_id}] prompt {i + 1}/{cfg.prompts_per_task} ✓")
            except Exception as e:
                print(f"  [warn] {task_id} prompt {i + 1} failed: {e}")

    if not rows:
        raise RuntimeError("Dataset is empty — check env server is running")

    print(f"[dataset] {len(rows)} prompts across {cfg.task_ids}")
    return Dataset.from_list(rows)


# ═══════════════════════════════════════════════════════════════════════════
# 4. Reward Functions (task-aware wrappers)
# ═══════════════════════════════════════════════════════════════════════════

# Dimension weights matching the grader
WEIGHTS: Dict[str, float] = {
    "threat_containment":     0.20,
    "ioc_blocking":           0.12,
    "forensic_investigation": 0.10,
    "siem_correlation":       0.08,
    "threat_intel_usage":     0.08,
    "vuln_root_cause":        0.08,
    "business_impact":        0.10,
    "step_efficiency":        0.07,
    "plan_coverage":          0.10,
    "plan_evidence_quality":  0.07,
}


def _extract_json(text: str) -> str:
    """Strip markdown fences if the model wraps output in ```json ... ```."""
    text = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]+?)```", text)
    if match:
        return match.group(1).strip()
    # Try to find a JSON array anywhere in the text
    match = re.search(r"(\[[\s\S]+\])", text)
    if match:
        return match.group(1).strip()
    return text


def _make_dimension_fn(env_url: str, dimension: str):
    """Task-aware reward function for one grading dimension."""

    def reward_fn(completions: List[str], **kwargs) -> List[float]:
        # TRL passes dataset columns as kwargs — extract task_id per sample
        raw_task_ids = kwargs.get("task_id", ["hard"] * len(completions))
        if isinstance(raw_task_ids, str):
            raw_task_ids = [raw_task_ids] * len(completions)

        scores: List[float] = []
        for completion, task_id in zip(completions, raw_task_ids):
            cleaned = _extract_json(completion)
            obs = _execute_completion(env_url, cleaned, task_id=task_id)
            if obs is None:
                scores.append(0.0)
                continue
            breakdown: dict = obs.get("grade_breakdown") or obs.get("reward_dimensions") or {}
            scores.append(float(breakdown.get(dimension, 0.0)))
        return scores

    reward_fn.__name__ = f"soc_{dimension}"
    return reward_fn


def _make_weighted_total_fn(env_url: str):
    """Weighted composite score across all 10 dimensions — used as the primary signal."""

    def reward_fn(completions: List[str], **kwargs) -> List[float]:
        raw_task_ids = kwargs.get("task_id", ["hard"] * len(completions))
        if isinstance(raw_task_ids, str):
            raw_task_ids = [raw_task_ids] * len(completions)

        scores: List[float] = []
        for completion, task_id in zip(completions, raw_task_ids):
            cleaned = _extract_json(completion)
            obs = _execute_completion(env_url, cleaned, task_id=task_id)
            if obs is None:
                scores.append(0.0)
                continue
            breakdown: dict = obs.get("grade_breakdown") or obs.get("reward_dimensions") or {}
            weighted = sum(breakdown.get(k, 0.0) * w for k, w in WEIGHTS.items())
            scores.append(float(weighted))
        return scores

    reward_fn.__name__ = "soc_weighted_total"
    return reward_fn


def make_all_reward_fns(env_url: str) -> List:
    """Return 11 reward functions: 10 per-dimension + 1 weighted composite."""
    fns = [_make_dimension_fn(env_url, dim) for dim in DIMENSION_NAMES]
    fns.append(_make_weighted_total_fn(env_url))
    return fns


# ═══════════════════════════════════════════════════════════════════════════
# 5. Main
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CyberSOC GRPO Training")
    p.add_argument("--model",     default="", help="HuggingFace model ID (overrides config)")
    p.add_argument("--steps",     type=int, default=0, help="Max training steps (overrides config)")
    p.add_argument("--tasks",     default="", help="Comma-separated task IDs, e.g. easy,medium,hard")
    p.add_argument("--hub-id",    default="", dest="hub_id", help="HF Hub model ID for checkpoint push")
    p.add_argument("--no-server", action="store_true", help="Skip starting env server (already running)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    cfg  = TrainingConfig()

    if args.model:  cfg.model_name   = args.model
    if args.steps:  cfg.max_steps    = args.steps
    if args.tasks:  cfg.task_ids     = args.tasks.split(",")
    if args.hub_id: cfg.hub_model_id = args.hub_id

    hf_token = os.environ.get("HF_TOKEN", "")

    print("=" * 60)
    print("  CyberSOC GRPO Training")
    print(f"  Model  : {cfg.model_name}")
    print(f"  Tasks  : {cfg.task_ids}")
    print(f"  Steps  : {cfg.max_steps}")
    print(f"  Hub    : {cfg.hub_model_id or '(local only)'}")
    print("=" * 60)

    # 1. Start env server ────────────────────────────────────────────────────
    server = EnvServer(cfg)
    if not args.no_server:
        server.start()

    try:
        # 2. Load model with Unsloth ─────────────────────────────────────────
        from unsloth import FastLanguageModel  # noqa: PLC0415
        from trl import GRPOTrainer, GRPOConfig  # noqa: PLC0415

        print(f"\n[model] loading {cfg.model_name} ...")
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=cfg.model_name,
            max_seq_length=cfg.max_seq_length,
            load_in_4bit=cfg.load_in_4bit,
            dtype=None,  # auto-detect (bfloat16 on Ampere+)
        )
        model = FastLanguageModel.get_peft_model(
            model,
            r=cfg.lora_r,
            target_modules=cfg.target_modules,
            lora_alpha=cfg.lora_alpha,
            lora_dropout=cfg.lora_dropout,
            bias="none",
            use_gradient_checkpointing="unsloth",
            random_state=cfg.seed,
        )
        print("[model] ✓ loaded with LoRA adapters")

        # 3. Build dataset ────────────────────────────────────────────────────
        print("\n[dataset] building prompts from env resets ...")
        dataset = build_dataset(cfg, tokenizer)

        # 4. Build reward functions ───────────────────────────────────────────
        print("\n[rewards] wiring 11 reward functions (10 dims + weighted total) ...")
        reward_fns = make_all_reward_fns(cfg.env_url)
        print(f"[rewards] ✓ {len(reward_fns)} functions registered")

        # 5. GRPO config ──────────────────────────────────────────────────────
        grpo_cfg = GRPOConfig(
            output_dir=cfg.output_dir,
            num_train_epochs=cfg.num_train_epochs,
            max_steps=cfg.max_steps,
            per_device_train_batch_size=cfg.per_device_train_batch_size,
            gradient_accumulation_steps=cfg.gradient_accumulation_steps,
            learning_rate=cfg.learning_rate,
            warmup_ratio=cfg.warmup_ratio,
            num_generations=cfg.num_generations,
            max_prompt_length=cfg.max_prompt_length,
            max_completion_length=cfg.max_completion_length,
            temperature=cfg.temperature,
            top_p=cfg.top_p,
            beta=cfg.beta,
            logging_steps=cfg.logging_steps,
            save_steps=cfg.save_steps,
            seed=cfg.seed,
            bf16=True,
            report_to="tensorboard",
            push_to_hub=bool(cfg.hub_model_id and hf_token),
            hub_model_id=cfg.hub_model_id or None,
            hub_strategy="checkpoint",
            hub_token=hf_token or None,
        )

        trainer = GRPOTrainer(
            model=model,
            tokenizer=tokenizer,
            reward_funcs=reward_fns,
            args=grpo_cfg,
            train_dataset=dataset,
        )

        # 6. Train ────────────────────────────────────────────────────────────
        print("\n[train] starting GRPO ...\n")
        trainer.train()

        # 7. Save ─────────────────────────────────────────────────────────────
        final_dir = os.path.join(cfg.output_dir, "final")
        model.save_pretrained(final_dir)
        tokenizer.save_pretrained(final_dir)
        print(f"\n[done] model saved → {final_dir}")

        if cfg.hub_model_id and hf_token:
            model.push_to_hub(cfg.hub_model_id, token=hf_token)
            tokenizer.push_to_hub(cfg.hub_model_id, token=hf_token)
            print(f"[done] pushed → huggingface.co/{cfg.hub_model_id}")

    finally:
        if not args.no_server:
            server.stop()


if __name__ == "__main__":
    main()
