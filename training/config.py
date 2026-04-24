"""Training configuration for CyberSOC GRPO."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class TrainingConfig:
    # ── Model ────────────────────────────────────────────────────────────────
    model_name: str = "unsloth/Qwen2.5-7B-Instruct"
    max_seq_length: int = 4096
    load_in_4bit: bool = True

    # ── LoRA ─────────────────────────────────────────────────────────────────
    lora_r: int = 16
    lora_alpha: int = 16
    lora_dropout: float = 0.0
    target_modules: List[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])

    # ── GRPO ─────────────────────────────────────────────────────────────────
    num_generations: int = 6            # completions sampled per prompt per step
    max_prompt_length: int = 1536
    max_completion_length: int = 2048
    learning_rate: float = 5e-6
    per_device_train_batch_size: int = 1
    gradient_accumulation_steps: int = 4
    num_train_epochs: int = 3
    max_steps: int = 300
    warmup_ratio: float = 0.1
    temperature: float = 0.9
    top_p: float = 0.95
    beta: float = 0.001                 # KL penalty — keeps model close to reference

    # ── Environment ──────────────────────────────────────────────────────────
    env_url: str = "http://localhost:8000"
    env_host: str = "0.0.0.0"
    env_port: int = 8000
    task_ids: List[str] = field(default_factory=lambda: ["easy", "medium", "hard"])
    prompts_per_task: int = 10          # unique reset-prompts per difficulty level
    server_startup_timeout: int = 60    # seconds

    # ── Output ───────────────────────────────────────────────────────────────
    output_dir: str = "./checkpoints/soc-grpo"
    hub_model_id: str = ""              # e.g. "your-hf-username/soc-analyst-7b"
    logging_steps: int = 5
    save_steps: int = 50
    seed: int = 42
