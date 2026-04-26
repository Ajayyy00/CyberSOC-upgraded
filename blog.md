# CyberSOC: Training an LLM to Defend Enterprise Networks Through Reinforcement Learning

> *Built for the Meta OpenEnv Hackathon, India 2026 · Qwen 2.5 3B Instruct · 4-bit QLoRA · TRL GRPOTrainer*

---

## The Problem With AI in Cybersecurity Today

Security Operations Centers don't fail because of a lack of tools — they fail because of **complex decision-making under pressure**. Analysts must interpret noisy alerts, correlate events across dozens of systems, understand attacker intent, and respond in real time — all while the attack continues to evolve.

Most AI systems attempt to automate parts of this workflow but remain fundamentally limited: they either follow rigid playbooks or imitate past actions without truly understanding the problem. They predict. They don't reason.

**CyberSOC is built on a different premise entirely.**

Instead of teaching an AI the correct answer, we place it inside a live simulated enterprise network under attack and let it learn through **Reinforcement Learning from Verifiable Rewards (RLVR)**. The agent is rewarded only when it actually contains the attack — not when it produces plausible-sounding responses. This transforms cybersecurity from a static prediction problem into a dynamic interactive learning task.

CyberSOC is a **two-agent system**: a Blue Team agent (the LLM defender) and a Red Team agent (the adaptive adversary) trained against each other in a zero-sum loop.

---

## Learning Through Reinforcement, Not Supervision

At the core of CyberSOC is a fundamental shift: from supervised learning to reinforcement learning in a dynamic, adversarial environment.

The model is not given labeled examples or step-by-step instructions. Instead, it receives:
- A stream of **SIEM alerts** from an enterprise network under active attack
- A set of **investigative tools** — querying hosts, running forensics, correlating alerts, blocking IOCs
- **No ground truth** — only the outcome of its actions

Every action the model takes is executed inside the environment and evaluated based on its real outcome. Correct actions — identifying malicious processes, correlating alerts, severing C2 channels — are rewarded. Incorrect, premature, or hallucinated actions are penalized.

Over repeated episodes, the model learns not just *which* actions to take, but *why* certain sequences are necessary — and why skipping steps leads to failure.

---

## The Environment: A Realistic Enterprise Under Attack

Each training episode procedurally generates a **multi-subnet enterprise network** across four segments — DMZ, Corporate, Database, and Finance — representing a realistic organizational topology. Within this network at episode start:

- Some hosts are **already compromised**
- Malicious processes are **actively running**
- The attacker has established **Command-and-Control (C2) channels** to maintain persistence

The agent has **no full visibility** into the system. It must reconstruct the attack picture entirely through investigation — querying hosts, running forensics, correlating alerts — before it can act. This partial observability mirrors real incident response, where the full scope of a breach is rarely known at the outset.

A critical design choice is **deterministic scenario generation**: each `task_id` maps to a fixed cryptographic seed, ensuring that the same network topology, attack chain, and initial alerts are reproduced identically across training runs. This is foundational for stable RL — without it, the model cannot learn causal patterns because every episode is a structurally different problem.

---

## End-to-End System Workflow

The figure below shows CyberSOC as a closed-loop pipeline — from episode generation through agent interaction, validation, adaptive adversary, reward computation, and GRPO training.

![Figure 1: End-to-end CyberSOC workflow — episode generation, agent interaction, 3-gate validation, adaptive Red Team, 10-dimensional reward signals, and GRPO training loop.](./images/fig1.png)

<div align="center"><em>Figure 1: End-to-end CyberSOC workflow.</em></div>

Each episode begins with task generation and alert injection. The agent observes alerts through a SIEM-style interface and interacts using structured JSON actions. These actions are validated, executed, and their effects recorded in a central **ThreatGraph** — a live causal graph representing the agent's evolving understanding of the attack. The episode concludes when the agent submits a containment plan or exhausts its step budget. Results feed into the GRPO training loop to update the model — creating a continuous feedback cycle where every episode improves the agent's reasoning for the next.

---

## Enforcing Real-World Incident Response

One of the most important properties of CyberSOC is that it **does not allow the model to take shortcuts**. Every action must pass through a 3-gate validation system before it is executed:

1. **Phase Whitelist** — Actions are gated by the current incident response phase
2. **Schema Validation** — Required arguments are checked; malformed actions are rejected
3. **Graph Groundedness** — Actions must reference entities the agent has already discovered

The **Blue agent** is required to follow the natural incident response lifecycle in strict sequence:

1. **Triage** — explains alert prioritization, the priority formula, and what tools are used
2. **Investigation** — covers forensics, IOC enrichment, CVE scanning, and how ThreatGraph gets populated with the −0.20 penalty for acting on undiscovered entities
3. **Remediation** — explains the causal ordering requirement (terminate → quarantine → block C2), the reinfection mechanic if C2 isn't severed, and specific penalties for wrong ordering
4. **Reporting** — explains that the containment plan is graded on evidence quality, threat coverage, and ThreatGraph citations — not just that it was submitted

Attempting to skip phases is both penalized and blocked. Submitting a containment plan before completing investigation, for example, results in a **−0.10 penalty** and the action is rejected entirely. The model cannot skip to the answer — it must earn it by doing the work.

![Figure 2: Phase state machine showing valid transitions and penalty conditions for each incident response stage.](./images/fig2.png)

<div align="center"><em>Figure 2: Phase state machine showing valid transitions and penalty conditions for each incident response stage.</em></div>

---

## ThreatGraph: The Agent's World Model

As the agent investigates the network, it builds a progressively richer understanding of the attack. CyberSOC formalizes this as the **ThreatGraph** — a dynamic causal graph that acts as the memory of the investigation.

Every discovery is recorded as a node or edge in the graph:
- **Nodes**: Compromised hosts, malicious processes, IOCs, vulnerabilities, alerts
- **Edges**: Exploits, beacons, lateral movement paths, C2 connections, pivot chains

Crucially, **future actions must be grounded in this graph**. If the agent attempts to enrich a threat indicator it has not yet discovered, or quarantine a file on a host it has never queried, the action is rejected.

![Figure 3: Live ThreatGraph showing discovered nodes (hosts, processes, IOCs) and causal edges built incrementally through agent investigation. Top: early investigation with unblocked IOC. Bottom: host identified in Finance subnet.](./images/fig.png)

<div align="center"><em>Figure 3: Live ThreatGraph showing discovered nodes (hosts, processes, IOCs) and causal edges built incrementally through agent investigation. Top: early investigation with unblocked IOC. Bottom: host identified in Finance subnet.</em></div>

This graph-groundedness constraint eliminates one of the most persistent failure modes in LLM-based agents: **confident hallucination**. The model cannot guess or fabricate threat intelligence — it must actually run the investigation to uncover the information it needs to act on.

---

## Tool Orchestration and Causal Ordering

Instead of selecting from predefined playbooks, the agent must orchestrate a sequence of **granular micro-tools**, each corresponding to a real analyst action:

| Action | Purpose |
|--------|---------|
| `query_host` | Map architecture, get endpoint info |
| `run_forensics` | Deep system artifact extraction |
| `kill_process` | Terminate malicious execution |
| `block_ioc` | Blacklist IOCs network-wide |
| `isolate_segment` | Quarantine subnet or host |
| `correlate_alerts` | Find shared entities across alerts |
| `enrich_ioc` | Threat-intel enrichment (actor, TTPs) |
| `scan_host_vulnerabilities` | Discover CVEs on a host |
| `submit_containment_plan` | Final report — ends episode |

The challenge is not knowing that these tools exist — it is learning the **correct causal order** in which they must be invoked.

For example: a file cannot be quarantined while a malicious process still holds a lock on it. Attempting to do so results in a **−0.20 penalty**. The agent must first terminate the process, then quarantine the file. Similarly, terminating a malicious process without severing its C2 channel causes the attacker to redeploy a new payload — undoing all remediation progress.

The model learns these dependencies through repeated interaction, gradually internalizing the sequencing logic that experienced analysts take years to develop — and it does so **without ever being directly told the rules**.

---

## Adaptive Red Team: A Multi-Agent Adversary

A deterministic Red Team creates a hard ceiling on Blue's capability. When the attacker follows a fixed script, Blue memorizes the pattern rather than learning to investigate. CyberSOC eliminates this by training **both Blue and Red as full RL agents** in a zero-sum multi-agent loop. Red evolves through four stages, constantly forcing Blue to develop genuine reasoning rather than pattern recognition.

![Figure 4: Four-stage Red Team training curriculum — from imitation warm-start through PFSP prioritized sampling, producing a Blue agent that generalizes rather than memorizes.](./images/fig3.png)

<div align="center"><em>Figure 4: Four-stage Red Team training curriculum.</em></div>

### Stage 1 — Imitation Warm-Start
Decisions across 1,000 scenarios are logged and used to SFT-train a language model, producing `red_v0`. This gives Red a meaningful baseline before any RL gradient is applied.

### Stage 2 — Freeze-Alternate
One agent trains while the other is completely frozen — never simultaneously. Blue trains against frozen Red, then Red trains against frozen Blue. Blue reward = +containment score; Red reward = −(Blue's score). This zero-sum separation keeps the training signal stable.

### Stage 3 — FSP Historical Archive
Blue trains against **all past Red checkpoints simultaneously**, not just the latest. Blue must maintain ≥55% win rate against every archived Red before graduating. It cannot specialize — it must generalize.

### Stage 4 — PFSP on top of FSP
Uniform archive sampling wastes compute on Red versions Blue already beats easily. PFSP weights opponents by difficulty: `weight = (1 − win_rate)^T`, with temperature ramping from 0.5 → 2.0. Hard opponents automatically get more training time. Blue's weakest points are targeted without any manual intervention.

As Blue improves, Red adapts — learning new pivot routes when C2 is blocked, evading detection earlier when processes are killed faster. The result is a Blue agent that is **genuinely robust**: it has never trained against a fixed target, so it has never had the opportunity to overfit.

---

## Reward System: Measuring What Actually Matters

CyberSOC evaluates agent performance across **10 independent dimensions** at the end of each episode, rather than a single binary success signal:

| Dimension | Weight | What It Measures |
|-----------|--------|-----------------|
| Threat Containment | 0.20 | Fraction of required malicious processes terminated |
| IOC Blocking | 0.12 | Known C2 addresses neutralized (penalizes blind blocking) |
| Forensic Investigation | 0.10 | Compromised hosts thoroughly examined |
| Plan Coverage | 0.10 | Final report addresses every active threat |
| Business Impact | 0.10 | Penalizes unnecessary downtime and over-isolation |
| SIEM Correlation | 0.08 | Alerts correlated (bonus for early correlation) |
| Threat Intel Usage | 0.08 | IOCs enriched with threat intelligence |
| Vuln Root Cause | 0.08 | CVE root causes discovered and cited |
| Step Efficiency | 0.07 | Rewards efficient actions, penalizes step overrun |
| Plan Evidence Quality | 0.07 | Evidence confidence from ThreatGraph |

Penalties apply for blind blocking without prior investigation, disrupting clean subnets, and hallucinated or invalid actions.

This multi-dimensional signal is what makes GRPO training effective. Rather than waiting for a sparse win/loss outcome at episode end, the model receives **precise feedback on exactly which components of the security workflow it executed correctly** — enabling fine-grained credit assignment across 30 steps of interaction.

---

## Training Pipeline: SFT Warm-Start → GRPO

Training proceeds in two stages:

**Stage 1 — SFT Warm-Start**: The model first learns to produce valid structured actions and interact correctly with the environment's API. This prevents early training from collapsing into random invalid actions.

**Stage 2 — GRPO Training Loop**: For each scenario, the trainer samples four distinct action sequences from the current model policy. Each sequence is replayed against the CyberSOC environment, and the full 10-dimensional reward breakdown is recorded. GRPO then computes the relative advantage of each completion against the group mean — reinforcing sequences that scored above average and penalizing those below — without requiring a separate critic model.

**Stack**: Qwen 2.5 3B Instruct · 4-bit QLoRA via Unsloth · TRL GRPOTrainer · Deterministic scenario seeding ensures all four GRPO completions face identical network conditions, making the relative advantage comparison meaningful and the training signal stable.

---

## Reward-Hacking Defense

Every RL environment is vulnerable to agents finding shortcuts that game the reward rather than solve the problem. CyberSOC implements 8 explicit defenses:

| Attack Vector | Defense |
|---|---|
| Editing timers | `EpisodeSandbox` wall-clock enforcement (120s) |
| Caching results | Idempotent step rewards via `_fired_step_rewards` |
| Abusing globals | Instance-scoped RNG per episode |
| Mutating protected state | Sandbox hash-snapshot + rollback |
| Exploiting env bugs | 3-gate validation middleware |
| Reward-function gaming | Evidence confidence normalization |
| Cheating via blind remediation | Graph-groundedness gate |
| Blind IOC blocking | Enrichment-before-block penalty |

---

## Why CyberSOC Works

Every design decision — the phase gates, graph-groundedness constraints, reinfection mechanic, 10-dimensional scorer, 4-stage Red Team curriculum — answers the same question:

> **What would make it impossible to score well without actually solving the security problem?**

That question is the right foundation for any environment intended to train professional task performance in LLMs. CyberSOC is not a simulation of cybersecurity — it is a training environment designed to produce real investigative capability in a language model.

---

## Links

| Resource | URL |
|---|---|
| 🖥️ Live Demo | [huggingface.co/spaces/Ajay00747/Demo](https://huggingface.co/spaces/Ajay00747/Demo) |
| ⚙️ Environment API | [huggingface.co/spaces/Ajay00747/CyberSOC-upgraded](https://huggingface.co/spaces/Ajay00747/CyberSOC-upgraded) |
| 🏋️ Training Space | [huggingface.co/spaces/Ajay00747/cyberSOC-trainer](https://huggingface.co/spaces/Ajay00747/cyberSOC-trainer) |
| 💻 Source Code | [github.com/Ajayyy00/CyberSOC-upgraded](https://github.com/Ajayyy00/CyberSOC-upgraded) |

---

*Built for the Meta OpenEnv Hackathon, India 2026.*  
*Base model: Qwen 2.5 3B Instruct · Fine-tuned with 4-bit QLoRA via Unsloth · Trained with TRL GRPOTrainer on Hugging Face JupyterLab GPU Spaces.*
