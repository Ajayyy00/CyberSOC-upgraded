"""
Collect SFT data by running a scripted 'perfect' agent through Easy tasks.
This satisfies Daniel's Law of RL: ensuring the base model can emit valid JSON
actions before starting GRPO.
"""

import json
import os
import sys

# Ensure server module can be imported
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.play_environment import CyberSOCEnvironment
from server.tasks import get_task
from models import SOCActionWrapper

def _format_as_chat(history: list) -> dict:
    """Format a sequence of observations and actions into a chat trace."""
    messages = [
        {
            "role": "system",
            "content": "You are an autonomous CyberSOC Agent. Analyze the environment and output JSON tool calls to contain the threat."
        }
    ]
    for step in history:
        if step["type"] == "observation":
            messages.append({"role": "user", "content": json.dumps(step["data"], indent=2)})
        elif step["type"] == "action":
            messages.append({"role": "assistant", "content": json.dumps(step["data"])})
    return {"messages": messages}

def collect_winning_traces(num_traces=100, output_file="training/sft_data.jsonl"):
    print(f"Collecting {num_traces} SFT traces...")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    env = CyberSOCEnvironment()
    traces = []
    
    for i in range(1, num_traces + 1):
        task_id = f"gen_{i:04d}"
        task_def = get_task(task_id)
        
        history = []
        obs = env.reset(task_id=task_id)
        history.append({"type": "observation", "data": obs.model_dump()})
        
        # Scripted "Perfect" Agent
        reqs = task_def.get("containment_requirements", {})
        
        # 1. Run forensics on compromised hosts
        for host in reqs.get("must_forensics", []):
            action = {"type": "run_forensics", "hostname": host}
            history.append({"type": "action", "data": action})
            obs = env.step(SOCActionWrapper(**action))
            history.append({"type": "observation", "data": obs.model_dump()})
            
        # 2. Kill malicious processes
        for proc in reqs.get("must_kill", []):
            action = {"type": "kill_process", "hostname": proc["hostname"], "process_name": proc["process"]}
            history.append({"type": "action", "data": action})
            obs = env.step(SOCActionWrapper(**action))
            history.append({"type": "observation", "data": obs.model_dump()})
            
        # 3. Block IOCs
        for ioc in reqs.get("must_block_iocs", []):
            action = {"type": "block_ioc", "ioc_type": "hash" if len(ioc) > 30 else "ip", "ioc_value": ioc}
            history.append({"type": "action", "data": action})
            obs = env.step(SOCActionWrapper(**action))
            history.append({"type": "observation", "data": obs.model_dump()})
            
        # 4. Submit plan
        plan_entries = []
        for threat in task_def.get("attack_chain", []):
            plan_entries.append({
                "threat_id": threat.get("threat_id"),
                "actions_taken": ["run_forensics", "kill_process", "block_ioc"],
                "root_cause": "Initial access via " + threat.get("threat_type"),
                "confidence": 0.95,
            })
            
        action = {
            "type": "submit_containment_plan",
            "plan": plan_entries,
            "executive_summary": "All threats contained. Malicious processes killed, IOCs blocked, forensics completed.",
        }
        history.append({"type": "action", "data": action})
        obs = env.step(SOCActionWrapper(**action))
        history.append({"type": "observation", "data": obs.model_dump()})
        
        if obs.final_score > 0.3:
            traces.append(_format_as_chat(history))
            print(f"Task {task_id}: Score = {obs.final_score:.2f} (Added)")
        else:
            print(f"Task {task_id}: Score = {obs.final_score:.2f} (Skipped - Score too low)")
            
    with open(output_file, "w") as f:
        for trace in traces:
            f.write(json.dumps(trace) + "\n")
            
    print(f"Saved {len(traces)} traces to {output_file}")

if __name__ == "__main__":
    collect_winning_traces()
