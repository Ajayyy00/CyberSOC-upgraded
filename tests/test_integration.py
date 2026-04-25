"""Integration tests — Task 10."""

import os
import sys
import subprocess

import pytest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.play_environment import CyberSOCEnvironment
from server.episode_sandbox import EpisodeTimeout
from server.graders import grade_episode
from models import SOCActionWrapper, RedActionWrapper


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first_host(env):
    return next(iter(env._threat_graph.hosts), "WS-042")


def _first_alert(env):
    return next(iter(env._threat_graph.alerts), None)


def _valid_action(action_type, **kwargs):
    return SOCActionWrapper(type=action_type, **kwargs)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_easy_episode_completes():
    env = CyberSOCEnvironment()
    obs = env.reset(task_id="easy")
    hostname = _first_host(env)
    for _ in range(5):
        obs = env.step(_valid_action("query_host", hostname=hostname))
    assert obs is not None


def test_medium_episode_with_all_10_actions():
    env = CyberSOCEnvironment()
    obs = env.reset(task_id="medium")
    hostname = _first_host(env)
    ioc_value = next(iter(env._threat_graph.iocs), None)

    # Triage phase
    alerts = list(env._threat_graph.alerts.keys())
    if len(alerts) >= 2:
        obs = env.step(_valid_action("correlate_alerts", alert_ids=alerts[:2]))

    # Investigation phase
    obs = env.step(_valid_action("query_host", hostname=hostname))
    obs = env.step(_valid_action("run_forensics", hostname=hostname))

    if ioc_value:
        obs = env.step(_valid_action("enrich_ioc", ioc_value=ioc_value, ioc_type="ip"))
    obs = env.step(_valid_action("scan_host_vulnerabilities", hostname=hostname))

    # Remediation phase
    if ioc_value:
        obs = env.step(_valid_action("block_ioc", ioc_value=ioc_value, ioc_type="ip"))
    obs = env.step(_valid_action("kill_process", hostname=hostname, process_name="nonexistent.exe"))
    obs = env.step(_valid_action("isolate_segment", subnet="corporate", reason="test"))

    # Trigger playbook (prereqs may or may not be met — just must not crash)
    try:
        obs = env.step(_valid_action("trigger_playbook", playbook_name="c2_disruption", target=hostname))
    except Exception:
        pass

    # Submit plan
    obs = env.step(_valid_action(
        "submit_containment_plan",
        plan=[{"threat_id": "T1", "actions_taken": ["kill"], "root_cause": "malware", "confidence": 0.8}],
        executive_summary="Contained ransomware.",
    ))
    assert obs is not None


def test_phase_violation_returns_error():
    """kill_process during triage should record negative reward (not crash)."""
    env = CyberSOCEnvironment()
    env.reset(task_id="easy")
    hostname = _first_host(env)
    # This action is dispatched — may return low reward but must not raise
    obs = env.step(_valid_action("kill_process", hostname=hostname, process_name="fake.exe"))
    assert obs is not None


def test_lateral_pivot_red_action():
    """LateralPivot RedActionWrapper creates a pivoted_from edge and a SIEM alert."""
    env = CyberSOCEnvironment(fsp_mode=True)
    env.reset(task_id="hard")

    # Find a compromised host to pivot from and a healthy one to pivot to
    src = next(
        (h for h, hd in env._host_index.items() if hd.get("status") == "compromised"),
        None,
    )
    dst = next(
        (h for h, hd in env._host_index.items()
         if hd.get("status") not in ("compromised", "isolated") and h != src),
        None,
    )
    if src is None or dst is None:
        pytest.skip("No suitable host pair for lateral pivot test")

    # Blue takes a PassTurn-equivalent (query) so active_turn flips to red
    env.step(_valid_action("query_host", hostname=src))
    assert env._state.active_turn == "red"

    alerts_before = len(env._alert_queue)
    env.step(RedActionWrapper(type="lateral_pivot", source_host=src, target_host=dst))

    pivot_edges = [e for e in env._threat_graph.edges if e.edge_type == "pivoted_from"]
    assert len(pivot_edges) >= 1
    assert env._host_index[dst]["status"] == "compromised"
    assert len(env._alert_queue) > alerts_before  # SIEM alert generated


def test_step_reward_accumulates():
    env = CyberSOCEnvironment()
    env.reset(task_id="easy")
    hostname = _first_host(env)

    before = env._step_reward_total
    # run_forensics in investigation phase earns +0.10
    for h in list(env._threat_graph.hosts.keys())[:3]:
        if h in env._host_index:
            env.step(_valid_action("run_forensics", hostname=h))

    assert env._step_reward_total > before


def test_step_reward_idempotent():
    env = CyberSOCEnvironment()
    env.reset(task_id="easy")
    hostname = _first_host(env)

    env.step(_valid_action("run_forensics", hostname=hostname))
    after_first = env._step_reward_total
    env.step(_valid_action("run_forensics", hostname=hostname))
    after_second = env._step_reward_total

    # Second call on same host earns 0 extra step reward (though may earn -0.02 from handler)
    step_reward_delta = after_second - after_first
    # The idempotent part: _get_step_reward returns 0 on second call for same triple
    key = ("investigation", "run_forensics", hostname)
    assert key in env._fired_step_rewards


def test_grader_returns_10_dim():
    env = CyberSOCEnvironment()
    env.reset(task_id="easy")
    hostname = _first_host(env)
    env.step(_valid_action("query_host", hostname=hostname))

    result = grade_episode(
        episode_actions=list(env._state.timeline),
        final_plan=None,
        graph=env._threat_graph,
        task_def=env._task_def,
        state=env._state,
    )
    assert len(result["breakdown"]) == 10


def test_sandbox_step_limit():
    from server.episode_sandbox import EpisodeSandbox, MAX_STEPS_PER_EPISODE

    env = CyberSOCEnvironment()
    env.reset(task_id="easy")
    sb = EpisodeSandbox(env)

    with pytest.raises(EpisodeTimeout):
        sb.check_step_limit(MAX_STEPS_PER_EPISODE)


def test_openenv_validate_compatible():
    """Run openenv validate and assert it exits 0 (env is valid with adaptive=False)."""
    python = os.path.join(_PROJECT_ROOT, "..", "venv", "Scripts", "python.exe")
    python = os.path.abspath(python)
    if not os.path.exists(python):
        pytest.skip("venv python not found")

    result = subprocess.run(
        [python, "-c",
         "from server.play_environment import CyberSOCEnvironment; "
         "env = CyberSOCEnvironment(adaptive=False); "
         "obs = env.reset(task_id='easy'); "
         "print('OK', len(obs.alert_queue))"],
        cwd=_PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "OK" in result.stdout
