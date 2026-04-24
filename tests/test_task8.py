"""Tests for Task 8 — 10-dimensional Grader."""

import os
import sys

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.graders import grade_episode, grade_easy
from server.threat_graph import (
    ThreatGraph,
    HostNode,
    ProcessNode,
    IOCNode,
    VulnerabilityNode,
    AlertNode,
)
from models import SOCState


def _state(**overrides):
    s = SOCState(episode_id="e", step_count=0)
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


def _task_def_simple():
    return {
        "containment_requirements": {
            "must_kill": [{"hostname": "WS-001", "process": "evil.exe", "threat_id": "T1"}],
            "must_block_iocs": ["1.2.3.4"],
            "must_forensics": ["WS-001"],
            "must_not_isolate": [],
        },
        "attack_chain": [{"threat_id": "T1"}],
    }


def _empty_graph():
    return ThreatGraph()


def test_returns_correct_keys():
    res = grade_episode([], None, _empty_graph(), _task_def_simple(), _state())
    for k in ("final_score", "breakdown", "penalties", "bonuses", "reward_functions"):
        assert k in res


def test_breakdown_has_10_keys():
    res = grade_episode([], None, _empty_graph(), _task_def_simple(), _state())
    assert len(res["breakdown"]) == 10


def test_reward_functions_has_10_keys():
    res = grade_episode([], None, _empty_graph(), _task_def_simple(), _state())
    assert len(res["reward_functions"]) == 10


def test_all_rubric_met_scores_high():
    g = ThreatGraph()
    g.add_host(HostNode(hostname="WS-001", subnet="corporate",
                         business_criticality="medium", status="contained"))
    g.add_ioc(IOCNode(ioc_value="1.2.3.4", ioc_type="ip", confidence=0.9, enriched=True, blocked=True))
    g.add_process(ProcessNode(process_id="WS-001:1", hostname="WS-001",
                               process_name="evil.exe", killed=True))
    g.add_vulnerability(VulnerabilityNode(
        cve_id="CVE-1", hostname="WS-001", cvss_score=9.0,
        exploitability="active", patch_available=True,
        exploited_by_threat="T1",
    ))
    state = _state(
        killed_processes=[{"hostname": "WS-001", "process": "evil.exe"}],
        blocked_iocs=["1.2.3.4"],
        scanned_hosts=["WS-001"],
        enriched_iocs=["1.2.3.4"],
        correlated_alert_pairs=[("A1", "A2")],
        triggered_playbooks=["ransomware_containment"],
    )
    actions = [
        {"action_type": "correlate_alerts", "target": "A"},
        {"action_type": "kill_process", "target": "WS-001"},
    ]
    plan = {"entries": [{"threat_id": "T1", "actions_taken": ["kill"], "root_cause": "CVE-1", "confidence": 0.9}],
            "primary_threat_id": "T1"}
    res = grade_episode(actions, plan, g, _task_def_simple(), state)
    assert res["final_score"] >= 0.7


def test_no_actions_scores_low():
    res = grade_episode([], None, _empty_graph(), _task_def_simple(), _state())
    assert res["final_score"] <= 0.3


def test_blind_blocking_penalty():
    state = _state(blocked_iocs=["1.2.3.4"], enriched_iocs=[])
    res = grade_episode([], None, _empty_graph(), _task_def_simple(), state)
    pen_types = [p["type"] for p in res["penalties"]]
    assert "blind_blocking" in pen_types


def test_business_impact_penalises_over_isolation():
    g = ThreatGraph()
    # 10 hosts, 3 isolated -> 30%
    for i in range(10):
        status = "isolated" if i < 3 else "healthy"
        g.add_host(HostNode(hostname=f"H{i}", subnet="corporate",
                             business_criticality="medium", status=status))
    res = grade_episode([], None, g, _task_def_simple(), _state())
    assert res["breakdown"]["business_impact"] < 0.5


def test_step_efficiency_bonus_for_playbook():
    state = _state(triggered_playbooks=["ransomware_containment"])
    res = grade_episode([], None, _empty_graph(), _task_def_simple(), state)
    assert res["breakdown"]["step_efficiency"] > 0.5


def test_plan_coverage_zero_without_plan():
    res = grade_episode([], None, _empty_graph(), _task_def_simple(), _state())
    assert res["breakdown"]["plan_coverage"] == 0.0


def test_final_score_clamped_0_to_1():
    res = grade_episode([], None, _empty_graph(), _task_def_simple(), _state())
    assert 0.0 <= res["final_score"] <= 1.0


def test_wrappers_still_return_float():
    val = grade_easy([], None, _empty_graph(), _task_def_simple(), _state())
    assert isinstance(val, float)
