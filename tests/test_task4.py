"""Tests for Task 4 — SOAR Playbook Library."""

import os
import sys

import pytest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.soar_playbooks import PLAYBOOKS, check_prerequisites
from server.threat_graph import ThreatGraph, HostNode, ProcessNode, IOCNode
from models import SOCState


def _fresh_state():
    return SOCState(episode_id="e", step_count=0)


def _empty_graph():
    return ThreatGraph()


def test_all_five_playbooks_defined():
    for k in [
        "ransomware_containment",
        "c2_disruption",
        "lateral_movement_lockdown",
        "phishing_response",
        "data_exfil_stop",
    ]:
        assert k in PLAYBOOKS


def test_playbook_structure():
    for name, p in PLAYBOOKS.items():
        for key in ["name", "description", "prerequisites", "sub_actions", "target_attack_types"]:
            assert key in p, f"{name} missing {key}"


def test_ransomware_containment_sub_actions():
    assert PLAYBOOKS["ransomware_containment"]["sub_actions"] == ["kill_process", "block_ioc"]


def test_check_prerequisites_fails_no_forensics():
    ok, reason = check_prerequisites("ransomware_containment", "WS-001", _fresh_state(), _empty_graph())
    assert ok is False
    assert isinstance(reason, str) and len(reason) > 0


def test_check_prerequisites_passes_when_met():
    state = _fresh_state()
    state.scanned_hosts = ["WS-001"]
    g = ThreatGraph()
    g.add_process(ProcessNode(process_id="WS-001:1234", hostname="WS-001", process_name="evil.exe"))
    ok, reason = check_prerequisites("ransomware_containment", "WS-001", state, g)
    assert ok is True
    assert reason == ""


def test_unknown_playbook_raises():
    with pytest.raises((KeyError, ValueError)):
        check_prerequisites("nonexistent_playbook", "WS-001", _fresh_state(), _empty_graph())


def test_c2_disruption_needs_enriched_ioc():
    g = ThreatGraph()
    # add IP IOC but not enriched
    g.add_ioc(IOCNode(ioc_value="1.2.3.4", ioc_type="ip", confidence=0.9, enriched=False))
    ok, reason = check_prerequisites("c2_disruption", "WS-001", _fresh_state(), g)
    assert ok is False
