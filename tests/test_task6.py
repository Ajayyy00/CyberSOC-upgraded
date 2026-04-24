"""Tests for Task 6 — Action Validation Middleware."""

import os
import sys

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.action_validation import (
    ActionValidationMiddleware,
    PHASE_VIOLATION,
    INVALID_PARAMS,
    UNGROUNDED_ACTION,
)
from server.threat_graph import ThreatGraph, IOCNode, ProcessNode


def _empty():
    return ThreatGraph()


def _graph_with_ioc(value="1.2.3.4"):
    g = ThreatGraph()
    g.add_ioc(IOCNode(ioc_value=value, ioc_type="ip", confidence=0.9))
    return g


def _graph_with_process(host="H", proc_name="evil.exe"):
    g = ThreatGraph()
    g.add_process(ProcessNode(process_id=f"{host}:{proc_name}", hostname=host, process_name=proc_name))
    return g


def test_gate1_rejects_wrong_phase():
    m = ActionValidationMiddleware()
    err = m.validate("triage", "kill_process", {}, _empty())
    assert err is not None
    assert err["error"] == PHASE_VIOLATION


def test_gate1_passes_correct_phase():
    m = ActionValidationMiddleware()
    err = m.validate("remediation", "kill_process", {"hostname": "H", "process_name": "evil.exe"}, _graph_with_process())
    assert err is None


def test_gate1_error_lists_allowed_tools():
    m = ActionValidationMiddleware()
    err = m.validate("triage", "kill_process", {}, _empty())
    assert err is not None
    msg = err["message"].lower()
    assert any(t in msg for t in ["read_alerts", "read_topology", "correlate_alerts"])


def test_gate2_rejects_missing_ioc_value():
    m = ActionValidationMiddleware()
    err = m.validate("remediation", "block_ioc", {}, _empty())
    assert err is not None and err["error"] == INVALID_PARAMS


def test_gate2_rejects_correlate_with_one_alert():
    m = ActionValidationMiddleware()
    err = m.validate("triage", "correlate_alerts", {"alert_ids": ["A1"]}, _empty())
    assert err is not None and err["error"] == INVALID_PARAMS


def test_gate3_rejects_ungrounded_block():
    m = ActionValidationMiddleware()
    err = m.validate("remediation", "block_ioc", {"ioc_value": "1.2.3.4"}, _empty())
    assert err is not None and err["error"] == UNGROUNDED_ACTION


def test_gate3_passes_grounded_block():
    m = ActionValidationMiddleware()
    err = m.validate("remediation", "block_ioc", {"ioc_value": "1.2.3.4"}, _graph_with_ioc())
    assert err is None


def test_gate3_rejects_ungrounded_kill():
    m = ActionValidationMiddleware()
    err = m.validate("remediation", "kill_process", {"hostname": "H", "process_name": "unknown.exe"}, _empty())
    assert err is not None and err["error"] == UNGROUNDED_ACTION


def test_all_gates_pass_returns_none():
    m = ActionValidationMiddleware()
    err = m.validate("remediation", "block_ioc", {"ioc_value": "1.2.3.4"}, _graph_with_ioc())
    assert err is None


def test_retry_flag_false_for_phase_violation():
    m = ActionValidationMiddleware()
    err = m.validate("triage", "kill_process", {}, _empty())
    assert err["retry"] is False


def test_retry_flag_true_for_invalid_params():
    m = ActionValidationMiddleware()
    err = m.validate("remediation", "block_ioc", {}, _empty())
    assert err["retry"] is True
