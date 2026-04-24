"""Tests for Task 3 — Action Models (10 actions)."""

import os
import sys

import pytest
from pydantic import ValidationError

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from models import (
    CorrelateAlerts,
    EnrichIOC,
    ScanHostVulnerabilities,
    TriggerPlaybook,
    SOCActionWrapper,
    SOCObservation,
    SOCState,
)


def test_correlate_alerts_model():
    a = CorrelateAlerts(alert_ids=["A1", "A2"])
    assert a.type == "correlate_alerts"


def test_enrich_ioc_model():
    a = EnrichIOC(ioc_value="1.2.3.4", ioc_type="ip")
    assert a.type == "enrich_ioc"


def test_scan_host_vulnerabilities_model():
    a = ScanHostVulnerabilities(hostname="WS-001")
    assert a.type == "scan_host_vulnerabilities"


def test_trigger_playbook_valid():
    a = TriggerPlaybook(playbook_name="ransomware_containment", target="WS-001")
    assert a.type == "trigger_playbook"


def test_trigger_playbook_invalid_name():
    with pytest.raises(ValidationError):
        TriggerPlaybook(playbook_name="fake_playbook", target="WS-001")


def test_wrapper_routes_correlate_alerts():
    w = SOCActionWrapper(type="correlate_alerts", alert_ids=["A", "B"])
    assert isinstance(w.to_typed_action(), CorrelateAlerts)


def test_wrapper_routes_enrich_ioc():
    w = SOCActionWrapper(type="enrich_ioc", ioc_value="x", ioc_type="ip")
    assert isinstance(w.to_typed_action(), EnrichIOC)


def test_observation_has_new_fields():
    obs = SOCObservation()
    for attr in [
        "correlation_results",
        "ioc_enrichment",
        "vulnerability_results",
        "playbook_result",
        "threat_graph_summary",
        "available_playbooks",
    ]:
        assert hasattr(obs, attr), f"missing {attr}"


def test_state_has_new_fields():
    st = SOCState(episode_id="e", step_count=0)
    for attr in [
        "enriched_iocs",
        "scanned_hosts",
        "correlated_alert_pairs",
        "triggered_playbooks",
        "live_requirements",
    ]:
        assert hasattr(st, attr), f"missing {attr}"
