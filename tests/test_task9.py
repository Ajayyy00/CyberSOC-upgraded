"""Tests for Task 9 — 4 New Action Handlers + Enhanced Existing Handlers."""

import os
import sys

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.play_environment import CyberSOCEnvironment
from server.threat_graph import HostNode, ProcessNode, IOCNode, AlertNode, Edge
from models import CorrelateAlerts, EnrichIOC, ScanHostVulnerabilities, TriggerPlaybook


def _env_with_graph():
    """Return a reset env with a seeded threat graph."""
    env = CyberSOCEnvironment()
    env.reset(task_id="easy")
    return env


def _add_alerts(env, alert_ids):
    """Add AlertNodes to the threat graph."""
    for aid in alert_ids:
        if aid not in env._threat_graph.alerts:
            env._threat_graph.add_alert(AlertNode(
                alert_id=aid, severity="high", priority_score=5.0, source_host="WS-001"
            ))


def _add_ioc(env, value="1.2.3.4"):
    if value not in env._threat_graph.iocs:
        env._threat_graph.add_ioc(IOCNode(ioc_value=value, ioc_type="ip", confidence=0.9))


def _add_host(env, hostname="WS-FAKE"):
    if hostname not in env._threat_graph.hosts:
        env._threat_graph.add_host(HostNode(
            hostname=hostname, subnet="corporate",
            business_criticality="medium", status="compromised"
        ))


def test_correlate_alerts_returns_correlation_results():
    env = _env_with_graph()
    _add_alerts(env, ["A1", "A2"])
    result = env._handle_correlate_alerts(CorrelateAlerts(alert_ids=["A1", "A2"]))
    assert "correlation_results" in result
    assert "correlation_score" in result["correlation_results"]


def test_correlate_alerts_error_on_single_id():
    env = _env_with_graph()
    _add_alerts(env, ["A1"])
    result = env._handle_correlate_alerts(CorrelateAlerts(alert_ids=["A1", "MISSING"]))
    # fewer than 2 alerts found in graph → error
    assert "error" in result


def test_enrich_ioc_updates_graph():
    env = _env_with_graph()
    # Grab any IOC already in graph (seeded from task def)
    ioc_value = next(iter(env._threat_graph.iocs), None)
    if ioc_value is None:
        _add_ioc(env)
        ioc_value = "1.2.3.4"
    env._handle_enrich_ioc(EnrichIOC(ioc_value=ioc_value, ioc_type="ip"))
    assert env._threat_graph.iocs[ioc_value].enriched is True


def test_enrich_ioc_error_when_not_in_graph():
    env = _env_with_graph()
    result = env._handle_enrich_ioc(EnrichIOC(ioc_value="not.in.graph", ioc_type="ip"))
    assert "error" in result


def test_scan_vulnerabilities_adds_vuln_nodes():
    env = _env_with_graph()
    # Use a host that exists in the graph
    hostname = next(iter(env._threat_graph.hosts), None)
    if hostname is None:
        _add_host(env)
        hostname = "WS-FAKE"
    # Seed a vulnerability_chain entry for this host
    env._task_def["vulnerability_chain"] = [{
        "hostname": hostname,
        "cve_id": "CVE-2024-9999",
        "cvss_score": 9.8,
        "exploitability": "active",
        "patch_available": True,
        "threat_id": "T1",
    }]
    env._handle_scan_vulnerabilities(ScanHostVulnerabilities(hostname=hostname))
    assert len(env._threat_graph.vulnerabilities) > 0


def test_scan_vulnerabilities_marks_host_scanned():
    env = _env_with_graph()
    hostname = next(iter(env._threat_graph.hosts), None)
    if hostname is None:
        _add_host(env)
        hostname = "WS-FAKE"
    env._task_def["vulnerability_chain"] = []
    env._handle_scan_vulnerabilities(ScanHostVulnerabilities(hostname=hostname))
    assert env._threat_graph.hosts[hostname].scanned is True


def test_trigger_playbook_fails_without_prerequisites():
    env = _env_with_graph()
    hostname = next(iter(env._threat_graph.hosts), "WS-001")
    result = env._handle_trigger_playbook(
        TriggerPlaybook(playbook_name="ransomware_containment", target=hostname)
    )
    assert "error" in result


def test_trigger_playbook_adds_to_triggered_list():
    env = _env_with_graph()
    hostname = next(iter(env._threat_graph.hosts), None)
    if hostname is None:
        _add_host(env)
        hostname = "WS-FAKE"

    # Satisfy prerequisites: forensics_run_on_target + process_identified
    env._state.scanned_hosts.append(hostname)
    if not any(p.hostname == hostname for p in env._threat_graph.processes.values()):
        env._threat_graph.add_process(ProcessNode(
            process_id=f"{hostname}:1", hostname=hostname, process_name="evil.exe"
        ))

    result = env._handle_trigger_playbook(
        TriggerPlaybook(playbook_name="ransomware_containment", target=hostname)
    )
    assert "error" not in result
    assert "ransomware_containment" in env._state.triggered_playbooks


def test_query_host_returns_process_tree():
    env = _env_with_graph()
    hostname = next(iter(env._threat_graph.hosts), None)
    if hostname is None:
        _add_host(env)
        hostname = "WS-FAKE"
        # also add to host_index
        env._host_index[hostname] = {
            "hostname": hostname, "subnet": "corporate",
            "status": "compromised", "running_processes": [], "criticality": 0.5
        }
    env._last_obs_extras = {}
    env._handle_query_host(type("QH", (), {"hostname": hostname})())
    assert "process_tree" in env._last_obs_extras


def test_isolate_single_host_sets_isolated():
    env = _env_with_graph()
    hostname = next(iter(env._threat_graph.hosts), None)
    if hostname is None:
        _add_host(env)
        hostname = "WS-FAKE"
        env._host_index[hostname] = {
            "hostname": hostname, "subnet": "corporate",
            "status": "compromised", "running_processes": [], "criticality": 0.5
        }

    from models import IsolateSegment
    action = IsolateSegment(target_host=hostname, reason="test")
    env._handle_isolate_segment(action)
    assert env._host_index[hostname]["status"] == "isolated"
    # Only this host isolated, not all of its subnet
    subnet = env._host_index[hostname].get("subnet", "corporate")
    subnet_hosts = env._network.get(subnet, [])
    still_up = sum(1 for h in subnet_hosts if h["status"] != "isolated")
    assert still_up > 0
