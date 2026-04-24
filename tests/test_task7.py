"""Tests for Task 7 — Tool Router + Triage Solver."""

import os
import sys

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.tool_router import (
    ToolRouter,
    compute_triage_priority,
    solve_triage_order,
)
from server.threat_graph import (
    ThreatGraph,
    AlertNode,
    HostNode,
    IOCNode,
    ProcessNode,
)


def _alert(aid="A1", severity="high", source="WS-001"):
    return AlertNode(alert_id=aid, severity=severity, priority_score=1.0, source_host=source)


def _host(name="WS-001", crit="medium", status="compromised"):
    return HostNode(hostname=name, subnet="corporate", business_criticality=crit, status=status)


def _full_evidence_graph():
    g = ThreatGraph()
    g.add_host(_host("WS-001"))
    g.add_ioc(IOCNode(ioc_value="1.1.1.1", ioc_type="ip", confidence=0.9))
    g.add_process(ProcessNode(process_id="WS-001:1", hostname="WS-001", process_name="x"))
    return g


def test_triage_to_investigation_with_alerts():
    g = ThreatGraph()
    g.add_alert(_alert())
    r = ToolRouter()
    assert r.next_phase("triage", g, 10) == "investigation"


def test_triage_to_report_no_alerts():
    g = ThreatGraph()
    r = ToolRouter()
    assert r.next_phase("triage", g, 10) == "report"


def test_investigation_loops_then_exits():
    g = ThreatGraph()  # evidence-free
    r = ToolRouter()
    out = "investigation"
    for _ in range(r.MAX_INVESTIGATION_LOOPS + 1):
        out = r.next_phase("investigation", g, 10)
    assert out == "remediation"


def test_investigation_exits_on_sufficient_evidence():
    r = ToolRouter()
    assert r.next_phase("investigation", _full_evidence_graph(), 10) == "remediation"


def test_remediation_exits_when_contained():
    r = ToolRouter()
    g = ThreatGraph()
    g.add_host(_host("WS-001", status="isolated"))
    assert r.next_phase("remediation", g, 10) == "report"


def test_report_returns_done():
    r = ToolRouter()
    assert r.next_phase("report", ThreatGraph(), 10) == "done"


def test_honor_pushback_rejects_no_graph_refs():
    r = ToolRouter()
    ok, _ = r.honor_pushback("investigation", [], ThreatGraph())
    assert ok is False


def test_honor_pushback_accepts_valid_critical_alert():
    g = ThreatGraph()
    g.add_alert(_alert("A1", severity="critical"))
    r = ToolRouter()
    ok, _ = r.honor_pushback("investigation", ["A1"], g)
    assert ok is True


def test_triage_priority_higher_for_critical():
    g = ThreatGraph()
    a_crit = _alert("A1", severity="critical")
    a_low = _alert("A2", severity="low", source="WS-002")
    h_crit = _host("WS-001", crit="critical")
    h_low = _host("WS-002", crit="low")
    s_crit = compute_triage_priority(a_crit, h_crit, g)
    s_low = compute_triage_priority(a_low, h_low, g)
    assert s_crit > s_low


def test_solve_triage_order_descending():
    g = ThreatGraph()
    g.add_host(_host("WS-001", crit="critical"))
    g.add_host(_host("WS-002", crit="medium"))
    g.add_host(_host("WS-003", crit="low"))
    g.add_alert(_alert("A1", severity="critical", source="WS-001"))
    g.add_alert(_alert("A2", severity="medium", source="WS-002"))
    g.add_alert(_alert("A3", severity="low", source="WS-003"))
    order = solve_triage_order(g)
    assert order == ["A1", "A2", "A3"]
