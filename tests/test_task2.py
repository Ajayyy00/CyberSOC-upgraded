"""Tests for Task 2 — Threat Graph Core."""

import os
import sys

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.threat_graph import (
    ThreatGraph,
    HostNode,
    ProcessNode,
    IOCNode,
    VulnerabilityNode,
    AlertNode,
    Edge,
)


def _make_host(name="WS-001"):
    return HostNode(
        hostname=name,
        subnet="corporate",
        business_criticality="medium",
        status="compromised",
    )


def _make_ioc(value="1.2.3.4", **kw):
    return IOCNode(ioc_value=value, ioc_type="ip", confidence=0.9, **kw)


def test_add_and_retrieve_host():
    g = ThreatGraph()
    g.add_host(_make_host("WS-001"))
    assert "WS-001" in g.hosts


def test_add_ioc_with_enrichment():
    g = ThreatGraph()
    g.add_ioc(_make_ioc("8.8.8.8", enriched=True))
    assert g.iocs["8.8.8.8"].enriched is True


def test_version_increments():
    g = ThreatGraph()
    assert g.version == 0
    g.add_host(_make_host("WS-001"))
    assert g.version == 1
    g.add_ioc(_make_ioc("1.1.1.1"))
    assert g.version == 2


def test_delta_since_zero_returns_all():
    g = ThreatGraph()
    g.add_host(_make_host("WS-001"))
    g.add_host(_make_host("WS-002"))
    g.add_ioc(_make_ioc("1.1.1.1"))
    delta = g.delta_since(0)
    counts = delta["counts"]
    assert counts.get("host", 0) == 2
    assert counts.get("ioc", 0) == 1


def test_delta_since_version_filters():
    g = ThreatGraph()
    g.add_host(_make_host("WS-001"))   # version becomes 1
    g.add_ioc(_make_ioc("1.1.1.1"))    # version becomes 2
    delta = g.delta_since(1)
    counts = delta["counts"]
    assert counts.get("host", 0) == 0
    assert counts.get("ioc", 0) == 1


def test_evidence_confidence_zero_when_no_edges():
    g = ThreatGraph()
    assert g.compute_evidence_confidence("THREAT-XYZ") == 0.0


def test_evidence_confidence_partial():
    g = ThreatGraph()
    g.add_host(_make_host("WS-001"))
    g.add_edge(Edge(edge_type="part_of_chain", source_id="THREAT-1", target_id="WS-001"))
    conf = g.compute_evidence_confidence("THREAT-1")
    assert 0.0 < conf < 1.0


def test_context_summary_under_100_words():
    g = ThreatGraph()
    g.add_host(_make_host("WS-001"))
    g.add_ioc(_make_ioc("1.1.1.1"))
    summary = g.get_context_summary()
    assert len(summary.split()) <= 100


def test_add_vulnerability():
    g = ThreatGraph()
    vuln = VulnerabilityNode(
        cve_id="CVE-2024-0001",
        hostname="WS-001",
        cvss_score=9.8,
        exploitability="active",
        patch_available=True,
    )
    g.add_vulnerability(vuln)
    assert "WS-001:CVE-2024-0001" in g.vulnerabilities
