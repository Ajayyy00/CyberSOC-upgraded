"""Deterministic Tool Router (phase machine) + Triage Solver."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .threat_graph import ThreatGraph, AlertNode, HostNode


class ToolRouter:
    PHASE_ORDER = ["triage", "investigation", "remediation", "report"]
    MAX_INVESTIGATION_LOOPS = 4
    MAX_REMEDIATION_LOOPS = 3

    def __init__(self):
        self._investigation_loop_count = 0
        self._remediation_loop_count = 0

    def next_phase(
        self,
        current_phase: str,
        graph: "ThreatGraph",
        steps_remaining: int,
    ) -> str:
        if current_phase == "triage":
            if len(graph.alerts) > 0:
                return "investigation"
            return "report"

        if current_phase == "investigation":
            if (
                self._has_sufficient_evidence(graph)
                or steps_remaining < 4
                or self._investigation_loop_count >= self.MAX_INVESTIGATION_LOOPS
            ):
                return "remediation"
            self._investigation_loop_count += 1
            return "investigation"

        if current_phase == "remediation":
            if (
                self._all_threats_contained(graph)
                or steps_remaining < 2
                or self._remediation_loop_count >= self.MAX_REMEDIATION_LOOPS
            ):
                return "report"
            if (
                self._remediation_loop_count < self.MAX_REMEDIATION_LOOPS
                and not self._all_threats_contained(graph)
                and steps_remaining >= 4
            ):
                self._remediation_loop_count += 1
                return "investigation"
            return "report"

        if current_phase == "report":
            return "done"

        return "done"

    def _has_sufficient_evidence(self, graph: "ThreatGraph") -> bool:
        has_unhealthy_host = any(h.status != "healthy" for h in graph.hosts.values())
        has_ioc = len(graph.iocs) > 0
        has_process = len(graph.processes) > 0
        return has_unhealthy_host and has_ioc and has_process

    def _all_threats_contained(self, graph: "ThreatGraph") -> bool:
        suspicious_or_compromised = [
            h for h in graph.hosts.values()
            if h.status in ("suspicious", "compromised")
        ]
        if not suspicious_or_compromised:
            return True
        return all(
            h.status in ("isolated", "contained") for h in graph.hosts.values()
        )

    def reset(self):
        self._investigation_loop_count = 0
        self._remediation_loop_count = 0

    def honor_pushback(
        self,
        proposed_next_phase: str,
        justification_graph_refs: list[str],
        graph: "ThreatGraph",
    ) -> tuple[bool, str]:
        if proposed_next_phase not in self.PHASE_ORDER and proposed_next_phase != "done":
            return False, f"invalid phase '{proposed_next_phase}'"
        if not justification_graph_refs:
            return False, "no justification graph references provided"

        all_node_ids = (
            set(graph.alerts.keys())
            | set(graph.hosts.keys())
            | set(graph.processes.keys())
            | set(graph.iocs.keys())
            | set(graph.vulnerabilities.keys())
        )
        for ref in justification_graph_refs:
            if ref not in all_node_ids:
                return False, f"reference '{ref}' not present in graph"

        has_critical_alert = any(
            ref in graph.alerts and graph.alerts[ref].severity in ("high", "critical")
            for ref in justification_graph_refs
        )
        if not has_critical_alert:
            return False, "at least one referenced alert must be high/critical severity"

        return True, ""


# ===========================================================================
# Triage Solver
# ===========================================================================

SEVERITY_W = {"low": 1, "medium": 3, "high": 7, "critical": 15}
CRITICALITY_W = {"low": 1, "medium": 2, "high": 4, "critical": 8}
REACHABILITY_SCALE = 10


def compute_triage_priority(
    alert: "AlertNode",
    host: "HostNode",
    graph: "ThreatGraph",
) -> float:
    blast_radius = sum(1 for e in graph.edges if e.source_id == host.hostname)
    return (
        SEVERITY_W[alert.severity]
        * CRITICALITY_W[host.business_criticality]
        * (1 + blast_radius / REACHABILITY_SCALE)
    )


def solve_triage_order(graph: "ThreatGraph") -> list[str]:
    scored: list[tuple[float, str]] = []
    for alert in graph.alerts.values():
        host = graph.hosts.get(alert.source_host)
        if host is None:
            continue
        score = compute_triage_priority(alert, host, graph)
        scored.append((score, alert.alert_id))
    scored.sort(key=lambda t: t[0], reverse=True)
    return [aid for _, aid in scored]
