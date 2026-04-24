"""ThreatGraph — typed knowledge graph of SOC entities, edges, and evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class HostNode(BaseModel):
    hostname: str
    subnet: str
    business_criticality: Literal["low", "medium", "high", "critical"]
    status: Literal["healthy", "suspicious", "compromised", "isolated", "contained"]
    first_seen_suspicious: Optional[datetime] = None
    scanned: bool = False


class ProcessNode(BaseModel):
    process_id: str  # format: "hostname:pid"
    hostname: str
    process_name: str
    killed: bool = False


class IOCNode(BaseModel):
    ioc_value: str
    ioc_type: Literal["ip", "domain", "hash", "filename"]
    confidence: float
    blocked: bool = False
    enriched: bool = False
    threat_actor: Optional[str] = None
    mitre_ttps: list[str] = Field(default_factory=list)


class VulnerabilityNode(BaseModel):
    cve_id: str
    hostname: str
    cvss_score: float
    exploitability: Literal["active", "theoretical", "patched"]
    patch_available: bool
    exploited_by_threat: Optional[str] = None


class AlertNode(BaseModel):
    alert_id: str
    severity: Literal["low", "medium", "high", "critical"]
    priority_score: float
    source_host: str
    correlated_with: list[str] = Field(default_factory=list)


class Edge(BaseModel):
    edge_type: Literal[
        "runs_on", "involves", "communicates_with",
        "pivoted_from", "part_of_chain", "exploits",
    ]
    source_id: str
    target_id: str
    evidence: dict = Field(default_factory=dict)


MAX_GRAPH_NODES = 200


class ThreatGraph:
    def __init__(self):
        self.hosts: dict[str, HostNode] = {}
        self.processes: dict[str, ProcessNode] = {}
        self.iocs: dict[str, IOCNode] = {}
        self.vulnerabilities: dict[str, VulnerabilityNode] = {}
        self.alerts: dict[str, AlertNode] = {}
        self.edges: list[Edge] = []
        self.version: int = 0
        # changelog entries: (version_after_add, entity_type, entity_id)
        self._changelog: list[tuple[int, str, str]] = []
        # insertion-order tracking for IOC pruning (oldest first)
        self._ioc_insertion_order: list[str] = []

    def _total_nodes(self) -> int:
        return (
            len(self.hosts) + len(self.processes) + len(self.iocs)
            + len(self.vulnerabilities) + len(self.alerts)
        )

    def _prune_oldest_iocs(self, needed: int = 1) -> None:
        """Remove the oldest `needed` IOCNodes to stay under MAX_GRAPH_NODES."""
        pruned = 0
        while pruned < needed and self._ioc_insertion_order:
            oldest = self._ioc_insertion_order.pop(0)
            if oldest in self.iocs:
                del self.iocs[oldest]
                pruned += 1

    def add_host(self, node: HostNode) -> None:
        self.hosts[node.hostname] = node
        self.version += 1
        self._changelog.append((self.version, "host", node.hostname))

    def add_process(self, node: ProcessNode) -> None:
        self.processes[node.process_id] = node
        self.version += 1
        self._changelog.append((self.version, "process", node.process_id))

    def add_ioc(self, node: IOCNode) -> None:
        if node.ioc_value in self.iocs:
            return  # already present — no cap action needed
        if self._total_nodes() >= MAX_GRAPH_NODES:
            self._prune_oldest_iocs(needed=1)
        self.iocs[node.ioc_value] = node
        self._ioc_insertion_order.append(node.ioc_value)
        self.version += 1
        self._changelog.append((self.version, "ioc", node.ioc_value))

    def add_vulnerability(self, node: VulnerabilityNode) -> None:
        key = f"{node.hostname}:{node.cve_id}"
        self.vulnerabilities[key] = node
        self.version += 1
        self._changelog.append((self.version, "vulnerability", key))

    def add_alert(self, node: AlertNode) -> None:
        self.alerts[node.alert_id] = node
        self.version += 1
        self._changelog.append((self.version, "alert", node.alert_id))

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)
        self.version += 1
        edge_id = f"{edge.edge_type}:{edge.source_id}->{edge.target_id}"
        self._changelog.append((self.version, "edge", edge_id))

    def delta_since(self, version: int) -> dict:
        """Return compact summary of nodes/edges added since `version`."""
        if version <= 0:
            entries = list(self._changelog)
        else:
            entries = [e for e in self._changelog if e[0] > version]

        counts: dict[str, int] = {}
        ids_by_type: dict[str, list[str]] = {}
        for _, etype, eid in entries:
            counts[etype] = counts.get(etype, 0) + 1
            ids_by_type.setdefault(etype, []).append(eid)

        # Truncate each id list to keep summary compact
        compact_ids = {k: v[:5] for k, v in ids_by_type.items()}

        summary_parts = [f"{t}={counts[t]}" for t in sorted(counts.keys())]
        summary_text = f"Δ since v{version}: " + ", ".join(summary_parts) if summary_parts else f"Δ since v{version}: (no changes)"

        return {
            "from_version": version,
            "to_version": self.version,
            "counts": counts,
            "ids": compact_ids,
            "summary": summary_text,
        }

    def compute_evidence_confidence(
        self, threat_id: str, rubric_item_count: int = 3
    ) -> float:
        """Confidence that a threat is well-evidenced.

        Denominator is normalized to task complexity: max(3, rubric_item_count * 1.5).
        This prevents reward hacking via forensics spam — a spammer who generates
        10 graph nodes only scores against the rubric-sized baseline, not 10.
        """
        linked_ids: set[str] = set()
        for edge in self.edges:
            if edge.source_id == threat_id:
                linked_ids.add(edge.target_id)
            elif edge.target_id == threat_id:
                linked_ids.add(edge.source_id)

        if not linked_ids:
            return 0.0

        non_alert_count = 0
        for nid in linked_ids:
            if nid in self.alerts:
                continue
            if (
                nid in self.hosts
                or nid in self.processes
                or nid in self.iocs
                or nid in self.vulnerabilities
            ):
                non_alert_count += 1

        denominator = max(3.0, rubric_item_count * 1.5)
        confidence = non_alert_count / denominator
        return max(0.0, min(1.0, confidence))

    def get_context_summary(self) -> str:
        """Compact LLM-injectable summary of current graph state."""
        compromised = sum(1 for h in self.hosts.values() if h.status == "compromised")
        critical_alerts = sum(1 for a in self.alerts.values() if a.severity == "critical")
        blocked = sum(1 for i in self.iocs.values() if i.blocked)
        enriched = sum(1 for i in self.iocs.values() if i.enriched)
        return (
            f"Hosts: {len(self.hosts)} ({compromised} compromised) "
            f"Alerts: {len(self.alerts)} ({critical_alerts} critical) "
            f"IOCs: {len(self.iocs)} ({blocked} blocked, {enriched} enriched) "
            f"Vulns: {len(self.vulnerabilities)} "
            f"Edges: {len(self.edges)}"
        )
