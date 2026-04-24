"""SOAR Playbook Library — 5 deterministic playbooks + prerequisite checker."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .threat_graph import ThreatGraph


PLAYBOOKS = {
    "ransomware_containment": {
        "name": "ransomware_containment",
        "description": "Kill encryption processes and block malware hashes",
        "prerequisites": ["forensics_run_on_target", "process_identified"],
        "sub_actions": ["kill_process", "block_ioc"],
        "target_attack_types": ["ransomware", "encryption"],
    },
    "c2_disruption": {
        "name": "c2_disruption",
        "description": "Block C2 IPs and disrupt command and control channel",
        "prerequisites": ["ioc_enriched", "c2_ip_identified"],
        "sub_actions": ["block_ioc", "isolate_segment"],
        "target_attack_types": ["c2", "backdoor", "remote_access"],
    },
    "lateral_movement_lockdown": {
        "name": "lateral_movement_lockdown",
        "description": "Block east-west traffic and kill lateral movement backdoors",
        "prerequisites": ["forensics_run_on_target", "lateral_movement_detected"],
        "sub_actions": ["kill_process", "isolate_segment"],
        "target_attack_types": ["lateral_movement", "pivot"],
    },
    "phishing_response": {
        "name": "phishing_response",
        "description": "Enrich phishing IOCs and block phishing domains",
        "prerequisites": ["phishing_vector_confirmed"],
        "sub_actions": ["enrich_ioc", "block_ioc"],
        "target_attack_types": ["phishing", "spearphishing"],
    },
    "data_exfil_stop": {
        "name": "data_exfil_stop",
        "description": "Block exfil destinations and kill exfil processes",
        "prerequisites": ["forensics_run_on_target", "exfil_destination_identified"],
        "sub_actions": ["block_ioc", "kill_process"],
        "target_attack_types": ["exfiltration", "data_theft"],
    },
}


def _check_single_prerequisite(
    prereq: str,
    target_hostname: str,
    state,
    graph: "ThreatGraph",
) -> tuple[bool, str]:
    if prereq == "forensics_run_on_target":
        scanned = getattr(state, "scanned_hosts", []) or []
        if target_hostname in scanned:
            return True, ""
        # Also accept if a forensic-type edge (exploits / runs_on) exists for this host
        for e in graph.edges:
            if e.edge_type in ("exploits", "runs_on") and (
                e.target_id == target_hostname or e.source_id == target_hostname
            ):
                return True, ""
        return False, f"forensics not run on {target_hostname}"

    if prereq == "process_identified":
        for p in graph.processes.values():
            if p.hostname == target_hostname:
                return True, ""
        return False, f"no process identified on {target_hostname}"

    if prereq == "ioc_enriched":
        for ioc in graph.iocs.values():
            if ioc.enriched:
                return True, ""
        return False, "no IOC has been enriched yet"

    if prereq == "c2_ip_identified":
        for ioc in graph.iocs.values():
            if ioc.ioc_type == "ip" and ioc.confidence > 0.7:
                return True, ""
        return False, "no high-confidence C2 IP identified"

    if prereq == "lateral_movement_detected":
        for e in graph.edges:
            if e.edge_type == "pivoted_from":
                return True, ""
        return False, "no lateral movement detected in graph"

    if prereq == "phishing_vector_confirmed":
        for a in graph.alerts.values():
            if a.source_host == target_hostname:
                return True, ""
        return False, f"no alert confirms phishing vector on {target_hostname}"

    if prereq == "exfil_destination_identified":
        for ioc in graph.iocs.values():
            if (
                ioc.ioc_type in ("ip", "domain")
                and ioc.confidence > 0.6
                and not ioc.blocked
            ):
                return True, ""
        return False, "no unblocked exfil destination identified"

    return False, f"unknown prerequisite: {prereq}"


def check_prerequisites(
    playbook_name: str,
    target_hostname: str,
    state,
    graph: "ThreatGraph",
) -> tuple[bool, str]:
    """Validate all prerequisites for a playbook against state + graph."""
    if playbook_name not in PLAYBOOKS:
        raise KeyError(f"Unknown playbook: {playbook_name}")

    for prereq in PLAYBOOKS[playbook_name]["prerequisites"]:
        ok, reason = _check_single_prerequisite(prereq, target_hostname, state, graph)
        if not ok:
            return False, reason
    return True, ""
