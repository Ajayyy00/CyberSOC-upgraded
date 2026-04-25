# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
10-dimensional deterministic graders for CyberSOCEnv.

grade_episode() returns a structured dict with per-dimension breakdown,
penalties, bonuses, and reward signals suitable for GRPO. Wrappers
grade_easy/medium/hard preserve their backward-compatible float return.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .threat_graph import ThreatGraph


_DIMENSION_WEIGHTS = {
    "threat_containment":     0.20,
    "ioc_blocking":           0.12,
    "forensic_investigation": 0.10,
    "siem_correlation":       0.08,
    "threat_intel_usage":     0.08,
    "vuln_root_cause":        0.08,
    "business_impact":        0.10,
    "step_efficiency":        0.07,
    "plan_coverage":          0.10,
    "plan_evidence_quality":  0.07,
}

_PER_OCCURRENCE_CAP = 0.15


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def _capped(delta: float) -> float:
    return max(-_PER_OCCURRENCE_CAP, min(_PER_OCCURRENCE_CAP, delta))


def grade_episode(
    episode_actions: List[Dict[str, Any]],
    final_plan: Optional[Dict[str, Any]],
    graph: "ThreatGraph",
    task_def: Dict[str, Any],
    state,
    disruption_cost: float = 0.0,
) -> Dict[str, Any]:
    """Score the episode across 10 dimensions and return structured output."""

    requirements = task_def.get("containment_requirements", {}) or {}
    must_kill = requirements.get("must_kill", []) or []
    must_block = requirements.get("must_block_iocs", []) or []
    breakdown: Dict[str, float] = {}
    penalties: List[Dict[str, Any]] = []
    bonuses: List[Dict[str, Any]] = []

    killed_processes = list(getattr(state, "killed_processes", []) or [])
    blocked_iocs = list(getattr(state, "blocked_iocs", []) or [])
    isolated_subnets = list(getattr(state, "isolated_subnets", []) or [])
    scanned_hosts = list(getattr(state, "scanned_hosts", []) or [])
    enriched_iocs = list(getattr(state, "enriched_iocs", []) or [])
    correlated_pairs = list(getattr(state, "correlated_alert_pairs", []) or [])
    triggered_playbooks = list(getattr(state, "triggered_playbooks", []) or [])

    # ---- 1. threat_containment ----
    if must_kill:
        matched = 0
        for req in must_kill:
            req_host = req.get("hostname") if isinstance(req, dict) else None
            req_proc = req.get("process") if isinstance(req, dict) else None
            for k in killed_processes:
                if k.get("hostname") == req_host and k.get("process") == req_proc:
                    matched += 1
                    break
        breakdown["threat_containment"] = matched / len(must_kill)
    else:
        breakdown["threat_containment"] = 1.0

    # ---- 2. ioc_blocking ----
    if must_block:
        matched_blocks = sum(1 for ioc in must_block if ioc in blocked_iocs)
        breakdown["ioc_blocking"] = matched_blocks / len(must_block)
    else:
        breakdown["ioc_blocking"] = 1.0

    # blind blocking penalty: blocked IOCs that were never enriched
    blind_count = sum(1 for ioc in blocked_iocs if ioc not in enriched_iocs)
    if blind_count > 0:
        delta = _capped(-0.05 * blind_count)
        penalties.append({
            "type": "blind_blocking",
            "delta": delta,
            "detail": f"{blind_count} IOC(s) blocked without enrichment",
        })
        breakdown["ioc_blocking"] = _clamp(breakdown["ioc_blocking"] + delta)

    # ---- 3. forensic_investigation ----
    compromised_hosts = [
        h for h, node in graph.hosts.items() if node.status == "compromised"
    ]
    if compromised_hosts:
        examined = sum(1 for h in compromised_hosts if h in scanned_hosts)
        breakdown["forensic_investigation"] = examined / len(compromised_hosts)
    else:
        breakdown["forensic_investigation"] = 1.0

    # ---- 4. siem_correlation ----
    if correlated_pairs:
        # Build a set of alert_ids that belong to the same threat chain
        alert_to_threat: Dict[str, str] = {}
        for threat in task_def.get("attack_chain", []) or []:
            tid = threat.get("threat_id", "")
            for a in task_def.get("initial_alerts", []) or []:
                src = a.get("source_host", "")
                if src in (threat.get("compromised_hosts", []) or []):
                    alert_to_threat[a.get("alert_id", "")] = tid

        correct_pairs = 0
        incorrect_pairs = 0
        for pair in correlated_pairs:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                t1 = alert_to_threat.get(pair[0], "__UNK1__")
                t2 = alert_to_threat.get(pair[1], "__UNK2__")
                if t1 == t2 and t1 != "__UNK1__":
                    correct_pairs += 1
                else:
                    incorrect_pairs += 1
            else:
                correct_pairs += 1  # legacy format: assume valid

        expected_pairs = max(1, len(set(alert_to_threat.values())))
        raw_corr = max(0.0, (correct_pairs - incorrect_pairs * 0.5)) / expected_pairs
        breakdown["siem_correlation"] = _clamp(raw_corr)

        # bonus if correlation happened before any remediation action
        first_remediation_idx = next(
            (i for i, a in enumerate(episode_actions)
             if a.get("action_type") in {"block_ioc", "kill_process",
                                         "isolate_segment", "terminate_pid",
                                         "create_firewall_rule", "quarantine_file"}),
            None,
        )
        first_correlation_idx = next(
            (i for i, a in enumerate(episode_actions)
             if a.get("action_type") == "correlate_alerts"),
            None,
        )
        if first_correlation_idx is not None and (
            first_remediation_idx is None or first_correlation_idx < first_remediation_idx
        ):
            delta = _capped(0.03)
            bonuses.append({
                "type": "early_correlation",
                "delta": delta,
                "detail": "correlation occurred before any remediation",
            })
            breakdown["siem_correlation"] = _clamp(breakdown["siem_correlation"] + delta)
    else:
        breakdown["siem_correlation"] = 0.0

    # ---- 5. threat_intel_usage ----
    total_iocs = len(graph.iocs)
    if total_iocs == 0:
        breakdown["threat_intel_usage"] = 0.5
    else:
        enriched_in_graph = sum(1 for ioc in graph.iocs.values() if ioc.enriched)
        breakdown["threat_intel_usage"] = enriched_in_graph / total_iocs

    # ---- 6. vuln_root_cause ----
    cve_found = any(
        v.exploited_by_threat is not None for v in graph.vulnerabilities.values()
    )
    breakdown["vuln_root_cause"] = 1.0 if cve_found else 0.0
    if cve_found and final_plan:
        cve_ids = {v.cve_id for v in graph.vulnerabilities.values()
                   if v.exploited_by_threat is not None}
        plan_blob = str(final_plan)
        if any(cid in plan_blob for cid in cve_ids):
            delta = _capped(0.05)
            bonuses.append({
                "type": "cve_in_plan",
                "delta": delta,
                "detail": "CVE root-cause referenced in final plan",
            })
            breakdown["vuln_root_cause"] = _clamp(breakdown["vuln_root_cause"] + delta)

    # ---- 7. business_impact ----
    # Driven by disruption_cost accumulated in play_environment: 0.25 per clean host
    # isolated in a subnet, 0.35 per clean single-host isolation.  A score of 1.0
    # means zero disruption; each unit of disruption_cost subtracts proportionally.
    base = max(0.0, 1.0 - disruption_cost)
    if disruption_cost > 0.0:
        penalties.append({
            "type": "business_disruption",
            "delta": -disruption_cost,
            "detail": (
                f"cumulative disruption cost {disruption_cost:.2f} from isolating "
                "non-compromised hosts/subnets"
            ),
        })

    # Additional penalty for explicitly prohibited subnet isolation
    must_not_isolate = requirements.get("must_not_isolate", []) or []
    for s in [s for s in isolated_subnets if s in must_not_isolate]:
        delta = _capped(-0.15)
        penalties.append({
            "type": "unnecessary_isolation",
            "delta": delta,
            "detail": f"subnet '{s}' is explicitly prohibited from isolation",
        })
        base = max(0.0, base + delta)

    # Over-isolation: penalise isolating hosts not in the attack chain.
    # justified_set = hosts from attack_chain.compromised_hosts + still-compromised graph nodes.
    total_hosts = len(graph.hosts)
    if total_hosts > 0:
        isolated_count = sum(1 for h in graph.hosts.values() if h.status == "isolated")

        if isolated_count > 0:
            justified_set: set = set()
            for threat in task_def.get("attack_chain", []) or []:
                for h in threat.get("compromised_hosts", []) or []:
                    justified_set.add(h)
            for hname, hnode in graph.hosts.items():
                if hnode.status == "compromised":
                    justified_set.add(hname)

            wrong_isolations = sum(
                1 for hname, hnode in graph.hosts.items()
                if hnode.status == "isolated" and hname not in justified_set
            )
            if wrong_isolations > 0:
                delta = -min(0.80, wrong_isolations * 0.20)
                penalties.append({
                    "type": "over_isolation",
                    "delta": delta,
                    "detail": f"{wrong_isolations} host(s) isolated without attack-chain justification",
                })
                base = max(0.0, base + delta)
            elif isolated_count / total_hosts > 0.20:
                # All isolations justified but scale is a blunt sweep
                delta = -0.20
                penalties.append({
                    "type": "over_isolation",
                    "delta": delta,
                    "detail": f">20% of hosts isolated ({isolated_count}/{total_hosts})",
                })
                base = max(0.0, base + delta)

    breakdown["business_impact"] = base

    # ---- 8. step_efficiency ----
    eff_base = 1.0 if triggered_playbooks else 0.5
    playbook_bonus_total = 0.0
    for _ in triggered_playbooks:
        delta = _capped(0.10)
        bonuses.append({
            "type": "playbook_triggered",
            "delta": delta,
            "detail": "SOAR playbook used",
        })
        playbook_bonus_total += delta
    playbook_bonus_total = min(playbook_bonus_total, 0.30)
    eff_base += playbook_bonus_total

    steps_used = len(episode_actions)
    over = max(0, steps_used - 15)
    if over > 0:
        delta = _capped(-0.05 * over)
        penalties.append({
            "type": "step_overrun",
            "delta": delta,
            "detail": f"used {steps_used} steps, over budget by {over}",
        })
        eff_base += delta
    breakdown["step_efficiency"] = _clamp(eff_base)

    # ---- 9. plan_coverage ----
    if final_plan is None:
        breakdown["plan_coverage"] = 0.0
    else:
        # total known threats = unique threat IDs in containment_requirements
        known_threats = set()
        for k in ("must_kill", "must_block_iocs", "must_forensics"):
            for entry in requirements.get(k, []) or []:
                if isinstance(entry, dict) and "threat_id" in entry:
                    known_threats.add(entry["threat_id"])
        # also include attack_chain threats
        for t in task_def.get("attack_chain", []) or []:
            if isinstance(t, dict) and "threat_id" in t:
                known_threats.add(t["threat_id"])

        if not known_threats:
            breakdown["plan_coverage"] = 1.0
        else:
            plan_blob = str(final_plan)
            covered = sum(1 for t in known_threats if t in plan_blob)
            raw_coverage = covered / len(known_threats)

            # Plan padding penalty: entries with no evidence are punished
            plan_entries = final_plan.get("entries", []) if isinstance(final_plan, dict) else []
            padded = sum(
                1 for e in plan_entries
                if isinstance(e, dict) and (
                    (e.get("confidence", 1.0) < 0.2) or
                    (not e.get("root_cause"))
                )
            )
            if padded > 0:
                delta = _capped(-0.10 * padded)
                penalties.append({
                    "type": "plan_padding",
                    "delta": delta,
                    "detail": f"{padded} plan entries lack evidence (confidence<0.2 or empty root_cause)",
                })
                raw_coverage = max(0.0, raw_coverage + delta)

            breakdown["plan_coverage"] = _clamp(raw_coverage)

    # ---- 10. plan_evidence_quality ----
    if final_plan is None:
        breakdown["plan_evidence_quality"] = 0.0
    else:
        primary = final_plan.get("primary_threat_id", "") if isinstance(final_plan, dict) else ""
        rubric_items = (
            len(must_kill)
            + len(must_block)
            + len(requirements.get("must_forensics", []) or [])
        )
        breakdown["plan_evidence_quality"] = _clamp(
            graph.compute_evidence_confidence(primary, rubric_item_count=rubric_items)
        )

    # Final weighted score
    raw_score = sum(_DIMENSION_WEIGHTS[k] * v for k, v in breakdown.items())
    final_score = _clamp(raw_score)

    reward_functions = {f"reward_{k}": v for k, v in breakdown.items()}

    return {
        "final_score": final_score,
        "breakdown": breakdown,
        "penalties": penalties,
        "bonuses": bonuses,
        "reward_functions": reward_functions,
    }


def grade_easy(
    episode_actions: List[Dict[str, Any]],
    final_plan: Optional[Dict[str, Any]],
    graph: "ThreatGraph",
    task_def: Dict[str, Any],
    state,
) -> float:
    """Backward-compatible: returns final_score float for the easy task."""
    return grade_episode(episode_actions, final_plan, graph, task_def, state)["final_score"]


def grade_medium(
    episode_actions: List[Dict[str, Any]],
    final_plan: Optional[Dict[str, Any]],
    graph: "ThreatGraph",
    task_def: Dict[str, Any],
    state,
) -> float:
    """Backward-compatible: returns final_score float for the medium task."""
    return grade_episode(episode_actions, final_plan, graph, task_def, state)["final_score"]


def grade_hard(
    episode_actions: List[Dict[str, Any]],
    final_plan: Optional[Dict[str, Any]],
    graph: "ThreatGraph",
    task_def: Dict[str, Any],
    state,
) -> float:
    """Backward-compatible: returns final_score float for the hard task."""
    return grade_episode(episode_actions, final_plan, graph, task_def, state)["final_score"]
