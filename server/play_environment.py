# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
CyberSOCEnv — Enterprise Cybersecurity Operations Center Environment.

Implements the OpenEnv Environment interface for a deterministic SOC
incident response simulation on a 500-node enterprise network.

The agent receives SIEM/EDR alerts, queries hosts, runs forensics,
isolates segments, blocks IOCs, kills processes, and submits a
containment plan — all while minimizing business downtime.
"""

from __future__ import annotations

import copy
import random
import uuid
from typing import Any, Dict, List, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from ..models import (
        SOCObservation,
        SOCActionWrapper,
        SOCState,
        Alert,
        NetworkTopology,
        ForensicsResult,
        TimelineEntry,
        QueryHost,
        IsolateSegment,
        BlockIOC,
        RunForensics,
        KillProcess,
        SubmitContainmentPlan,
        CorrelateAlerts,
        EnrichIOC,
        ScanHostVulnerabilities,
        TriggerPlaybook,
    )
except ImportError:
    from models import (
        SOCObservation,
        SOCActionWrapper,
        SOCState,
        Alert,
        NetworkTopology,
        ForensicsResult,
        TimelineEntry,
        QueryHost,
        IsolateSegment,
        BlockIOC,
        RunForensics,
        KillProcess,
        SubmitContainmentPlan,
        CorrelateAlerts,
        EnrichIOC,
        ScanHostVulnerabilities,
        TriggerPlaybook,
    )

from .tasks import get_task, build_network
from .graders import grade_episode
from .threat_graph import (
    ThreatGraph,
    HostNode,
    ProcessNode,
    IOCNode,
    VulnerabilityNode,
    AlertNode,
    Edge,
)
from .soar_playbooks import PLAYBOOKS, check_prerequisites


class ActionMiddleware:
    """Pre-flight validation for SOC actions.

    Detects phase violations (action out of order) and graph-ungrounded actions
    (action references an entity not yet discovered in the ThreatGraph).
    Returns None if the action is valid, or an error dict otherwise.
    """

    def validate(
        self,
        current_phase: str,
        action_type: str,
        args: Dict[str, Any],
        graph,
    ) -> Optional[Dict[str, str]]:
        # Phase violation: plan submission before any investigation
        if action_type == "submit_containment_plan" and current_phase == "triage":
            return {
                "error_type": "PHASE_VIOLATION",
                "message": "submit_containment_plan requires investigation phase first",
            }

        # Graph-groundedness: IOC must be discovered before enrichment
        if action_type == "enrich_ioc":
            ioc_val = args.get("ioc_value", "")
            if ioc_val and graph is not None and ioc_val not in graph.iocs:
                return {
                    "error_type": "GRAPH_FAILURE",
                    "message": f"IOC '{ioc_val}' not in threat graph; receive an alert or run forensics first",
                }

        # Graph-groundedness: host must be known before vulnerability scan
        if action_type == "scan_host_vulnerabilities":
            hostname = args.get("hostname", "")
            if hostname and graph is not None and hostname not in graph.hosts:
                return {
                    "error_type": "GRAPH_FAILURE",
                    "message": f"Host '{hostname}' not in threat graph; run query_host first",
                }

        return None


class CyberSOCEnvironment(Environment):
    """
    Deterministic SOC incident response environment.

    Simulates a 500-node enterprise network under attack. The agent must
    investigate alerts, contain threats, and submit a containment plan
    while minimizing business downtime.

    Supports concurrent WebSocket sessions (each gets own instance).

    Example:
        >>> env = CyberSOCEnvironment()
        >>> obs = env.reset(task_id="easy")
        >>> print(len(obs.alert_queue))  # Initial alerts
        >>> obs = env.step(SOCActionWrapper(type="query_host", hostname="WS-042"))
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, adaptive: bool = False):
        """Initialize the environment (actual state set in reset)."""
        super().__init__()
        self._adaptive = adaptive
        self._live_requirements: Dict[str, Any] = {}
        self._threat_graph = None  # will be initialized on reset()
        self._state = SOCState(episode_id=str(uuid4()), step_count=0)
        self._network: Dict[str, List[Dict[str, Any]]] = {}
        self._task_def: Dict[str, Any] = {}
        self._alert_queue: List[Dict[str, Any]] = []
        self._host_index: Dict[str, Dict[str, Any]] = {}  # hostname -> host dict
        self._plan_entries: List[Dict[str, Any]] = []
        self._last_forensics: Optional[ForensicsResult] = None
        self._middleware = ActionMiddleware()
        self._rng = random.Random(0)  # overwritten in reset()
        self._pending_followup: Dict[str, bool] = {}  # hostname -> responded_to

    def _reset_rubric(self):
        """Initialize live containment requirements for dynamic grading in adaptive mode."""
        import copy
        self._live_requirements = copy.deepcopy(
            self._task_def.get("containment_requirements", {})
        )

    # ===========================================================================
    # reset()
    # ===========================================================================

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SOCObservation:
        """Reset the environment for a specific task.

        Args:
            seed: Ignored (environment is fully deterministic).
            episode_id: Optional custom episode ID.
            **kwargs: Must include task_id ('easy', 'medium', or 'hard').

        Returns:
            Initial SOCObservation with alert queue and network state.
        """
        task_id = kwargs.get("task_id", "easy")
        self._rng = random.Random(hash(task_id))
        self._task_def = get_task(task_id)
        self._recent_actions = []  # reset stall detector

        # Build deterministic network (cached per task for GRPO throughput)
        if not hasattr(CyberSOCEnvironment, "_network_cache"):
            CyberSOCEnvironment._network_cache = {}
        cache_key = task_id
        if cache_key in CyberSOCEnvironment._network_cache:
            self._network = copy.deepcopy(CyberSOCEnvironment._network_cache[cache_key])
        else:
            self._network = build_network()
            CyberSOCEnvironment._network_cache[cache_key] = copy.deepcopy(self._network)

        # Build hostname index for O(1) lookups
        self._host_index = {}
        for subnet_name, hosts in self._network.items():
            for host in hosts:
                self._host_index[host["hostname"]] = host

        # Inject attack chain: mark compromised hosts, add malicious processes
        for threat in self._task_def["attack_chain"]:
            for hostname in threat["compromised_hosts"]:
                if hostname in self._host_index:
                    host = self._host_index[hostname]
                    host["status"] = "compromised"
                    for proc in threat["malicious_processes"]:
                        if proc not in host["running_processes"]:
                            host["running_processes"].append(proc)

        # Initialize alert queue (deep copy so mutations don't affect task def)
        self._alert_queue = copy.deepcopy(self._task_def["initial_alerts"])

        # Reset state
        eid = episode_id or str(uuid4())
        self._state = SOCState(
            episode_id=eid,
            step_count=0,
            task_id=task_id,
            max_steps=self._task_def["max_steps"],
            total_reward=0.0,
            business_impact=self._task_def["initial_business_impact"],
            contained_threats=[],
            active_threats=[t["threat_id"] for t in self._task_def["attack_chain"]],
            blocked_iocs=[],
            isolated_subnets=[],
            forensics_run=[],
            killed_processes=[],
            queried_hosts=[],
            timeline=[],
            is_done=False,
            submitted_plan=False,
        )

        self._plan_entries = []
        self._last_forensics = None
        self._reset_rubric()
        self._fired_step_rewards: set = set()
        self._step_reward_total: float = 0.0
        self._pending_followup: Dict[str, bool] = {}

        # Initialize threat graph from task definition
        self._threat_graph = ThreatGraph()
        self._populate_threat_graph()
        self._last_obs_extras: Dict[str, Any] = {}

        return self._build_observation(reward=0.0, done=False)

    def _populate_threat_graph(self) -> None:
        """Seed the threat graph with hosts, processes, IOCs, and alerts from task_def."""
        graph = self._threat_graph

        # Hosts: include compromised hosts from attack chain + every host they live on
        compromised_set: set[str] = set()
        for threat in self._task_def.get("attack_chain", []):
            for hn in threat.get("compromised_hosts", []):
                compromised_set.add(hn)

        for hostname in compromised_set:
            host_dict = self._host_index.get(hostname)
            if host_dict is None:
                continue
            graph.add_host(HostNode(
                hostname=hostname,
                subnet=host_dict.get("subnet", "corporate"),
                business_criticality="high" if host_dict.get("criticality", 0.5) >= 0.7 else "medium",
                status="compromised",
            ))

        # Processes: malicious processes per compromised host
        for threat in self._task_def.get("attack_chain", []):
            tid = threat.get("threat_id", "T?")
            for hostname in threat.get("compromised_hosts", []):
                if hostname not in graph.hosts:
                    continue
                for proc in threat.get("malicious_processes", []):
                    pid = f"{hostname}:{proc}"
                    if pid not in graph.processes:
                        graph.add_process(ProcessNode(
                            process_id=pid,
                            hostname=hostname,
                            process_name=proc,
                        ))
                # Add part_of_chain edge
                graph.add_edge(Edge(
                    edge_type="part_of_chain",
                    source_id=tid,
                    target_id=hostname,
                ))

        # IOCs from attack chain
        for threat in self._task_def.get("attack_chain", []):
            iocs = threat.get("iocs", {}) or {}
            for ioc_value in iocs.get("hashes", []):
                if ioc_value not in graph.iocs:
                    graph.add_ioc(IOCNode(ioc_value=ioc_value, ioc_type="hash", confidence=0.85))
            for ioc_value in iocs.get("ips", []):
                if ioc_value not in graph.iocs:
                    graph.add_ioc(IOCNode(ioc_value=ioc_value, ioc_type="ip", confidence=0.85))
            for ioc_value in iocs.get("domains", []):
                if ioc_value not in graph.iocs:
                    graph.add_ioc(IOCNode(ioc_value=ioc_value, ioc_type="domain", confidence=0.85))
            for c2 in threat.get("c2_servers", []):
                if c2 not in graph.iocs:
                    graph.add_ioc(IOCNode(ioc_value=c2, ioc_type="ip", confidence=0.95))

        # Alerts
        for a in self._task_def.get("initial_alerts", []):
            aid = a.get("alert_id")
            if aid and aid not in graph.alerts:
                graph.add_alert(AlertNode(
                    alert_id=aid,
                    severity=a.get("severity", "medium"),
                    priority_score=1.0,
                    source_host=a.get("source_host", ""),
                ))

    # ===========================================================================
    # step()
    # ===========================================================================

    def step(
        self,
        action: SOCActionWrapper,  # type: ignore[override]
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> SOCObservation:
        """Process one agent action.

        Args:
            action: SOCActionWrapper containing the typed action.
            timeout_s: Ignored.

        Returns:
            SOCObservation with updated state, reward, and done flag.
        """
        if self._state.is_done:
            return self._build_observation(reward=0.0, done=True)

        # Convert wrapper to typed action (before consuming a step)
        typed_action = action.to_typed_action()
        args = typed_action.model_dump(exclude={"metadata", "type"})

        # Pre-flight validation — invalid actions are penalised without consuming a step
        current_phase = self._get_current_phase()
        validation_error = self._middleware.validate(
            current_phase, typed_action.type, args, self._threat_graph
        )
        if validation_error:
            error_type = validation_error.get("error_type", "")
            penalty = -0.10 if error_type == "PHASE_VIOLATION" else -0.05
            self._state.total_reward += penalty
            return self._build_observation(reward=penalty, done=False)

        # Action is valid — now consume the step
        self._state.step_count += 1

        # Dispatch to handler
        reward = 0.0
        result_description = "unknown action"

        # Reset per-step observation extras at the start of every step
        self._last_obs_extras = {}

        if isinstance(typed_action, QueryHost):
            reward, result_description = self._handle_query_host(typed_action)
        elif isinstance(typed_action, IsolateSegment):
            reward, result_description = self._handle_isolate_segment(typed_action)
        elif isinstance(typed_action, BlockIOC):
            reward, result_description = self._handle_block_ioc(typed_action)
        elif isinstance(typed_action, RunForensics):
            reward, result_description = self._handle_run_forensics(typed_action)
        elif isinstance(typed_action, KillProcess):
            reward, result_description = self._handle_kill_process(typed_action)
        elif isinstance(typed_action, SubmitContainmentPlan):
            reward, result_description = self._handle_submit_plan(typed_action)
        elif isinstance(typed_action, CorrelateAlerts):
            result = self._handle_correlate_alerts(typed_action)
            self._last_obs_extras.update(result)
            reward = 0.05 if "error" not in result else -0.05
            result_description = result.get("description", "correlate_alerts")
        elif isinstance(typed_action, EnrichIOC):
            result = self._handle_enrich_ioc(typed_action)
            self._last_obs_extras.update(result)
            reward = 0.05 if "error" not in result else -0.05
            result_description = result.get("description", "enrich_ioc")
        elif isinstance(typed_action, ScanHostVulnerabilities):
            result = self._handle_scan_vulnerabilities(typed_action)
            self._last_obs_extras.update(result)
            reward = 0.05 if "error" not in result else -0.05
            result_description = result.get("description", "scan_host_vulnerabilities")
        elif isinstance(typed_action, TriggerPlaybook):
            result = self._handle_trigger_playbook(typed_action)
            self._last_obs_extras.update(result)
            reward = 0.10 if "error" not in result else -0.05
            result_description = result.get("description", "trigger_playbook")

        # Step reward (idempotent per triple)
        target = self._get_action_target(typed_action)
        step_r = self._get_step_reward(phase="investigation", action_type=typed_action.type, target=target)
        reward += step_r
        self._step_reward_total += step_r

        # Stall detection: penalise 3+ consecutive identical actions
        stall_key = (typed_action.type, target)
        if not hasattr(self, "_recent_actions"):
            self._recent_actions = []
        self._recent_actions.append(stall_key)
        if len(self._recent_actions) >= 3:
            last_three = self._recent_actions[-3:]
            if last_three[0] == last_three[1] == last_three[2]:
                reward -= 0.05  # stall penalty

        # Adaptive adversary reaction
        self._adversary_react(action_type=typed_action.type, target=target)

        # Business impact grows each step (attacker progresses)
        if not self._state.is_done:
            impact_rate = self._task_def.get("impact_per_step", 0.02)
            # Reduce impact growth if threats are being contained
            active_ratio = len(self._state.active_threats) / max(1, len(self._task_def["attack_chain"]))
            self._state.business_impact = min(
                1.0,
                self._state.business_impact + impact_rate * active_ratio,
            )

        # Record timeline
        self._state.timeline.append({
            "step": self._state.step_count,
            "action_type": typed_action.type,
            "target": self._get_action_target(typed_action),
            "result": result_description,
            "reward": reward,
        })

        # Accumulate reward
        self._state.total_reward += reward

        # Check termination
        done = False
        if self._state.submitted_plan:
            done = True
            self._state.is_done = True
        elif self._state.step_count >= self._state.max_steps:
            done = True
            self._state.is_done = True
            reward -= 0.20  # Penalty for running out of time
            self._state.total_reward += (-0.20)

        return self._build_observation(reward=reward, done=done)

    # ===========================================================================
    # Action Handlers (return (reward, description))
    # ===========================================================================

    def _handle_query_host(self, action: QueryHost) -> tuple[float, str]:
        """Query a host for status info."""
        hostname = action.hostname
        self._last_forensics = None  # Clear forensics from previous step

        if hostname not in self._host_index:
            return -0.05, f"Host '{hostname}' not found in network"

        host = self._host_index[hostname]

        # Reward for querying compromised hosts (useful investigation)
        reward = 0.0
        if host["status"] == "compromised" and hostname not in self._state.queried_hosts:
            reward = 0.05  # Good: investigating a compromised host
        elif hostname in self._state.queried_hosts:
            reward = -0.02  # Penalty: re-querying same host wastes time

        self._state.queried_hosts.append(hostname)

        # Enhanced observation extras: process_tree + network_connections from graph
        process_tree = []
        if self._threat_graph is not None:
            for p in self._threat_graph.processes.values():
                if p.hostname == hostname:
                    process_tree.append({
                        "process_id": p.process_id,
                        "process_name": p.process_name,
                        "killed": p.killed,
                    })
        network_connections = []
        if self._threat_graph is not None:
            for e in self._threat_graph.edges:
                if e.edge_type == "communicates_with" and (
                    e.source_id == hostname or e.target_id == hostname
                ):
                    other = e.target_id if e.source_id == hostname else e.source_id
                    if other in self._threat_graph.iocs:
                        network_connections.append(other)
        self._last_obs_extras["process_tree"] = process_tree
        self._last_obs_extras["network_connections"] = network_connections

        return reward, f"Queried {hostname}: status={host['status']}, procs={len(host['running_processes'])}"

    def _handle_isolate_segment(self, action: IsolateSegment) -> tuple[float, str]:
        """Isolate a network segment, or a single host if target_host is set."""
        self._last_forensics = None

        # Single-host isolation path
        target_host = getattr(action, "target_host", None)
        if target_host:
            if target_host not in self._host_index:
                return -0.05, f"Host '{target_host}' not found"
            self._host_index[target_host]["status"] = "isolated"
            if self._threat_graph is not None and target_host in self._threat_graph.hosts:
                self._threat_graph.hosts[target_host].status = "isolated"
            if target_host in self._pending_followup:
                self._pending_followup[target_host] = True
            return 0.10, f"Isolated single host '{target_host}'"

        subnet = action.subnet

        if subnet not in self._network:
            return -0.05, f"Subnet '{subnet}' does not exist"

        if subnet in self._state.isolated_subnets:
            return -0.02, f"Subnet '{subnet}' is already isolated"

        # Isolate all hosts in the subnet
        for host in self._network[subnet]:
            host["status"] = "isolated"
            if self._threat_graph is not None and host["hostname"] in self._threat_graph.hosts:
                self._threat_graph.hosts[host["hostname"]].status = "isolated"
            if host["hostname"] in self._pending_followup:
                self._pending_followup[host["hostname"]] = True

        self._state.isolated_subnets.append(subnet)

        # Check if this contains any active threats
        reward = 0.0
        threats_contained = []
        for threat in self._task_def["attack_chain"]:
            if threat["threat_id"] in self._state.active_threats:
                # Check if any compromised hosts are in this subnet
                for ch in threat["compromised_hosts"]:
                    if ch in self._host_index and self._host_index[ch]["subnet"] == subnet:
                        threats_contained.append(threat["threat_id"])
                        break

        if threats_contained:
            reward = 0.15 * len(threats_contained)  # Good: containing lateral movement
            for tid in threats_contained:
                if tid not in self._state.contained_threats:
                    self._state.contained_threats.append(tid)
                if tid in self._state.active_threats:
                    self._state.active_threats.remove(tid)

        # Check if this is an unnecessary isolation (business downtime)
        must_not_isolate = self._task_def["containment_requirements"].get("must_not_isolate", [])
        if subnet in must_not_isolate:
            reward -= 0.10  # Penalty: unnecessary downtime
            self._state.business_impact = min(1.0, self._state.business_impact + 0.08)

        return reward, f"Isolated subnet '{subnet}'. Threats contained: {threats_contained}"

    def _handle_block_ioc(self, action: BlockIOC) -> tuple[float, str]:
        """Block an IOC at the perimeter."""
        ioc = action.ioc_value
        self._last_forensics = None

        if ioc in self._state.blocked_iocs:
            return -0.02, f"IOC '{ioc}' is already blocked"

        self._state.blocked_iocs.append(ioc)

        # Mark any forensics-confirmed host as responded-to if this IOC belongs to its threat chain
        for hostname, responded in list(self._pending_followup.items()):
            if responded:
                continue
            for threat in self._task_def["attack_chain"]:
                if hostname in threat["compromised_hosts"]:
                    all_threat_iocs = (
                        threat["iocs"].get("hashes", [])
                        + threat["iocs"].get("ips", [])
                        + threat["iocs"].get("domains", [])
                        + threat.get("c2_servers", [])
                    )
                    if ioc in all_threat_iocs:
                        self._pending_followup[hostname] = True
                        break

        # Check if this IOC is relevant to any active threat
        reward = 0.0
        relevant = False
        for threat in self._task_def["attack_chain"]:
            all_iocs = (
                threat["iocs"].get("hashes", [])
                + threat["iocs"].get("ips", [])
                + threat["iocs"].get("domains", [])
            )
            if ioc in all_iocs:
                relevant = True
                # Extra reward for blocking C2 server IPs
                if ioc in threat.get("c2_servers", []):
                    reward += 0.15  # High value: cutting C2
                else:
                    reward += 0.10  # Good: blocking relevant IOC
                break

        if not relevant:
            reward = -0.03  # Noise: blocking irrelevant IOC

        return reward, f"Blocked IOC '{ioc}' (type={action.ioc_type}). Relevant: {relevant}"

    def _handle_run_forensics(self, action: RunForensics) -> tuple[float, str]:
        """Run forensic analysis on a host."""
        hostname = action.hostname

        if hostname not in self._host_index:
            self._last_forensics = None
            return -0.05, f"Host '{hostname}' not found"

        host = self._host_index[hostname]

        # Build forensics result based on actual host state
        is_compromised = host["status"] == "compromised"
        malicious_procs = []
        suspicious_files = []
        network_conns = []
        registry_mods = []
        memory_artifacts = []

        if is_compromised:
            # Find which threat(s) affect this host
            for threat in self._task_def["attack_chain"]:
                if hostname in threat["compromised_hosts"]:
                    malicious_procs.extend(threat["malicious_processes"])
                    # Generate deterministic forensic artifacts
                    for proc in threat["malicious_processes"]:
                        suspicious_files.append(f"C:\\Windows\\Temp\\{proc}.dat")
                        registry_mods.append(f"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{proc}")
                    for c2 in threat.get("c2_servers", []):
                        network_conns.append(f"{c2}:443")
                    for ioc_hash in threat["iocs"].get("hashes", []):
                        memory_artifacts.append(f"memory_inject_{ioc_hash[:8]}")

        self._last_forensics = ForensicsResult(
            hostname=hostname,
            malicious_processes=malicious_procs,
            suspicious_files=suspicious_files,
            network_connections=network_conns,
            registry_modifications=registry_mods,
            memory_artifacts=memory_artifacts,
            is_compromised=is_compromised,
        )

        # Reward
        reward = 0.0
        if hostname not in self._state.forensics_run:
            if is_compromised:
                reward = 0.10  # Good: found evidence
                self._pending_followup.setdefault(hostname, False)  # needs response action
            else:
                reward = 0.02  # Cleared a host (some value)
            self._state.forensics_run.append(hostname)
        else:
            reward = -0.02  # Re-running forensics wastes time

        # Enhanced: behavioral_chain and network_flows from graph
        behavioral_chain = []
        network_flows = []
        if self._threat_graph is not None:
            for e in self._threat_graph.edges:
                if e.source_id == hostname or e.target_id == hostname:
                    behavioral_chain.append({
                        "edge_type": e.edge_type,
                        "source_id": e.source_id,
                        "target_id": e.target_id,
                    })
            for e in self._threat_graph.edges:
                if e.edge_type == "communicates_with":
                    if e.source_id == hostname or e.target_id == hostname:
                        other = e.target_id if e.source_id == hostname else e.source_id
                        if other in self._threat_graph.iocs:
                            network_flows.append(other)
        self._last_obs_extras["behavioral_chain"] = behavioral_chain
        self._last_obs_extras["network_flows"] = network_flows

        return reward, f"Forensics on {hostname}: compromised={is_compromised}, procs={malicious_procs}"

    def _handle_kill_process(self, action: KillProcess) -> tuple[float, str]:
        """Kill a process on a host."""
        hostname = action.hostname
        process = action.process_name
        self._last_forensics = None

        if hostname not in self._host_index:
            return -0.05, f"Host '{hostname}' not found"

        host = self._host_index[hostname]

        if host["status"] == "isolated":
            return -0.02, f"Host '{hostname}' is isolated — cannot interact"

        if process not in host["running_processes"]:
            return -0.03, f"Process '{process}' not running on {hostname}"

        # Kill the process
        host["running_processes"].remove(process)
        self._state.killed_processes.append({"hostname": hostname, "process": process})
        if hostname in self._pending_followup:
            self._pending_followup[hostname] = True

        # Check if this was a malicious process
        reward = 0.0
        was_malicious = False
        for threat in self._task_def["attack_chain"]:
            if hostname in threat["compromised_hosts"] and process in threat["malicious_processes"]:
                was_malicious = True
                reward = 0.15  # Major reward: stopping malicious activity

                # Check if all processes for this threat are killed
                all_killed = True
                for th_host in threat["compromised_hosts"]:
                    for th_proc in threat["malicious_processes"]:
                        still_running = (
                            th_host in self._host_index
                            and th_proc in self._host_index[th_host]["running_processes"]
                        )
                        if still_running:
                            all_killed = False
                            break

                if all_killed and threat["threat_id"] in self._state.active_threats:
                    self._state.active_threats.remove(threat["threat_id"])
                    if threat["threat_id"] not in self._state.contained_threats:
                        self._state.contained_threats.append(threat["threat_id"])
                    reward += 0.10  # Bonus: fully contained a threat
                break

        if not was_malicious:
            reward = -0.08  # Penalty: killing legitimate process = downtime
            self._state.business_impact = min(1.0, self._state.business_impact + 0.03)

        if was_malicious:
            self._maybe_reinfect(hostname, process)

        return reward, f"Killed '{process}' on {hostname}. Malicious: {was_malicious}"

    def _handle_submit_plan(self, action: SubmitContainmentPlan) -> tuple[float, str]:
        """Submit the final containment plan."""
        self._last_forensics = None
        self._state.submitted_plan = True
        self._plan_entries = [entry.model_dump() for entry in action.plan]

        # Grade the episode using new 10-dim grader
        final_plan_dict = {
            "entries": self._plan_entries,
            "primary_threat_id": (self._plan_entries[0]["threat_id"]
                                  if self._plan_entries else ""),
        }
        grade_result = grade_episode(
            episode_actions=list(self._state.timeline),
            final_plan=final_plan_dict,
            graph=self._threat_graph,
            task_def=self._task_def,
            state=self._state,
        )
        final_score = grade_result["final_score"]

        # Reward proportional to final grade
        reward = final_score * 1.0  # Scale: perfect score = 1.0 reward
        description = (
            f"Containment plan submitted. "
            f"Grade: {final_score:.3f}. "
            f"Threats contained: {len(self._state.contained_threats)}/{len(self._task_def['attack_chain'])}. "
            f"Business impact: {self._state.business_impact:.2f}"
        )

        return reward, description

    # ===========================================================================
    # New Action Handlers (return observation-update dict)
    # ===========================================================================

    def _handle_correlate_alerts(self, action: CorrelateAlerts) -> dict:
        """Correlate alerts to find shared hosts/IOCs."""
        if len(action.alert_ids) < 2:
            return {"error": "correlate_alerts requires at least 2 alert IDs",
                    "description": "correlate_alerts error"}

        graph = self._threat_graph
        known_alerts = {aid: graph.alerts[aid] for aid in action.alert_ids if aid in graph.alerts}
        if len(known_alerts) < 2:
            return {"error": "fewer than 2 alert IDs found in graph",
                    "description": "correlate_alerts error"}

        # Find shared source hosts
        source_hosts: dict[str, list[str]] = {}
        for aid, alert in known_alerts.items():
            source_hosts.setdefault(alert.source_host, []).append(aid)
        shared_hosts = [h for h, aids in source_hosts.items() if len(aids) >= 2]

        # Find shared IOCs via "involves" edges
        shared_iocs: set[str] = set()
        for e in graph.edges:
            if e.edge_type == "involves" and e.source_id in known_alerts:
                if any(
                    e2.edge_type == "involves" and e2.target_id == e.target_id
                    and e2.source_id in known_alerts and e2.source_id != e.source_id
                    for e2 in graph.edges
                ):
                    shared_iocs.add(e.target_id)

        # Update correlated_with on each alert
        all_ids = list(known_alerts.keys())
        for aid, alert in known_alerts.items():
            for other_id in all_ids:
                if other_id != aid and other_id not in alert.correlated_with:
                    alert.correlated_with.append(other_id)

        self._state.correlated_alert_pairs.append(tuple(all_ids))

        shared_count = len(shared_hosts) + len(shared_iocs)
        correlation_score = min(1.0, shared_count / len(all_ids))

        result = {
            "correlation_results": {
                "shared_hosts": shared_hosts,
                "shared_iocs": list(shared_iocs),
                "correlation_score": correlation_score,
            },
            "description": f"Correlated {len(all_ids)} alerts: {len(shared_hosts)} shared hosts",
        }
        return result

    def _handle_enrich_ioc(self, action: EnrichIOC) -> dict:
        """Enrich an IOC with threat-intel data."""
        graph = self._threat_graph

        if action.ioc_value not in graph.iocs:
            return {"error": "IOC not yet discovered",
                    "description": "enrich_ioc error"}

        intel = self._task_def.get("threat_intel_data", {}) or {}
        data = intel.get(action.ioc_value, {
            "reputation": 0.5,
            "threat_actor": "unknown",
            "mitre_ttps": [],
        })

        # Update IOC node in graph
        ioc_node = graph.iocs[action.ioc_value]
        ioc_node.enriched = True
        ioc_node.threat_actor = data.get("threat_actor")
        ioc_node.mitre_ttps = data.get("mitre_ttps", [])

        if action.ioc_value not in self._state.enriched_iocs:
            self._state.enriched_iocs.append(action.ioc_value)

        return {
            "ioc_enrichment": data,
            "description": f"Enriched IOC {action.ioc_value}: actor={data.get('threat_actor')}",
        }

    def _handle_scan_vulnerabilities(self, action: ScanHostVulnerabilities) -> dict:
        """Scan a host for CVE vulnerabilities."""
        graph = self._threat_graph
        hostname = action.hostname

        if hostname not in graph.hosts:
            return {"error": f"Host '{hostname}' not in Threat Graph",
                    "description": "scan_host_vulnerabilities error"}

        vuln_chain = self._task_def.get("vulnerability_chain", []) or []
        vuln_results: list[dict] = []
        for entry in vuln_chain:
            if not isinstance(entry, dict):
                continue
            if entry.get("hostname") == hostname or entry.get("affected_hosts") and hostname in entry["affected_hosts"]:
                cve_id = entry.get("cve_id", "CVE-UNKNOWN")
                vuln_node = VulnerabilityNode(
                    cve_id=cve_id,
                    hostname=hostname,
                    cvss_score=entry.get("cvss_score", 5.0),
                    exploitability=entry.get("exploitability", "theoretical"),
                    patch_available=entry.get("patch_available", False),
                    exploited_by_threat=entry.get("threat_id"),
                )
                graph.add_vulnerability(vuln_node)
                graph.add_edge(Edge(
                    edge_type="exploits",
                    source_id=cve_id,
                    target_id=hostname,
                ))
                vuln_results.append(entry)

        # Mark host as scanned
        graph.hosts[hostname].scanned = True
        if hostname not in self._state.scanned_hosts:
            self._state.scanned_hosts.append(hostname)

        return {
            "vulnerability_results": vuln_results,
            "description": f"Scanned {hostname}: found {len(vuln_results)} CVEs",
        }

    def _handle_trigger_playbook(self, action: TriggerPlaybook) -> dict:
        """Trigger a SOAR playbook against a target host."""
        ok, reason = check_prerequisites(
            action.playbook_name, action.target, self._state, self._threat_graph
        )
        if not ok:
            return {"error": reason,
                    "description": f"trigger_playbook failed: {reason}"}

        sub_actions = PLAYBOOKS[action.playbook_name]["sub_actions"]
        if action.playbook_name not in self._state.triggered_playbooks:
            self._state.triggered_playbooks.append(action.playbook_name)

        return {
            "playbook_result": {
                "playbook": action.playbook_name,
                "sub_actions": sub_actions,
                "status": "executed",
            },
            "description": f"Executed playbook '{action.playbook_name}' on {action.target}",
        }

    # ===========================================================================
    # Helpers
    # ===========================================================================

    def _compute_reward_dimensions(self) -> Dict[str, float]:
        """Per-step heuristic partial scores for all 10 grading dimensions.

        Evidence-gated: actions only score if prior evidence justified them.
        Result-usage: forensics-confirmed hosts with no followup are penalized.
        Scores in [0, 1]; terminal grade_breakdown supersedes these on plan submission.
        """
        state = self._state
        task_chain = self._task_def.get("attack_chain", [])
        total_threats = max(1, len(task_chain))

        total_compromised = max(1, sum(len(t.get("compromised_hosts", [])) for t in task_chain))
        total_iocs = max(1, sum(
            len(t.get("iocs", {}).get("hashes", []))
            + len(t.get("iocs", {}).get("ips", []))
            + len(t.get("iocs", {}).get("domains", []))
            for t in task_chain
        ))

        # --- Build evidence pools: what the agent could have observed ---
        # Hosts mentioned as alert source (visible from turn 0)
        alert_source_hosts: set = set()
        for a in self._task_def.get("initial_alerts", []):
            alert_source_hosts.add(a.get("source_host", ""))
        for a in self._alert_queue:
            alert_source_hosts.add(a.get("source_host", ""))
        alert_source_hosts.discard("")

        # IOCs visible from alert ioc_indicators
        alert_iocs: set = set()
        for a_list in (self._task_def.get("initial_alerts", []), self._alert_queue):
            for a in a_list:
                for ioc in a.get("ioc_indicators", []):
                    alert_iocs.add(ioc)

        # IOCs revealed by running forensics on a host
        forensics_revealed_iocs: set = set()
        for hostname in state.forensics_run:
            for threat in task_chain:
                if hostname in threat.get("compromised_hosts", []):
                    forensics_revealed_iocs.update(threat.get("c2_servers", []))
                    forensics_revealed_iocs.update(threat["iocs"].get("hashes", []))
                    forensics_revealed_iocs.update(threat["iocs"].get("ips", []))
                    forensics_revealed_iocs.update(threat["iocs"].get("domains", []))

        discovered_iocs = alert_iocs | forensics_revealed_iocs

        # 1. threat_containment — fraction of threats neutralised (no evidence gate; outcome IS evidence)
        threat_containment = min(1.0, len(state.contained_threats) / total_threats)

        # 2. ioc_blocking — only blocks of IOCs the agent actually discovered count
        justified_blocks = [ioc for ioc in state.blocked_iocs if ioc in discovered_iocs]
        ioc_blocking = min(1.0, len(justified_blocks) / total_iocs)

        # 3. forensic_investigation — only counts forensics on alert-mentioned or previously queried
        #    hosts; penalizes confirmed compromises left with no response action
        justified_forensics = [
            h for h in state.forensics_run
            if h in alert_source_hosts or h in state.queried_hosts
        ]
        pending = self._pending_followup
        unresponded = sum(1 for v in pending.values() if not v)
        followup_penalty = min(0.30, unresponded * 0.10)
        forensic_investigation = max(0.0,
            min(1.0, len(justified_forensics) / total_compromised) - followup_penalty
        )

        # 4. siem_correlation — scored by semantic quality (shared source hosts or IOCs)
        if not state.correlated_alert_pairs:
            siem_correlation = 0.0
        else:
            alert_map: Dict[str, Any] = {}
            for a in self._task_def.get("initial_alerts", []):
                alert_map[a.get("alert_id", "")] = a
            for a in self._alert_queue:
                alert_map[a.get("alert_id", "")] = a
            quality_scores = []
            for pair in state.correlated_alert_pairs:
                pair_alerts = [alert_map[aid] for aid in pair if aid in alert_map]
                if len(pair_alerts) < 2:
                    quality_scores.append(0.3)
                    continue
                sources = [a.get("source_host") for a in pair_alerts]
                ioc_sets = [set(a.get("ioc_indicators", [])) for a in pair_alerts]
                shared_hosts = len(sources) != len({s for s in sources if s})
                shared_iocs = bool(ioc_sets[0] & ioc_sets[1]) if len(ioc_sets) >= 2 else False
                quality_scores.append(1.0 if (shared_hosts or shared_iocs) else 0.2)
            siem_correlation = sum(quality_scores) / max(1, len(quality_scores))

        # 5. threat_intel_usage — only enrichments of discovered IOCs count
        justified_enrichments = [ioc for ioc in state.enriched_iocs if ioc in discovered_iocs]
        threat_intel_usage = min(1.0, len(justified_enrichments) / total_iocs)

        # 6. vuln_root_cause — fraction of threats with a scanned host
        vuln_root_cause = min(1.0, len(state.scanned_hosts) / total_threats)

        # 7. business_impact — proportionate isolation + low overall impact
        #    Reward: isolating confirmed-compromised hosts  Penalize: isolating clean hosts
        isolated_host_set = {
            h for h, hd in self._host_index.items() if hd.get("status") == "isolated"
        } if self._host_index else set()
        compromised_host_set = {
            h for threat in task_chain for h in threat.get("compromised_hosts", [])
        }
        if isolated_host_set:
            over_isolated = isolated_host_set - compromised_host_set
            isolation_proportion = (
                len(isolated_host_set - over_isolated) / len(isolated_host_set)
            )
            over_iso_penalty = min(0.40, len(over_isolated) * 0.15)
        else:
            isolation_proportion = 1.0
            over_iso_penalty = 0.0
        raw_impact_score = max(0.0, 1.0 - state.business_impact)
        business_impact = max(0.0, min(1.0,
            0.6 * raw_impact_score + 0.4 * isolation_proportion - over_iso_penalty
        ))

        # 8. step_efficiency — reward early resolution
        ratio = state.step_count / max(1, state.max_steps)
        step_efficiency = max(0.0, 1.0 - max(0.0, ratio - 0.5) * 1.5)

        # 9. plan_coverage — partial credit scales with threats addressed
        if state.submitted_plan:
            plan_coverage = min(1.0, len(self._plan_entries) / total_threats)
        else:
            plan_coverage = min(0.5, len(state.contained_threats) / total_threats * 0.5)

        # 10. plan_evidence_quality — confidence of submitted plan; else evidence depth proxy
        if state.submitted_plan and self._plan_entries:
            avg_conf = sum(e.get("confidence", 0.0) for e in self._plan_entries) / len(self._plan_entries)
            plan_evidence_quality = float(avg_conf)
        else:
            evidence_count = len(justified_forensics) + len(justified_enrichments) + len(state.scanned_hosts)
            plan_evidence_quality = min(0.5, evidence_count / (total_compromised * 3) * 0.5)

        return {
            "threat_containment":     round(threat_containment,     4),
            "ioc_blocking":           round(ioc_blocking,           4),
            "forensic_investigation": round(forensic_investigation, 4),
            "siem_correlation":       round(siem_correlation,       4),
            "threat_intel_usage":     round(threat_intel_usage,     4),
            "vuln_root_cause":        round(vuln_root_cause,        4),
            "business_impact":        round(business_impact,        4),
            "step_efficiency":        round(step_efficiency,        4),
            "plan_coverage":          round(plan_coverage,          4),
            "plan_evidence_quality":  round(plan_evidence_quality,  4),
        }

    def _get_current_phase(self) -> str:
        """Derive episode phase from the action history in the timeline."""
        action_types = {t["action_type"] for t in self._state.timeline}
        if any(t in action_types for t in ["kill_process", "block_ioc", "isolate_segment", "trigger_playbook"]):
            return "remediation"
        if any(t in action_types for t in ["run_forensics", "enrich_ioc", "scan_host_vulnerabilities", "query_host"]):
            return "investigation"
        return "triage"

    def _build_observation(self, reward: float, done: bool) -> SOCObservation:
        """Build the observation from current state."""
        # Compute network topology summary
        subnet_counts = {name: len(hosts) for name, hosts in self._network.items()}
        compromised = sum(
            1 for hosts in self._network.values()
            for h in hosts if h["status"] == "compromised"
        )
        isolated = sum(
            1 for hosts in self._network.values()
            for h in hosts if h["status"] == "isolated"
        )
        total = sum(len(hosts) for hosts in self._network.values())

        topology = NetworkTopology(
            total_hosts=total,
            subnets=subnet_counts,
            compromised_count=compromised,
            isolated_count=isolated,
            online_count=total - compromised - isolated,
        )

        # Build alert list
        alerts = [Alert(**a) for a in self._alert_queue]

        # Build timeline
        timeline = [
            TimelineEntry(
                step=t["step"],
                action_type=t["action_type"],
                target=t["target"],
                result=t["result"],
                reward=t["reward"],
            )
            for t in self._state.timeline
        ]

        # Compute final grade if done
        final_score_val = None
        grade_breakdown_val = None

        if done and self._state.submitted_plan:
            final_plan_dict = {
                "entries": self._plan_entries,
                "primary_threat_id": (self._plan_entries[0]["threat_id"]
                                      if self._plan_entries else ""),
            }
            computed = grade_episode(
                episode_actions=list(self._state.timeline),
                final_plan=final_plan_dict,
                graph=self._threat_graph,
                task_def=self._task_def,
                state=self._state,
            )
            final_score_val = round(computed["final_score"], 4)
            grade_breakdown_val = computed["breakdown"]

        # Merge per-step observation extras (process_tree, correlation_results, etc.)
        extras = getattr(self, "_last_obs_extras", {}) or {}
        threat_graph_summary = None
        if self._threat_graph is not None:
            threat_graph_summary = self._threat_graph.get_context_summary()

        # Per-step partial reward dimensions for GRPO credit assignment
        reward_dimensions = self._compute_reward_dimensions()

        return SOCObservation(
            episode_id=self._state.episode_id or "",
            alert_queue=alerts,
            network_topology=topology,
            host_forensics=self._last_forensics,
            timeline=timeline,
            business_impact_score=round(self._state.business_impact, 4),
            step_count=self._state.step_count,
            active_threats=list(self._state.active_threats),
            max_steps=self._state.max_steps,
            task_id=self._state.task_id,
            total_reward=round(self._state.total_reward, 4),
            final_score=final_score_val,
            grade_breakdown=grade_breakdown_val,
            done=done,
            reward=round(reward, 4),
            correlation_results=extras.get("correlation_results"),
            ioc_enrichment=extras.get("ioc_enrichment"),
            vulnerability_results=extras.get("vulnerability_results"),
            playbook_result=extras.get("playbook_result"),
            threat_graph_summary=threat_graph_summary,
            available_playbooks=list(PLAYBOOKS.keys()),
            reward_dimensions=reward_dimensions,
        )

    def _get_action_target(self, action: Any) -> str:
        """Extract the target string from a typed action for timeline logging."""
        if isinstance(action, QueryHost):
            return action.hostname
        elif isinstance(action, IsolateSegment):
            return getattr(action, "target_host", None) or action.subnet
        elif isinstance(action, BlockIOC):
            return f"{action.ioc_type}:{action.ioc_value}"
        elif isinstance(action, RunForensics):
            return action.hostname
        elif isinstance(action, KillProcess):
            return f"{action.hostname}/{action.process_name}"
        elif isinstance(action, SubmitContainmentPlan):
            return f"{len(action.plan)} entries"
        elif isinstance(action, CorrelateAlerts):
            return ",".join(action.alert_ids)
        elif isinstance(action, EnrichIOC):
            return action.ioc_value
        elif isinstance(action, ScanHostVulnerabilities):
            return action.hostname
        elif isinstance(action, TriggerPlaybook):
            return f"{action.playbook_name}@{action.target}"
        return "unknown"

    # ===========================================================================
    # Adaptive Red Team + Step Rewards (Task 10)
    # ===========================================================================

    STEP_REWARDS: Dict[Any, float] = {
        ("investigation", "run_forensics"):              +0.10,
        ("investigation", "enrich_ioc"):                 +0.05,
        ("investigation", "scan_host_vulnerabilities"):  +0.05,
        ("triage",        "correlate_alerts"):            +0.05,
        "phase_violation_attempt":                       -0.20,
        "ungrounded_action_attempt":                     -0.10,
    }

    def _get_step_reward(self, phase: str, action_type: str, target: str) -> float:
        """Idempotent step reward — fires only once per (phase, action_type, target) triple.

        Hard cap: total step rewards per episode never exceed 0.40.
        """
        if not hasattr(self, "_fired_step_rewards"):
            self._fired_step_rewards = set()
        # Hard cap: once we've reached 0.40 in step rewards, return 0 for all subsequent
        if getattr(self, "_step_reward_total", 0.0) >= 0.40:
            return 0.0
        key = (phase, action_type, target)
        if key in self._fired_step_rewards:
            return 0.0
        reward = self.STEP_REWARDS.get((phase, action_type), 0.0)
        if reward != 0.0:
            self._fired_step_rewards.add(key)
        return reward

    def _maybe_reinfect(self, hostname: str, process_name: str) -> None:
        """30 % chance to reinfect with a _v2 variant when unblocked IOCs exist in the threat chain."""
        if not self._adaptive:
            return
        graph = self._threat_graph
        if graph is None:
            return

        # Check whether any IOC in the host's threat chain is still unblocked
        unblocked_chain_iocs = False
        for ioc_node in graph.iocs.values():
            if not ioc_node.blocked:
                # Is this IOC linked (via any edge) to the same host's chain?
                for e in graph.edges:
                    if e.target_id == hostname or e.source_id == hostname:
                        unblocked_chain_iocs = True
                        break
            if unblocked_chain_iocs:
                break

        if not unblocked_chain_iocs:
            return

        if self._rng.random() >= 0.3:
            return

        # Reinfect: spawn a _v2 variant process on the host
        variant_name = f"{process_name}_v2"
        if hostname in self._host_index:
            host = self._host_index[hostname]
            if variant_name not in host["running_processes"]:
                host["running_processes"].append(variant_name)
                host["status"] = "compromised"

        # Add the variant to the threat graph
        pid = f"{hostname}:{variant_name}"
        if pid not in graph.processes:
            graph.add_process(ProcessNode(
                process_id=pid,
                hostname=hostname,
                process_name=variant_name,
                killed=False,
            ))

        # Emit a CRITICAL alert to signal the reinfection
        alert_id = f"REINFECT-{uuid.uuid4().hex[:6].upper()}"
        graph.add_alert(AlertNode(
            alert_id=alert_id,
            severity="critical",
            priority_score=18.0,
            source_host=hostname,
        ))
        self._alert_queue.append({
            "alert_id": alert_id,
            "timestamp": "2024-01-01T00:00:00Z",
            "source_host": hostname,
            "severity": "critical",
            "threat_type": "malware",
            "description": f"Reinfection detected: {variant_name} spawned on {hostname} (IOC-assisted persistence)",
            "ioc_indicators": [],
            "subnet": self._host_index.get(hostname, {}).get("subnet", "unknown"),
            "is_acknowledged": False,
        })

    def _adversary_react(self, action_type: str, target: str) -> None:
        """Adaptive red team response — fires after each step when adaptive=True."""
        if not self._adaptive:
            return

        difficulty = self._task_def.get("difficulty") or getattr(self._state, "task_id", "easy")
        # Reduced medium base probability for better GRPO credit assignment
        pivot_probability = {"easy": 0.0, "medium": 0.3, "hard": 1.0}.get(difficulty, 0.0)

        # Time-pressure escalation: attacker moves faster when uncontained and late in episode
        if self._state.step_count > 10 and len(self._state.contained_threats) == 0:
            pivot_probability += 0.2

        # Trigger on isolate_segment OR kill_process (extended pivot trigger)
        if action_type in ("isolate_segment", "kill_process") and pivot_probability > 0:
            if self._rng.random() < pivot_probability:
                self._execute_lateral_pivot(source_host=target)

    def _execute_lateral_pivot(self, source_host: str) -> None:
        """Copy-not-move lateral pivot: spread to an adjacent healthy host.

        Rubric is capped at MAX_RUBRIC_ITEMS to prevent competent agents from
        being penalised by an impossible-to-complete rubric.
        """
        MAX_RUBRIC_ITEMS = 12
        graph = self._threat_graph
        if graph is None:
            return

        # Rubric cap: stop pivoting once live_requirements is full
        if self._live_requirements:
            current_items = (
                len(self._live_requirements.get("must_kill", []))
                + len(self._live_requirements.get("must_isolate", []))
            )
            if current_items >= MAX_RUBRIC_ITEMS:
                return

        adjacent_hosts = [
            e.target_id for e in graph.edges
            if e.source_id == source_host and e.target_id in graph.hosts
            and graph.hosts[e.target_id].status == "healthy"
        ]
        if not adjacent_hosts:
            # Try graph hosts first, then fall back to full host_index
            healthy_hosts = [
                h for h, node in graph.hosts.items()
                if node.status == "healthy" and h != source_host
            ]
            if not healthy_hosts:
                # Expand search to the full network
                healthy_hosts = [
                    h for h, hd in self._host_index.items()
                    if hd.get("status", "online") not in ("compromised", "isolated")
                    and h != source_host
                    and h not in graph.hosts
                ]
            if not healthy_hosts:
                return
            adjacent_hosts = healthy_hosts

        dest_host = self._rng.choice(adjacent_hosts)

        # Ensure destination host is in graph
        if dest_host not in graph.hosts:
            hd = self._host_index.get(dest_host, {})
            graph.add_host(HostNode(
                hostname=dest_host,
                subnet=hd.get("subnet", "corporate"),
                business_criticality="medium",
                status="healthy",
            ))

        source_processes = [p for p in graph.processes.values() if p.hostname == source_host]
        if not source_processes:
            return
        original = source_processes[0]

        new_pid = str(uuid.uuid4())[:8]  # uuid imported at module level
        new_process = ProcessNode(
            process_id=f"{dest_host}:{new_pid}",
            hostname=dest_host,
            process_name=original.process_name,
            killed=False,
        )
        graph.add_process(new_process)

        graph.add_edge(Edge(
            edge_type="pivoted_from",
            source_id=dest_host,
            target_id=source_host,
            evidence={"trigger_action": "isolate_segment", "step": self._state.step_count},
        ))

        if self._live_requirements is None:
            self._live_requirements = {}
        self._live_requirements.setdefault("must_kill", []).append(
            f"{dest_host}:{original.process_name}"
        )
        self._live_requirements.setdefault("must_isolate", []).append(dest_host)

        new_alert = AlertNode(
            alert_id=f"PIVOT-{new_pid}",
            severity="critical",
            priority_score=15.0,
            source_host=dest_host,
        )
        graph.add_alert(new_alert)

    @property
    def state(self) -> SOCState:
        """Get the current internal environment state."""
        return self._state
