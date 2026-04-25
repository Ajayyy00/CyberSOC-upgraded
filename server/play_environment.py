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
from typing import Any, Callable, Dict, List, Optional
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
        TerminatePID,
        CreateFirewallRule,
        QuarantineFile,
        RedActionWrapper,
        LateralPivot,
        DeployPayload,
        EvadeDetection,
        PassTurn,
        RED_ACTION_TYPES,
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
        TerminatePID,
        CreateFirewallRule,
        QuarantineFile,
        RedActionWrapper,
        LateralPivot,
        DeployPayload,
        EvadeDetection,
        PassTurn,
        RED_ACTION_TYPES,
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

    def __init__(
        self,
        adaptive: bool = False,
        neural_red_policy: Optional[Any] = None,
        red_team_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        fsp_mode: bool = False,
    ):
        """Initialize the environment (actual state set in reset).

        Args:
            adaptive: Legacy adaptive-adversary flag (kept for backward compat).
            neural_red_policy: Optional callable for neural Red policy (legacy hook).
            red_team_logger: Optional callback for recording Red decisions.
            fsp_mode: When True, step() uses strict alternating turns and
                step_count only increments after BOTH Blue and Red have acted.
                When False (default), step(SOCActionWrapper) behaves exactly as
                before — Red's PassTurn is applied automatically so existing code
                and tests remain unaffected.
        """
        super().__init__()
        self._adaptive = adaptive
        self._neural_red_policy = neural_red_policy
        self._red_team_logger = red_team_logger
        self._fsp_mode = fsp_mode
        self._red_team_decisions: List[Dict[str, Any]] = []
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
        self._disruption_cost: float = 0.0  # accumulates per clean host/subnet isolated
        self._discovered_iocs: set = set()  # IOCs revealed via run_forensics or enrich_ioc
        self._quarantined_files: set[tuple[str, str]] = set()
        self._step_reward_total: float = 0.0

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
            active_turn="blue",
        )

        self._plan_entries = []
        self._last_forensics = None
        self._reset_rubric()
        self._fired_step_rewards: set = set()
        self._step_reward_total: float = 0.0
        self._pending_followup: Dict[str, bool] = {}
        self._disruption_cost = 0.0
        self._discovered_iocs: set = set()
        self._quarantined_files: set[tuple[str, str]] = set()
        self._red_team_decisions = []

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
        action,  # SOCActionWrapper | RedActionWrapper
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> SOCObservation:
        """Process one agent action — Blue (SOCActionWrapper) or Red (RedActionWrapper).

        Turn semantics (fsp_mode=True):
          • Blue step: execute, flip active_turn → 'red', do NOT increment step_count.
          • Red step:  execute, flip active_turn → 'blue', increment step_count.

        When fsp_mode=False (default / backward-compat):
          • Blue step auto-applies a Red PassTurn so step_count always increments,
            preserving all existing test and dashboard behaviour.

        Returns:
            SOCObservation; includes active_turn and red_observation fields.
        """
        if self._state.is_done:
            return self._build_observation(reward=0.0, done=True)

        if isinstance(action, RedActionWrapper):
            return self._step_red(action)
        return self._step_blue(action)

    # ------------------------------------------------------------------
    # _step_blue — execute a Blue (SOC analyst) action
    # ------------------------------------------------------------------

    def _step_blue(
        self,
        action: SOCActionWrapper,
    ) -> SOCObservation:
        """Execute one Blue turn."""
        # Convert wrapper to typed action
        typed_action = action.to_typed_action()
        args = typed_action.model_dump(exclude={"metadata", "type"})

        # Pre-flight validation — penalise without consuming a step
        current_phase = self._get_current_phase()
        validation_error = self._middleware.validate(
            current_phase, typed_action.type, args, self._threat_graph
        )
        if validation_error:
            error_type = validation_error.get("error_type", "")
            penalty = -0.10 if error_type == "PHASE_VIOLATION" else -0.05
            self._state.total_reward += penalty
            return self._build_observation(reward=penalty, done=False)

        # Reset per-step extras
        self._last_obs_extras = {}

        # Dispatch to Blue handler
        reward = 0.0
        result_description = "unknown action"

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
        elif isinstance(typed_action, TerminatePID):
            reward, result_description = self._handle_terminate_pid(typed_action)
        elif isinstance(typed_action, CreateFirewallRule):
            reward, result_description = self._handle_create_firewall_rule(typed_action)
        elif isinstance(typed_action, QuarantineFile):
            reward, result_description = self._handle_quarantine_file(typed_action)

        # Idempotent step reward
        target = self._get_action_target(typed_action)
        step_r = self._get_step_reward(
            phase="investigation", action_type=typed_action.type, target=target
        )
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
                reward -= 0.05

        # Business impact grows each step (attacker progresses)
        if not self._state.is_done:
            impact_rate = self._task_def.get("impact_per_step", 0.02)
            active_ratio = len(self._state.active_threats) / max(
                1, len(self._task_def["attack_chain"])
            )
            self._state.business_impact = min(
                1.0, self._state.business_impact + impact_rate * active_ratio
            )

        # Round label: step_count+1 = current round being played (not yet closed)
        round_label = self._state.step_count + 1

        # Record timeline
        self._state.timeline.append({
            "step": round_label,
            "action_type": typed_action.type,
            "target": target,
            "result": result_description,
            "reward": reward,
        })

        # Accumulate reward
        self._state.total_reward += reward

        # Check if episode ends due to Blue action (plan submission)
        done = False
        if self._state.submitted_plan:
            done = True
            self._state.is_done = True
            self._state.active_turn = "blue"  # episode over — keep at blue
            # In non-FSP mode, still increment step_count for consistency
            if not self._fsp_mode:
                self._state.step_count += 1
            return self._build_observation(reward=reward, done=done)

        # Flip turn to Red
        self._state.active_turn = "red"

        # fsp_mode=False (backward compat): auto-apply Red PassTurn so
        # callers that only drive Blue see step_count increment as before.
        if not self._fsp_mode:
            # Embedded Red dynamics: execute neural or deterministic policy.
            # Only fires when a policy is wired (training) or adaptive=True (SFT).
            if self._neural_red_policy is not None or self._adaptive:
                self._apply_red_team_dynamics(typed_action.type, target)
            self._state.step_count += 1
            self._state.active_turn = "blue"
            # Timeout check (done after Red's "auto turn")
            if self._state.step_count >= self._state.max_steps:
                reward -= 0.20
                self._state.total_reward -= 0.20
                self._state.is_done = True
                done = True

        return self._build_observation(reward=reward, done=done)

    # ------------------------------------------------------------------
    # _step_red — execute a Red Team action
    # ------------------------------------------------------------------

    def _step_red(self, action: RedActionWrapper) -> SOCObservation:
        """Execute one Red turn. Only valid when active_turn == 'red'."""
        if self._state.active_turn != "red":
            # Wrong turn — return current obs with 0 reward (no state change)
            return self._build_observation(reward=0.0, done=False)

        typed_action = action.to_typed_action()
        self._last_obs_extras = {}

        reward = 0.0
        result_description = "red: noop"

        if isinstance(typed_action, LateralPivot):
            reward, result_description = self._handle_lateral_pivot(typed_action)
        elif isinstance(typed_action, DeployPayload):
            reward, result_description = self._handle_deploy_payload(typed_action)
        elif isinstance(typed_action, EvadeDetection):
            reward, result_description = self._handle_evade_detection(typed_action)
        elif isinstance(typed_action, PassTurn):
            reward, result_description = self._handle_pass_turn(typed_action)

        # Close the round: increment step_count, flip turn back to Blue
        self._state.step_count += 1
        self._state.active_turn = "blue"

        # Record Red's action in timeline (prefixed with "red:" to distinguish)
        self._state.timeline.append({
            "step": self._state.step_count,
            "action_type": f"red:{typed_action.type}",
            "target": self._get_red_action_target(typed_action),
            "result": result_description,
            "reward": 0.0,  # Red actions don't add to Blue's reward total
        })

        # Timeout check after the full round
        done = False
        if self._state.step_count >= self._state.max_steps:
            done = True
            self._state.is_done = True

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
            # Penalise isolating a clean (non-compromised) host — business disruption
            compromised_host_set = {
                h for threat in self._task_def["attack_chain"]
                for h in threat.get("compromised_hosts", [])
            }
            if target_host not in compromised_host_set:
                self._disruption_cost += 0.35
                self._state.business_impact = min(1.0, self._state.business_impact + 0.10)
                return -0.35, (
                    f"Isolated clean host '{target_host}' — unjustified business disruption "
                    f"(cumulative cost={self._disruption_cost:.2f})"
                )
            return 0.10, f"Isolated single host '{target_host}'"

        subnet = action.subnet

        if subnet not in self._network:
            return -0.05, f"Subnet '{subnet}' does not exist"

        if subnet in self._state.isolated_subnets:
            return -0.02, f"Subnet '{subnet}' is already isolated"

        # Build compromised host set for disruption tracking
        compromised_host_set = {
            h for threat in self._task_def["attack_chain"]
            for h in threat.get("compromised_hosts", [])
        }

        # Isolate all hosts in the subnet; count clean hosts for disruption cost
        clean_isolated_count = 0
        for host in self._network[subnet]:
            host["status"] = "isolated"
            if self._threat_graph is not None and host["hostname"] in self._threat_graph.hosts:
                self._threat_graph.hosts[host["hostname"]].status = "isolated"
            if host["hostname"] in self._pending_followup:
                self._pending_followup[host["hostname"]] = True
            if host["hostname"] not in compromised_host_set:
                clean_isolated_count += 1

        self._state.isolated_subnets.append(subnet)

        # Accumulate disruption cost for each clean host swept up in the isolation
        if clean_isolated_count > 0:
            self._disruption_cost += 0.25 * clean_isolated_count
            self._state.business_impact = min(
                1.0, self._state.business_impact + 0.05 * clean_isolated_count
            )

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
            # Reduced reward — isolation is a blunt instrument; prefer kill_process / block_ioc
            reward = 0.07 * len(threats_contained)
            for tid in threats_contained:
                if tid not in self._state.contained_threats:
                    self._state.contained_threats.append(tid)
                if tid in self._state.active_threats:
                    self._state.active_threats.remove(tid)

        # Heavy per-clean-host penalty to deter blunt-force isolation spam
        if clean_isolated_count > 0:
            reward -= 0.25 * clean_isolated_count

        # Additional penalty for explicitly prohibited isolation
        must_not_isolate = self._task_def["containment_requirements"].get("must_not_isolate", [])
        if subnet in must_not_isolate:
            reward -= 0.10
            self._state.business_impact = min(1.0, self._state.business_impact + 0.08)

        return reward, (
            f"Isolated subnet '{subnet}'. Threats contained: {threats_contained}. "
            f"Clean hosts disrupted: {clean_isolated_count} "
            f"(cumulative cost={self._disruption_cost:.2f})"
        )

    def _handle_block_ioc(self, action: BlockIOC) -> tuple[float, str]:
        """Block an IOC at the perimeter.

        Requires prior discovery via run_forensics or enrich_ioc; blind blocks
        are recorded but yield 0 reward to prevent reward hacking.
        """
        ioc = action.ioc_value
        self._last_forensics = None

        if ioc in self._state.blocked_iocs:
            return -0.02, f"IOC '{ioc}' is already blocked"

        # Prerequisite gate: IOC must have been discovered via run_forensics or enrich_ioc
        if ioc not in self._discovered_iocs:
            self._state.blocked_iocs.append(ioc)  # record the block, but no reward
            return 0.0, (
                f"IOC '{ioc}' blocked without prior investigation — 0 reward "
                "(run_forensics or enrich_ioc required to unlock reward)"
            )

        self._state.blocked_iocs.append(ioc)

        # Mark forensics-confirmed hosts as responded-to — only valid for discovered IOCs,
        # ensuring _pending_followup accurately reflects investigated-then-actioned flow
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

        # Boosted rewards: surgical strikes are heavily preferred over blunt isolation
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
                if ioc in threat.get("c2_servers", []):
                    reward += 0.30  # High value: severing C2 command channel
                else:
                    reward += 0.20  # Good: blocking an investigated IOC
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
                # Reveal all IOCs tied to this host's threat chain so block_ioc can earn reward
                for threat in self._task_def["attack_chain"]:
                    if hostname in threat.get("compromised_hosts", []):
                        for ioc in (
                            threat["iocs"].get("hashes", [])
                            + threat["iocs"].get("ips", [])
                            + threat["iocs"].get("domains", [])
                            + threat.get("c2_servers", [])
                        ):
                            self._discovered_iocs.add(ioc)
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
                reward = 0.25  # Surgical strike: high reward for targeted process kill

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
                    reward += 0.15  # Bonus: fully contained a threat via surgical action
                break

        if not was_malicious:
            reward = -0.08  # Penalty: killing legitimate process = downtime
            self._state.business_impact = min(1.0, self._state.business_impact + 0.03)

        return reward, f"Killed '{process}' on {hostname}. Malicious: {was_malicious}"

    def _handle_terminate_pid(self, action: TerminatePID) -> tuple[float, str]:
        """Terminate a process by PID. PID is mapped to process name in this simulation."""
        hostname = action.hostname
        pid = action.pid
        self._last_forensics = None

        if hostname not in self._host_index:
            return -0.05, f"Host '{hostname}' not found"

        host = self._host_index[hostname]
        if host["status"] == "isolated":
            return -0.02, f"Host '{hostname}' is isolated - cannot interact"

        process_name = pid
        if ":" in pid:
            pid_host, _, pid_proc = pid.partition(":")
            if pid_host == hostname and pid_proc:
                process_name = pid_proc

        if process_name not in host["running_processes"]:
            return -0.03, f"PID '{pid}' is not running on {hostname}"

        host["running_processes"].remove(process_name)
        self._state.killed_processes.append({"hostname": hostname, "process": process_name, "pid": pid})
        if hostname in self._pending_followup:
            self._pending_followup[hostname] = True

        was_malicious = False
        reward = 0.0
        for threat in self._task_def["attack_chain"]:
            if hostname in threat["compromised_hosts"] and process_name in threat["malicious_processes"]:
                was_malicious = True
                reward = 0.24
                all_killed = True
                for th_host in threat["compromised_hosts"]:
                    for th_proc in threat["malicious_processes"]:
                        if th_host in self._host_index and th_proc in self._host_index[th_host]["running_processes"]:
                            all_killed = False
                            break
                if all_killed and threat["threat_id"] in self._state.active_threats:
                    self._state.active_threats.remove(threat["threat_id"])
                    if threat["threat_id"] not in self._state.contained_threats:
                        self._state.contained_threats.append(threat["threat_id"])
                    reward += 0.12
                break

        if not was_malicious:
            reward = -0.10
            self._state.business_impact = min(1.0, self._state.business_impact + 0.04)
            return reward, f"Terminated benign PID '{pid}' on {hostname} - business disruption"

        return reward, f"Terminated PID '{pid}' on {hostname}. Malicious: True"

    def _handle_create_firewall_rule(self, action: CreateFirewallRule) -> tuple[float, str]:
        """Create firewall rule; drop blocks target IP as IOC, allow is neutral."""
        hostname = action.hostname
        target_ip = action.target_ip

        if hostname not in self._host_index:
            return -0.05, f"Host '{hostname}' not found"

        if action.action == "drop":
            if target_ip in self._state.blocked_iocs:
                return -0.01, f"Firewall drop rule already exists for {target_ip}"
            self._state.blocked_iocs.append(target_ip)
            return 0.08, f"Created firewall DROP rule on {hostname} for {target_ip}"

        return 0.0, f"Created firewall ALLOW rule on {hostname} for {target_ip}"

    def _handle_quarantine_file(self, action: QuarantineFile) -> tuple[float, str]:
        """Quarantine suspicious files; requires terminating associated malicious PID first."""
        hostname = action.hostname
        file_path = action.file_path

        if hostname not in self._host_index:
            return -0.05, f"Host '{hostname}' not found"

        file_key = (hostname, file_path)
        if file_key in self._quarantined_files:
            return -0.01, f"File '{file_path}' already quarantined on {hostname}"

        associated_processes: List[str] = []
        lowered = file_path.lower()
        for threat in self._task_def.get("attack_chain", []):
            if hostname not in threat.get("compromised_hosts", []):
                continue
            for proc in threat.get("malicious_processes", []):
                expected_suffix = f"\\{proc}.dat".lower()
                if lowered.endswith(expected_suffix):
                    associated_processes.append(proc)

        if not associated_processes:
            self._quarantined_files.add(file_key)
            return -0.02, f"Quarantined untracked file '{file_path}' on {hostname}"

        host = self._host_index[hostname]
        locked = any(proc in host["running_processes"] for proc in associated_processes)
        if locked:
            self._state.business_impact = min(1.0, self._state.business_impact + 0.01)
            return -0.04, (
                f"Quarantine failed: file '{file_path}' is locked. "
                "Terminate associated PID first."
            )

        self._quarantined_files.add(file_key)
        return 0.10, f"Quarantined file '{file_path}' on {hostname}"

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
            disruption_cost=self._disruption_cost,
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

        # Mark IOC as discovered — future block_ioc on it will receive full reward
        self._discovered_iocs.add(action.ioc_value)

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

    # ===========================================================================
    # Red Team Action Handlers
    # ===========================================================================

    def _handle_lateral_pivot(self, action: LateralPivot) -> tuple[float, str]:
        """Red: spread from a compromised host to a new target."""
        src = action.source_host
        dst = action.target_host

        if src not in self._host_index:
            return 0.0, f"red: lateral_pivot — source '{src}' not in network"
        if self._host_index[src].get("status") != "compromised":
            return 0.0, f"red: lateral_pivot — '{src}' not under Red control"
        if dst not in self._host_index:
            return 0.0, f"red: lateral_pivot — target '{dst}' not in network"

        dst_status = self._host_index[dst].get("status", "online")
        if dst_status == "isolated":
            return 0.0, f"red: lateral_pivot — '{dst}' is isolated, pivot blocked by Blue"
        if dst_status == "compromised":
            return 0.0, f"red: lateral_pivot — '{dst}' already compromised"

        # Compromise target and copy a process from source
        self._host_index[dst]["status"] = "compromised"
        src_procs = (
            [p for p in self._threat_graph.processes.values() if p.hostname == src]
            if self._threat_graph else []
        )
        proc_name = src_procs[0].process_name if src_procs else "cmd.exe"
        self._host_index[dst].setdefault("running_processes", [])
        if proc_name not in self._host_index[dst]["running_processes"]:
            self._host_index[dst]["running_processes"].append(proc_name)

        # Update threat graph
        if self._threat_graph is not None:
            if dst not in self._threat_graph.hosts:
                hd = self._host_index[dst]
                self._threat_graph.add_host(HostNode(
                    hostname=dst,
                    subnet=hd.get("subnet", "corporate"),
                    business_criticality="medium",
                    status="compromised",
                ))
            else:
                self._threat_graph.hosts[dst].status = "compromised"

            pid = f"{dst}:{proc_name}"
            if pid not in self._threat_graph.processes:
                self._threat_graph.add_process(ProcessNode(
                    process_id=pid, hostname=dst, process_name=proc_name
                ))
            self._threat_graph.add_edge(Edge(
                edge_type="pivoted_from", source_id=dst, target_id=src
            ))

        # Generate SIEM alert for Blue
        alert_id = f"PIVOT-{uuid.uuid4().hex[:6].upper()}"
        subnet = self._host_index.get(dst, {}).get("subnet", "unknown")
        self._alert_queue.append({
            "alert_id": alert_id,
            "timestamp": "2024-01-01T00:00:00Z",
            "source_host": dst,
            "severity": "critical",
            "threat_type": "lateral_movement",
            "description": (
                f"Lateral movement detected: {proc_name} spawned on {dst} "
                f"(pivot from {src})"
            ),
            "ioc_indicators": [],
            "subnet": subnet,
            "is_acknowledged": False,
        })
        if self._threat_graph is not None:
            self._threat_graph.add_alert(AlertNode(
                alert_id=alert_id, severity="critical",
                priority_score=15.0, source_host=dst,
            ))

        # Update live rubric
        if self._live_requirements is not None:
            self._live_requirements.setdefault("must_kill", []).append({
                "hostname": dst, "process": proc_name, "threat_id": "FSP_PIVOT",
            })

        return 0.0, f"red: lateral_pivot {src} → {dst} (proc={proc_name})"

    def _handle_deploy_payload(self, action: DeployPayload) -> tuple[float, str]:
        """Red: deploy a malicious payload on a host Red controls."""
        hostname = action.hostname
        payload_type = action.payload_type

        if hostname not in self._host_index:
            return 0.0, f"red: deploy_payload — '{hostname}' not in network"
        if self._host_index[hostname].get("status") != "compromised":
            return 0.0, f"red: deploy_payload — no shell on '{hostname}'"

        proc_name = {
            "ransomware": "ransomware.exe",
            "exfiltration": "exfil_agent.exe",
            "c2": "c2_beacon.exe",
        }[payload_type]

        host = self._host_index[hostname]
        if proc_name not in host.get("running_processes", []):
            host.setdefault("running_processes", []).append(proc_name)

        if self._threat_graph is not None:
            pid = f"{hostname}:{proc_name}"
            if pid not in self._threat_graph.processes:
                self._threat_graph.add_process(ProcessNode(
                    process_id=pid, hostname=hostname, process_name=proc_name
                ))

        impact_delta = {"ransomware": 0.15, "exfiltration": 0.08, "c2": 0.05}[payload_type]
        self._state.business_impact = min(1.0, self._state.business_impact + impact_delta)

        severity = {"ransomware": "critical", "exfiltration": "high", "c2": "high"}[payload_type]
        alert_id = f"PAYLOAD-{uuid.uuid4().hex[:6].upper()}"
        self._alert_queue.append({
            "alert_id": alert_id,
            "timestamp": "2024-01-01T00:00:00Z",
            "source_host": hostname,
            "severity": severity,
            "threat_type": payload_type,
            "description": (
                f"{payload_type.capitalize()} payload deployed on {hostname}: {proc_name}"
            ),
            "ioc_indicators": [],
            "subnet": host.get("subnet", "unknown"),
            "is_acknowledged": False,
        })
        if self._threat_graph is not None:
            self._threat_graph.add_alert(AlertNode(
                alert_id=alert_id, severity=severity,
                priority_score=18.0, source_host=hostname,
            ))

        return 0.0, f"red: deployed {payload_type} payload on {hostname}"

    def _handle_evade_detection(self, action: EvadeDetection) -> tuple[float, str]:
        """Red: apply a detection-evasion technique on a controlled host."""
        hostname = action.hostname
        technique = action.technique

        if hostname not in self._host_index:
            return 0.0, f"red: evade_detection — '{hostname}' not in network"
        if self._host_index[hostname].get("status") != "compromised":
            return 0.0, f"red: evade_detection — no shell on '{hostname}'"

        if technique == "migrate_pid":
            host = self._host_index[hostname]
            malicious_procs = {
                proc
                for threat in self._task_def.get("attack_chain", [])
                if hostname in threat.get("compromised_hosts", [])
                for proc in threat.get("malicious_processes", [])
            }
            for i, proc in enumerate(list(host.get("running_processes", []))):
                if proc in malicious_procs:
                    new_name = f"svchost_{i}.exe"
                    host["running_processes"][i] = new_name
                    if self._threat_graph:
                        old_pid = f"{hostname}:{proc}"
                        if old_pid in self._threat_graph.processes:
                            self._threat_graph.processes.pop(old_pid)
                            new_pid = f"{hostname}:{new_name}"
                            self._threat_graph.add_process(ProcessNode(
                                process_id=new_pid, hostname=hostname,
                                process_name=new_name,
                            ))
            return 0.0, f"red: migrated PIDs on {hostname} to blend with system processes"

        if technique == "clear_logs":
            before = len(self._alert_queue)
            self._alert_queue = [
                a for a in self._alert_queue
                if a.get("source_host") != hostname
            ]
            removed = before - len(self._alert_queue)
            return 0.0, f"red: cleared {removed} SIEM alert(s) from {hostname}"

        return 0.0, f"red: evasion '{technique}' applied on {hostname}"

    def _handle_pass_turn(self, action: PassTurn) -> tuple[float, str]:  # noqa: ARG002
        """Red: remain stealthy, take no action."""
        return 0.0, "red: pass_turn (stealth)"

    def _get_red_action_target(self, action: Any) -> str:
        """Extract a compact target string from a Red action for timeline logging."""
        if isinstance(action, LateralPivot):
            return f"{action.source_host}→{action.target_host}"
        if isinstance(action, DeployPayload):
            return f"{action.hostname}/{action.payload_type}"
        if isinstance(action, EvadeDetection):
            return f"{action.hostname}/{action.technique}"
        return "—"

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
        if any(t in action_types for t in ["kill_process", "block_ioc", "isolate_segment", "terminate_pid", "create_firewall_rule", "quarantine_file"]):
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
                disruption_cost=self._disruption_cost,
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

        # Red observation — only populated when it is Red's turn next
        red_obs = (
            self._generate_red_observation()
            if self._state.active_turn == "red"
            else None
        )

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
            playbook_result=None,
            threat_graph_summary=threat_graph_summary,
            available_playbooks=[],
            reward_dimensions=reward_dimensions,
            active_turn=self._state.active_turn,
            red_observation=red_obs,
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
        elif isinstance(action, TerminatePID):
            return f"{action.hostname}/{action.pid}"
        elif isinstance(action, CreateFirewallRule):
            return f"{action.hostname}:{action.action}:{action.target_ip}"
        elif isinstance(action, QuarantineFile):
            return f"{action.hostname}:{action.file_path}"
        return "unknown"

    # ===========================================================================
    # Adaptive Red Team + Step Rewards (Task 10)
    # ===========================================================================

    def _generate_red_observation(self) -> Dict[str, Any]:
        """What the Red Team LLM sees: footholds it controls + Blue's last action.

        Returned as the ``red_observation`` field in SOCObservation whenever
        ``active_turn == 'red'``, so inference.py can feed it straight to the
        Red LLM without a separate API call.
        """
        compromised_hosts = [
            h for h, hd in self._host_index.items()
            if hd.get("status") == "compromised"
        ]

        # Most recent Blue action from the timeline (exclude Red's own entries)
        blue_actions_detected: List[Dict[str, Any]] = []
        for entry in reversed(self._state.timeline):
            action_type = entry.get("action_type", "")
            if not action_type.startswith("red:"):
                blue_actions_detected.append({
                    "step": entry["step"],
                    "action": action_type,
                    "target": entry["target"],
                    "result": entry["result"],
                })
                break  # Only the single most recent Blue action

        return {
            "episode_id": self._state.episode_id,
            "round": self._state.step_count + 1,
            "compromised_hosts": compromised_hosts,
            "blue_actions_detected": blue_actions_detected,
            "active_threats": list(self._state.active_threats),
            "business_impact": round(self._state.business_impact, 4),
        }

    def _log_red_decision(self, observation: Dict[str, Any], action: Dict[str, Any]) -> None:
        """Record (observation -> action) tuples for red-team imitation warm-start."""
        record = {"observation": observation, "action": action}
        self._red_team_decisions.append(record)
        if self._red_team_logger is not None:
            try:
                self._red_team_logger(record)
            except Exception:
                # Logging is best effort and should never affect environment execution.
                pass

    def _apply_red_team_dynamics(self, action_type: str, target: str) -> None:
        """Execute embedded Red dynamics in non-FSP mode.

        When neural_red_policy is callable: invoke it with the current red
        observation, route the returned action through the Red handlers, and
        log the (obs → action) pair for offline SFT.

        When neural_red_policy is None (adaptive=True path): apply the
        deterministic fallback policy and log the pair.
        """
        red_obs = self._generate_red_observation()

        if callable(self._neural_red_policy):
            try:
                action_dict = self._neural_red_policy(red_obs)
                if not isinstance(action_dict, dict):
                    action_dict = {"type": "pass_turn"}
            except Exception:
                action_dict = {"type": "pass_turn"}

            atype = action_dict.get("type", "pass_turn")
            if atype == "lateral_pivot":
                src = action_dict.get("source_host", "")
                dst = action_dict.get("target_host", "")
                if src and dst:
                    self._handle_lateral_pivot(
                        LateralPivot(type="lateral_pivot", source_host=src, target_host=dst)
                    )
            elif atype == "deploy_payload":
                h = action_dict.get("hostname", "")
                pl = action_dict.get("payload_type", "ransomware")
                if h:
                    self._handle_deploy_payload(
                        DeployPayload(type="deploy_payload", hostname=h, payload_type=pl)
                    )
            elif atype == "evade_detection":
                h = action_dict.get("hostname", "")
                tech = action_dict.get("technique", "migrate_pid")
                if h:
                    self._handle_evade_detection(
                        EvadeDetection(type="evade_detection", hostname=h, technique=tech)
                    )
            # pass_turn → no graph mutation needed

            self._log_red_decision(red_obs, action_dict)
        else:
            # Deterministic fallback for imitation warm-start (adaptive=True path)
            det_action = self._deterministic_red_policy(action_type, target, red_obs)
            if det_action.get("type") == "lateral_pivot":
                self._handle_lateral_pivot(
                    LateralPivot(
                        type="lateral_pivot",
                        source_host=det_action["source_host"],
                        target_host=det_action["target_host"],
                    )
                )
            self._log_red_decision(red_obs, det_action)

    def _deterministic_red_policy(
        self, blue_action: str, blue_target: str, red_obs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Rule-based Red policy for SFT imitation warm-start data collection.

        Pivots from a compromised host to a healthy neighbour whenever Blue
        just killed a process, isolated a segment, or blocked an IOC (i.e.
        Blue is actively containing). Otherwise passes to stay stealthy.
        """
        if blue_action in ("kill_process", "isolate_segment", "block_ioc"):
            compromised = red_obs.get("compromised_hosts", [])
            src = compromised[0] if compromised else (blue_target or None)
            if src is not None and src in self._host_index:
                dst = next(
                    (
                        h for h, hd in self._host_index.items()
                        if hd.get("status") not in ("compromised", "isolated") and h != src
                    ),
                    None,
                )
                if dst:
                    return {"type": "lateral_pivot", "source_host": src, "target_host": dst}
        return {"type": "pass_turn"}

    def export_red_team_decisions(self) -> List[Dict[str, Any]]:
        """Return a copy of recorded red-team decisions for offline SFT."""
        return list(self._red_team_decisions)

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

    def _adversary_react(self, action_type: str, target: str) -> Optional[Dict[str, Any]]:
        """Legacy hook — disabled; Red Team now acts via explicit RedActionWrapper steps."""
        return None

    @property
    def state(self) -> SOCState:
        """Get the current internal environment state."""
        return self._state
