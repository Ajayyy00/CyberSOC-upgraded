# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Data models for the CyberSOCEnv — Enterprise Cybersecurity Operations Center.

Defines strict Pydantic models for:
- Observation: What the agent sees (alerts, forensics, network state, business impact)
- Action: What the agent can do (discriminated union of 6 action types)
- Internal state: Deterministic network graph, attack chains, and task tracking
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Optional, Union

from openenv.core.env_server.types import Action, Observation, State
from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# Enums
# =============================================================================


class Severity(str, Enum):
    """SIEM alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    """Classification of threat types in the SOC environment."""
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE = "malware"
    CRYPTOMINING = "cryptomining"
    SUPPLY_CHAIN = "supply_chain"
    INSIDER_THREAT = "insider_threat"
    WEBSHELL = "webshell"
    BOTNET = "botnet"


class HostStatus(str, Enum):
    """Host operational status."""
    ONLINE = "online"
    COMPROMISED = "compromised"
    ISOLATED = "isolated"
    OFFLINE = "offline"


class SubnetRole(str, Enum):
    """Business function of a network subnet."""
    CORPORATE = "corporate"
    ENGINEERING = "engineering"
    FINANCE = "finance"
    DMZ = "dmz"
    DATACENTER = "datacenter"
    EXECUTIVE = "executive"


# =============================================================================
# Alert & Network Sub-Models (used in Observation)
# =============================================================================


class Alert(BaseModel):
    """A single SIEM/EDR alert in the queue."""
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(..., description="Unique alert identifier")
    timestamp: str = Field(..., description="ISO-8601 timestamp of the alert")
    source_host: str = Field(..., description="Hostname that generated the alert")
    severity: Severity = Field(..., description="Alert severity level")
    threat_type: ThreatType = Field(..., description="Classified threat type")
    description: str = Field(..., description="Human-readable alert description")
    ioc_indicators: List[str] = Field(
        default_factory=list,
        description="Indicators of compromise (IPs, hashes, domains)",
    )
    subnet: str = Field(..., description="Subnet where the alert originated")
    is_acknowledged: bool = Field(default=False, description="Whether the SOC analyst has acknowledged this alert")


class HostInfo(BaseModel):
    """Summary information about a single network host."""
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(..., description="Host FQDN")
    ip_address: str = Field(..., description="IPv4 address")
    subnet: str = Field(..., description="Subnet the host belongs to")
    role: SubnetRole = Field(..., description="Business function")
    status: HostStatus = Field(default=HostStatus.ONLINE, description="Current status")
    running_processes: List[str] = Field(default_factory=list, description="Running process names")
    open_ports: List[int] = Field(default_factory=list, description="Open TCP ports")
    criticality: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description="Business criticality score (0=low, 1=mission-critical)",
    )


class NetworkTopology(BaseModel):
    """Summarized view of the 500-node enterprise network."""
    model_config = ConfigDict(extra="forbid")

    total_hosts: int = Field(default=500, description="Total hosts in the network")
    subnets: Dict[str, int] = Field(
        default_factory=dict,
        description="Map of subnet name -> host count",
    )
    compromised_count: int = Field(default=0, description="Number of compromised hosts")
    isolated_count: int = Field(default=0, description="Number of isolated hosts")
    online_count: int = Field(default=500, description="Number of online hosts")


class ForensicsResult(BaseModel):
    """Results from running forensics on a host."""
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(..., description="Analyzed host")
    malicious_processes: List[str] = Field(default_factory=list, description="Detected malicious processes")
    suspicious_files: List[str] = Field(default_factory=list, description="Suspicious file paths found")
    network_connections: List[str] = Field(
        default_factory=list,
        description="Suspicious outbound connections (ip:port)",
    )
    registry_modifications: List[str] = Field(default_factory=list, description="Modified registry keys")
    memory_artifacts: List[str] = Field(default_factory=list, description="In-memory IOCs found")
    is_compromised: bool = Field(default=False, description="Whether forensics confirm compromise")


class TimelineEntry(BaseModel):
    """A single entry in the analyst action timeline."""
    model_config = ConfigDict(extra="forbid")

    step: int = Field(..., description="Step number when this action was taken")
    action_type: str = Field(..., description="Type of action taken")
    target: str = Field(..., description="Target of the action (host, subnet, IOC)")
    result: str = Field(..., description="Outcome description")
    reward: float = Field(default=0.0, description="Reward received for this action")


# =============================================================================
# Observation
# =============================================================================


class SOCObservation(Observation):
    """What the SOC agent sees at each step.

    Extends OpenEnv Observation (inherits: done, reward, metadata).
    """

    episode_id: str = Field(
        default="",
        description="Unique UUID for this episode — used by the RL training loop to prevent hash collisions in GRPO batched rollouts.",
    )
    alert_queue: List[Alert] = Field(
        default_factory=list,
        description="Current queue of unresolved SIEM/EDR alerts",
    )
    network_topology: NetworkTopology = Field(
        default_factory=NetworkTopology,
        description="Summary of the enterprise network state",
    )
    host_forensics: Optional[ForensicsResult] = Field(
        default=None,
        description="Forensics results if RunForensics was the last action, else None",
    )
    timeline: List[TimelineEntry] = Field(
        default_factory=list,
        description="Chronological log of all actions taken in this episode",
    )
    business_impact_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Current business impact (0=no impact, 1=catastrophic outage)",
    )
    step_count: int = Field(default=0, ge=0, description="Current step number")
    active_threats: List[str] = Field(
        default_factory=list,
        description="List of threat IDs that are still active/uncontained",
    )
    max_steps: int = Field(default=30, description="Maximum steps allowed in this episode")
    task_id: str = Field(default="easy", description="Current task identifier")
    total_reward: float = Field(default=0.0, description="Accumulated episode reward")
    final_score: Optional[float] = Field(
        default=None,
        description="Post-episode grader score (0.0-1.0). Only set when done=True and plan submitted.",
    )
    grade_breakdown: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Detailed grading breakdown. Only set when done=True and plan submitted.",
    )
    correlation_results: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Results from the most recent correlate_alerts call.",
    )
    ioc_enrichment: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Results from the most recent enrich_ioc call.",
    )
    vulnerability_results: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Results from the most recent scan_host_vulnerabilities call.",
    )
    playbook_result: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Results from the most recent trigger_playbook call.",
    )
    threat_graph_summary: Optional[str] = Field(
        default=None,
        description="Compact textual summary of the current threat graph.",
    )
    available_playbooks: List[str] = Field(
        default_factory=list,
        description="Names of SOAR playbooks available to the agent.",
    )
    reward_dimensions: Optional[Dict[str, float]] = Field(
        default=None,
        description=(
            "Running partial scores for each of the 10 grading dimensions, "
            "updated every step for live GRPO credit-assignment signals. "
            "Keys match grade_breakdown (threat_containment, ioc_blocking, etc.)."
        ),
    )
    active_turn: str = Field(
        default="blue",
        description="Whose turn it is next: 'blue' or 'red'. Used by FSP inference loops.",
    )
    red_observation: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Red Team's current view of the world (populated when active_turn='red'). "
            "Contains compromised_hosts and blue_actions_detected."
        ),
    )


# =============================================================================
# Actions (Discriminated Union)
# =============================================================================


class QueryHost(Action):
    """Query a specific host for status, processes, and connections."""
    type: Literal["query_host"] = Field(default="query_host", description="Action discriminator")
    hostname: str = Field(..., description="Target hostname to query")


class IsolateSegment(Action):
    """Isolate an entire network segment, or a single host from the network."""
    type: Literal["isolate_segment"] = Field(default="isolate_segment", description="Action discriminator")
    subnet: str = Field(default="", description="Subnet name to isolate (mutually exclusive with target_host)")
    target_host: Optional[str] = Field(
        default=None,
        description="If set, isolate only this single host instead of the whole subnet",
    )
    reason: str = Field(default="", description="Justification for isolation")


class BlockIOC(Action):
    """Block an Indicator of Compromise at the perimeter firewall."""
    type: Literal["block_ioc"] = Field(default="block_ioc", description="Action discriminator")
    ioc_value: str = Field(..., description="The IOC to block (IP, domain, or file hash)")
    ioc_type: Literal["ip", "domain", "hash"] = Field(..., description="Type of IOC")


class RunForensics(Action):
    """Run deep forensic analysis on a specific host."""
    type: Literal["run_forensics"] = Field(default="run_forensics", description="Action discriminator")
    hostname: str = Field(..., description="Target hostname for forensics")


class KillProcess(Action):
    """Terminate a specific process on a host."""
    type: Literal["kill_process"] = Field(default="kill_process", description="Action discriminator")
    hostname: str = Field(..., description="Host where the process is running")
    process_name: str = Field(..., description="Name of the process to terminate")


class ContainmentEntry(BaseModel):
    """A single entry in the containment plan."""
    model_config = ConfigDict(extra="forbid")

    threat_id: str = Field(..., description="Threat being addressed")
    actions_taken: List[str] = Field(..., description="List of actions taken to contain this threat")
    root_cause: str = Field(..., description="Identified root cause")
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confidence in the containment (0-1)",
    )


class SubmitContainmentPlan(Action):
    """Submit the final containment plan to end the episode."""
    type: Literal["submit_containment_plan"] = Field(
        default="submit_containment_plan", description="Action discriminator"
    )
    plan: List[ContainmentEntry] = Field(
        ..., description="The containment plan addressing all identified threats"
    )
    executive_summary: str = Field(
        ..., description="Brief executive summary for CISO reporting"
    )


class CorrelateAlerts(Action):
    """Correlate two or more alerts to find shared entities/IOCs."""
    type: Literal["correlate_alerts"] = Field(default="correlate_alerts")
    alert_ids: List[str] = Field(..., min_length=2, description="At least 2 alert IDs to correlate")


class EnrichIOC(Action):
    """Enrich an IOC with threat-intelligence data (actor, MITRE TTPs)."""
    type: Literal["enrich_ioc"] = Field(default="enrich_ioc")
    ioc_value: str = Field(..., description="The IOC value to enrich")
    ioc_type: Literal["ip", "domain", "hash", "filename"] = Field(..., description="Type of IOC")


class ScanHostVulnerabilities(Action):
    """Run a vulnerability scan on a host to discover CVEs."""
    type: Literal["scan_host_vulnerabilities"] = Field(default="scan_host_vulnerabilities")
    hostname: str = Field(..., description="Target hostname for vulnerability scan")


class TerminatePID(Action):
    """Terminate a process by PID on a host."""
    type: Literal["terminate_pid"] = Field(default="terminate_pid")
    hostname: str = Field(..., description="Host where the PID is running")
    pid: str = Field(..., description="Target process PID")


class CreateFirewallRule(Action):
    """Create a host-level firewall rule for a target IP."""
    type: Literal["create_firewall_rule"] = Field(default="create_firewall_rule")
    hostname: str = Field(..., description="Host where firewall rule is applied")
    target_ip: str = Field(..., description="Target IP for the rule")
    action: Literal["drop", "allow"] = Field(..., description="Firewall action to apply")


class QuarantineFile(Action):
    """Quarantine a suspicious file on a host."""
    type: Literal["quarantine_file"] = Field(default="quarantine_file")
    hostname: str = Field(..., description="Host where file is located")
    file_path: str = Field(..., description="File path to quarantine")


# =============================================================================
# Red Team Actions (FSP — Fictitious Self-Play)
# =============================================================================

class LateralPivot(Action):
    """Red Team: move laterally from a compromised host to a new target."""
    type: Literal["lateral_pivot"] = Field(default="lateral_pivot")
    source_host: str = Field(..., description="Already-compromised host used as the pivot point")
    target_host: str = Field(..., description="Destination host to compromise")


class DeployPayload(Action):
    """Red Team: deploy a malicious payload on a host Red already controls."""
    type: Literal["deploy_payload"] = Field(default="deploy_payload")
    hostname: str = Field(..., description="Compromised host to deploy payload on")
    payload_type: Literal["ransomware", "exfiltration", "c2"] = Field(
        ..., description="Class of payload to deploy"
    )


class EvadeDetection(Action):
    """Red Team: apply an evasion technique on a compromised host."""
    type: Literal["evade_detection"] = Field(default="evade_detection")
    hostname: str = Field(..., description="Compromised host to apply evasion on")
    technique: Literal["migrate_pid", "clear_logs"] = Field(
        ...,
        description=(
            "migrate_pid: rename running malicious processes to blend with system names; "
            "clear_logs: remove SIEM alerts originating from this host"
        ),
    )


class PassTurn(Action):
    """Red Team: remain stealthy and take no action this turn."""
    type: Literal["pass_turn"] = Field(default="pass_turn")


# Constant used by dashboard_server and inference to route payloads
RED_ACTION_TYPES: frozenset = frozenset(
    {"lateral_pivot", "deploy_payload", "evade_detection", "pass_turn"}
)

# Discriminated union of all Red actions
RedAction = Annotated[
    Union[LateralPivot, DeployPayload, EvadeDetection, PassTurn],
    Field(discriminator="type"),
]


class RedActionWrapper(Action):
    """Wrapper for Red Team actions — mirrors SOCActionWrapper for the WS/HTTP layer."""

    type: str = Field(..., description="Red action type discriminator")
    model_config = ConfigDict(extra="allow")

    def to_typed_action(self):
        """Deserialize to the correctly-typed Red action."""
        data = self.model_dump(exclude={"metadata"})
        action_map = {
            "lateral_pivot": LateralPivot,
            "deploy_payload": DeployPayload,
            "evade_detection": EvadeDetection,
            "pass_turn": PassTurn,
        }
        cls = action_map.get(data["type"])
        if cls is None:
            raise ValueError(
                f"Unknown red action type: {data['type']}. "
                f"Valid types: {list(action_map)}"
            )
        return cls(**data)


# Discriminated union of all SOC actions
SOCAction = Annotated[
    Union[
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
    ],
    Field(discriminator="type"),
]

# Wrapper model so OpenEnv's create_app can accept it as a single Action class
class SOCActionWrapper(Action):
    """Wrapper that deserializes the discriminated union action.

    OpenEnv's create_app expects a single Action subclass. This wrapper
    uses a discriminated union field so the HTTP/WS layer can parse
    any of the 6 action types from a flat JSON payload.

    Client sends:  {"action": {"type": "query_host", "hostname": "WS-001"}}
    The wrapper validates -> QueryHost(hostname="WS-001")
    """
    type: str = Field(..., description="Action type discriminator")

    model_config = ConfigDict(extra="allow")  # Allow action-specific fields

    def to_typed_action(self):
        """Convert the raw wrapper into the correctly typed action."""
        data = self.model_dump(exclude={"metadata"})
        action_map = {
            "query_host": QueryHost,
            "isolate_segment": IsolateSegment,
            "block_ioc": BlockIOC,
            "run_forensics": RunForensics,
            "kill_process": KillProcess,
            "submit_containment_plan": SubmitContainmentPlan,
            "correlate_alerts": CorrelateAlerts,
            "enrich_ioc": EnrichIOC,
            "scan_host_vulnerabilities": ScanHostVulnerabilities,
            "terminate_pid": TerminatePID,
            "create_firewall_rule": CreateFirewallRule,
            "quarantine_file": QuarantineFile,
        }
        cls = action_map.get(data["type"])
        if cls is None:
            raise ValueError(
                f"Unknown action type: {data['type']}. "
                f"Valid types: {list(action_map.keys())}"
            )
        return cls(**data)


# =============================================================================
# Internal State (not exposed to agent directly)
# =============================================================================


class SOCState(State):
    """Internal environment state tracking the attack simulation.

    Extends OpenEnv State (inherits: episode_id, step_count).
    Uses extra='allow' from base State.
    """

    task_id: str = Field(default="easy", description="Current task: 'easy', 'medium', or 'hard'")
    max_steps: int = Field(default=30, description="Maximum steps for this episode")
    total_reward: float = Field(default=0.0, description="Accumulated reward")
    business_impact: float = Field(default=0.0, ge=0.0, le=1.0, description="Current business impact score")
    contained_threats: List[str] = Field(default_factory=list, description="Threat IDs that have been contained")
    active_threats: List[str] = Field(default_factory=list, description="Currently active threat IDs")
    blocked_iocs: List[str] = Field(default_factory=list, description="IOCs blocked at perimeter")
    isolated_subnets: List[str] = Field(default_factory=list, description="Isolated network segments")
    forensics_run: List[str] = Field(default_factory=list, description="Hosts that had forensics run")
    killed_processes: List[Dict[str, str]] = Field(default_factory=list, description="Processes killed")
    queried_hosts: List[str] = Field(default_factory=list, description="Hosts queried")
    timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Action timeline")
    is_done: bool = Field(default=False, description="Whether episode has ended")
    submitted_plan: bool = Field(default=False, description="Whether containment plan was submitted")
    enriched_iocs: List[str] = Field(default_factory=list, description="IOCs that have been threat-intel enriched")
    scanned_hosts: List[str] = Field(default_factory=list, description="Hosts that had vulnerability scans")
    correlated_alert_pairs: List[Any] = Field(default_factory=list, description="Pairs/groups of alert IDs correlated together")
    live_requirements: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Mutable copy of containment_requirements (for adaptive grading).",
    )
    active_turn: str = Field(
        default="blue",
        description="Current active turn in the FSP engine: 'blue' or 'red'.",
    )
