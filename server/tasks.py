# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Deterministic task definitions for CyberSOCEnv.

Each task defines a fixed attack chain, network layout, and expected
containment actions. No randomness — every run of the same task_id
produces identical initial state.

Tasks:
    - easy:   Single ransomware endpoint on the corporate subnet.
    - medium: Multi-stage lateral movement (phishing -> cred theft -> 3 subnets).
    - hard:   APT + ransomware with C2, exfiltration, and executive pressure.
"""

from __future__ import annotations

from typing import Any, Dict, List


# =============================================================================
# Network Topology Builder (deterministic, 500-node)
# =============================================================================

def _build_subnet(
    name: str,
    role: str,
    prefix: str,
    ip_base: str,
    count: int,
    start_idx: int,
    criticality: float,
    default_ports: List[int],
    default_procs: List[str],
) -> List[Dict[str, Any]]:
    """Build a list of host dicts for a subnet."""
    hosts = []
    for i in range(count):
        idx = start_idx + i
        hosts.append({
            "hostname": f"{prefix}-{idx:03d}",
            "ip_address": f"{ip_base}.{idx}",
            "subnet": name,
            "role": role,
            "status": "online",
            "running_processes": list(default_procs),
            "open_ports": list(default_ports),
            "criticality": criticality,
        })
    return hosts


def build_network() -> Dict[str, List[Dict[str, Any]]]:
    """Build the deterministic enterprise network (~50 active hosts).

    Reduced from 400 to ~50 nodes for GRPO training throughput (target ≥8 eps/min).
    Host indices are chosen to cover all hand-crafted task references (WS-042, WS-088,
    DEV-033, FIN-008, FIN-012, SRV-002..SRV-015, EXEC-003) plus a small buffer for
    procedural generation and lateral pivot targets. The README still describes a
    "500-node enterprise" — the simulation covers the same topology, but only
    materializes the operationally relevant hosts.

    Returns:
        Dict mapping subnet name -> list of host dicts.
    """
    network: Dict[str, List[Dict[str, Any]]] = {}

    # Corporate: WS-001..WS-005 (buffer) + WS-015..WS-020 (covers WS-017)
    #            + WS-040..WS-045 (covers WS-042) + WS-085..WS-090 (covers WS-088)
    corporate: List[Dict[str, Any]] = []
    for start, count in [(1, 5), (15, 6), (40, 6), (85, 6)]:
        corporate.extend(_build_subnet(
            name="corporate", role="corporate", prefix="WS",
            ip_base="10.1.1", count=count, start_idx=start,
            criticality=0.3,
            default_ports=[135, 445, 3389],
            default_procs=["outlook.exe", "chrome.exe", "explorer.exe"],
        ))
    network["corporate"] = corporate  # 23 hosts

    # Engineering: DEV-001..DEV-005 + DEV-030..DEV-036 (covers DEV-033)
    engineering: List[Dict[str, Any]] = []
    for start, count in [(1, 5), (30, 7)]:
        engineering.extend(_build_subnet(
            name="engineering", role="engineering", prefix="DEV",
            ip_base="10.2.1", count=count, start_idx=start,
            criticality=0.5,
            default_ports=[22, 443, 8080, 3389],
            default_procs=["vscode.exe", "python.exe", "docker.exe", "git.exe"],
        ))
    network["engineering"] = engineering  # 12 hosts

    # Finance: FIN-001..FIN-005 + FIN-008..FIN-014 (covers FIN-008, FIN-012)
    finance: List[Dict[str, Any]] = []
    for start, count in [(1, 5), (8, 7)]:
        finance.extend(_build_subnet(
            name="finance", role="finance", prefix="FIN",
            ip_base="10.3.1", count=count, start_idx=start,
            criticality=0.8,
            default_ports=[443, 1433, 3389],
            default_procs=["excel.exe", "sap.exe", "sqlcmd.exe"],
        ))
    network["finance"] = finance  # 12 hosts

    # DMZ: DMZ-001..DMZ-003 (no tasks reference DMZ hosts)
    network["dmz"] = _build_subnet(
        name="dmz", role="dmz", prefix="DMZ",
        ip_base="10.4.1", count=3, start_idx=1,
        criticality=0.6,
        default_ports=[80, 443, 8443],
        default_procs=["nginx", "node", "java"],
    )  # 3 hosts

    # Datacenter: SRV-001..SRV-020 (covers SRV-002, SRV-005, SRV-010, SRV-015)
    network["datacenter"] = _build_subnet(
        name="datacenter", role="datacenter", prefix="SRV",
        ip_base="10.5.1", count=20, start_idx=1,
        criticality=0.9,
        default_ports=[22, 443, 5432, 6379, 9200],
        default_procs=["postgres", "redis-server", "elasticsearch", "kubelet"],
    )  # 20 hosts

    # Executive: EXEC-001..EXEC-005 (covers EXEC-003)
    network["executive"] = _build_subnet(
        name="executive", role="executive", prefix="EXEC",
        ip_base="10.6.1", count=5, start_idx=1,
        criticality=1.0,
        default_ports=[443, 3389],
        default_procs=["outlook.exe", "teams.exe", "chrome.exe"],
    )  # 5 hosts

    return network  # Total: ~75 hosts


# =============================================================================
# Attack Chain Definitions
# =============================================================================

TASKS: Dict[str, Dict[str, Any]] = {
    # ----- EASY: Single ransomware endpoint -----
    "easy": {
        "description": "Ransomware detected on a single corporate workstation. Isolate and contain.",
        "max_steps": 15,
        "initial_business_impact": 0.05,
        "impact_per_step": 0.02,  # Impact grows slowly per step
        "attack_chain": [
            {
                "threat_id": "T-EASY-001",
                "threat_type": "ransomware",
                "phase": "execution",
                "compromised_hosts": ["WS-042"],
                "malicious_processes": ["cryptolocker.exe"],
                "c2_servers": [],
                "iocs": {
                    "hashes": ["e99a18c428cb38d5f260853678922e03"],
                    "ips": [],
                    "domains": [],
                },
                "lateral_targets": [],
                "exfil_targets": [],
            },
        ],
        "initial_alerts": [
            {
                "alert_id": "ALERT-E001",
                "timestamp": "2025-01-15T09:23:17Z",
                "source_host": "WS-042",
                "severity": "critical",
                "threat_type": "ransomware",
                "description": "EDR detected file encryption activity on WS-042. Process 'cryptolocker.exe' is encrypting files in C:\\Users\\jsmith\\Documents.",
                "ioc_indicators": ["e99a18c428cb38d5f260853678922e03"],
                "subnet": "corporate",
                "is_acknowledged": False,
            },
            {
                "alert_id": "ALERT-E002",
                "timestamp": "2025-01-15T09:23:45Z",
                "source_host": "WS-042",
                "severity": "high",
                "threat_type": "ransomware",
                "description": "Anomalous file system activity: 147 files renamed with .locked extension in 28 seconds.",
                "ioc_indicators": [],
                "subnet": "corporate",
                "is_acknowledged": False,
            },
        ],
        # Optimal containment: kill process, run forensics, block hash, submit plan
        "optimal_actions": ["kill_process", "run_forensics", "block_ioc", "submit_containment_plan"],
        "containment_requirements": {
            "must_kill": [{"hostname": "WS-042", "process": "cryptolocker.exe"}],
            "must_block_iocs": ["e99a18c428cb38d5f260853678922e03"],
            "must_forensics": ["WS-042"],
            "must_not_isolate": ["finance", "engineering", "datacenter"],  # Unnecessary isolation = downtime
        },
    },

    # ----- MEDIUM: Multi-stage lateral movement -----
    "medium": {
        "description": "Phishing attack led to credential theft and lateral movement across 3 subnets.",
        "max_steps": 25,
        "initial_business_impact": 0.10,
        "impact_per_step": 0.03,
        "attack_chain": [
            {
                "threat_id": "T-MED-001",
                "threat_type": "phishing",
                "phase": "initial_access",
                "compromised_hosts": ["WS-017"],
                "malicious_processes": ["powershell.exe"],
                "c2_servers": [],
                "iocs": {
                    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
                    "ips": [],
                    "domains": ["evil-login.example.com"],
                },
                "lateral_targets": [],
                "exfil_targets": [],
            },
            {
                "threat_id": "T-MED-002",
                "threat_type": "credential_theft",
                "phase": "credential_access",
                "compromised_hosts": ["WS-017"],
                "malicious_processes": ["mimikatz.exe"],
                "c2_servers": [],
                "iocs": {
                    "hashes": ["aabbccdd11223344eeff5566778899aa"],
                    "ips": [],
                    "domains": [],
                },
                "lateral_targets": ["DEV-033", "FIN-012"],
                "exfil_targets": [],
            },
            {
                "threat_id": "T-MED-003",
                "threat_type": "lateral_movement",
                "phase": "lateral_movement",
                "compromised_hosts": ["DEV-033", "FIN-012"],
                "malicious_processes": ["svchost_backdoor.exe"],
                "c2_servers": [],
                "iocs": {
                    "hashes": ["112233445566778899aabbccddeeff00"],
                    "ips": ["203.0.113.50"],
                    "domains": [],
                },
                "lateral_targets": ["SRV-005"],
                "exfil_targets": [],
            },
        ],
        "initial_alerts": [
            {
                "alert_id": "ALERT-M001",
                "timestamp": "2025-01-15T08:15:00Z",
                "source_host": "WS-017",
                "severity": "medium",
                "threat_type": "phishing",
                "description": "User clicked suspicious link in email. PowerShell execution detected downloading payload from evil-login.example.com.",
                "ioc_indicators": ["evil-login.example.com"],
                "subnet": "corporate",
                "is_acknowledged": False,
            },
            {
                "alert_id": "ALERT-M002",
                "timestamp": "2025-01-15T08:32:00Z",
                "source_host": "WS-017",
                "severity": "high",
                "threat_type": "credential_theft",
                "description": "LSASS memory access detected — possible credential dumping via Mimikatz.",
                "ioc_indicators": ["aabbccdd11223344eeff5566778899aa"],
                "subnet": "corporate",
                "is_acknowledged": False,
            },
            {
                "alert_id": "ALERT-M003",
                "timestamp": "2025-01-15T09:05:00Z",
                "source_host": "DEV-033",
                "severity": "high",
                "threat_type": "lateral_movement",
                "description": "Suspicious RDP login from WS-017 using admin credentials. New process svchost_backdoor.exe spawned.",
                "ioc_indicators": ["203.0.113.50", "112233445566778899aabbccddeeff00"],
                "subnet": "engineering",
                "is_acknowledged": False,
            },
            {
                "alert_id": "ALERT-M004",
                "timestamp": "2025-01-15T09:12:00Z",
                "source_host": "FIN-012",
                "severity": "critical",
                "threat_type": "lateral_movement",
                "description": "Unauthorized access to FIN-012 from compromised credentials. Backdoor process active.",
                "ioc_indicators": ["112233445566778899aabbccddeeff00"],
                "subnet": "finance",
                "is_acknowledged": False,
            },
        ],
        "optimal_actions": [
            "query_host", "run_forensics", "kill_process", "block_ioc",
            "isolate_segment", "run_forensics", "submit_containment_plan",
        ],
        "containment_requirements": {
            "must_kill": [
                {"hostname": "WS-017", "process": "powershell.exe"},
                {"hostname": "WS-017", "process": "mimikatz.exe"},
                {"hostname": "DEV-033", "process": "svchost_backdoor.exe"},
                {"hostname": "FIN-012", "process": "svchost_backdoor.exe"},
            ],
            "must_block_iocs": [
                "evil-login.example.com",
                "203.0.113.50",
                "d41d8cd98f00b204e9800998ecf8427e",
                "aabbccdd11223344eeff5566778899aa",
                "112233445566778899aabbccddeeff00",
            ],
            "must_forensics": ["WS-017", "DEV-033", "FIN-012"],
            "must_not_isolate": ["executive", "datacenter"],
        },
    },

    # ----- HARD: APT + Ransomware, C2, exfiltration, executive pressure -----
    "hard": {
        "description": "Advanced Persistent Threat with active C2 comms, data exfiltration in progress, and ransomware deployment imminent. Board is watching — minimize downtime.",
        "max_steps": 30,
        "initial_business_impact": 0.20,
        "impact_per_step": 0.04,
        "attack_chain": [
            {
                "threat_id": "T-HARD-001",
                "threat_type": "phishing",
                "phase": "initial_access",
                "compromised_hosts": ["EXEC-003"],
                "malicious_processes": ["outlook_macro.exe"],
                "c2_servers": ["198.51.100.77"],
                "iocs": {
                    "hashes": ["deadbeef0123456789abcdef01234567"],
                    "ips": ["198.51.100.77"],
                    "domains": ["cdn-update.malware-c2.net"],
                },
                "lateral_targets": ["WS-088"],
                "exfil_targets": [],
            },
            {
                "threat_id": "T-HARD-002",
                "threat_type": "c2_communication",
                "phase": "command_and_control",
                "compromised_hosts": ["EXEC-003", "WS-088"],
                "malicious_processes": ["svchost_c2.exe"],
                "c2_servers": ["198.51.100.77"],
                "iocs": {
                    "hashes": ["cafebabe9876543210fedcba98765432"],
                    "ips": ["198.51.100.77"],
                    "domains": ["cdn-update.malware-c2.net", "exfil.malware-c2.net"],
                },
                "lateral_targets": ["SRV-002", "FIN-008"],
                "exfil_targets": [],
            },
            {
                "threat_id": "T-HARD-003",
                "threat_type": "privilege_escalation",
                "phase": "privilege_escalation",
                "compromised_hosts": ["SRV-002"],
                "malicious_processes": ["exploit_kernel.exe"],
                "c2_servers": ["198.51.100.77"],
                "iocs": {
                    "hashes": ["1122334455667788aabbccddeeff0011"],
                    "ips": ["198.51.100.77"],
                    "domains": [],
                },
                "lateral_targets": ["SRV-010", "SRV-015"],
                "exfil_targets": ["SRV-002"],
            },
            {
                "threat_id": "T-HARD-004",
                "threat_type": "data_exfiltration",
                "phase": "exfiltration",
                "compromised_hosts": ["SRV-002", "FIN-008"],
                "malicious_processes": ["data_pump.exe"],
                "c2_servers": ["198.51.100.77"],
                "iocs": {
                    "hashes": ["ffeeddccbbaa99887766554433221100"],
                    "ips": ["198.51.100.77", "203.0.113.99"],
                    "domains": ["exfil.malware-c2.net"],
                },
                "lateral_targets": [],
                "exfil_targets": ["SRV-002", "FIN-008"],
            },
            {
                "threat_id": "T-HARD-005",
                "threat_type": "ransomware",
                "phase": "impact",
                "compromised_hosts": ["SRV-010", "SRV-015"],
                "malicious_processes": ["blackcat_ransom.exe"],
                "c2_servers": [],
                "iocs": {
                    "hashes": ["aabb0011ccdd2233eeff4455667788"],
                    "ips": [],
                    "domains": [],
                },
                "lateral_targets": [],
                "exfil_targets": [],
            },
        ],
        "initial_alerts": [
            {
                "alert_id": "ALERT-H001",
                "timestamp": "2025-01-15T06:00:00Z",
                "source_host": "EXEC-003",
                "severity": "medium",
                "threat_type": "phishing",
                "description": "Executive VP opened macro-enabled document. Outbound connection to cdn-update.malware-c2.net detected.",
                "ioc_indicators": ["cdn-update.malware-c2.net", "198.51.100.77"],
                "subnet": "executive",
                "is_acknowledged": False,
            },
            {
                "alert_id": "ALERT-H002",
                "timestamp": "2025-01-15T06:45:00Z",
                "source_host": "WS-088",
                "severity": "high",
                "threat_type": "c2_communication",
                "description": "Periodic beaconing detected to 198.51.100.77 every 60 seconds. Encrypted payload exchange observed.",
                "ioc_indicators": ["198.51.100.77", "cafebabe9876543210fedcba98765432"],
                "subnet": "corporate",
                "is_acknowledged": False,
            },
            {
                "alert_id": "ALERT-H003",
                "timestamp": "2025-01-15T07:30:00Z",
                "source_host": "SRV-002",
                "severity": "critical",
                "threat_type": "privilege_escalation",
                "description": "Kernel exploit attempt on SRV-002 (database server). Process exploit_kernel.exe gained SYSTEM privileges.",
                "ioc_indicators": ["1122334455667788aabbccddeeff0011"],
                "subnet": "datacenter",
                "is_acknowledged": False,
            },
            {
                "alert_id": "ALERT-H004",
                "timestamp": "2025-01-15T08:00:00Z",
                "source_host": "SRV-002",
                "severity": "critical",
                "threat_type": "data_exfiltration",
                "description": "Large data transfer (2.3 GB) to external IP 203.0.113.99 from database server SRV-002. Possible exfiltration of customer PII.",
                "ioc_indicators": ["203.0.113.99", "exfil.malware-c2.net"],
                "subnet": "datacenter",
                "is_acknowledged": False,
            },
            {
                "alert_id": "ALERT-H005",
                "timestamp": "2025-01-15T08:10:00Z",
                "source_host": "FIN-008",
                "severity": "critical",
                "threat_type": "data_exfiltration",
                "description": "Financial records being staged for exfiltration on FIN-008. Process data_pump.exe accessing sensitive directories.",
                "ioc_indicators": ["ffeeddccbbaa99887766554433221100"],
                "subnet": "finance",
                "is_acknowledged": False,
            },
            {
                "alert_id": "ALERT-H006",
                "timestamp": "2025-01-15T08:30:00Z",
                "source_host": "SRV-010",
                "severity": "critical",
                "threat_type": "ransomware",
                "description": "BlackCat ransomware deployment detected on SRV-010! File encryption starting on production storage.",
                "ioc_indicators": ["aabb0011ccdd2233eeff4455667788"],
                "subnet": "datacenter",
                "is_acknowledged": False,
            },
        ],
        "optimal_actions": [
            "block_ioc", "kill_process", "run_forensics", "isolate_segment",
            "kill_process", "block_ioc", "run_forensics", "kill_process",
            "submit_containment_plan",
        ],
        "containment_requirements": {
            "must_kill": [
                {"hostname": "EXEC-003", "process": "outlook_macro.exe"},
                {"hostname": "EXEC-003", "process": "svchost_c2.exe"},
                {"hostname": "WS-088", "process": "svchost_c2.exe"},
                {"hostname": "SRV-002", "process": "exploit_kernel.exe"},
                {"hostname": "SRV-002", "process": "data_pump.exe"},
                {"hostname": "FIN-008", "process": "data_pump.exe"},
                {"hostname": "SRV-010", "process": "blackcat_ransom.exe"},
                {"hostname": "SRV-015", "process": "blackcat_ransom.exe"},
            ],
            "must_block_iocs": [
                "198.51.100.77",
                "203.0.113.99",
                "cdn-update.malware-c2.net",
                "exfil.malware-c2.net",
                "deadbeef0123456789abcdef01234567",
                "cafebabe9876543210fedcba98765432",
            ],
            "must_forensics": ["EXEC-003", "WS-088", "SRV-002", "FIN-008", "SRV-010"],
            "must_not_isolate": [],  # In APT scenario, any isolation decision is valid
        },
    },
}


def get_task(task_id: str) -> Dict[str, Any]:
    """Retrieve a task definition by ID.

    Supports:
        - 'easy', 'medium', 'hard': Hand-crafted curated benchmarks
        - 'gen_0001' through 'gen_1000': Procedurally generated scenarios
        - Any other string: Generated on-the-fly via seeded procedural generation

    Args:
        task_id: Task identifier string.

    Returns:
        Task definition dict.
    """
    # Check hand-crafted tasks first
    if task_id in TASKS:
        return TASKS[task_id]

    # Fall back to procedural generation
    try:
        from .task_generator import generate_task
    except ImportError:
        from server.task_generator import generate_task

    return generate_task(task_id)

