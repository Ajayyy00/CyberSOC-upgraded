# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Procedural Task Generator for CyberSOCEnv.

Generates 1000+ unique, deterministic attack scenarios from a task_id seed.
Each task_id (e.g. 'gen_0001') always produces the exact same scenario.

Design:
    - hash(task_id) -> deterministic seed -> random.Random instance
    - Seed drives ALL choices: attack type, hosts, processes, IOCs, alerts
    - 12 attack categories, 50+ malware names, 40+ C2 domains
    - 3 difficulty tiers based on task number

No actual randomness — reproducible across runs and platforms.
"""

from __future__ import annotations

import hashlib
import random
import itertools
from typing import Any, Dict, List, Tuple

# =============================================================================
# Validation & Exclusions
# =============================================================================

INCOMPATIBLE_THREATS = {
    ("ransomware", "cryptomining"),      # Ransomware kills host, no mining possible
    ("data_exfiltration", "ransomware"), # Exfil needs host alive
}

def validate_task_def(task_def: dict) -> List[str]:
    errors = []
    compromised_hosts = set()
    for threat in task_def.get("attack_chain", []):
        compromised_hosts.update(threat.get("compromised_hosts", []))

    reqs = task_def.get("containment_requirements", {})
    for req in reqs.get("must_kill", []):
        hostname = req.get("hostname") if isinstance(req, dict) else req.split(":")[0]
        if hostname not in compromised_hosts:
            errors.append(f"must_kill references non-compromised host: {hostname}")

    for host in reqs.get("must_isolate", []):
        if host not in compromised_hosts:
            errors.append(f"must_isolate references non-compromised host: {host}")

    return errors


# =============================================================================
# Template Pools (the "vocabulary" of the generator)
# =============================================================================

# --- Malware process names by category ---
MALWARE_PROCESSES = {
    "ransomware": [
        "cryptolocker.exe", "wannacry.exe", "blackcat_ransom.exe",
        "lockbit3.exe", "revil_encrypt.exe", "hive_locker.exe",
        "conti_crypt.exe", "ryuk_payload.exe", "maze_encrypt.exe",
        "darkside_enc.exe", "babuk_lock.exe", "avaddon_crypt.exe",
    ],
    "phishing": [
        "outlook_macro.exe", "word_dropper.exe", "macro_loader.exe",
        "vba_agent.exe", "pdf_exploit.exe", "html_smuggler.exe",
        "iso_mounter.exe", "lnk_runner.exe",
    ],
    "credential_theft": [
        "mimikatz.exe", "lazagne.exe", "hashdump.exe",
        "procdump_lsass.exe", "rubeus.exe", "kerbrute.exe",
        "sharphound.exe", "bloodhound_collect.exe",
    ],
    "lateral_movement": [
        "svchost_backdoor.exe", "psexec_svc.exe", "wmic_lateral.exe",
        "rdp_hijack.exe", "ssh_brute.exe", "evil_winrm.exe",
        "dcom_exec.exe", "smb_relay.exe",
    ],
    "c2_communication": [
        "svchost_c2.exe", "cobalt_beacon.exe", "sliver_implant.exe",
        "meterpreter.exe", "covenant_grunt.exe", "mythic_agent.exe",
        "dns_tunnel.exe", "icmp_beacon.exe",
    ],
    "privilege_escalation": [
        "exploit_kernel.exe", "potato_exploit.exe", "uac_bypass.exe",
        "printspoofer.exe", "juicy_potato.exe", "named_pipe_exploit.exe",
        "token_impersonate.exe", "dll_hijack.exe",
    ],
    "data_exfiltration": [
        "data_pump.exe", "rclone_sync.exe", "mega_upload.exe",
        "ftp_exfil.exe", "dns_exfil.exe", "cloud_sync_mal.exe",
        "archive_send.exe", "stealer_agent.exe",
    ],
    "cryptomining": [
        "xmrig_miner.exe", "ethminer.exe", "cpuminer.exe",
        "nicehash_mal.exe", "coinhive_svc.exe", "monero_mine.exe",
    ],
    "supply_chain": [
        "update_agent_mal.exe", "npm_backdoor.exe", "pip_trojan.exe",
        "vscode_ext_mal.exe", "docker_implant.exe", "nuget_poison.exe",
    ],
    "insider_threat": [
        "usb_copy.exe", "screen_capture.exe", "keylogger_svc.exe",
        "email_forward.exe", "cloud_upload.exe", "print_spooler_mal.exe",
    ],
    "webshell": [
        "cmd_webshell.php", "asp_backdoor.exe", "jsp_shell.exe",
        "python_rshell.exe", "nodejs_shell.exe", "perl_cgi_shell.exe",
    ],
    "botnet": [
        "mirai_bot.exe", "emotet_loader.exe", "trickbot_svc.exe",
        "qbot_agent.exe", "dridex_dll.exe", "zloader_inject.exe",
    ],
}

# --- C2 domains ---
C2_DOMAINS = [
    "cdn-update.malware-c2.net", "api.darkc2.io", "telemetry-svc.ru",
    "secure-update.evil.net", "cdn.payload-delivery.com", "api.shadownet.io",
    "sync.cloud-c2.xyz", "update.legit-looking.com", "beacon.covert-ops.net",
    "dns.tunnel-relay.org", "img.cdn-malware.com", "static.evil-cdn.net",
    "api.stealthc2.io", "ws.encrypted-relay.net", "feed.darkweb-proxy.com",
    "auth.phish-server.net", "login.fake-portal.com", "mail.spoof-relay.org",
    "git.supply-chain.dev", "npm.compromised-pkg.io", "pypi.trojan-lib.org",
    "dl.ransomware-pay.onion", "tor.exit-node-c2.net", "i2p.covert-chan.net",
    "iot.botnet-c2.xyz", "cam.mirai-variant.net", "mqtt.iot-exploit.io",
    "ftp.exfil-server.ru", "sftp.data-steal.com", "mega.cloud-drop.io",
    "gist.code-exfil.dev", "paste.data-dump.xyz", "bin.steganography.net",
    "vpn.tunnel-c2.com", "proxy.relay-beacon.org", "socks.covert-proxy.io",
    "wpad.evil-config.net", "ntp.time-beacon.com", "ldap.ad-exploit.org",
    "kerberos.ticket-steal.net",
]

# --- C2 IPs (RFC 5737 documentation ranges + realistic-looking) ---
C2_IPS = [
    "198.51.100.10", "198.51.100.22", "198.51.100.33", "198.51.100.44",
    "198.51.100.55", "198.51.100.66", "198.51.100.77", "198.51.100.88",
    "198.51.100.99", "198.51.100.110", "198.51.100.121", "198.51.100.132",
    "203.0.113.10", "203.0.113.21", "203.0.113.32", "203.0.113.43",
    "203.0.113.54", "203.0.113.65", "203.0.113.76", "203.0.113.87",
    "203.0.113.98", "203.0.113.109", "203.0.113.120", "203.0.113.131",
    "192.0.2.10", "192.0.2.21", "192.0.2.32", "192.0.2.43",
    "192.0.2.54", "192.0.2.65", "192.0.2.76", "192.0.2.87",
    "100.64.0.10", "100.64.0.22", "100.64.0.33", "100.64.0.44",
]

# --- Subnet definitions (must match build_network() in tasks.py) ---
SUBNETS = {
    "corporate":   {"prefix": "WS",   "count": 90,  "criticality": 0.3},
    "engineering": {"prefix": "DEV",  "count": 36,  "criticality": 0.5},
    "finance":     {"prefix": "FIN",  "count": 14,  "criticality": 0.8},
    "dmz":         {"prefix": "DMZ",  "count": 3,   "criticality": 0.6},
    "datacenter":  {"prefix": "SRV",  "count": 20,  "criticality": 0.9},
    "executive":   {"prefix": "EXEC", "count": 5,   "criticality": 1.0},
}

# --- Attack phases in kill-chain order ---
ATTACK_PHASES = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "credential_access", "lateral_movement", "command_and_control",
    "exfiltration", "impact",
]

# --- Alert description templates ---
ALERT_TEMPLATES = {
    "ransomware": [
        "EDR detected file encryption activity on {host}. Process '{proc}' is encrypting files in user directories.",
        "Anomalous file system activity: {count} files renamed with .{ext} extension in {secs} seconds on {host}.",
        "Ransomware signature detected in process '{proc}' on {host}. Volume shadow copies being deleted.",
    ],
    "phishing": [
        "User on {host} clicked suspicious link in email. {proc} execution detected downloading payload from {domain}.",
        "Macro-enabled document opened on {host}. Outbound connection to {domain} detected.",
        "Suspicious email attachment executed on {host}. Process '{proc}' spawned child processes.",
    ],
    "credential_theft": [
        "LSASS memory access detected on {host} — possible credential dumping via {proc}.",
        "Kerberos ticket request anomaly on {host}. Process '{proc}' attempting ticket manipulation.",
        "SAM database access detected on {host}. Credential harvesting tool '{proc}' identified.",
    ],
    "lateral_movement": [
        "Suspicious RDP login to {host} from compromised source using admin credentials. Process '{proc}' spawned.",
        "SMB lateral movement detected: '{proc}' deployed on {host} via remote service creation.",
        "WMI remote execution detected on {host}. Process '{proc}' launched from external host.",
    ],
    "c2_communication": [
        "Periodic beaconing detected from {host} to {ip} every {interval} seconds. Encrypted payload exchange observed.",
        "DNS tunneling activity from {host}. Suspicious queries to {domain} with encoded payloads.",
        "Cobalt Strike beacon profile detected on {host}. Process '{proc}' communicating with {ip}.",
    ],
    "privilege_escalation": [
        "Kernel exploit attempt on {host}. Process '{proc}' gained SYSTEM privileges.",
        "UAC bypass detected on {host}. Process '{proc}' elevated to admin without user consent.",
        "Token impersonation attack on {host}. Process '{proc}' obtained domain admin token.",
    ],
    "data_exfiltration": [
        "Large data transfer ({size} GB) to external IP {ip} from {host}. Possible exfiltration of {data_type}.",
        "Staging activity detected on {host}. Process '{proc}' archiving sensitive directories for extraction.",
        "Cloud storage upload from {host} to unauthorized account. Process '{proc}' transferring {data_type}.",
    ],
    "cryptomining": [
        "High CPU usage (98%) on {host}. Process '{proc}' identified as cryptocurrency miner.",
        "Mining pool connection from {host} to {ip}:{port}. Process '{proc}' consuming all available cores.",
        "Stratum protocol detected on {host}. Unauthorized mining process '{proc}' active.",
    ],
    "supply_chain": [
        "Compromised package detected in CI/CD pipeline on {host}. Process '{proc}' executing post-install scripts.",
        "Backdoored update agent on {host}. Process '{proc}' downloading payloads from {domain}.",
        "Malicious dependency loaded on {host}. Process '{proc}' establishing covert communication channels.",
    ],
    "insider_threat": [
        "Unusual data access pattern on {host}. Process '{proc}' accessing files outside user's normal scope.",
        "USB mass storage device connected on {host}. Process '{proc}' copying sensitive files to removable media.",
        "After-hours bulk file download on {host}. Process '{proc}' archiving {data_type} documents.",
    ],
    "webshell": [
        "Web shell detected on {host}. Process '{proc}' executing system commands via HTTP POST requests.",
        "Suspicious file upload on {host}. Process '{proc}' created in web-accessible directory with bash capabilities.",
        "Remote code execution on {host}. Process '{proc}' spawned from web server with SYSTEM context.",
    ],
    "botnet": [
        "Bot agent detected on {host}. Process '{proc}' joining command pool at {ip}.",
        "DDoS toolkit loaded on {host}. Process '{proc}' ready to receive attack instructions from {domain}.",
        "Worm propagation from {host}. Process '{proc}' scanning network for vulnerable hosts.",
    ],
}

# --- Severity levels with weights ---
SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHTS = {"easy": [0.1, 0.4, 0.4, 0.1], "medium": [0.0, 0.2, 0.5, 0.3], "hard": [0.0, 0.1, 0.3, 0.6]}

# --- Data types for exfil descriptions ---
DATA_TYPES = [
    "customer PII", "financial records", "employee credentials",
    "source code", "trade secrets", "medical records",
    "encryption keys", "database backups", "API tokens",
    "board meeting minutes", "M&A documents", "patent filings",
]

# --- File extensions for ransomware ---
RANSOM_EXTENSIONS = [
    "locked", "encrypted", "crypted", "crypt", "enc", "pay",
    "ransom", "darkside", "blackcat", "hive", "lockbit", "ryuk",
]


# =============================================================================
# Deterministic Seed Helper
# =============================================================================

def _seed_from_task_id(task_id: str) -> int:
    """Create a deterministic integer seed from a task_id string."""
    h = hashlib.sha256(task_id.encode("utf-8")).hexdigest()
    return int(h[:16], 16)


def _make_hash(rng: random.Random) -> str:
    """Generate a fake MD5-like hash deterministically."""
    return "".join(rng.choice("0123456789abcdef") for _ in range(32))


# =============================================================================
# Difficulty Classification
# =============================================================================

def _get_difficulty(task_id: str, rng: random.Random) -> str:
    """Determine difficulty from task_id pattern or seed."""
    # If task_id has an explicit difficulty prefix, use it
    if task_id.startswith("easy_") or task_id.startswith("gen_easy_"):
        return "easy"
    if task_id.startswith("medium_") or task_id.startswith("gen_medium_"):
        return "medium"
    if task_id.startswith("hard_") or task_id.startswith("gen_hard_"):
        return "hard"

    # For gen_NNNN pattern, use number ranges
    if task_id.startswith("gen_"):
        try:
            num = int(task_id.split("_")[1])
            if num <= 333:
                return "easy"
            elif num <= 666:
                return "medium"
            else:
                return "hard"
        except (ValueError, IndexError):
            pass

    # Fallback: use seed-based distribution
    return rng.choice(["easy", "medium", "hard"])


# =============================================================================
# Core Generator
# =============================================================================

def _pick_hosts(rng: random.Random, subnet: str, count: int) -> List[str]:
    """Pick `count` unique host names from a subnet."""
    info = SUBNETS[subnet]
    prefix = info["prefix"]
    max_idx = info["count"]
    indices = rng.sample(range(1, max_idx + 1), min(count, max_idx))
    return [f"{prefix}-{idx:03d}" for idx in indices]


def _pick_subnets(rng: random.Random, count: int) -> List[str]:
    """Pick `count` unique subnet names."""
    all_subnets = list(SUBNETS.keys())
    return rng.sample(all_subnets, min(count, len(all_subnets)))


def _generate_threat(
    rng: random.Random,
    threat_id: str,
    attack_type: str,
    phase: str,
    available_subnets: List[str],
    used_hosts: set,
) -> Tuple[Dict[str, Any], List[str]]:
    """Generate a single threat in the attack chain.

    Returns:
        (threat_dict, list_of_compromised_hosts)
    """
    # Pick target subnet and hosts
    subnet = rng.choice(available_subnets)
    num_hosts = rng.randint(1, 3) if attack_type != "ransomware" else rng.randint(1, 2)

    hosts = _pick_hosts(rng, subnet, num_hosts + 3)  # Pick extra to avoid collisions
    hosts = [h for h in hosts if h not in used_hosts][:num_hosts]
    if not hosts:
        # Fallback: pick from any subnet
        fallback_subnet = rng.choice(list(SUBNETS.keys()))
        hosts = _pick_hosts(rng, fallback_subnet, num_hosts + 5)
        hosts = [h for h in hosts if h not in used_hosts][:max(1, num_hosts)]

    # Pick malware process
    procs = MALWARE_PROCESSES.get(attack_type, MALWARE_PROCESSES["lateral_movement"])
    proc = rng.choice(procs)

    # Generate IOCs
    num_hashes = rng.randint(1, 2)
    hashes = [_make_hash(rng) for _ in range(num_hashes)]

    num_ips = rng.randint(0, 2) if attack_type in ("c2_communication", "data_exfiltration", "cryptomining", "botnet") else rng.randint(0, 1)
    ips = rng.sample(C2_IPS, min(num_ips, len(C2_IPS))) if num_ips > 0 else []

    num_domains = rng.randint(0, 2) if attack_type in ("c2_communication", "phishing", "supply_chain", "botnet") else rng.randint(0, 1)
    domains = rng.sample(C2_DOMAINS, min(num_domains, len(C2_DOMAINS))) if num_domains > 0 else []

    # C2 servers (subset of IPs for c2/exfil types)
    c2_servers = ips[:1] if attack_type in ("c2_communication", "data_exfiltration", "botnet") else []

    # Lateral targets (for movement-type threats)
    lateral_targets: List[str] = []
    if attack_type in ("lateral_movement", "credential_theft", "c2_communication"):
        lat_subnet = rng.choice(list(SUBNETS.keys()))
        lat_hosts = _pick_hosts(rng, lat_subnet, 2)
        lateral_targets = [h for h in lat_hosts if h not in used_hosts and h not in hosts][:rng.randint(0, 2)]

    # Exfil targets
    exfil_targets: List[str] = []
    if attack_type == "data_exfiltration":
        exfil_targets = list(hosts)

    threat = {
        "threat_id": threat_id,
        "threat_type": attack_type,
        "phase": phase,
        "compromised_hosts": hosts,
        "malicious_processes": [proc],
        "c2_servers": c2_servers,
        "iocs": {
            "hashes": hashes,
            "ips": ips,
            "domains": domains,
        },
        "lateral_targets": lateral_targets,
        "exfil_targets": exfil_targets,
    }

    return threat, hosts


def _generate_alert(
    rng: random.Random,
    alert_idx: int,
    task_prefix: str,
    threat: Dict[str, Any],
    timestamp_base: int,
) -> Dict[str, Any]:
    """Generate a single SIEM alert for a threat."""
    attack_type = threat["threat_type"]
    host = rng.choice(threat["compromised_hosts"])
    proc = threat["malicious_processes"][0]

    # Pick template
    templates = ALERT_TEMPLATES.get(attack_type, ALERT_TEMPLATES["lateral_movement"])
    template = rng.choice(templates)

    # Fill template
    description = template.format(
        host=host,
        proc=proc,
        domain=rng.choice(threat["iocs"]["domains"]) if threat["iocs"]["domains"] else "unknown.example.com",
        ip=rng.choice(threat["iocs"]["ips"]) if threat["iocs"]["ips"] else "0.0.0.0",
        count=rng.randint(50, 500),
        ext=rng.choice(RANSOM_EXTENSIONS),
        secs=rng.randint(10, 120),
        interval=rng.choice([30, 60, 90, 120, 300]),
        size=round(rng.uniform(0.5, 15.0), 1),
        data_type=rng.choice(DATA_TYPES),
        port=rng.choice([3333, 4444, 5555, 8080, 8443, 9090]),
    )

    # Collect IOC indicators for the alert
    ioc_indicators = []
    if threat["iocs"]["hashes"]:
        ioc_indicators.append(rng.choice(threat["iocs"]["hashes"]))
    if threat["iocs"]["ips"]:
        ioc_indicators.append(rng.choice(threat["iocs"]["ips"]))
    if threat["iocs"]["domains"]:
        ioc_indicators.append(rng.choice(threat["iocs"]["domains"]))

    # Determine subnet from host prefix
    subnet = "corporate"
    for sn, info in SUBNETS.items():
        if host.startswith(info["prefix"]):
            subnet = sn
            break

    # Severity
    severity_weights = SEVERITY_WEIGHTS.get(
        "hard" if attack_type in ("data_exfiltration", "ransomware", "privilege_escalation") else "medium",
        SEVERITY_WEIGHTS["medium"]
    )
    severity = rng.choices(SEVERITIES, weights=severity_weights, k=1)[0]

    # Timestamp (spread across a few hours)
    minutes_offset = timestamp_base + alert_idx * rng.randint(5, 45)
    hour = 6 + (minutes_offset // 60)
    minute = minutes_offset % 60
    timestamp = f"2025-01-15T{hour:02d}:{minute:02d}:00Z"

    return {
        "alert_id": f"ALERT-{task_prefix}{alert_idx + 1:03d}",
        "timestamp": timestamp,
        "source_host": host,
        "severity": severity,
        "threat_type": attack_type,
        "description": description,
        "ioc_indicators": ioc_indicators,
        "subnet": subnet,
        "is_acknowledged": False,
    }


# =============================================================================
# Main Generator Function
# =============================================================================

def generate_task(task_id: str, eval_mode: bool = False) -> Dict[str, Any]:
    """Generate a complete, deterministic task definition from a task_id.

    The task_id is hashed to create a seed, ensuring the same task_id
    always produces the exact same scenario.

    Args:
        task_id: Any string (e.g. 'gen_0001', 'gen_0500', 'phishing_test')

    Returns:
        A task_def dict compatible with CyberSOCEnvironment.reset()
    """
    seed_offset = 0
    # Add offset if eval_mode to ensure different data for same ID format
    if eval_mode:
        seed_offset += 10000

    while True:
        seed = _seed_from_task_id(task_id) + seed_offset
        rng = random.Random(seed)

        # Determine difficulty
        difficulty = _get_difficulty(task_id, rng)

        # Configure parameters based on difficulty
        if difficulty == "easy":
            num_threats = 1
            max_steps = rng.randint(12, 18)
            initial_impact = round(rng.uniform(0.02, 0.08), 2)
            impact_per_step = round(rng.uniform(0.01, 0.03), 3)
            num_subnets = rng.randint(1, 2)
        elif difficulty == "medium":
            num_threats = rng.randint(2, 3)
            max_steps = rng.randint(20, 28)
            initial_impact = round(rng.uniform(0.08, 0.15), 2)
            impact_per_step = round(rng.uniform(0.02, 0.04), 3)
            num_subnets = rng.randint(2, 4)
        else:  # hard
            num_threats = rng.randint(3, 6)
            max_steps = rng.randint(25, 35)
            initial_impact = round(rng.uniform(0.15, 0.25), 2)
            impact_per_step = round(rng.uniform(0.03, 0.05), 3)
            num_subnets = rng.randint(3, 6)

        # Pick attack types for this scenario
        all_attack_types = list(MALWARE_PROCESSES.keys())
        if difficulty == "easy":
            # Easy: single focused attack
            attack_types = [rng.choice(all_attack_types)]
        elif difficulty == "medium":
            # Medium: multi-stage, pick a plausible chain
            chains = [
                ["phishing", "credential_theft", "lateral_movement"],
                ["phishing", "c2_communication", "data_exfiltration"],
                ["webshell", "privilege_escalation", "lateral_movement"],
                ["supply_chain", "c2_communication", "credential_theft"],
                ["botnet", "cryptomining", "lateral_movement"],
                ["insider_threat", "data_exfiltration"],
            ]
            chain = rng.choice(chains)
            attack_types = chain[:num_threats]
        else:
            # Hard: complex multi-phase APT
            chains = [
                ["phishing", "c2_communication", "privilege_escalation", "data_exfiltration", "ransomware"],
                ["supply_chain", "c2_communication", "lateral_movement", "credential_theft", "data_exfiltration", "ransomware"],
                ["webshell", "privilege_escalation", "c2_communication", "lateral_movement", "data_exfiltration"],
                ["phishing", "credential_theft", "lateral_movement", "cryptomining", "botnet"],
                ["insider_threat", "privilege_escalation", "data_exfiltration", "c2_communication"],
                ["botnet", "lateral_movement", "privilege_escalation", "ransomware", "data_exfiltration"],
            ]
            chain = rng.choice(chains)
            attack_types = chain[:num_threats]

        # Re-roll if incompatible threats are chosen
        if any((t1, t2) in INCOMPATIBLE_THREATS or (t2, t1) in INCOMPATIBLE_THREATS
               for t1, t2 in itertools.combinations(attack_types, 2)):
            seed_offset += 1
            continue

        # Pick subnets involved
        involved_subnets = _pick_subnets(rng, num_subnets)

        # Generate attack chain
        attack_chain: List[Dict[str, Any]] = []
        used_hosts: set = set()
        task_prefix = task_id.replace("gen_", "G").upper()[:6]

        for i, attack_type in enumerate(attack_types):
            phase_idx = min(i, len(ATTACK_PHASES) - 1)
            # Use realistic phase based on attack type
            phase_map = {
                "phishing": "initial_access",
                "webshell": "initial_access",
                "supply_chain": "initial_access",
                "credential_theft": "credential_access",
                "privilege_escalation": "privilege_escalation",
                "lateral_movement": "lateral_movement",
                "c2_communication": "command_and_control",
                "data_exfiltration": "exfiltration",
                "ransomware": "impact",
                "cryptomining": "impact",
                "insider_threat": "exfiltration",
                "botnet": "command_and_control",
            }
            phase = phase_map.get(attack_type, ATTACK_PHASES[phase_idx])

            threat_id = f"T-{task_prefix}-{i + 1:03d}"
            threat, new_hosts = _generate_threat(
                rng, threat_id, attack_type, phase, involved_subnets, used_hosts
            )
            attack_chain.append(threat)
            used_hosts.update(new_hosts)

        # Generate alerts (1-2 per threat)
        initial_alerts: List[Dict[str, Any]] = []
        timestamp_base = rng.randint(0, 60)
        for i, threat in enumerate(attack_chain):
            num_alerts = rng.randint(1, 2)
            for j in range(num_alerts):
                alert = _generate_alert(
                    rng, len(initial_alerts), task_prefix, threat, timestamp_base
                )
                initial_alerts.append(alert)

        # Generate containment requirements
        must_kill = []
        must_block_iocs = []
        must_forensics = []
        must_not_isolate = []

        for threat in attack_chain:
            for host in threat["compromised_hosts"]:
                for proc in threat["malicious_processes"]:
                    must_kill.append({"hostname": host, "process": proc})
                if host not in must_forensics:
                    must_forensics.append(host)

            # Collect all IOCs as required blocks
            for h in threat["iocs"]["hashes"]:
                if h not in must_block_iocs:
                    must_block_iocs.append(h)
            for ip in threat["iocs"]["ips"]:
                if ip not in must_block_iocs:
                    must_block_iocs.append(ip)
            for d in threat["iocs"]["domains"]:
                if d not in must_block_iocs:
                    must_block_iocs.append(d)

        # Subnets that should NOT be isolated (business-critical ones not in the attack)
        non_involved = [s for s in SUBNETS if s not in involved_subnets]
        if difficulty == "easy":
            must_not_isolate = non_involved
        elif difficulty == "medium":
            must_not_isolate = [s for s in non_involved if SUBNETS[s]["criticality"] >= 0.8]

        # Build description
        type_names = list(set(t["threat_type"] for t in attack_chain))
        host_count = len(used_hosts)
        desc = (
            f"[{difficulty.upper()}] {', '.join(type_names).replace('_', ' ').title()} "
            f"across {host_count} host(s) in {', '.join(involved_subnets)}."
        )

        task_def = {
            "description": desc,
            "max_steps": max_steps,
            "initial_business_impact": initial_impact,
            "impact_per_step": impact_per_step,
            "attack_chain": attack_chain,
            "initial_alerts": initial_alerts,
            "optimal_actions": [
                "run_forensics", "kill_process", "block_ioc", "submit_containment_plan"
            ],
            "containment_requirements": {
                "must_kill": must_kill,
                "must_block_iocs": must_block_iocs,
                "must_forensics": must_forensics,
                "must_not_isolate": must_not_isolate,
            },
        }

        errors = validate_task_def(task_def)
        if not errors:
            return task_def

        # If validation fails, try again with a different seed
        seed_offset += 1


# =============================================================================
# Batch Generation (for openenv.yaml and validation)
# =============================================================================

def list_generated_task_ids(count: int = 1000) -> List[str]:
    """Return the list of generated task IDs."""
    return [f"gen_{i:04d}" for i in range(1, count + 1)]


def get_task_summary(task_id: str) -> Dict[str, str]:
    """Get a short summary of a generated task (for openenv.yaml)."""
    task_def = generate_task(task_id)
    difficulty = _get_difficulty(task_id, random.Random(_seed_from_task_id(task_id)))
    return {
        "description": task_def["description"],
        "max_steps": task_def["max_steps"],
        "difficulty": difficulty,
    }
