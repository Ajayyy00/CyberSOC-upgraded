"""3-gate action validation middleware: phase whitelist + schema + graph groundedness."""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .threat_graph import ThreatGraph


PHASE_TOOL_WHITELIST = {
    "triage":        {"read_alerts", "read_topology", "correlate_alerts"},
    "investigation": {"query_host", "run_forensics", "add_ioc",
                      "enrich_ioc", "scan_host_vulnerabilities"},
    "remediation":   {"block_ioc", "kill_process", "isolate_segment",
                      "trigger_playbook", "request_human_approval"},
    "report":        {"submit_containment_plan"},
}

PHASE_VIOLATION = "PHASE_VIOLATION"
INVALID_PARAMS = "INVALID_PARAMS"
UNGROUNDED_ACTION = "UNGROUNDED_ACTION"


_REQUIRED_ARGS = {
    "block_ioc":                 ["ioc_value"],
    "kill_process":              ["hostname", "process_name"],
    "isolate_segment":           ["target"],
    "correlate_alerts":          ["alert_ids"],
    "enrich_ioc":                ["ioc_value", "ioc_type"],
    "scan_host_vulnerabilities": ["hostname"],
    "trigger_playbook":          ["playbook_name", "target"],
}


class ActionValidationMiddleware:

    def validate(
        self,
        phase: str,
        tool_name: str,
        arguments: dict,
        graph: "ThreatGraph",
    ) -> Optional[dict]:
        # Gate 1 — Phase whitelist
        allowed = PHASE_TOOL_WHITELIST.get(phase, set())
        if tool_name not in allowed:
            return {
                "error": PHASE_VIOLATION,
                "message": (
                    f"Tool '{tool_name}' is not allowed in phase '{phase}'. "
                    f"Allowed tools: {sorted(allowed)}"
                ),
                "retry": False,
            }

        # Gate 2 — Argument presence (basic schema check)
        required = _REQUIRED_ARGS.get(tool_name, [])
        for arg in required:
            if arg not in arguments:
                return {
                    "error": INVALID_PARAMS,
                    "message": f"Missing required argument '{arg}' for tool '{tool_name}'",
                    "retry": True,
                }
        if tool_name == "correlate_alerts":
            ids = arguments.get("alert_ids", [])
            if not isinstance(ids, (list, tuple)) or len(ids) < 2:
                return {
                    "error": INVALID_PARAMS,
                    "message": "correlate_alerts requires at least 2 alert_ids",
                    "retry": True,
                }

        # Gate 3 — Graph groundedness
        if tool_name == "block_ioc":
            if arguments["ioc_value"] not in graph.iocs:
                return {
                    "error": UNGROUNDED_ACTION,
                    "message": "IOC not in Threat Graph. Run investigation first.",
                    "retry": True,
                }
        elif tool_name == "kill_process":
            key = f"{arguments['hostname']}:{arguments['process_name']}"
            if key not in graph.processes:
                return {
                    "error": UNGROUNDED_ACTION,
                    "message": "Process not in Threat Graph.",
                    "retry": True,
                }
        elif tool_name == "enrich_ioc":
            if arguments["ioc_value"] not in graph.iocs:
                return {
                    "error": UNGROUNDED_ACTION,
                    "message": "IOC not known. Discover it during investigation first.",
                    "retry": True,
                }

        return None
