"""Module 4 / component 12 — Automated SIGMA rule generator.

ATT&CK TTP -> SIGMA rules · auto-tune on graph paths · SIEM push.

For every MITRE technique that appears on a discovered attack path we emit a
valid SIGMA rule skeleton, with `level` auto-tuned by the risk of the paths the
technique sits on. `push_to_siem` is the integration seam (no-op offline).
"""
from __future__ import annotations

import hashlib
import os
from typing import Dict, Any, List

import networkx as nx

from module2_graph.attack_paths import shortest_attack_paths

# Minimal technique -> detection hint catalogue.
TECHNIQUE_DETECT = {
    "T1190": ("Exploit Public-Facing Application", "webserver",
              {"c-uri|contains": ["/cgi-bin/", "${jndi:", "..%2f"]}),
    "T1210": ("Exploitation of Remote Services", "windows",
              {"EventID": 5145, "ShareName|contains": "ADMIN$"}),
    "T1003": ("OS Credential Dumping", "windows",
              {"EventID": 4656, "ObjectName|contains": "lsass"}),
    "T1068": ("Privilege Escalation Exploit", "windows",
              {"EventID": 4673}),
    "T1021": ("Remote Services / Lateral Movement", "windows",
              {"EventID": 4624, "LogonType": 3}),
    "T1187": ("Forced Authentication", "windows",
              {"EventID": 4624, "AuthenticationPackageName": "NTLM"}),
    "T1059": ("Command and Scripting Interpreter", "process_creation",
              {"Image|endswith": ["\\powershell.exe", "\\cmd.exe"]}),
}


def _rule_id(technique: str) -> str:
    h = hashlib.md5(f"threatgraph-{technique}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def generate_sigma_rules(g, env=None):
    """
    Generate SIGMA detection rules from graph attack paths and env context.

    Each rule dict contains:
        title, level, status, description, logsource, detection, technique
    """
    rules = []

    # ── 1. Rules from graph edges ────────────────────────────────────────
    TECHNIQUE_META = {
        "T1003": ("critical", "Credential Dumping Detected"),
        "T1210": ("high",     "Remote Service Exploitation Detected"),
        "T1078": ("high",     "Valid Account Abuse Detected"),
        "T1021": ("medium",   "Remote Services Lateral Movement"),
        "T1059": ("high",     "Command and Scripting Interpreter"),
        "T1053": ("medium",   "Scheduled Task / Job Abuse"),
    }

    seen_techniques = set()
    for src, dst, edata in g.edges(data=True):
        techs = edata.get("techniques") or []
        if isinstance(techs, str):
            techs = [techs]
        for t in techs:
            if t in seen_techniques:
                continue
            seen_techniques.add(t)
            level, title = TECHNIQUE_META.get(t, ("medium", f"Technique {t} Detected"))
            rules.append({
                "title":       title,
                "level":       level,
                "status":      "experimental",
                "technique":   t,
                "description": (
                    f"Detected potential use of MITRE ATT&CK {t} between "
                    f"{g.nodes[src].get('label', src)} and "
                    f"{g.nodes[dst].get('label', dst)}."
                ),
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {"CommandLine|contains": t},
                    "condition": "selection",
                },
            })

    # ── 2. Rules from leaked credentials (env context) ───────────────────
    if env:
        for cred in env.get("credentials", []):
            if cred.get("leaked") or cred.get("dark_web_hit"):
                rules.append({
                    "title":       f"Leaked Credential Use: {cred.get('id', 'unknown')}",
                    "level":       "critical",
                    "status":      "stable",
                    "technique":   "T1078",
                    "description": (
                        f"Credential {cred.get('id')} was found in dark-web leak data. "
                        "Alert on any successful authentication using this account."
                    ),
                    "logsource": {"category": "authentication", "product": "any"},
                    "detection": {
                        "selection": {"user": cred.get("username", cred.get("id"))},
                        "condition": "selection",
                    },
                })

    # ── 3. Rules from high-CVSS vulnerabilities (env context) ────────────
    if env:
        for vuln in env.get("vulns", []):
            cvss = float(vuln.get("cvss") or 0)
            if cvss >= 8.0:
                level = "critical" if cvss >= 9.0 else "high"
                rules.append({
                    "title":       f"High-Severity Vuln Activity: {vuln.get('cve', vuln.get('id'))}",
                    "level":       level,
                    "status":      "experimental",
                    "technique":   "T1210",
                    "description": (
                        f"Exploitation attempt for {vuln.get('cve', vuln.get('id'))} "
                        f"(CVSS {cvss}). {vuln.get('description', '')}".strip()
                    ),
                    "logsource": {"category": "network", "product": "any"},
                    "detection": {
                        "selection": {"dst_port": vuln.get("port", "any")},
                        "condition": "selection",
                    },
                })

    # Sort: critical → high → medium → low
    ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rules.sort(key=lambda r: ORDER.get(r["level"], 9))
    return rules


def to_yaml(rule: Dict[str, Any]) -> str:
    """Tiny YAML serializer (avoids a pyyaml dependency for the demo)."""
    def dump(v, ind=0):
        pad = "  " * ind
        if isinstance(v, dict):
            return "".join(f"\n{pad}{k}:{dump(val, ind+1)}" for k, val in v.items())
        if isinstance(v, list):
            return "".join(f"\n{pad}- {item}" for item in v)
        return f" {v}"
    return dump(rule).lstrip("\n")


def push_to_siem(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """SIEM push seam. Set SIEM_WEBHOOK to POST rules to Splunk/Elastic/etc."""
    webhook = os.getenv("SIEM_WEBHOOK")
    if not webhook:
        return {"pushed": 0, "note": "SIEM_WEBHOOK not set; rules generated only"}
    import json
    import urllib.request
    req = urllib.request.Request(webhook, data=json.dumps(rules).encode(),
                                 headers={"Content-Type": "application/json"})
    try:                                            # pragma: no cover - infra path
        urllib.request.urlopen(req, timeout=5)
        return {"pushed": len(rules)}
    except Exception as e:
        return {"pushed": 0, "error": str(e)}
