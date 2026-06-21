"""Module 4 / component 12 — Automated SIGMA rule generator.

ATT&CK TTP -> SIGMA rules · auto-tune on graph paths · SIEM push.

For every MITRE technique that appears on a discovered attack path we emit a
valid SIGMA rule skeleton, with `level` auto-tuned by the risk of the paths the
technique sits on. `push_to_siem` is the integration seam (no-op offline).
"""
from __future__ import annotations

import hashlib
import os
from typing import Dict, Any, List, Optional

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
    "T1078": ("Valid Accounts / Credential Use", "windows",
              {"EventID": 4624, "LogonType": [2, 3, 10]}),
}


def _rule_id(technique: str) -> str:
    h = hashlib.md5(f"threatgraph-{technique}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def generate_sigma_rules(
    g: nx.DiGraph,
    env: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    paths = shortest_attack_paths(g, top_n=50)
    # technique -> max risk of paths it appears on (for auto-tuning severity)
    tech_risk: Dict[str, float] = {}
    for p in paths:
        for tech in p["techniques"]:
            tech_risk[tech] = max(tech_risk.get(tech, 0.0), p["risk"])
    if env:
        for tech, cve_list in env.get("technique_index", {}).items():
            if tech not in tech_risk:
                # Assign a baseline risk proportional to the highest CVSS in
                # the correlated CVE list so the rule level is not arbitrary.
                vuln_index = {v["id"]: v for v in env.get("vulns", [])}
                max_cvss = max(
                    (vuln_index[c]["cvss"] for c in cve_list if c in vuln_index),
                    default=5.0,
                )
                tech_risk[tech] = max_cvss * 5.0   # scale CVSS 0-10 → risk 0-50
    rules = []
    for tech, risk in sorted(tech_risk.items(), key=lambda kv: -kv[1]):
        title, logsource, selection = TECHNIQUE_DETECT.get(
            tech, (f"Activity for {tech}", "generic", {"technique": tech}))
        level = "critical" if risk >= 80 else "high" if risk >= 60 else "medium"
        rules.append({
            "title": f"ThreatGraph: {title}",
            "id": _rule_id(tech),
            "status": "experimental",
            "description": f"Auto-generated from a ThreatGraph attack path "
                           f"(max path risk {risk}). Detects {tech}.",
            "references": [f"https://attack.mitre.org/techniques/{tech}/"],
            "tags": [f"attack.{tech.lower()}"],
            "logsource": {"category": logsource},
            "detection": {"selection": selection, "condition": "selection"},
            "level": level,
        })
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

def transitive_risk(g, top_n: int = 10):
    """
    Calculate transitive supply-chain risk for every vendor node in the graph.

    Walks DEPENDS_ON edges from assets → vendor to find blast-radius exposure,
    aggregates CVSS scores, and flags which crown jewels are reachable.

    Returns a list of dicts sorted by transitive_risk (desc):
        [{'name': str,
          'vendor_id': str,
          'dependent_assets': int,
          'transitive_risk': float,
          'crown_jewels_at_risk': list[str]}, ...]
    """
    # ---------- helpers -------------------------------------------------
    vendor_nodes = [
        n for n, d in g.nodes(data=True) if d.get("kind") == "vendor"
    ]
    if not vendor_nodes:
        return []

    # Crown jewels: nodes tagged as high-value targets
    cj_set = set(
        n for n, d in g.nodes(data=True)
        if d.get("crown_jewel") or d.get("is_crown_jewel") or d.get("critical")
    )

    def _label(node_id: str) -> str:
        d = g.nodes.get(node_id, {})
        return d.get("label") or d.get("name") or node_id

    # ---------- per-vendor analysis -------------------------------------
    results = []
    for vendor in vendor_nodes:
        vdata    = g.nodes[vendor]
        v_name   = _label(vendor)

        # Assets that directly depend on this vendor  (asset -DEPENDS_ON-> vendor)
        dependent = set()
        for src, dst, edata in g.edges(data=True):
            if dst == vendor and edata.get("rel") == "DEPENDS_ON":
                dependent.add(src)

        # Walk each dependent asset for vuln scores + crown-jewel exposure
        cj_hit    = []
        vuln_sum  = 0.0

        for asset in dependent:
            # Is the asset itself a crown jewel?
            if asset in cj_set:
                lbl = _label(asset)
                if lbl not in cj_hit:
                    cj_hit.append(lbl)

            # Accumulate CVSS from HAS_VULN edges off the asset
            for _, vuln, ed in g.out_edges(asset, data=True):
                if ed.get("rel") == "HAS_VULN":
                    cvss = float(g.nodes[vuln].get("cvss") or 5.0)
                    vuln_sum += cvss

            # Reachable crown jewels via CONNECTS_TO / CAN_ACCESS from this asset
            for src2, dst2, ed2 in g.out_edges(asset, data=True):
                if ed2.get("rel") in ("CONNECTS_TO", "CAN_ACCESS", "ESCALATES_TO"):
                    if dst2 in cj_set:
                        lbl = _label(dst2)
                        if lbl not in cj_hit:
                            cj_hit.append(lbl)

        # Composite score (0–100)
        #   40 % — vendor's own risk weight
        #   40 % — total CVSS burden (capped at 100)
        #   20 % — breadth penalty (number of dependent assets, capped at 2)
        vendor_weight = float(vdata.get("risk_score") or vdata.get("risk") or 50)
        breadth_pen   = min(len(dependent) * 10, 20)
        t_risk = round(
            min(100.0,
                vendor_weight * 0.4
                + min(vuln_sum, 100) * 0.4
                + breadth_pen),
            2
        )

        results.append({
            "name":               v_name,
            "vendor_id":          vendor,
            "dependent_assets":   len(dependent),
            "transitive_risk":    t_risk,
            "crown_jewels_at_risk": cj_hit,
        })

    results.sort(key=lambda x: x["transitive_risk"], reverse=True)
    return results[:top_n]

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