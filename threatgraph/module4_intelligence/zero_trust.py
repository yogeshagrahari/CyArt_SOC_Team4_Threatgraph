"""Module 4 / component 9 — Zero trust posture score.

Continuous identity & access verification · trust score per node · policy gap
detection. Trust score is 0..100 (higher = better posture).
"""
from __future__ import annotations

from typing import Dict, Any, List

import networkx as nx

from module2_graph.attack_paths import movement_subgraph, crown_jewels, entry_points
from module2_graph.model import is_crown_jewel


def trust_score_per_node(g: nx.DiGraph) -> List[Dict[str, Any]]:
    scores = []
    for n, d in g.nodes(data=True):
        if d.get("kind") not in ("user", "asset"):
            continue
        s = 100.0
        if d.get("kind") == "user":
            if not d.get("mfa_enabled"):
                s -= 30
            if d.get("privilege") in ("admin", "domain_admin"):
                s -= 15            # high-value identity = higher inherent exposure
        else:
            if d.get("internet_facing"):
                s -= 25
            s -= (d.get("criticality", 1) - 1) * 4
        scores.append({"node": n, "kind": d.get("kind"),
                       "label": d.get("hostname") or d.get("name"),
                       "trust_score": round(max(0.0, s), 1)})
    scores.sort(key=lambda x: x["trust_score"])
    return scores


def detect_policy_gaps(g: nx.DiGraph, env: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []
    cred_by_user: Dict[str, list] = {}
    for c in env["credentials"]:
        cred_by_user.setdefault(c["user_id"], []).append(c)

#Identify and Credential Gaps
    for u in env["users"]:
        if u["privilege"] in ("admin", "domain_admin") and not u["mfa_enabled"]:
            gaps.append({"severity": "high", "type": "admin_without_mfa",
                         "node": f"user:{u['id']}",
                         "detail": f"{u['name']} ({u['privilege']}) has no MFA"})
        weak = [c for c in cred_by_user.get(u["id"], []) if c["strength"] == "weak"]
        if u["privilege"] != "standard" and weak:
            gaps.append({"severity": "high", "type": "weak_privileged_credential",
                         "node": f"user:{u['id']}",
                         "detail": f"{u['name']} holds a weak credential"})
#Asset Exposure Gaps
    for a in env["assets"]:
        cves = env.get("vuln_findings", {}).get(a["id"], [])
        if a["internet_facing"] and cves:
            gaps.append({"severity": "critical", "type": "exposed_vulnerable_asset",
                         "node": f"asset:{a['id']}",
                         "detail": f"{a['hostname']} is internet-facing with {cves}"})

    # crown jewels reachable from an entry point in the movement graph
    sub = movement_subgraph(g)
    entries = set(entry_points(g))
    for cj in crown_jewels(g):
        if any(nx.has_path(sub, e, cj) for e in entries):
            gaps.append({"severity": "critical", "type": "crown_jewel_reachable",
                         "node": cj,
                         "detail": "reachable from an external entry point"})
    
    for seg in env.get("segments", []):
        policy    = seg.get("firewall_policy", "standard")
        zone_type = seg.get("zone_type", "internal")
        seg_node  = f"segment:{seg['id']}"
 
        # Gap 1: permissive policy on any non-external segment
        if policy == "permissive" and zone_type != "external":
            gaps.append({
                "severity": "high",
                "type":     "permissive_internal_segment",
                "node":     seg_node,
                "detail":   (
                    f"Segment {seg['id']} ({zone_type}, {seg.get('cidr')}) "
                    f"has permissive firewall policy — violates zero-trust "
                    "least-privilege network access principle."
                ),
            })
 
        # Gap 2: restricted segment reachable via movement subgraph from external
        if zone_type == "restricted" and seg_node in g:
            if any(nx.has_path(sub, e, seg_node) for e in entries
                   if seg_node != e):
                gaps.append({
                    "severity": "critical",
                    "type":     "restricted_segment_reachable",
                    "node":     seg_node,
                    "detail":   (
                        f"Restricted segment {seg['id']} ({seg.get('cidr')}) "
                        "is reachable from an external entry point through the "
                        "movement graph — segment isolation has failed."
                    ),
                })
 
    # ── Leaked credential gaps (supplemental) ────────────────────────────────
    # [NEW] Flag every credential marked as leaked — these should be revoked
    # immediately regardless of privilege level.
    for c in env.get("credentials", []):
        if c.get("leaked"):
            gaps.append({
                "severity": "critical",
                "type":     "leaked_credential_active",
                "node":     f"cred:{c['id']}",
                "detail":   (
                    f"Credential {c['id']} (type={c['cred_type']}, "
                    f"user={c['user_id']}) is flagged as leaked on the dark web "
                    "and must be revoked immediately."
                ),
            })
    return gaps


def posture_summary(g: nx.DiGraph, env: Dict[str, Any]) -> Dict[str, Any]:
    scores = trust_score_per_node(g)
    gaps = detect_policy_gaps(g, env)
    avg = round(sum(s["trust_score"] for s in scores) / max(1, len(scores)), 1)
    gap_by_severity: Dict[str, int] = {}
    for gp in gaps:
        gap_by_severity[gp["severity"]] = gap_by_severity.get(gp["severity"], 0) + 1
    return {"average_trust_score": avg, "lowest_trust": scores[:5],
            "policy_gaps": gaps, "gap_count": len(gaps), "gap_by_severity": gap_by_severity}