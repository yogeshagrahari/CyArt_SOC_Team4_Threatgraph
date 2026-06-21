"""Module 4 — Exports: STIX 2.1 bundle + remediation roadmap.

These are the final outputs in the diagram (SOC dashboard · STIX2 exports ·
remediation roadmap). The STIX bundle is hand-built valid 2.1 JSON (attack
patterns for the techniques on real paths, an identity, and relationships) so it
imports into OpenCTI / MISP without extra dependencies.
"""
from __future__ import annotations

import datetime as _dt
import uuid
from typing import Dict, Any, List

import networkx as nx

from module4_intelligence.ai_prediction import rank_paths, remediation_hints
from module4_intelligence.zero_trust import detect_policy_gaps

from module2_graph.attack_paths import crown_jewel_exposure
def _ts() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sid(kind: str) -> str:
    return f"{kind}--{uuid.uuid4()}"


def to_stix_bundle(g: nx.DiGraph) -> Dict[str, Any]:
    now = _ts()
    identity = {"type": "identity", "spec_version": "2.1", "id": _sid("identity"),
                "created": now, "modified": now,
                "name": "ThreatGraph", "identity_class": "system"}
    objects: List[Dict[str, Any]] = [identity]

    techniques: Dict[str, str] = {}
    for p in rank_paths(g, top_n=10):
        for tech in p["techniques"]:
            if tech not in techniques:
                ap_obj = {"type": "attack-pattern", "spec_version": "2.1",
                      "id": _sid("attack-pattern"), "created": now, "modified": now,
                      "name": tech, "created_by_ref": identity["id"],
                      "external_references": [{
                          "source_name": "mitre-attack", "external_id": tech,
                          "url": f"https://attack.mitre.org/techniques/{tech}/"}]}
                techniques[tech] = ap_obj["id"]
                objects.append(ap_obj)

        # one observed-data-style note per ranked path
        objects.append({
            "type": "note", "spec_version": "2.1", "id": _sid("note"),
            "created": now, "modified": now, "created_by_ref": identity["id"],
            "abstract": f"Attack path risk {p['risk']} (likelihood "
                        f"{p['predicted_likelihood']})",
            "content": f"{p['entry']} -> {p['target']} via "
                       f"{', '.join(p['techniques']) or 'access'}; "
                       f"{p['length']} hops, cost {p['cost']}.",
            "object_refs": [techniques[t] for t in p["techniques"]] or [identity["id"]],
        })

    return {"type": "bundle", "id": _sid("bundle"), "objects": objects}


def remediation_roadmap(g: nx.DiGraph, env: Dict[str, Any]) -> Dict[str, Any]:
    """Ordered, de-duplicated action plan combining choke-point fixes and zero
    trust policy gaps, sequenced by risk reduction vs effort."""
    items: List[Dict[str, Any]] = []
    rank = {"low": 0, "medium": 1, "high": 2}
#choke-point fixes
    for h in remediation_hints(g, top_n=10):
        items.append({"priority": None, "action": h["action"], "target": h["target"],
                      "rationale": h["detail"], "effort": h["effort"],
                      "risk_reduction": h["breaks_paths"]})
#zero trust policy gaps
    for gap in detect_policy_gaps(g, env):
        items.append({"priority": None, "action": f"close_gap:{gap['type']}",
                      "target": gap["node"], "rationale": gap["detail"],
                      "effort": "low",
                      "risk_reduction": 3 if gap["severity"] == "critical" else 2})

#Crown jewel exposure fixes
    for exposure in crown_jewel_exposure(g)[:5]:
        items.append({
            "priority":  None,
            "action":    "harden_crown_jewel_access_paths",
            "target":    exposure["crown_jewel"],
            "rationale": (
                f"{exposure['label']} ({exposure['kind']}) is reachable from "
                f"{exposure['reaching_entry_count']} entry point(s); cheapest "
                f"traversal cost = {exposure['cheapest_cost']}. Reduce exposure "
                "by adding network segmentation or MFA on all inbound paths."
            ),
            "effort":         "high",
            # Risk reduction = entry paths × 2 (each closed path removes an
            # adversary route and the secondary blast-radius from that route)
            "risk_reduction": exposure["reaching_entry_count"] * 2,
        })

    # sort by risk reduction desc, then lower effort first
    items.sort(key=lambda x: (-x["risk_reduction"], rank.get(x["effort"], 1)))
    for i, it in enumerate(items, 1):
        it["priority"] = i
    return {"generated": _ts(), "total_actions": len(items), "actions": items}