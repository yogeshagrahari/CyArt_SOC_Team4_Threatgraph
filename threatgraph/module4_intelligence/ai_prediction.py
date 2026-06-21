"""Module 4 / component 15 — AI-powered attack path prediction.

ML-ranked path prioritization · blast radius forecast · automated remediation
hints.

The ranking model here is a transparent, hand-weighted logistic score over path
features. It is deliberately interpretable; in production you would train a
gradient-boosted / logistic model on labelled incident outcomes and load the
weights here. The remediation engine finds choke-point nodes whose removal
breaks the most high-risk paths (an approximate minimum-cut over attack paths).
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Dict, Any, List

import networkx as nx

from module2_graph.attack_paths import (
    shortest_attack_paths, blast_radius, movement_subgraph,
)

# Interpretable "model" weights over engineered path features.
WEIGHTS = {"bias": -2.2, "risk": 0.045, "inv_cost": 1.1,
           "n_techniques": 0.25, "has_exploit": 0.8, "hops": -0.15}


def _features(g: nx.DiGraph, p: Dict[str, Any]) -> Dict[str, float]:
    has_exploit = any(e["rel"] == "EXPLOITS" for e in p["edges"])
    return {"risk": p["risk"], "inv_cost": 1.0 / (1.0 + p["cost"]),
            "n_techniques": len(p["techniques"]),
            "has_exploit": 1.0 if has_exploit else 0.0,
            "hops": p["length"]}


def rank_paths(g: nx.DiGraph, top_n: int = 10) -> List[Dict[str, Any]]:
    paths = shortest_attack_paths(g, top_n=50)
    ranked = []
    for p in paths:
        f = _features(g, p)
        z = WEIGHTS["bias"] + sum(WEIGHTS[k] * f[k] for k in f)
        prob = 1.0 / (1.0 + math.exp(-z))         # predicted exploit likelihood
        ranked.append({**p, "predicted_likelihood": round(prob, 3),
                       "priority_score": round(prob * p["risk"], 1)})
    ranked.sort(key=lambda x: x["priority_score"], reverse=True)
    return ranked[:top_n]


def blast_radius_forecast(g: nx.DiGraph, node: str,
                          growth_rate: float = 0.15) -> Dict[str, Any]:
    """Current blast radius + a simple projection of how it grows as the estate
    expands (more access edges) if the node stays unremediated."""
    base = blast_radius(g, node)
    projection = [round(base["reachable_count"] * (1 + growth_rate) ** h, 1)
                  for h in range(1, 5)]
    return {**base, "projection_next_4_periods": projection}


def remediation_hints(g: nx.DiGraph, top_n: int = 8) -> List[Dict[str, Any]]:
    """Rank fixes by how many top attack paths they break (choke points)."""
    paths = shortest_attack_paths(g, top_n=50)
    if not paths:
        return []
    # count appearances of intermediate nodes + the exploited vulns/edges
    node_counter: Counter = Counter()
    vuln_counter: Counter = Counter()
    for p in paths:
        for n in p["nodes"][1:-1]:                # exclude entry + target
            node_counter[n] += 1
        for e in p["edges"]:
            if e["rel"] == "EXPLOITS" and e.get("cve"):
                vuln_counter[e["cve"]] += 1

    hints: List[Dict[str, Any]] = []
    for cve, cnt in vuln_counter.most_common(top_n):
        hints.append({"action": "patch_vulnerability", "target": cve,
                      "breaks_paths": cnt, "effort": "medium",
                      "detail": f"Patching {cve} breaks {cnt} attack path(s)."})
    for node, cnt in node_counter.most_common(top_n):
        d = g.nodes[node]
        if d.get("kind") == "user" and d.get("privilege") in ("admin", "domain_admin"):
            action, detail = "enforce_mfa_and_pam", \
                f"Harden {d.get('name')} (MFA/PAM): sits on {cnt} path(s)."
        elif d.get("kind") == "asset":
            action, detail = "segment_or_isolate", \
                f"Network-segment {d.get('hostname')}: sits on {cnt} path(s)."
        else:
            action, detail = "review_access", f"Review {node}: on {cnt} path(s)."
        hints.append({"action": action, "target": node, "breaks_paths": cnt,
                      "effort": "low" if action == "enforce_mfa_and_pam" else "medium",
                      "detail": detail})
    hints.sort(key=lambda h: h["breaks_paths"], reverse=True)
    return hints[:top_n]