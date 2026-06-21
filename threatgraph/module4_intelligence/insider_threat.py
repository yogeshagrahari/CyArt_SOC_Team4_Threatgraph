"""Module 4 / component 11 — Insider threat behavior analytics.

Anomalous access patterns · privilege abuse detection · UEBA correlation.

A production UEBA learns each identity's behavioural baseline from event streams.
Here we derive a transparent anomaly score from the access graph + a synthetic
access-log sample, which is the same signal shape a UEBA would consume.
"""
from __future__ import annotations

import random
from typing import Dict, Any, List

import networkx as nx

from module2_graph.model import is_crown_jewel


def _accessible_assets(g: nx.DiGraph, user_node: str) -> List[str]:
    """Assets reachable through the user's credentials (user -> cred -> asset)."""
    assets = []
    for _, cred in g.out_edges(user_node):
        if g.nodes[cred].get("kind") != "credential":
            continue
        for _, tgt in g.out_edges(cred):
            if g.nodes[tgt].get("kind") == "asset":
                assets.append(tgt)
    return assets


def behaviour_scores(g: nx.DiGraph, env: Dict[str, Any],
                     seed: int = 11) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    out = []
    for u in env["users"]:
        un = f"user:{u['id']}"
        if un not in g:
            continue
        assets = _accessible_assets(g, un)
        depts = {g.nodes[a].get("environment") for a in assets}
        crown = [a for a in assets if is_crown_jewel(g.nodes[a])]

        # UEBA-style signals (synthetic where no real telemetry exists)
        off_hours_logins = rng.randint(0, 5)
        failed_logins = rng.randint(0, 8)
        volume_spike = rng.random() < 0.15

        score = 0.0
        if u["privilege"] == "standard" and crown:
            score += 40                                  # privilege abuse
        score += min(20, len(depts) * 6)                 # cross-segment breadth
        score += off_hours_logins * 3
        score += failed_logins * 2
        if volume_spike:
            score += 15
        reasons = []
        if u["privilege"] == "standard" and crown:
            reasons.append("standard user can reach crown-jewel asset")
        if len(depts) > 1:
            reasons.append(f"access spans {len(depts)} environments")
        if off_hours_logins:
            reasons.append(f"{off_hours_logins} off-hours logins")
        if volume_spike:
            reasons.append("access-volume spike vs baseline")

        out.append({"user": un, "name": u["name"], "role": u["role"],
                    "privilege": u["privilege"],
                    "insider_risk": round(min(100.0, score), 1),
                    "reachable_crown_jewels": crown, "reasons": reasons})
    out.sort(key=lambda x: x["insider_risk"], reverse=True)
    return out