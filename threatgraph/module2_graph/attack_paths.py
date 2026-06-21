"""
Module 2 — Attack path analysis (component 5).

Shortest paths · lateral movement · privilege escalation · blast radius · risk
scoring. All algorithms run on a NetworkX DiGraph built by graph_store. The
"movement subgraph" is the projection over edges an attacker can actually
traverse (CAN_ACCESS, EXPLOITS, ESCALATES_TO, HAS_CREDENTIAL, CONNECTS_TO).
"""
from __future__ import annotations

from typing import Dict, Any, List

import networkx as nx

from module1_ingestion.schemas import TRAVERSABLE_RELS
from module2_graph.model import is_entry_point, is_crown_jewel, impact_weight


def movement_subgraph(g: nx.DiGraph) -> nx.DiGraph:
    keep = [(s, t) for s, t, d in g.edges(data=True) if d["rel"] in TRAVERSABLE_RELS]
    sub = nx.DiGraph()
    sub.add_nodes_from((n, g.nodes[n]) for n in g.nodes)
    for s, t in keep:
        sub.add_edge(s, t, **g.edges[s, t])
    return sub


def entry_points(g: nx.DiGraph) -> List[str]:
    return [n for n, d in g.nodes(data=True) if is_entry_point(d)]


def crown_jewels(g: nx.DiGraph) -> List[str]:
    return [n for n, d in g.nodes(data=True) if is_crown_jewel(d)]


def _path_edges(g: nx.DiGraph, path: List[str]) -> List[Dict[str, Any]]:
    out = []
    for s, t in zip(path, path[1:]):
        d = g.edges[s, t]
        out.append({"source": s, "target": t, "rel": d["rel"],
                    "cve": d.get("cve"), "technique": d.get("technique"),
                    "cost": d.get("cost")})
    return out


def score_path(g: nx.DiGraph, path: List[str], total_cost: float) -> float:
    """Transparent 0..100 risk score: high-impact target + cheap + high CVSS."""
    target_impact = impact_weight(g.nodes[path[-1]])
    max_cvss = 0.0
    for s, t in zip(path, path[1:]):
        d = g.edges[s, t]
        if d["rel"] == "EXPLOITS" and d.get("cve"):
            cve_node = g.nodes.get(f"vuln:{d['cve']}", {})
            max_cvss = max(max_cvss, float(cve_node.get("cvss", 0.0)))
    exploitability = 1.0 / (1.0 + total_cost)
    score = 100.0 * (0.5 * target_impact + 0.3 * exploitability + 0.2 * (max_cvss / 10.0))
    return round(min(100.0, score), 1)


def shortest_attack_paths(g: nx.DiGraph, top_n: int = 15) -> List[Dict[str, Any]]:
    """Cheapest path from every entry point to every crown jewel, ranked by risk."""
    sub = movement_subgraph(g)
    entries, targets = entry_points(g), crown_jewels(g)
    paths: List[Dict[str, Any]] = []
    for e in entries:
        # single-source Dijkstra is cheaper than pairwise
        try:
            lengths, routes = nx.single_source_dijkstra(sub, e, weight="cost")
        except nx.NodeNotFound:
            continue
        for tgt in targets:
            if tgt == e or tgt not in routes:
                continue
            path = routes[tgt]
            cost = round(lengths[tgt], 2)
            paths.append({
                "entry": e, "target": tgt, "length": len(path) - 1,
                "cost": cost, "risk": score_path(g, path, cost),
                "nodes": path, "edges": _path_edges(g, path),
                "techniques": sorted({pe["technique"] for pe in _path_edges(g, path)
                                      if pe["technique"]}),
            })
    paths.sort(key=lambda p: p["risk"], reverse=True)
    return paths[:top_n]


def lateral_movement(g: nx.DiGraph) -> Dict[str, Any]:
    """Asset-to-asset moves (CAN_ACCESS / EXPLOITS between hosts) + reachable
    asset cluster from each entry asset."""
    moves = []
    for s, t, d in g.edges(data=True):
        if d["rel"] in ("CAN_ACCESS", "EXPLOITS", "CONNECTS_TO") \
                and g.nodes[s].get("kind") == "asset" \
                and g.nodes[t].get("kind") == "asset":
            moves.append({"source": s, "target": t, "rel": d["rel"],
                          "cve": d.get("cve"), "technique": d.get("technique")})
    sub = movement_subgraph(g)
    reach = {}
    for e in entry_points(g):
        if g.nodes[e].get("kind") != "asset":
            continue
        assets = [n for n in nx.descendants(sub, e)
                  if g.nodes[n].get("kind") == "asset"]
        reach[e] = assets
    return {"moves": moves, "reachable_assets": reach}


def privilege_escalation(g: nx.DiGraph) -> List[Dict[str, Any]]:
    """Attack paths that reach an admin/domain-admin principal via an
    ESCALATES_TO edge."""
    chains = []
    for p in shortest_attack_paths(g, top_n=50):
        if g.nodes[p["target"]].get("kind") != "user":
            continue
        esc = [e for e in p["edges"] if e["rel"] == "ESCALATES_TO"]
        if esc:
            chains.append({
                "entry": p["entry"], "target": p["target"],
                "privilege": g.nodes[p["target"]].get("privilege"),
                "risk": p["risk"], "nodes": p["nodes"],
                "escalation_steps": esc,
            })
    return chains


def blast_radius(g: nx.DiGraph, start: str) -> Dict[str, Any]:
    """Everything reachable once `start` is compromised."""
    sub = movement_subgraph(g)
    if start not in sub:
        return {"start": start, "error": "node not found"}
    reachable = nx.descendants(sub, start)
    assets = [n for n in reachable if g.nodes[n].get("kind") == "asset"]
    users = [n for n in reachable if g.nodes[n].get("kind") == "user"]
    impact = round(sum(impact_weight(g.nodes[n]) for n in reachable), 2)
    crown = [n for n in reachable if is_crown_jewel(g.nodes[n])]
    return {"start": start, "reachable_count": len(reachable),
            "assets": assets, "users": users, "crown_jewels_hit": crown,
            "blast_score": impact}


def risk_score_nodes(g: nx.DiGraph, top_n: int = 20) -> List[Dict[str, Any]]:
    """Per-node risk: business impact + exposure + how central the node is to
    attack paths (betweenness over the movement subgraph)."""
    sub = movement_subgraph(g)
    try:
        btw = nx.betweenness_centrality(sub, weight="cost", normalized=True)
    except Exception:
        btw = {n: 0.0 for n in sub.nodes}
    scored = []
    for n, d in g.nodes(data=True):
        if d.get("kind") not in ("asset", "user"):
            continue
        exposure = 0.3 if d.get("internet_facing") else 0.0
        score = round(100.0 * (0.45 * impact_weight(d) + 0.35 * btw.get(n, 0.0)
                               + exposure), 1)
        scored.append({"node": n, "kind": d.get("kind"),
                       "label": d.get("hostname") or d.get("name"),
                       "impact": round(impact_weight(d), 2),
                       "centrality": round(btw.get(n, 0.0), 3),
                       "risk": min(100.0, score)})
    scored.sort(key=lambda x: x["risk"], reverse=True)
    return scored[:top_n]

def crown_jewel_exposure(g: nx.DiGraph) -> List[Dict[str, Any]]:
    """For each crown jewel, list every entry point that can reach it and the
    cheapest traversal cost from that entry. 
    Returns a list sorted by the number of unique entry points that can reach
    each crown jewel (most-exposed first).
    """
    sub     = movement_subgraph(g)
    jewels  = crown_jewels(g)
    entries = entry_points(g)
    exposure: List[Dict[str, Any]] = []
 
    for jewel in jewels:
        reaching: List[Dict[str, Any]] = []
        for e in entries:
            if e == jewel:
                continue
            try:
                cost = nx.dijkstra_path_length(sub, e, jewel, weight="cost")
                reaching.append({"entry": e, "cost": round(cost, 2)})
            except (nx.NodeNotFound, nx.NetworkXNoPath):
                continue
        if reaching:
            reaching.sort(key=lambda x: x["cost"])
            d = g.nodes[jewel]
            exposure.append({
                "crown_jewel":          jewel,
                "kind":                 d.get("kind"),
                "label":                d.get("hostname") or d.get("name"),
                "reaching_entry_count": len(reaching),
                "cheapest_cost":        reaching[0]["cost"],
                "entry_paths":          reaching,
            })
 
    exposure.sort(key=lambda x: x["reaching_entry_count"], reverse=True)
    return exposure