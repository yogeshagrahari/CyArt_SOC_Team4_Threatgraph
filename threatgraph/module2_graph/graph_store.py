"""
Module 2 — Graph construction (component 4).

Builds the property graph that the diagram assigns to Neo4j. The default backend
is an in-memory NetworkX DiGraph so the platform runs with no database; the
Neo4j backend (module2_graph/neo4j_loader.py) loads the same model via Cypher
for production and can hydrate a DiGraph back for analysis.

Nodes : users, assets, vulns, credentials, vendors
Edges : CAN_ACCESS, EXPLOITS, ESCALATES_TO, HAS_VULN, HAS_CREDENTIAL, DEPENDS_ON
"""
from __future__ import annotations

from typing import Dict, Any

import networkx as nx

from module2_graph.model import nid, edge_cost


def build_attack_graph(env: Dict[str, Any]) -> nx.DiGraph:
    g = nx.DiGraph()

    # ---- Nodes --------------------------------------------------------------
    for a in env["assets"]:
        g.add_node(nid("asset", a["id"]), **a)
    for u in env["users"]:
        g.add_node(nid("user", u["id"]), **u)
    for v in env["vulns"]:
        g.add_node(nid("vuln", v["id"]), **v)
    for c in env["credentials"]:
        g.add_node(nid("cred", c["id"]), **c)
    for vd in env.get("vendors", []):
        g.add_node(nid("vendor", vd["id"]), **vd)
    for seg in env.get("segments", []):
        g.add_node(nid("segment", seg["id"]), **seg)
    for svc in env.get("services", []):
        g.add_node(nid("service", svc["id"]), **svc)
    for ta in env.get("threat_actors", []):
        g.add_node(nid("threat_actor", ta["id"]), **ta)

    vuln_index = {v["id"]: v for v in env["vulns"]}
    cred_index = {c["id"]: c for c in env["credentials"]}

    # ---- HAS_VULN edges (informational) ------------------------------------
    for asset_id, cves in env.get("vuln_findings", {}).items():
        for cve in cves:
            if nid("vuln", cve) in g:
                g.add_edge(nid("asset", asset_id), nid("vuln", cve),
                           rel="HAS_VULN", cost=0.0, technique=None, cve=cve)
                
    segment_list = env.get("segments", [])
    if segment_list:
        for a in env["assets"]:
            try:
                octet = int(a["ip"].split(".")[1])   # 10.X.y.z → use X
            except (IndexError, ValueError):
                octet = 0
            seg     = segment_list[octet % len(segment_list)]
            a_node  = nid("asset", a["id"])
            s_node  = nid("segment", seg["id"])
            if a_node in g and s_node in g:
                g.add_edge(a_node, s_node,
                           rel="IN_SEGMENT", cost=0.0, technique=None, cve=None)
    for svc in env.get("services", []):
        a_node = nid("asset", svc["asset_id"])
        s_node = nid("service", svc["id"])
        if a_node in g and s_node in g:
            g.add_edge(a_node, s_node,
                       rel="HAS_SERVICE", cost=0.0, technique=None, cve=None)

    # ---- Explicit topology relationships -----------------------------------
    for r in env.get("relationships", []):
        rel = r["rel"]
        src, tgt = r["source"], r["target"]
        if src not in g or tgt not in g:
            continue
        ctx: Dict[str, Any] = {}
        if rel == "EXPLOITS" and r.get("cve") in vuln_index:
            ctx.update(cvss=vuln_index[r["cve"]]["cvss"],
                       exploit_available=vuln_index[r["cve"]]["exploit_available"])
        if rel == "CAN_ACCESS":
            cred_raw = src.split(":", 1)[1] if src.startswith("cred:") else None
            if cred_raw and cred_raw in cred_index:
                ctx.update(strength=cred_index[cred_raw]["strength"],
                           leaked=cred_index[cred_raw].get("leaked", False))
        if rel == "ESCALATES_TO":
            ctx.update(severity=r.get("severity", 2.0))
        cost = r.get("cost")
        if cost is None:
            cost = edge_cost(rel, ctx)
        g.add_edge(src, tgt, rel=rel, cost=cost,
                   technique=r.get("technique"), cve=r.get("cve"),
                   note=r.get("note", ""))

    return g


def graph_stats(g: nx.DiGraph) -> Dict[str, Any]:
    rels: Dict[str, int] = {}
    for _, _, d in g.edges(data=True):
        rels[d["rel"]] = rels.get(d["rel"], 0) + 1
    kinds: Dict[str, int] = {}
    for _, d in g.nodes(data=True):
        kinds[d.get("kind", "?")] = kinds.get(d.get("kind", "?"), 0) + 1
    return {
        "nodes": g.number_of_nodes(),
        "edges": g.number_of_edges(),
        "by_kind": kinds,
        "by_rel": rels}


def to_cytoscape(g: nx.DiGraph) -> Dict[str, Any]:
    """Serialize for the Module 3 Cytoscape.js front-end."""
    elements = []
    for n, d in g.nodes(data=True):
        elements.append({"data": {
            "id": n, "label": d.get("hostname") or d.get("name") or d.get("id", n),
            "kind": d.get("kind", "?"),
            "criticality": d.get("criticality"),
            "privilege": d.get("privilege"),
            "cvss": d.get("cvss"),
            "internet_facing": d.get("internet_facing", False),
            "zone_type":     d.get("zone_type"),       # NetworkSegment
            "port":          d.get("port"),             # Service
            "breach_risk":   d.get("breach_risk"),      # Vendor
            "motivation":    d.get("motivation"),       # ThreatActor
            "cidr":          d.get("cidr"),             # NetworkSegment
        }})
    for s, t, d in g.edges(data=True):
        elements.append({"data": {
            "id": f"{s}->{t}:{d['rel']}", 
            "source": s, 
            "target": t,
            "rel": d["rel"], 
            "cve": d.get("cve"),
        }})
    return {"elements": elements}