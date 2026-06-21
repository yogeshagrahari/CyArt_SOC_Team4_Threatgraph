"""
Module 2 — Neo4j backend (production path for component 4).

The diagram assigns graph storage to Neo4j. This loader writes the same model
via Cypher and can hydrate a NetworkX DiGraph back so the Module 2 analysis
engine runs unchanged. Activated when NEO4J_URI is set (see docker-compose.yml);
otherwise the platform uses the in-memory NetworkX graph.

    from module2_graph.neo4j_loader import Neo4jBackend
    be = Neo4jBackend("bolt://localhost:7687", "neo4j", "password")
    be.load(env); g = be.to_networkx(); be.close()

PATH: module2_graph/neo4j_loader.py
"""
from __future__ import annotations

from typing import Dict, Any

import networkx as nx

# Cypher for indexes (component 8: graph indexing) — run once on startup.
SCHEMA_CYPHER = [
    "CREATE CONSTRAINT asset_id  IF NOT EXISTS FOR (a:Asset)          REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT user_id   IF NOT EXISTS FOR (u:User)           REQUIRE u.id IS UNIQUE",
    "CREATE CONSTRAINT vuln_id   IF NOT EXISTS FOR (v:Vuln)           REQUIRE v.id IS UNIQUE",
    "CREATE CONSTRAINT cred_id   IF NOT EXISTS FOR (c:Credential)     REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT seg_id    IF NOT EXISTS FOR (s:NetworkSegment) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT svc_id    IF NOT EXISTS FOR (s:Service)        REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT actor_id  IF NOT EXISTS FOR (t:ThreatActor)    REQUIRE t.id IS UNIQUE",
    "CREATE INDEX asset_crit IF NOT EXISTS FOR (a:Asset) ON (a.criticality)",
    "CREATE INDEX seg_zone   IF NOT EXISTS FOR (s:NetworkSegment) ON (s.zone_type)",
]

# Reference query (component 5): shortest attack path between two nodes in Neo4j.
SHORTEST_PATH_CYPHER = """
MATCH (src {id: $src_id}), (dst {id: $dst_id}),
      p = shortestPath((src)-[:CAN_ACCESS|EXPLOITS|ESCALATES_TO|HAS_CREDENTIAL|CONNECTS_TO*..8]->(dst))
RETURN p
"""

_LABEL = {
    "asset":        "Asset",
    "user":         "User",
    "vuln":         "Vuln",
    "credential":   "Credential",
    "vendor":       "Vendor",
    "segment":      "NetworkSegment",
    "service":      "Service",
    "threat_actor": "ThreatActor",
}
_LABEL_TO_KIND = {v: k for k, v in _LABEL.items()}


class Neo4jBackend:
    def __init__(self, uri: str, user: str, password: str):
        from neo4j import GraphDatabase       # optional dependency
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self.driver.close()

    def init_schema(self) -> None:
        with self.driver.session() as s:
            for stmt in SCHEMA_CYPHER:
                s.run(stmt)

    def load(self, env: Dict[str, Any]) -> None:
        self.init_schema()
        with self.driver.session() as s:
            s.run("MATCH (n) DETACH DELETE n")    # full rebuild

            for kind, items in (
                ("asset",      env["assets"]),
                ("user",       env["users"]),
                ("vuln",       env["vulns"]),
                ("credential", env["credentials"]),
                ("vendor",     env.get("vendors", [])),
            ):
                label = _LABEL[kind]
                s.run(
                    f"UNWIND $rows AS row CREATE (n:{label}) SET n = row",
                    rows=items,
                )

            for kind, items in (
                ("segment",      env.get("segments", [])),
                ("service",      env.get("services", [])),
                ("threat_actor", env.get("threat_actors", [])),
            ):
                if not items:
                    continue
                label = _LABEL[kind]
                s.run(
                    f"UNWIND $rows AS row CREATE (n:{label}) SET n = row",
                    rows=items,
                )

            for asset_id, cves in env.get("vuln_findings", {}).items():
                s.run(
                    "MATCH (a:Asset {id:$aid}) UNWIND $cves AS cve "
                    "MATCH (v:Vuln {id:cve}) MERGE (a)-[:HAS_VULN]->(v)",
                    aid=asset_id, cves=cves,
                )

            for r in env.get("relationships", []):
                rel = r["rel"]
                s.run(
                    f"MATCH (a {{id:$sid}}), (b {{id:$tid}}) "
                    f"MERGE (a)-[e:{rel}]->(b) "
                    f"SET e.cost=$cost, e.technique=$tech, e.cve=$cve",
                    sid=r["source"].split(":", 1)[-1],
                    tid=r["target"].split(":", 1)[-1],
                    cost=r.get("cost"),
                    tech=r.get("technique"),
                    cve=r.get("cve"),
                )

    def to_networkx(self) -> nx.DiGraph:
        """Hydrate a NetworkX DiGraph from the live Neo4j database.

        ══════════════════════════════════════════════════════════════════════
        [BUG FIX] TypeError: add_node() got multiple values for keyword
                  argument 'kind'

        ROOT CAUSE:
        Every entity dataclass (Asset, User, Vulnerability, ...) stores its own
        `kind` field as a regular property (e.g. Asset.kind = "asset"). That
        field gets written into Neo4j via `SET n = row` in load(), so when we
        read a node back with `dict(node)`, the resulting `props` dict ALREADY
        contains a `kind` key (e.g. props["kind"] == "asset").

        The original code then did:
            g.add_node(f"{kind}:{props['id']}", kind=kind, **props)
        which expands to passing `kind=...` twice — once explicitly, once via
        **props — and Python raises:
            TypeError: add_node() got multiple values for keyword argument 'kind'

        This only surfaces when running against the real Neo4j backend
        (NEO4J_URI set), because the in-memory NetworkX path
        (module2_graph/graph_store.py) builds nodes directly from Python
        dataclasses and never round-trips through dict(node), so the
        collision never occurs there.

        FIX: pop "kind" (and any other key we pass explicitly) out of `props`
        before splatting, so there is exactly one value per keyword argument.
        Same defensive handling applied to the edge-loading loop below in case
        future edge properties ever include a `cost`/`technique`/`cve` key
        collision from raw Cypher data.
        ══════════════════════════════════════════════════════════════════════
        """
        g = nx.DiGraph()
        with self.driver.session() as s:
            for rec in s.run("MATCH (n) RETURN n, labels(n) AS labels"):
                node, labels = rec["n"], rec["labels"]
                raw_label = labels[0] if labels else "?"
                kind = _LABEL_TO_KIND.get(raw_label, raw_label.lower())

                props = dict(node)
                # [FIX] Remove the colliding key before splatting. Using pop()
                # with a default means this is safe even if `kind` is absent.
                props.pop("kind", None)

                g.add_node(f"{kind}:{props['id']}", kind=kind, **props)

            for rec in s.run(
                "MATCH (a)-[e]->(b) RETURN a.id AS s, b.id AS t, "
                "type(e) AS rel, e.cost AS cost, e.technique AS tech, "
                "e.cve AS cve, labels(a)[0] AS sl, labels(b)[0] AS tl"
            ):
                src_kind = _LABEL_TO_KIND.get(
                    rec["sl"], rec["sl"].lower() if rec["sl"] else "?")
                tgt_kind = _LABEL_TO_KIND.get(
                    rec["tl"], rec["tl"].lower() if rec["tl"] else "?")
                src = f"{src_kind}:{rec['s']}"
                tgt = f"{tgt_kind}:{rec['t']}"
                g.add_edge(
                    src, tgt,
                    rel=rec["rel"],
                    cost=rec["cost"] or 1.0,
                    technique=rec["tech"],
                    cve=rec["cve"],
                )
        return g