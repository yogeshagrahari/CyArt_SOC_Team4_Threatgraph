"""Module 3 / component 8 — Continuous optimization.

Query tuning · graph indexing · pipeline monitoring · threat-model updates.
"""
from __future__ import annotations

import functools
import time
from typing import Dict, Any, Callable

import networkx as nx

# Neo4j index DDL lives with the loader (module2_graph.neo4j_loader.SCHEMA_CYPHER).
from module2_graph.neo4j_loader import SCHEMA_CYPHER  # re-exported for ops tooling

_QUERY_TIMINGS: Dict[str, list] = {}


def timed(name: str) -> Callable:
    """Decorator that records query latency for tuning dashboards."""
    def deco(fn):
        @functools.wraps(fn)
        def wrap(*a, **k):
            t0 = time.perf_counter()
            out = fn(*a, **k)
            _QUERY_TIMINGS.setdefault(name, []).append(time.perf_counter() - t0)
            return out
        return wrap
    return deco


def query_tuning_report() -> Dict[str, Any]:
    rep = {}
    for name, samples in _QUERY_TIMINGS.items():
        rep[name] = {"calls": len(samples),
                     "avg_ms": round(1000 * sum(samples) / len(samples), 2),
                     "max_ms": round(1000 * max(samples), 2)}
    return rep


def pipeline_health(env: Dict[str, Any], g: nx.DiGraph) -> Dict[str, Any]:
    """Lightweight pipeline-monitoring snapshot."""
    orphan_vulns = [n for n, d in g.nodes(data=True)
                    if d.get("kind") == "vuln" and g.in_degree(n) == 0]
    return {"entities_ingested": len(env["assets"]) + len(env["users"])
            + len(env["vulns"]) + len(env["credentials"]) + len(env.get("segments", []))
            + len(env.get("services", []))
            + len(env.get("monitoring_logs", [])),
             "graph_nodes":  g.number_of_nodes(),
        "graph_edges":  g.number_of_edges(),
        "orphan_vulns": len(orphan_vulns),
        "identity_dedup_ratio": round(
            len(set(env.get("identity_map", {}).values()))
            / max(1, len(env["users"])),
            2,
        ),
        # [NEW] Relationship count by type — useful for spotting missing edge classes.
        "relationships_by_type": {
            d["rel"]: 0
            for _, _, d in g.edges(data=True)
        },
    }


def threat_model_update(env: Dict[str, Any], new_cves: Dict[str, dict]) -> Dict[str, Any]:
    """Fold newly published CVEs into the catalogue at runtime so the next graph
    rebuild reflects the latest threat model."""
    from module1_ingestion.collectors import CVE_CATALOGUE
    added = 0
    for cve, meta in new_cves.items():
        if cve not in CVE_CATALOGUE:
            CVE_CATALOGUE[cve] = meta
            added += 1
    return {"catalogue_size": len(CVE_CATALOGUE), "added": added}

_CACHE: Dict[str, Dict[str, Any]] = {}
_DEFAULT_TTL: int = 300   # seconds
 
 
def cached(key: str, ttl: int = _DEFAULT_TTL) -> Callable:
    """TTL decorator for expensive graph operations.
 
    Usage:
        @cached("attack_paths_15", ttl=120)
        def get_paths(g):
            return ap.shortest_attack_paths(g, top_n=15)
 
    The cache is keyed by `key` (not by arguments) so callers are responsible
    for using a unique key per distinct logical query.
    """
    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrap(*a, **k):
            entry = _CACHE.get(key)
            if entry and (time.monotonic() - entry["ts"]) < ttl:
                return entry["val"]
            val = fn(*a, **k)
            _CACHE[key] = {"val": val, "ts": time.monotonic()}
            return val
        return wrap
    return deco
 
 
def cache_invalidate(key: str = None) -> None:
    """Invalidate one cache entry (by key) or the entire cache (no argument).
 
    Called by api._load_graph() after every graph rebuild so that stale
    betweenness-centrality and attack-path results are never served after a
    threat-model update.
    """
    if key:
        _CACHE.pop(key, None)
    else:
        _CACHE.clear()
 
 
def cache_stats() -> Dict[str, Any]:
    """Return the current cache occupancy for the /api/health dashboard."""
    now = time.monotonic()
    return {
        k: {
            "age_s":   round(now - v["ts"], 1),
            "expired": (now - v["ts"]) > _DEFAULT_TTL,
        }
        for k, v in _CACHE.items()
    }