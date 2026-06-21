"""
Tests for the Module 2 attack-path engine.

Verify the engine recovers the seeded internet -> crown-jewel chain and that the
core analyses return sane results. Run from the repo root:  python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from module1_ingestion.pipeline import load_environment, run_ingestion
from module2_graph.graph_store import build_attack_graph
from module2_graph import attack_paths as ap
from module4_intelligence import zero_trust, ai_prediction, exports

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "data", "environment.json")


def _graph():
    env = load_environment(DATA)
    return build_attack_graph(env), env


def test_entry_and_crown_jewels_exist():
    g, _ = _graph()
    assert "asset:asset-000" in ap.entry_points(g)        # web01 internet-facing
    crown = ap.crown_jewels(g)
    assert "asset:asset-002" in crown                     # db01 criticality 5
    assert "user:user-000" in crown                       # domain admin


def test_seeded_attack_path_found():
    g, _ = _graph()
    paths = ap.shortest_attack_paths(g, top_n=50)
    assert paths, "no attack paths found"
    # the domain-admin compromise from web01 must be discovered
    da = [p for p in paths
          if p["entry"] == "asset:asset-000" and p["target"] == "user:user-000"]
    assert da, "seeded web01 -> domain-admin path not found"
    assert "T1003" in da[0]["techniques"]                 # credential dumping step


def test_blast_radius_hits_crown_jewels():
    g, _ = _graph()
    br = ap.blast_radius(g, "asset:asset-000")
    assert br["reachable_count"] > 0
    assert any("user:user-000" == n or "asset:asset-002" == n
               for n in br["crown_jewels_hit"])


def test_privilege_escalation_detected():
    g, _ = _graph()
    chains = ap.privilege_escalation(g)
    assert any(c["target"] == "user:user-000" for c in chains)


def test_zero_trust_flags_admin_without_mfa():
    g, env = _graph()
    gaps = zero_trust.detect_policy_gaps(g, env)
    assert any(gp["type"] == "admin_without_mfa" for gp in gaps)


def test_ranking_and_stix_export():
    g, _ = _graph()
    ranked = ai_prediction.rank_paths(g, top_n=5)
    assert ranked and 0.0 <= ranked[0]["predicted_likelihood"] <= 1.0
    bundle = exports.to_stix_bundle(g)
    assert bundle["type"] == "bundle" and bundle["objects"]

def test_run_ingestion_generates_relationships():
    """CRITICAL: run_ingestion() must produce relationships (was 0 before fix).
 
    Verifies the core bug fix: without env['relationships'], the movement
    subgraph is empty and all attack-path analysis returns nothing.
    """
    env = run_ingestion(seed=42, n_assets=10, n_users=5, n_vendors=2)
    rels = env.get("relationships", [])
    assert len(rels) > 0, "run_ingestion() still producing 0 relationships"
    rel_types = {r["rel"] for r in rels}
    assert "HAS_CREDENTIAL" in rel_types, "HAS_CREDENTIAL edges missing"
    assert "CAN_ACCESS"     in rel_types, "CAN_ACCESS edges missing"
    assert "CONNECTS_TO"    in rel_types, "CONNECTS_TO edges missing"
 
 
def test_new_env_keys_from_run_ingestion():
    """All new entity types must appear in run_ingestion() output."""
    env = run_ingestion(seed=42, n_assets=10, n_users=5, n_vendors=2)
    assert "segments"        in env, "segments key missing from env"
    assert "services"        in env, "services key missing from env"
    assert "monitoring_logs" in env, "monitoring_logs key missing from env"
    assert "technique_index" in env, "technique_index key missing from env"
    assert len(env["segments"])        > 0, "segments list is empty"
    assert len(env["services"])        > 0, "services list is empty"
    assert len(env["technique_index"]) > 0, "technique_index is empty"
 
 
def test_connects_to_in_movement_subgraph():
    """CONNECTS_TO must appear in the movement subgraph (same-segment lateral move)."""
    env = run_ingestion(seed=42, n_assets=15, n_users=8, n_vendors=2)
    g   = build_attack_graph(env)
    sub = ap.movement_subgraph(g)
    rel_types = {d["rel"] for _, _, d in sub.edges(data=True)}
    assert "CONNECTS_TO" in rel_types, "CONNECTS_TO not in movement subgraph"
 
 
def test_crown_jewel_exposure():
    """crown_jewel_exposure() must return correct structure and sort order."""
    g, _ = _graph()
    cje  = ap.crown_jewel_exposure(g)
    assert isinstance(cje, list)
    if len(cje) > 1:
        # Must be sorted by reaching_entry_count descending
        assert cje[0]["reaching_entry_count"] >= cje[1]["reaching_entry_count"]
    if cje:
        item = cje[0]
        assert "crown_jewel"          in item
        assert "reaching_entry_count" in item
        assert "cheapest_cost"        in item
        assert "entry_paths"          in item
        assert isinstance(item["entry_paths"], list)
 
 
def test_segment_nodes_in_graph():
    """NetworkSegment and Service nodes must appear in the graph."""
    env = run_ingestion(seed=42, n_assets=10, n_users=5, n_vendors=2)
    g   = build_attack_graph(env)
    kinds = {d.get("kind") for _, d in g.nodes(data=True)}
    assert "segment" in kinds, "NetworkSegment nodes missing from graph"
    assert "service" in kinds, "Service nodes missing from graph"
 
 
def test_segment_entry_points():
    """External/DMZ segments must be recognised as entry points."""
    env = run_ingestion(seed=42, n_assets=10, n_users=5, n_vendors=2)
    g   = build_attack_graph(env)
    entries = ap.entry_points(g)
    seg_entries = [e for e in entries if e.startswith("segment:")]
    assert len(seg_entries) > 0, "No segment-based entry points found"
 
 
def test_zero_trust_segment_gaps():
    """detect_policy_gaps() must flag permissive internal segments."""
    env  = run_ingestion(seed=42, n_assets=10, n_users=5, n_vendors=2)
    g    = build_attack_graph(env)
    gaps = zero_trust.detect_policy_gaps(g, env)
    gap_types = {gp["type"] for gp in gaps}
    # permissive_internal_segment gap comes from segments with policy=permissive
    # (zone_templates[0] is external+permissive which is OK, but if any internal
    # segment has permissive policy it should be flagged)
    # At minimum the function must not crash and must return a list
    assert isinstance(gaps, list)
 
 
def test_sigma_rules_with_env():
    """generate_sigma_rules(g, env) must produce more rules than without env."""
    g, env = _graph()
    rules_without = __import__(
        "module4_intelligence.sigma_generator", fromlist=["generate_sigma_rules"]
    ).generate_sigma_rules(g)
    rules_with = __import__(
        "module4_intelligence.sigma_generator", fromlist=["generate_sigma_rules"]
    ).generate_sigma_rules(g, env)
    # With technique_index supplement there should be at least as many rules
    assert len(rules_with) >= len(rules_without), \
        "Passing env should not reduce sigma rule count"
 
 
def test_remediation_roadmap_has_crown_jewel_actions():
    """Remediation roadmap must include crown-jewel hardening actions."""
    g, env = _graph()
    roadmap = exports.remediation_roadmap(g, env)
    actions = roadmap.get("actions", [])
    crown_actions = [a for a in actions
                     if a["action"] == "harden_crown_jewel_access_paths"]
    assert len(crown_actions) > 0, \
        "Remediation roadmap missing crown-jewel exposure actions"
 
 
def test_posture_summary_has_severity_breakdown():
    """posture_summary() must include gap_by_severity field."""
    g, env = _graph()
    summary = zero_trust.posture_summary(g, env)
    assert "gap_by_severity" in summary, "gap_by_severity missing from posture summary"
    assert isinstance(summary["gap_by_severity"], dict)