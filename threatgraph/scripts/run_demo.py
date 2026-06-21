"""
End-to-end ThreatGraph demo across all four modules.

  Module 1  ingest + enrich + dark-web leak correlation
  Module 2  build graph + attack-path analysis
  Module 4  intelligence / AI scoring
  outputs   SOC report, STIX2 bundle, remediation roadmap

Run from the repo root:  python scripts/run_demo.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from module1_ingestion.pipeline import load_environment, run_ingestion, save_environment
from module2_graph.graph_store import build_attack_graph, graph_stats
from module2_graph import attack_paths as ap
from module3_ops import alerting, optimization
from module4_intelligence import (
    zero_trust, supply_chain, insider_threat, sigma_generator, darkweb,
    risk_forecast, ai_prediction, exports,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "environment.json")
OUT = os.path.join(ROOT, "data", "outputs")


def h(t: str) -> None:
    print("\n" + "=" * 68 + f"\n  {t}\n" + "=" * 68)


def main():
    os.makedirs(OUT, exist_ok=True)

    # ---- Module 1 ----------------------------------------------------------
    h("MODULE 1 — Data Collection & Ingestion")
    env = load_environment(DATA) if os.path.exists(DATA) else run_ingestion()
    if not os.path.exists(DATA):
        save_environment(env, DATA)
    leaked = darkweb.apply_leaks_to_env(env)
    print(f"Ingested: {len(env['assets'])} assets · {len(env['users'])} users · "
          f"{len(env['vulns'])} vulns · {len(env['credentials'])} credentials")
    print(
        f"New entities: {len(env.get('segments', []))} segments · "
        f"{len(env.get('services', []))} services · "
        f"{len(env.get('monitoring_logs', []))} monitoring events"
    )
    print(
        f"MITRE technique index: {len(env.get('technique_index', {}))} techniques"
    )
    print(f"Dark-web correlation flagged {leaked} leaked credential(s) as entry points")
    print(f"Relationships in env: {len(env.get('relationships', []))}")


    # ---- Module 2 ----------------------------------------------------------
    h("MODULE 2 — Graph Engine & Attack-Path Analysis")
    g = build_attack_graph(env)
    print("Graph:", graph_stats(g))
    paths = ap.shortest_attack_paths(g, top_n=5)
    print(f"\nEntry points: {len(ap.entry_points(g))} · "
          f"Crown jewels: {len(ap.crown_jewels(g))}")
    print("\nTop attack paths:")
    for i, p in enumerate(paths, 1):
        print(f"  {i}. risk={p['risk']:<5} cost={p['cost']:<5} "
              f"{p['entry']} -> {p['target']} ({p['length']} hops) "
              f"{p['techniques']}")
    pe = ap.privilege_escalation(g)
    print(f"\nPrivilege-escalation chains: {len(pe)}")
    if paths:
        br = ap.blast_radius(g, paths[0]["entry"])
        print(f"Blast radius from {paths[0]['entry']}: {br['reachable_count']} "
              f"nodes, crown jewels hit: {br['crown_jewels_hit']}")
    cje = ap.crown_jewel_exposure(g)
    if cje:
        print(f"\nCrown-jewel exposure ({len(cje)} crown jewels reachable):")
        for c in cje[:3]:
            print(
                f"  {c['label']} ({c['kind']}) — "
                f"{c['reaching_entry_count']} entry path(s), "
                f"cheapest cost = {c['cheapest_cost']}"
            )
    lm = ap.lateral_movement(g)
    connects_to_moves = [m for m in lm["moves"] if m["rel"] == "CONNECTS_TO"]
    print(
        f"\nLateral moves: {len(lm['moves'])} total "
        f"({len(connects_to_moves)} via CONNECTS_TO network reachability)"
    )
    # ---- Module 4 ----------------------------------------------------------
    h("MODULE 4 — Intelligence & AI")
    zt = zero_trust.posture_summary(g, env)
    print(f"Zero-trust avg score: {zt['average_trust_score']} · "
          f"policy gaps: {zt['gap_count']}"
          f"{zt.get('gap_by_severity', {})}")

    sc = supply_chain.transitive_risk(g)
    if sc:
        top = sc[0]
        print(f"Supply chain: top vendor risk {top['name']} "
              f"(transitive_risk={top['transitive_risk']}, "
              f"crown jewels at risk={len(top['crown_jewels_at_risk'])})")

    it = insider_threat.behaviour_scores(g, env)
    if it:
        print(f"Insider threat: highest {it[0]['name']} "
              f"(risk={it[0]['insider_risk']}) {it[0]['reasons']}")

    rules = sigma_generator.generate_sigma_rules(g, env)
    print(f"SIGMA rules generated: {len(rules)} "
          f"({', '.join(r['level'] for r in rules[:5])})")

    chatter = darkweb.threat_actor_chatter(env)
    print(f"Dark-web chatter relevant to estate: {len(chatter)}")

    fc = risk_forecast.forecast(risk_forecast.synthetic_history(
        paths[0]["risk"] if paths else 50))
    print(f"Risk forecast: {fc['direction']} (slope={fc['trend_slope']}), "
          f"predicted exposure window: {fc['predicted_exposure_window']}")

    ranked = ai_prediction.rank_paths(g, top_n=3)
    print("\nAI-ranked priorities:")
    for r in ranked:
        print(f"  priority={r['priority_score']:<5} P(exploit)={r['predicted_likelihood']} "
              f"{r['entry']} -> {r['target']}")
    hints = ai_prediction.remediation_hints(g, top_n=3)
    print("\nTop remediation hints:")
    for hint in hints:
        print(f"  [{hint['action']}] {hint['detail']}")

    # ---- Outputs -----------------------------------------------------------
    h("OUTPUTS — SOC report · STIX2 · remediation roadmap")
    report = alerting.automated_report(g, env)
    with open(os.path.join(OUT, "soc_report.md"), "w") as f:
        f.write(report)
    bundle = exports.to_stix_bundle(g)
    with open(os.path.join(OUT, "threatgraph_stix.json"), "w") as f:
        json.dump(bundle, f, indent=2)
    roadmap = exports.remediation_roadmap(g, env)
    with open(os.path.join(OUT, "remediation_roadmap.json"), "w") as f:
        json.dump(roadmap, f, indent=2)

    all_alerts = alerting.generate_alerts(g, env)
    siem_result = alerting.push_to_siem(all_alerts)
    if siem_result.get("sent"):
        print(f"SIEM push: indexed {siem_result['indexed']}/{siem_result['total']} alerts")
    else:
        print(f"SIEM push: {siem_result.get('note', 'skipped')} "
              f"(set ELASTIC_URL + ELASTIC_API_KEY to enable)")
 
    print(
        f"\nWrote:\n  {OUT}/soc_report.md"
        f"\n  {OUT}/threatgraph_stix.json ({len(bundle['objects'])} STIX objects)"
        f"\n  {OUT}/remediation_roadmap.json ({roadmap['total_actions']} actions)"
    )
    print(f"\nPipeline health: {optimization.pipeline_health(env, g)}")
 
    # WebSocket note
    print(
        "\nReal-time graph push: connect to ws://localhost:8000/ws/graph "
        "after starting the API server for live Cytoscape.js updates."
    )
    print("\nDemo complete.  Start the API:  uvicorn module3_ops.api:app --reload")
 

if __name__ == "__main__":
    main()