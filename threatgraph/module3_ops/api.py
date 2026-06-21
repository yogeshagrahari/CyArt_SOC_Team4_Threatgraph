"""Module 3 / component 6 — Visualization layer (backend + API).

FastAPI service that wires Modules 1, 2 and 4 together and serves the
Cytoscape.js front-end. The diagram's stack is D3.js + Cytoscape.js + React; the
shipped front-end (static/index.html) uses Cytoscape.js so it runs with no build
step. Run with:  uvicorn module3_ops.api:app --reload
"""
from __future__ import annotations
import asyncio
import json
import os
from contextlib import asynccontextmanager   # ✅ moved to top
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse

from module1_ingestion.pipeline import load_environment, run_ingestion
from module2_graph.graph_store import build_attack_graph, graph_stats, to_cytoscape
from module2_graph import attack_paths as ap
from module2_graph.neo4j_loader import Neo4jBackend
from module3_ops import alerting, optimization
from module4_intelligence import (
    zero_trust, supply_chain, insider_threat, sigma_generator, darkweb,
    risk_forecast, ai_prediction, exports,
)

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(os.path.dirname(HERE), "data", "environment.json")

STATE: Dict[str, Any] = {}


def _load_graph():
    env = load_environment(DATA_PATH) if os.path.exists(DATA_PATH) else run_ingestion()
    darkweb.apply_leaks_to_env(env)
    uri = os.getenv("NEO4J_URI")
    if uri:
        be = Neo4jBackend(uri, os.getenv("NEO4J_USER", "neo4j"),
                          os.getenv("NEO4J_PASSWORD", "password"))
        be.load(env)
        g = be.to_networkx()
        be.close()
    else:
        g = build_attack_graph(env)
    STATE["env"], STATE["graph"] = env, g
    optimization.cache_invalidate()


@asynccontextmanager
async def lifespan(app: FastAPI):       # ✅ defined before app
    _load_graph()                        # startup
    yield                                # app runs
                                         # shutdown cleanup goes here if needed

# ✅ Only ONE app definition, with lifespan attached
app = FastAPI(
    title="ThreatGraph API",
    version="1.0",
    description="Graph-based attack-path analysis & threat intelligence",
    lifespan=lifespan
)


def G():
    if "graph" not in STATE:
        _load_graph()
    return STATE["graph"], STATE["env"]


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(HERE, "static", "index.html")) as f:
        return f.read()


@app.get("/api/health")
def health():
    g, env = G()
    return {"status": "ok", **optimization.pipeline_health(env, g)}


@app.get("/api/stats")
def stats():
    g, _ = G()
    return graph_stats(g)


@app.get("/api/graph")
def graph():
    g, _ = G()
    return JSONResponse(to_cytoscape(g))


@app.get("/api/attack-paths")
def attack_paths(top_n: int = 15):
    g, _ = G()
    return optimization.timed("attack_paths")(ap.shortest_attack_paths)(g, top_n)


@app.get("/api/attack-paths/ranked")
def ranked(top_n: int = 10):
    g, _ = G()
    return ai_prediction.rank_paths(g, top_n)


@app.get("/api/blast-radius/{node:path}")
def blast(node: str):
    g, _ = G()
    res = ap.blast_radius(g, node)
    if "error" in res:
        raise HTTPException(404, res["error"])
    return res


@app.get("/api/lateral-movement")
def lateral():
    g, _ = G()
    return ap.lateral_movement(g)


@app.get("/api/privilege-escalation")
def privesc():
    g, _ = G()
    return ap.privilege_escalation(g)


@app.get("/api/risk/nodes")
def risk_nodes(top_n: int = 20):
    g, _ = G()
    return ap.risk_score_nodes(g, top_n)


@app.get("/api/zero-trust")
def zt():
    g, env = G()
    return zero_trust.posture_summary(g, env)


@app.get("/api/supply-chain")
def supply():
    g, _ = G()
    return supply_chain.transitive_risk(g)


@app.get("/api/insider-threat")
def insider():
    g, env = G()
    return insider_threat.behaviour_scores(g, env)


@app.get("/api/sigma")
def sigma():
    g, _ = G()
    return sigma_generator.generate_sigma_rules(g)


@app.get("/api/darkweb")
def dark():
    _, env = G()
    return {"leaked_credentials": darkweb.match_leaked_credentials(env),
            "threat_actor_chatter": darkweb.threat_actor_chatter(env)}


@app.get("/api/forecast")
def forecast():
    g, env = G()
    paths = ap.shortest_attack_paths(g, top_n=5)
    current = paths[0]["risk"] if paths else 50.0
    return {"risk_forecast": risk_forecast.forecast(
                risk_forecast.synthetic_history(current)),
            "vulnerability_trend": risk_forecast.vulnerability_trend(env)}


@app.get("/api/remediation")
def remediation():
    g, env = G()
    return exports.remediation_roadmap(g, env)


@app.get("/api/alerts")
def alerts():
    g, env = G()
    return alerting.generate_alerts(g, env)


@app.get("/api/report", response_class=PlainTextResponse)
def report():
    g, env = G()
    return alerting.automated_report(g, env)


@app.get("/api/export/stix")
def stix():
    g, _ = G()
    return JSONResponse(exports.to_stix_bundle(g))


@app.post("/api/reload")
def reload_graph() -> Dict[str, Any]:
    _load_graph()
    g, _ = G()
    return {"status": "reloaded", **graph_stats(g)}


@app.get("/api/crown-jewel-exposure")
def crown_jewel_exp() -> list:
    g, _ = G()
    return ap.crown_jewel_exposure(g)


@app.get("/api/monitoring-events")
def monitoring_events(severity: str = None) -> list:
    _, env = G()
    events = env.get("monitoring_logs", [])
    if severity:
        events = [e for e in events if e.get("severity") == severity]
    return events


@app.websocket("/ws/graph")
async def ws_graph(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        g, _ = G()
        await websocket.send_text(json.dumps(to_cytoscape(g)))
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except (WebSocketDisconnect, Exception):
        pass