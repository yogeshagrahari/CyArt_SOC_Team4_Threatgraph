"""Module 3 / component 7 — Alerting & integration.

SOC alerts · automated reports · SIEM · TheHive · Grafana.

Alerts are derived from ranked attack paths + policy gaps. The integration
functions are seams: they POST to the relevant system when its env var is set,
and no-op (returning a clear status) when running offline.
"""
from __future__ import annotations

import json
import os
from typing import Dict, Any, List

import networkx as nx

from module4_intelligence.ai_prediction import rank_paths
from module4_intelligence.zero_trust import detect_policy_gaps


def generate_alerts(g: nx.DiGraph, env: Dict[str, Any],
                    risk_threshold: float = 60.0) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    for p in rank_paths(g, top_n=10):
        if p["risk"] >= risk_threshold:
            alerts.append({
                "severity": "critical" if p["risk"] >= 80 else "high",
                "title": f"Attack path to {p['target']}",
                "risk": p["risk"], "likelihood": p["predicted_likelihood"],
                "entry": p["entry"], "target": p["target"],
                "techniques": p["techniques"], "path": p["nodes"],
            })
    for gap in detect_policy_gaps(g, env):
        if gap["severity"] in ("critical", "high"):
            alerts.append({"severity": gap["severity"],
                           "title": gap["type"].replace("_", " ").title(),
                           "detail": gap["detail"], "node": gap["node"]})
    return alerts


def automated_report(g: nx.DiGraph, env: Dict[str, Any]) -> str:
    """Markdown SOC report for the SOC dashboard / email digest."""
    paths = rank_paths(g, top_n=5)
    alerts = generate_alerts(g, env)
    lines = ["# ThreatGraph — Automated SOC Report", "",
             f"- Open alerts: **{len(alerts)}**",
             f"- Critical: **{sum(a['severity']=='critical' for a in alerts)}**",
             "", "## Top attack paths", ""]
    for i, p in enumerate(paths, 1):
        lines.append(f"{i}. **risk {p['risk']}** "
                     f"(likelihood {p['predicted_likelihood']}) — "
                     f"`{p['entry']}` → `{p['target']}` "
                     f"via {', '.join(p['techniques']) or 'access'} "
                     f"({p['length']} hops)")
    return "\n".join(lines)


def _post(url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    import urllib.request
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", **headers})
    try:                                            # pragma: no cover - infra path
        with urllib.request.urlopen(req, timeout=5) as r:
            return {"status": r.status}
    except Exception as e:
        return {"error": str(e)}


def push_to_thehive(alert: Dict[str, Any]) -> Dict[str, Any]:
    url, key = os.getenv("THEHIVE_URL"), os.getenv("THEHIVE_KEY")
    if not (url and key):
        return {"sent": False, "note": "set THEHIVE_URL + THEHIVE_KEY to create cases"}
    payload = {"title": alert["title"], "description": json.dumps(alert),
               "severity": 3 if alert["severity"] == "critical" else 2,
               "tlp": 2, "type": "external", "source": "threatgraph",
               "sourceRef": alert.get("target", "tg")}
    return {"sent": True, **_post(f"{url}/api/alert", payload,
                                  {"Authorization": f"Bearer {key}"})}


def push_to_grafana(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Grafana dashboards read from a metrics endpoint; expose via env var."""
    url = os.getenv("GRAFANA_PUSH_URL")
    if not url:
        return {"sent": False, "note": "set GRAFANA_PUSH_URL to push metrics"}
    return {"sent": True, **_post(url, metrics, {})}

def push_to_siem(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:

    url = os.getenv("ELASTIC_URL")
    key = os.getenv("ELASTIC_API_KEY")
    if not (url and key):
        return {
            "sent": False,
            "note": "set ELASTIC_URL + ELASTIC_API_KEY to push to SIEM",
        }
    index_url = f"{url}/threatgraph-alerts/_doc"
    headers   = {"Authorization": f"ApiKey {key}"}
 
    indexed, errors = 0, 0
    for alert in alerts[:20]:   # cap at 20 per call to avoid gateway timeout
        result = _post(index_url, alert, headers)
        if "status" in result and result["status"] in (200, 201):
            indexed += 1
        else:
            errors += 1
 
    return {
        "sent":    True,
        "indexed": indexed,
        "errors":  errors,
        "total":   len(alerts),
    }