"""Module 4 / component 13 — Dark web intelligence correlation.

Leaked credential matching · threat actor chatter · IOC enrichment via OpenCTI.

`SAMPLE_LEAK_FEED` stands in for a breach/credential-dump feed (HaveIBeenPwned,
DeHashed, a CTI vendor). `enrich_ioc_opencti` is the OpenCTI integration seam.
"""
from __future__ import annotations

import os
from typing import Dict, Any, List

# Synthetic "leaked credentials" feed: usernames found in dumps.
SAMPLE_LEAK_FEED = ["user005", "user012", "da_admin", "user018"]

# Synthetic threat-actor chatter referencing techniques/CVEs of interest.
SAMPLE_CHATTER = [
    {"actor": "FIN-Echo", "ioc": "CVE-2017-0144",
     "context": "selling access via SMB exploit", "confidence": 0.7},
    {"actor": "LapsusClone", "ioc": "da_admin",
     "context": "admin credentials advertised on forum", "confidence": 0.6},
]


def match_leaked_credentials(env: Dict[str, Any],
                             feed: List[str] = None) -> List[Dict[str, Any]]:
    feed = set(feed or SAMPLE_LEAK_FEED)
    hits = []
    for u in env["users"]:
        if u["name"] in feed:
            hits.append({"user": f"user:{u['id']}", "name": u["name"],
                         "privilege": u["privilege"], "source": "dark_web_dump"})
    return hits


def apply_leaks_to_env(env: Dict[str, Any], feed: List[str] = None) -> int:
    """Flag credentials of leaked users so they become graph entry points.
    Returns the number of credentials flagged. Call BEFORE building the graph."""
    leaked_users = {h["user"].split(":", 1)[1]
                    for h in match_leaked_credentials(env, feed)}
    count = 0
    for c in env["credentials"]:
        if c["user_id"] in leaked_users:
            c["leaked"] = True
            count += 1
    return count


def threat_actor_chatter(env: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Correlate chatter IOCs against the environment (matching CVEs / users)."""
    known_cves = {v["id"] for v in env["vulns"]}
    known_users = {u["name"] for u in env["users"]}
    relevant = []
    for c in SAMPLE_CHATTER:
        if c["ioc"] in known_cves or c["ioc"] in known_users:
            relevant.append({**c, "relevant_to_environment": True})
    return relevant


def enrich_ioc_opencti(indicator: str) -> Dict[str, Any]:
    """OpenCTI enrichment seam. Set OPENCTI_URL + OPENCTI_TOKEN for live lookups;
    returns a stub enrichment offline."""
    url, token = os.getenv("OPENCTI_URL"), os.getenv("OPENCTI_TOKEN")
    if not (url and token):
        return {"indicator": indicator, "source": "stub",
                "labels": ["unverified"], "score": None,
                "note": "set OPENCTI_URL + OPENCTI_TOKEN for live enrichment"}
    try:                                            # pragma: no cover - infra path
        from pycti import OpenCTIApiClient # type: ignore
        client = OpenCTIApiClient(url, token)
        res = client.indicator.read(filters={"key": "pattern", "values": [indicator]})
        return {"indicator": indicator, "source": "opencti", "result": res}
    except Exception as e:
        return {"indicator": indicator, "source": "opencti", "error": str(e)}