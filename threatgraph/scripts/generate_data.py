"""
Generate a synthetic environment + attack-graph topology and write data/environment.json.

Runs Module 1 ingestion, then lays down relationships:
  HAS_CREDENTIAL · CAN_ACCESS · EXPLOITS · ESCALATES_TO · DEPENDS_ON
including one guaranteed internet -> crown-jewel chain so the analysis engine has
a clear story to find:

    asset-000 (web, internet-facing, exploitable)
        --EXPLOITS--> asset-001 (app)
            --CAN_ACCESS--> asset-002 (critical DB, crown jewel)
            --ESCALATES_TO--> user-000 (domain admin, no MFA)
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from module1_ingestion.pipeline import run_ingestion, save_environment  # noqa: E402
from module1_ingestion.collectors import CVE_CATALOGUE                   # noqa: E402
from module1_ingestion.enrichment import enrich_cves, generate_relationships  # noqa: E402

SEED = 7
DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "data", "environment.json")


def _ensure_vuln(env, cve):
    if not any(v["id"] == cve for v in env["vulns"]):
        env["vulns"].extend(v.to_dict() for v in enrich_cves([cve], env["threat_intel"]))


def main():
    rng = random.Random(SEED)
    env = run_ingestion(seed=SEED, n_assets=40, n_users=25, n_vendors=4)

    assets = {a["id"]: a for a in env["assets"]}
    users = {u["id"]: u for u in env["users"]}
    creds = env["credentials"]

    # ---- Seed the guaranteed scenario --------------------------------------
    assets["asset-000"].update(internet_facing=True, environment="prod",
                               criticality=3, hostname="web01.corp.local")
    assets["asset-001"].update(internet_facing=False, environment="prod",
                               criticality=3, hostname="app01.corp.local")
    assets["asset-002"].update(internet_facing=False, environment="prod",
                               criticality=5, hostname="db01.corp.local")
    users["user-000"].update(privilege="domain_admin", mfa_enabled=False,
                             role="sysadmin", name="da_admin")

    _ensure_vuln(env, "CVE-2021-44228")   # on web01
    _ensure_vuln(env, "CVE-2017-0144")    # on app01
    env["vuln_findings"]["asset-000"] = ["CVE-2021-44228"]
    env["vuln_findings"]["asset-001"] = ["CVE-2017-0144"]

    # mark a low-priv user's credential as leaked (dark-web entry point)
    leaked = next((c for c in creds if c["user_id"] == "user-005"), creds[0])
    leaked["leaked"] = True
    leaked["strength"] = "weak"
    env["assets"] = list(assets.values())
    env["users"]  = list(users.values())
    relationships = []
    asset_ids = list(assets)

    # HAS_CREDENTIAL: principal -> credential
    for c in creds:
        relationships.append({"source": f"user:{c['user_id']}",
                              "target": f"cred:{c['id']}", "rel": "HAS_CREDENTIAL"})

    # CAN_ACCESS: each credential reaches 1-2 assets
    asset_ids = list(assets)
    for c in creds:
        for tgt in rng.sample(asset_ids, rng.randint(1, 2)):
            relationships.append({"source": f"cred:{c['id']}",
                                  "target": f"asset:{tgt}", "rel": "CAN_ACCESS"})

    # Random network reachability between assets in the same environment
    for a in asset_ids:
        peers = [b for b in asset_ids if b != a
                 and assets[b]["environment"] == assets[a]["environment"]]
        for tgt in rng.sample(peers, min(len(peers), rng.randint(0, 2))):
            rel = "EXPLOITS" if env["vuln_findings"].get(tgt) and rng.random() < 0.5 \
                  else "CAN_ACCESS"
            edge = {"source": f"asset:{a}", "target": f"asset:{tgt}", "rel": rel}
            if rel == "EXPLOITS":
                cve = env["vuln_findings"][tgt][0]
                edge["cve"] = cve
                edge["technique"] = CVE_CATALOGUE.get(cve, {}).get("tech", [None])[0]
            relationships.append(edge)

    # A few ESCALATES_TO edges (cached creds / token theft -> privileged user)
    privileged = [u for u in users if users[u]["privilege"] in
                  ("privileged", "admin", "domain_admin")]
    for u in privileged:
        host = rng.choice(asset_ids)
        relationships.append({"source": f"asset:{host}", "target": f"user:{u}",
                              "rel": "ESCALATES_TO", "technique": "T1003",
                              "severity": 2.0})

    # DEPENDS_ON: assets -> vendors (supply chain)
    for a in rng.sample(asset_ids, min(12, len(asset_ids))):
        v = rng.choice(env["vendors"])
        relationships.append({"source": f"asset:{a}", "target": f"vendor:{v['id']}",
                              "rel": "DEPENDS_ON"})

    # ---- Guaranteed crown-jewel chain (explicit, low cost) -----------------
    relationships += [
        {"source": "asset:asset-000", "target": "asset:asset-001", "rel": "EXPLOITS",
         "cve": "CVE-2017-0144", "technique": "T1210", "note": "lateral via SMB RCE"},
        {"source": "asset:asset-001", "target": "asset:asset-002", "rel": "CAN_ACCESS",
         "note": "app server reaches the database"},
        {"source": "asset:asset-001", "target": "user:user-000", "rel": "ESCALATES_TO",
         "technique": "T1003", "severity": 1.5, "note": "cached domain-admin creds"},
        {"source": f"cred:{leaked['id']}", "target": "asset:asset-001",
         "rel": "CAN_ACCESS", "note": "leaked credential reaches app server"},
    ]
    existing_keys = {(r["source"], r["target"], r["rel"]) for r in relationships}
    auto_rels     = generate_relationships(env, rng=random.Random(SEED))
    connects_to   = [
        r for r in auto_rels
        if r["rel"] == "CONNECTS_TO"
        and (r["source"], r["target"], r["rel"]) not in existing_keys
    ]
    relationships.extend(connects_to)
    print(f"[generate_data] added {len(connects_to)} CONNECTS_TO edges")
    env["relationships"] = relationships
    env["assets"] = list(assets.values())
    env["users"] = list(users.values())

    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    save_environment(env, DATA_PATH)
    print(f"[generate_data] wrote {DATA_PATH}")
    print(
        f"  assets={len(env['assets'])}  users={len(env['users'])}  "
        f"vulns={len(env['vulns'])}  creds={len(env['credentials'])}  "
        f"segments={len(env.get('segments', []))}  "     # [NEW]
        f"services={len(env.get('services', []))}  "     # [NEW]
        f"relationships={len(relationships)}"
    )
if __name__ == "__main__":
    main()