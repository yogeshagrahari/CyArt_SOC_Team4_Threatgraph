"""
Module 1 — Data processing & enrichment (component 3).

CVE enrichment · MITRE ATT&CK mapping · identity resolution · deduplication.
"""
from __future__ import annotations
import random
from typing import Dict, List, Any, Optional

from module1_ingestion.schemas import Vulnerability
from module1_ingestion.collectors import CVE_CATALOGUE


def enrich_cves(cve_ids: List[str], threat_intel: Dict[str, Any]) -> List[Vulnerability]:
    """Join raw CVE ids against the catalogue + threat intel to build Vulnerability
    records with CVSS, exploit availability, MITRE techniques and an EPSS-style
    score."""
    actively = set(threat_intel.get("actively_exploited", []))
    out: List[Vulnerability] = []
    seen = set()
    for cve in cve_ids:
        if cve in seen:                       # dedup at the CVE level
            continue
        seen.add(cve)
        meta = CVE_CATALOGUE.get(cve)
        if not meta:
            out.append(Vulnerability(id=cve, cvss=5.0, description="unknown CVE"))
            continue
        epss = 0.9 if cve in actively else (0.4 if meta["exploit"] else 0.05)
        out.append(Vulnerability(
            id=cve,
            cvss=meta["cvss"],
            exploit_available=meta["exploit"] or cve in actively,
            description=meta["desc"],
            mitre_techniques=list(meta["tech"]),
            epss=epss,
        ))
    return out


def resolve_identities(users: List[Dict[str, Any]]) -> Dict[str, str]:
    """Identity resolution: collapse duplicate identities that refer to the same
    human (e.g. AD account + cloud IAM principal + email). Returns a map of
    raw_id -> canonical_id. Here we key on `name`."""
    canonical: Dict[str, str] = {}
    by_name: Dict[str, str] = {}
    for u in users:
        name = u["name"].lower()
        if name not in by_name:
            by_name[name] = u["id"]
        canonical[u["id"]] = by_name[name]
    return canonical


def deduplicate(records: List[Dict[str, Any]], key: str = "id") -> List[Dict[str, Any]]:
    """Drop duplicate records, last-write-wins on the chosen key."""
    merged: Dict[Any, Dict[str, Any]] = {}
    for r in records:
        merged[r[key]] = r
    return list(merged.values())


def map_mitre_techniques(vulns: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    technique_map: Dict[str, List[str]] = {}
    for v in vulns:
        for tech in v.get("mitre_techniques", []):
            technique_map.setdefault(tech, []).append(v["id"])
    return technique_map
 
def generate_relationships(
    env: Dict[str, Any],
    rng: Optional[random.Random] = None,
) -> List[Dict[str, Any]]:
    """Infer traversable attack-graph edges from the ingested environment.
 
    Returns a list of relationship dicts compatible with the format consumed by
    module2_graph.graph_store.build_attack_graph() (the "relationships" list
    inside the env document).
 
    Edge types produced:
      HAS_CREDENTIAL — user  → credential
      CAN_ACCESS     — credential → asset   (cost driven by strength / leaked)
      EXPLOITS       — asset → asset        (only when exploit_available=True)
      ESCALATES_TO   — user  → user         (standard → privileged → admin)
      DEPENDS_ON     — asset → vendor       (high breach-risk vendors only)
      CONNECTS_TO    — asset → asset        (same cloud/segment reachability)
 
    Fan-out is intentionally limited (≤3 targets per CVE, ≤2 CONNECTS_TO peers)
    to keep the graph tractable. In production these would be replaced by real
    network-topology data from BloodHound CE / cloud-graph APIs.
    """
    if rng is None:
        rng = random.Random(42)
 
    rels: List[Dict[str, Any]] = []
 
    # ── Index lookups ────────────────────────────────────────────────────────
    vuln_index    = {v["id"]: v for v in env.get("vulns", [])}
    asset_list    = env.get("assets", [])
    user_list     = env.get("users", [])
    cred_list     = env.get("credentials", [])
    vendor_list   = env.get("vendors", [])
    vuln_findings = env.get("vuln_findings", {})
 
    user_by_id  = {u["id"]: u for u in user_list}
    priv_order  = {"standard": 1, "privileged": 2, "admin": 3, "domain_admin": 4}
 
    for cred in cred_list:
        rels.append({
            "source":    f"user:{cred['user_id']}",
            "target":    f"cred:{cred['id']}",
            "rel":       "HAS_CREDENTIAL",
            "cost":      0.5,
            "technique": None,
            "cve":       None,
            "note":      "User owns credential",
        })
 
    # ── 2. CAN_ACCESS  credential → asset ───────────────────────────────────
    
    # model.py edge_cost: leaked→0.5, weak→1.0, medium→2.0, strong→3.0.
    # Access scope:
    #   admin/domain_admin → all assets
    #   leaked or weak     → all assets
    #   medium             → non-prod only
    #   privileged         → prod assets
    for cred in cred_list:
        user = user_by_id.get(cred["user_id"])
        if not user:
            continue
        u_priv   = priv_order.get(user.get("privilege", "standard"), 1)
        strength = cred.get("strength", "strong")
        leaked   = cred.get("leaked", False)
 
        for asset in asset_list:
            env_tier   = asset.get("environment", "dev")
            accessible = (
                u_priv >= 3                                       # admin  → anywhere
                or leaked                                         # leaked → anywhere
                or strength == "weak"                             # weak   → anywhere
                or (strength == "medium" and env_tier != "prod")  # medium → non-prod
                or (u_priv >= 2 and env_tier == "prod")           # priv   → prod
            )
            if accessible:
                rels.append({
                    "source":    f"cred:{cred['id']}",
                    "target":    f"asset:{asset['id']}",
                    "rel":       "CAN_ACCESS",
                    "cost":      None,  # graph_store looks up cred props for edge_cost
                    "technique": "T1078",
                    "cve":       None,
                    "note":      f"Credential access (strength={strength}, leaked={leaked})",
                })
 
    # ── 3. EXPLOITS  asset → asset (via exploitable CVE) ────────────────────
    # internal hosts. Fan-out capped at 3 targets per CVE to avoid O(n²) edges.
    internal_assets = [a for a in asset_list if not a.get("internet_facing")]
 
    for asset_id, cves in vuln_findings.items():
        src_asset = next((a for a in asset_list if a["id"] == asset_id), None)
        if not src_asset:
            continue
        for cve in cves:
            meta = vuln_index.get(cve)
            if not meta or not meta.get("exploit_available"):
                continue
 
            # Internet-facing hosts pivot inward; internal hosts pivot laterally
            candidates = internal_assets if src_asset.get("internet_facing") else asset_list
            candidates = [a for a in candidates if a["id"] != asset_id]
            targets    = rng.sample(candidates, min(3, len(candidates)))
 
            techniques = meta.get("mitre_techniques", [])
            tech       = techniques[0] if techniques else None
 
            for tgt in targets:
                rels.append({
                    "source":    f"asset:{asset_id}",
                    "target":    f"asset:{tgt['id']}",
                    "rel":       "EXPLOITS",
                    "cost":      None,   # edge_cost uses cvss + exploit_available
                    "technique": tech,
                    "cve":       cve,
                    "note":      f"Exploit: {meta.get('description', cve)}",
                })
 
    # ── 4. ESCALATES_TO  user → higher-privilege user ───────────────────────
    # Each lower-priv user maps to one randomly-sampled higher-priv user to keep
    # the graph sparse. In production BloodHound CE supplies real AD paths.
    priv_levels: Dict[int, List[str]] = {}
    for u in user_list:
        lvl = priv_order.get(u.get("privilege", "standard"), 1)
        priv_levels.setdefault(lvl, []).append(u["id"])
 
    for lvl in sorted(priv_levels):
        next_lvl = lvl + 1
        if next_lvl not in priv_levels:
            continue
        for uid in priv_levels[lvl]:
            target_uid = rng.choice(priv_levels[next_lvl])
            rels.append({
                "source":    f"user:{uid}",
                "target":    f"user:{target_uid}",
                "rel":       "ESCALATES_TO",
                "cost":      None,        # edge_cost uses severity ctx
                "technique": "T1068",
                "cve":       None,
                "note":      "Privilege escalation path",
                "severity":  2.0,         # picked up by graph_store → edge_cost
            })
 
    # ── 5. DEPENDS_ON  asset → high-risk vendor ─────────────────────────────
    #supply-chain risk on the graph.
    high_risk  = [v for v in vendor_list if v.get("breach_risk", 0) > 0.25]
    prod_assets = [a for a in asset_list if a.get("environment") == "prod"]
    for vendor in high_risk:
        affected = rng.sample(prod_assets, min(3, len(prod_assets)))
        for asset in affected:
            rels.append({
                "source":    f"asset:{asset['id']}",
                "target":    f"vendor:{vendor['id']}",
                "rel":       "DEPENDS_ON",
                "cost":      4.0,
                "technique": None,
                "cve":       None,
                "note":      f"Supply chain: {vendor['name']} (risk={vendor.get('breach_risk')})",
            })
 
    # ── 6. CONNECTS_TO  asset → asset (same cloud/network segment) ──────────
    # segment. Fan-out is 1–2 peers per asset to keep the graph sparse.
    # model.py edge_cost: 3.0 (moderate — reachable but not authenticated).
    cloud_groups: Dict[str, List[Dict[str, Any]]] = {}
    for a in asset_list:
        key = a.get("cloud") or "on-prem"
        cloud_groups.setdefault(key, []).append(a)
 
    for group in cloud_groups.values():
        if len(group) < 2:
            continue
        for src_asset in group:
            peers  = [a for a in group if a["id"] != src_asset["id"]]
            chosen = rng.sample(peers, min(2, len(peers)))
            for peer in chosen:
                rels.append({
                    "source":    f"asset:{src_asset['id']}",
                    "target":    f"asset:{peer['id']}",
                    "rel":       "CONNECTS_TO",
                    "cost":      3.0,
                    "technique": "T1021",
                    "cve":       None,
                    "note":      f"Network reachability ({src_asset.get('cloud', 'on-prem')})",
                })
 
    return rels