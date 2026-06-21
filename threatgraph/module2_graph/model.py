"""
Module 2 — graph model helpers.

Node id scheme:  user:<id> · asset:<id> · vuln:<CVE> · cred:<id> · vendor:<id>
Edge cost is the attacker traversal cost (lower = easier). Path-finding minimises
total cost; risk scoring rewards short, high-impact paths.
"""
from __future__ import annotations

from typing import Dict, Any


def nid(kind: str, raw_id: str) -> str:
    return f"{kind}:{raw_id}"


def edge_cost(rel: str, ctx: Dict[str, Any]) -> float:
    """Traversal cost for an attacker. `ctx` carries referenced entity props."""
    if rel == "HAS_CREDENTIAL":
        # controlling a principal yields its credentials for free
        return 0.5
    if rel == "CAN_ACCESS":
        # weak/leaked creds make access trivial
        if ctx.get("leaked"):
            return 0.5
        return {"weak": 1.0, "medium": 2.0, "strong": 3.0}.get(
            ctx.get("strength", "strong"), 3.0)
    if rel == "EXPLOITS":
        cvss = float(ctx.get("cvss", 5.0))
        cost = max(0.5, 11.0 - cvss)          # CVSS 10 -> ~1.0, CVSS 5 -> ~6.0
        if ctx.get("exploit_available"):
            cost *= 0.5                        # public exploit halves the cost
        return round(cost, 2)
    if rel == "ESCALATES_TO":
        return float(ctx.get("severity", 2.0))
    if rel == "CONNECTS_TO":
        return 3.0
    return 4.0                                 # default


def is_entry_point(node_attrs: Dict[str, Any]) -> bool:
    """Where an external attacker can plausibly start."""
    if node_attrs.get("kind") == "asset" and node_attrs.get("internet_facing"):
        return True
    if node_attrs.get("kind") == "credential" and node_attrs.get("leaked"):
        return True
    if node_attrs.get("kind") == "segment" and node_attrs.get("zone_type") in (
            "external", "dmz"):
        return True
    return bool(node_attrs.get("entry"))


def is_crown_jewel(node_attrs: Dict[str, Any]) -> bool:
    """High-value targets an attacker wants to reach."""
    if node_attrs.get("kind") == "asset" and node_attrs.get("criticality", 0) >= 5:
        return True
    if node_attrs.get("kind") == "user" and node_attrs.get("privilege") in (
            "admin", "domain_admin"):
        return True
    if node_attrs.get("kind") == "segment" and node_attrs.get("zone_type") == "restricted":
        return True
    return bool(node_attrs.get("crown_jewel"))


def impact_weight(node_attrs: Dict[str, Any]) -> float:
    """Business impact contribution of compromising a node (0..1)."""
    if node_attrs.get("kind") == "asset":
        return node_attrs.get("criticality", 1) / 5.0
    if node_attrs.get("kind") == "user":
        return {"standard": 0.2, "privileged": 0.6, "admin": 0.9,
                "domain_admin": 1.0}.get(node_attrs.get("privilege"), 0.2)
    if node_attrs.get("kind") == "segment":
        # Restricted zones have near-crown-jewel impact; external zones are low.
        return {"external": 0.1, "dmz": 0.3, "internal": 0.5,
                "restricted": 0.9}.get(node_attrs.get("zone_type", "internal"), 0.5)
    if node_attrs.get("kind") == "service":
        # High-risk ports (SSH, RDP, SMB, DB) carry higher impact if compromised.
        port = node_attrs.get("port", 0)
        return 0.6 if port in (22, 3389, 445, 5432, 3306, 27017) else 0.3
    if node_attrs.get("kind") == "vendor":
        # Vendor impact directly equals its breach-risk score.
        return float(node_attrs.get("breach_risk", 0.1))
    return 0.3