"""
Module 1 — canonical entity schemas.

Plain dataclasses so the ingestion + graph + analysis core runs with only the
standard library + networkx. The FastAPI layer (Module 3) layers pydantic on top.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class Asset:
    id: str
    hostname: str
    ip: str
    os: str
    environment: str               # prod | staging | dev
    criticality: int               # 1 (low) .. 5 (crown jewel)
    internet_facing: bool = False
    cloud: Optional[str] = None     # aws | azure | gcp | None
    owner_user_id: Optional[str] = None
    kind: str = "asset"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class User:
    id: str
    name: str
    role: str                      # developer | sysadmin | analyst | service ...
    department: str
    privilege: str                 # standard | privileged | admin | domain_admin
    mfa_enabled: bool = False
    kind: str = "user"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Vulnerability:
    id: str                        # CVE id
    cvss: float                    # 0.0 .. 10.0
    exploit_available: bool = False
    description: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    epss: float = 0.0              # exploit prediction score (0..1), set in enrichment
    kind: str = "vuln"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Credential:
    id: str
    cred_type: str                 # password | ssh_key | api_token | kerberos_ticket
    user_id: str
    strength: str = "strong"       # weak | medium | strong
    leaked: bool = False           # set by dark-web correlation (Module 4)
    kind: str = "credential"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Vendor:
    id: str
    name: str
    breach_risk: float = 0.1       # 0..1 likelihood/severity of a vendor compromise
    kind: str = "vendor"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class NetworkSegment:
    id: str
    cidr: str                       # e.g. "10.1.0.0/24"
    vlan_id: Optional[str] = None   # e.g. "vlan-101"
    firewall_policy: str = "standard"  # strict | standard | permissive
    zone_type: str = "internal"     # external | dmz | internal | restricted
    kind: str = "segment"
 
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
 
 
@dataclass
class Service:
    id: str
    asset_id: str
    port: int
    protocol: str = "tcp"          # tcp | udp
    banner: str = ""               # e.g. "OpenSSH/8.9"
    version: str = ""
    kind: str = "service"
 
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
 
 
@dataclass
class ThreatActor:
    id: str
    name: str
    motivation: str = "unknown"    # financial | espionage | hacktivism | unknown
    sophistication: str = "medium" # low | medium | high | nation-state
    country: Optional[str] = None
    kind: str = "threat_actor"
 
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
 
@dataclass
class Relationship:
    source: str
    target: str
    rel: str                       # CAN_ACCESS | EXPLOITS | ESCALATES_TO | HAS_VULN | HAS_CREDENTIAL | DEPENDS_ON
    cost: float = 1.0
    technique: Optional[str] = None   # MITRE ATT&CK technique id
    cve: Optional[str] = None
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Relationship types that represent forward attacker movement (used for pathing).
TRAVERSABLE_RELS = {
    "CAN_ACCESS", 
    "EXPLOITS", 
    "ESCALATES_TO",
    "HAS_CREDENTIAL",
    "CONNECTS_TO"}