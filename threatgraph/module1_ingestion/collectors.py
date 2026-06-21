"""
Module 1 — Data collection (component 1).

The diagram lists six feeds: ASM assets, monitoring logs, vuln data, threat
intel, IAM, cloud telemetry. In a real deployment each is a connector to an
external system. Here each `collect_*` function returns synthetic-but-realistic
records so the whole platform runs offline. Swap the bodies for real API calls
(Nessus/Qualys, AWS Config, Okta, etc.) without changing anything downstream.
"""
from __future__ import annotations

import random
from typing import Dict, List, Any

from module1_ingestion.schemas import (
    Asset, User, Vulnerability, Credential, Vendor,
    NetworkSegment, Service, ThreatActor,
)

# A small CVE catalogue used by the synthetic vuln feed + enrichment join.
CVE_CATALOGUE = {
    "CVE-2021-44228": dict(cvss=10.0, exploit=True, desc="Log4Shell RCE",
                           tech=["T1190", "T1059"]),
    "CVE-2014-0160":  dict(cvss=7.5, exploit=True, desc="Heartbleed info leak",
                           tech=["T1190"]),
    "CVE-2017-0144":  dict(cvss=8.1, exploit=True, desc="EternalBlue SMB RCE",
                           tech=["T1210", "T1021"]),
    "CVE-2019-0708":  dict(cvss=9.8, exploit=True, desc="BlueKeep RDP RCE",
                           tech=["T1210", "T1021"]),
    "CVE-2020-1472":  dict(cvss=10.0, exploit=True, desc="Zerologon priv-esc",
                           tech=["T1068", "T1210"]),
    "CVE-2018-13379": dict(cvss=9.8, exploit=True, desc="Fortinet path traversal",
                           tech=["T1190"]),
    "CVE-2022-22965": dict(cvss=9.8, exploit=True, desc="Spring4Shell RCE",
                           tech=["T1190"]),
    "CVE-2016-5195":  dict(cvss=7.8, exploit=True, desc="Dirty COW local priv-esc",
                           tech=["T1068"]),
    "CVE-2021-34527": dict(cvss=8.8, exploit=True, desc="PrintNightmare priv-esc",
                           tech=["T1068"]),
    "CVE-2023-23397": dict(cvss=9.8, exploit=False, desc="Outlook NTLM leak",
                           tech=["T1187"]),
}

OS_CHOICES = ["Ubuntu 22.04", "Windows Server 2019", "RHEL 8", "Windows 10",
              "Amazon Linux 2"]
DEPARTMENTS = ["Engineering", "Finance", "IT", "Sales", "HR", "Security"]
ROLES = ["developer", "sysadmin", "analyst", "service", "manager"]

_COMMON_SERVICES = [
    (22,    "tcp", "OpenSSH",       "8.9"),
    (80,    "tcp", "nginx",         "1.22"),
    (443,   "tcp", "nginx",         "1.22"),
    (3389,  "tcp", "MS-RDP",        "10.0"),
    (5432,  "tcp", "PostgreSQL",    "14.5"),
    (8080,  "tcp", "Apache Tomcat", "9.0"),
    (445,   "tcp", "SMB",           "3.0"),
    (3306,  "tcp", "MySQL",         "8.0"),
    (6379,  "tcp", "Redis",         "7.0"),
    (27017, "tcp", "MongoDB",       "6.0"),
]
def collect_asm_assets(rng: random.Random, n: int) -> List[Asset]:
    """Attack Surface Management feed -> Asset inventory."""
    assets = []
    for i in range(n):
        internet = rng.random() < 0.18
        env = rng.choice(["prod", "prod", "staging", "dev"])
        crit = rng.choice([1, 2, 2, 3, 3, 4]) if env != "prod" else rng.choice([2, 3, 3, 4, 5])
        assets.append(Asset(
            id=f"asset-{i:03d}",
            hostname=f"host{i:03d}.corp.local",
            ip=f"10.{rng.randint(0,3)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
            os=rng.choice(OS_CHOICES),
            environment=env,
            criticality=crit,
            internet_facing=internet,
            cloud=rng.choice([None, None, "aws", "azure"]),
        ))
    return assets


def collect_iam_users(rng: random.Random, n: int) -> List[User]:
    """IAM feed -> identities."""
    users = []
    for i in range(n):
        priv = rng.choice(["standard", "standard", "standard", "privileged",
                           "admin"])
        users.append(User(
            id=f"user-{i:03d}",
            name=f"user{i:03d}",
            role=rng.choice(ROLES),
            department=rng.choice(DEPARTMENTS),
            privilege=priv,
            mfa_enabled=rng.random() < 0.6,
        ))
    return users


def collect_vuln_data(rng: random.Random, assets: List[Asset]) -> Dict[str, List[str]]:
    """Vulnerability scanner feed -> {asset_id: [cve, ...]}."""
    findings: Dict[str, List[str]] = {}
    cves = list(CVE_CATALOGUE)
    for a in assets:
        # internet-facing / prod hosts carry more findings
        base = 2 if a.internet_facing else 1
        k = rng.randint(0, base + (1 if a.environment == "prod" else 0))
        if k:
            findings[a.id] = rng.sample(cves, k)
    return findings


def collect_credentials(rng: random.Random, users: List[User]) -> List[Credential]:
    creds = []
    for u in users:
        for j in range(rng.choice([1, 1, 2])):
            ctype = rng.choice(["password", "password", "ssh_key", "api_token"])
            strength = rng.choice(["weak", "medium", "strong", "strong"])
            creds.append(Credential(
                id=f"cred-{u.id}-{j}",
                cred_type=ctype,
                user_id=u.id,
                strength=strength,
            ))
    return creds


def collect_threat_intel(rng: random.Random) -> Dict[str, Any]:
    """Threat-intel feed -> which CVEs are being actively exploited in the wild."""
    actively_exploited = [c for c, v in CVE_CATALOGUE.items()
                          if v["exploit"] and rng.random() < 0.8]
    return {"actively_exploited": actively_exploited}


def collect_cloud_telemetry(rng: random.Random, assets: List[Asset]) -> Dict[str, Any]:
    """Cloud telemetry -> public exposure / open ports per cloud asset."""
    telem = {}
    for a in assets:
        if a.cloud:
            telem[a.id] = dict(
                public_ip=a.internet_facing,
                open_ports=rng.sample([22, 80, 443, 3389, 445, 5432, 8080],
                                      rng.randint(1, 3)),
            )
    return telem


def collect_vendors(rng: random.Random, n: int) -> List[Vendor]:
    names = ["AcmeSoft", "NimbusCloud", "PipelineCI", "AuthGate", "DataVault",
             "EdgeProxy", "MetricsHub", "LogStream"]
    return [Vendor(id=f"vendor-{i:02d}", name=rng.choice(names),
                   breach_risk=round(rng.uniform(0.05, 0.5), 2))
            for i in range(n)]

def collect_monitoring_logs(
    rng: random.Random, assets: List[Asset]
) -> List[Dict[str, Any]]:
    """Team 2 Monitoring / SIEM feed → security events and configuration changes.
      "Team 2 continuously streams monitoring and configuration
    changes." In production this connects to Elastic / Splunk / Azure Sentinel.
    The synthetic version produces plausible auth failures, port scans, config
    changes, privilege-use events, and lateral-attempt indicators.
    """
    event_types = [
        "auth_failure", "port_scan", "config_change",
        "privilege_use", "lateral_attempt", "data_exfil_suspect",
    ]
    severity_pool = ["low", "low", "medium", "medium", "high"]
    events: List[Dict[str, Any]] = []
    for i, asset in enumerate(assets):
        n_events = rng.randint(0, 3)
        for j in range(n_events):
            events.append({
                "id": f"event-{i:03d}-{j}",
                "asset_id": asset.id,
                "type": rng.choice(event_types),
                "severity": rng.choice(severity_pool),
                "timestamp": (
                    f"2024-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"
                    f"T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:00Z"
                ),
                "detail": f"Security event on {asset.hostname}",
                "source_ip": (
                    f"{rng.randint(1,254)}.{rng.randint(0,255)}"
                    f".{rng.randint(0,255)}.{rng.randint(1,254)}"
                    if rng.random() < 0.4 else None
                ),
            })
    return events
 
 
def collect_network_segments(
    rng: random.Random, n: int = 6
) -> List[NetworkSegment]:
    """Team 1 Recon — network segmentation / VLAN inventory.
    NetworkSegment node  ·  properties: cidr, vlan_id,
    firewall_policy, zone_type  ·  source: Team 1 Recon.
    Produces a realistic external → DMZ → internal → restricted zone stack.
    """
    zone_templates = [
        ("external",   "permissive"),
        ("dmz",        "standard"),
        ("internal",   "standard"),
        ("internal",   "strict"),
        ("restricted", "strict"),
        ("restricted", "strict"),
    ]
    segments: List[NetworkSegment] = []
    for i in range(n):
        zone, policy = zone_templates[i % len(zone_templates)]
        segments.append(NetworkSegment(
            id=f"seg-{i:02d}",
            cidr=f"10.{i}.0.0/24",
            vlan_id=f"vlan-{100 + i}",
            firewall_policy=policy,
            zone_type=zone,
        ))
    return segments
 
 
def collect_services(
    rng: random.Random, assets: List[Asset]
) -> List[Service]:
    """Team 1 Nmap / service-scan feed → exposed services per asset.
    Service node  ·  properties: port, protocol, banner, version
    ·  source: Team 1 Nmap.
    Internet-facing assets expose more services; internal hosts fewer.
    """
    services: List[Service] = []
    svc_id = 0
    for asset in assets:
        max_svc = 4 if asset.internet_facing else 2
        n_svc = rng.randint(1, max_svc)
        picks = rng.sample(_COMMON_SERVICES, min(n_svc, len(_COMMON_SERVICES)))
        for port, proto, name, version in picks:
            services.append(Service(
                id=f"svc-{svc_id:04d}",
                asset_id=asset.id,
                port=port,
                protocol=proto,
                banner=f"{name}/{version}",
                version=version,
            ))
            svc_id += 1
    return services