"""
Module 1 — Ingestion pipeline (component 2).

In production this is Kafka + Logstash/Fluent Bit/Telegraf doing streaming,
parsing and schema validation. Here the same stages run in-process and emit a
single validated `environment` document. If a Kafka broker is configured
(KAFKA_BROKER env var) records are also published to topics; otherwise the file
sink is used so everything works offline.
"""
from __future__ import annotations

import json
import os
import random
from dataclasses import asdict
from typing import Dict, Any

from module1_ingestion import collectors as col
from module1_ingestion import enrichment as enr
from module1_ingestion.schemas import Asset, User, Credential, Vendor


REQUIRED_FIELDS = {
    "assets": {"id", "hostname", "ip", "os", "criticality"},
    "users": {"id", "name", "role", "privilege"},
    "vulns": {"id", "cvss"},
    "credentials": {"id", "cred_type", "user_id"},
}


def _validate(kind: str, records, required) -> None:
    """Schema validation stage — reject records missing required fields."""
    for r in records:
        missing = required - set(r.keys())
        if missing:
            raise ValueError(f"{kind} record {r.get('id')} missing fields {missing}")


def _maybe_publish_kafka(env: Dict[str, Any]) -> None:
    broker = os.getenv("KAFKA_BROKER")
    if not broker:
        return
    try:
        from kafka import KafkaProducer  # type: ignore # optional dependency
        producer = KafkaProducer(
            bootstrap_servers=broker,
            value_serializer=lambda v: json.dumps(v).encode(),
        )
        for topic, items in env.items():
            for item in items if isinstance(items, list) else [items]:
                producer.send(f"threatgraph.{topic}", item)
        producer.flush()
    except Exception as e:                      # pragma: no cover - infra path
        print(f"[pipeline] Kafka publish skipped: {e}")


def run_ingestion(
        seed: int = 7,
        n_assets: int = 40,
        n_users: int = 25,
        n_vendors: int = 4
        ) -> Dict[str, Any]:
    """Run the full collect -> enrich -> validate flow and return one document."""
    rng = random.Random(seed)

    # ---- Collect (component 1) ---------------------------------------------
    assets = col.collect_asm_assets(rng, n_assets)
    users = col.collect_iam_users(rng, n_users)
    creds = col.collect_credentials(rng, users)
    vendors = col.collect_vendors(rng, n_vendors)
    vuln_findings = col.collect_vuln_data(rng, assets)        # {asset_id: [cve]}
    threat_intel = col.collect_threat_intel(rng)
    cloud = col.collect_cloud_telemetry(rng, assets)
    segments = col.collect_network_segments(rng)
    services  = col.collect_services(rng, assets)
    monitoring_logs = col.collect_monitoring_logs(rng, assets)
    # ---- Enrich (component 3) ----------------------------------------------
    all_cves = sorted({c for cves in vuln_findings.values() for c in cves})
    vulns = enr.enrich_cves(all_cves, threat_intel)

    user_dicts = enr.deduplicate([u.to_dict() for u in users])
    identity_map = enr.resolve_identities(user_dicts)
    vuln_dicts = [v.to_dict() if hasattr(v, "to_dict") else v for v in vulns]
    technique_index = enr.map_mitre_techniques(vuln_dicts) 

    env = {
        "assets": enr.deduplicate([a.to_dict() for a in assets]),
        "users": user_dicts,
        "credentials": enr.deduplicate([c.to_dict() for c in creds]),
        "vulns": enr.deduplicate([v.to_dict() for v in vulns]),
        "vendors": [v.to_dict() for v in vendors],
        "vuln_findings": vuln_findings,
        "cloud_telemetry": cloud,
        "threat_intel": threat_intel,
        "identity_map": identity_map,
        "segments":         [s.to_dict() for s in segments],
        "services":         [s.to_dict() for s in services],
        "monitoring_logs":  monitoring_logs,
        "technique_index":  technique_index,
        
    }
    env["relationships"] = enr.generate_relationships(env, rng=rng)
    # ---- Validate -----------------------------------------------------------
    for kind, req in REQUIRED_FIELDS.items():
        _validate(kind, env[kind], req)

    _maybe_publish_kafka(env)
    return env


def save_environment(env: Dict[str, Any], path: str) -> None:
    with open(path, "w") as f:
        json.dump(env, f, indent=2)


def load_environment(path: str) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)