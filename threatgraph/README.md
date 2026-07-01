# ThreatGraph

**Graph-based attack-path analysis & threat-intelligence platform.**

ThreatGraph ingests your asset / identity / vulnerability data, builds a property
graph of who-can-reach-what, and finds the attack paths an adversary could use to
get from an internet-facing foothold to your crown jewels — then scores, predicts,
and produces a remediation roadmap. It is a *defensive* (blue-team) tool in the
spirit of BloodHound / attack-graph products: it models how an attacker *could*
move so you can cut the paths first.

The codebase follows the exact four-module architecture in the design diagram.

```
internet  ──►  [M1 ingest]  ──►  [M2 graph + paths]  ──►  [M3 viz/ops]  ──►  [M4 intel/AI]
                                                                                   │
                          SOC dashboard · STIX2 export · remediation roadmap  ◄────┘
                                        (continuous feedback loop)
```

---

## Quick start (no database needed)

```bash
pip install -r requirements.txt

python scripts/generate_data.py     # build a synthetic environment -> data/environment.json
python scripts/run_demo.py          # run all 4 modules end-to-end, write outputs/
uvicorn module3_ops.api:app --reload   # then open http://127.0.0.1:8000
python -m pytest -q                 # verify the engine
```
```
If the venv doesn't exist yet or is broken
Create a fresh one and install:
bashcd ~/Desktop/Threatgraph
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

The core (Modules 1, 2, 4) runs on an in-memory NetworkX graph with **only
`networkx`** installed — no Neo4j, Kafka, or external services required. The API
and the Cytoscape.js dashboard add `fastapi`/`uvicorn`.

## Production stack (Neo4j)

```bash
docker compose up        # Neo4j + the API, graph loaded via Cypher
```

Setting `NEO4J_URI` (see `.env.example`) switches Module 2 from the in-memory
graph to Neo4j automatically; the same analysis engine runs against either.

---

## Repository layout — mapped to the diagram

### Module 1 — Data Collection & Ingestion  (`module1_ingestion/`)
| Diagram component | Where |
|---|---|
| 1. Data collection (ASM, logs, vuln, threat intel, IAM, cloud telemetry) | `collectors.py` — one `collect_*` per feed |
| 2. Ingestion pipeline (Kafka/Logstash/Fluent Bit/Telegraf · streaming, parsing, schema validation) | `pipeline.py` — `run_ingestion()`, schema validation, optional Kafka publish |
| 3. Data processing & enrichment (CVE enrichment · MITRE ATT&CK mapping · identity resolution · dedup) | `enrichment.py` |

### Module 2 — Graph Engine & Analysis  (`module2_graph/`)
| Diagram component | Where |
|---|---|
| 4. Graph construction (Neo4j) — nodes: users/assets/vulns/credentials · edges: CAN_ACCESS, EXPLOITS, ESCALATES_TO | `graph_store.py` (NetworkX) + `neo4j_loader.py` (Cypher) |
| 5. Attack-path analysis — shortest paths · lateral movement · privilege escalation · blast radius · risk scoring | `attack_paths.py` |

### Module 3 — Visualization & Operations  (`module3_ops/`)
| Diagram component | Where |
|---|---|
| 6. Visualization layer (D3.js + Cytoscape.js + React) | `api.py` (FastAPI) + `static/index.html` (interactive Cytoscape.js graph) |
| 7. Alerting & integration (SOC alerts · automated reports · SIEM · TheHive · Grafana) | `alerting.py` |
| 8. Continuous optimization (query tuning · graph indexing · pipeline monitoring · threat-model updates) | `optimization.py` |

### Module 4 — Intelligence & AI  (`module4_intelligence/`)
| Diagram component | Where |
|---|---|
| 9. Zero-trust posture score | `zero_trust.py` |
| 10. Supply-chain attack graph | `supply_chain.py` |
| 11. Insider-threat behavior analytics (UEBA) | `insider_threat.py` |
| 12. Automated SIGMA rule generator | `sigma_generator.py` |
| 13. Dark-web intelligence correlation (OpenCTI) | `darkweb.py` |
| 14. Risk forecast & trend analysis | `risk_forecast.py` |
| 15. AI-powered attack-path prediction | `ai_prediction.py` |
| Outputs: SOC dashboard · STIX2 export · remediation roadmap | `exports.py` + `module3_ops/static` |

---

## The data model

**Nodes:** `Asset`, `User`, `Vulnerability`, `Credential`, `Vendor`
**Edges:** `CAN_ACCESS`, `EXPLOITS`, `ESCALATES_TO`, `HAS_CREDENTIAL`, `HAS_VULN`, `DEPENDS_ON`

Each traversable edge carries a `cost` (attacker effort — derived from CVSS,
credential strength, MFA, misconfig severity) and, where relevant, a MITRE
ATT&CK `technique`. Attack-path finding is shortest-path over the movement
subgraph from **entry points** (internet-facing assets, leaked credentials) to
**crown jewels** (criticality-5 assets, admin/domain-admin identities).

The synthetic generator plants one guaranteed chain so the analytics always have
a clear story:

```
web01 (internet-facing, Log4Shell)
  ──EXPLOITS (CVE-2017-0144 / T1210)──►  app01
        ──CAN_ACCESS──►  db01   (criticality-5 crown jewel)
        ──ESCALATES_TO (T1003)──►  domain-admin (no MFA)
```

---

## API endpoints (Module 3)

`GET /` dashboard · `/api/graph` · `/api/stats` · `/api/attack-paths` ·
`/api/attack-paths/ranked` · `/api/blast-radius/{node}` · `/api/lateral-movement` ·
`/api/privilege-escalation` · `/api/risk/nodes` · `/api/zero-trust` ·
`/api/supply-chain` · `/api/insider-threat` · `/api/sigma` · `/api/darkweb` ·
`/api/forecast` · `/api/remediation` · `/api/alerts` · `/api/report` ·
`/api/export/stix`

---

## What is real vs. what is a seam

This is a working reference implementation, honest about its boundaries:

- **Fully implemented and tested:** the graph model, all five Module-2 analyses,
  zero-trust scoring, supply-chain propagation, insider-threat heuristics, SIGMA
  generation, risk forecasting, path ranking, remediation choke-point analysis,
  STIX 2.1 export, and the API + dashboard. `run_demo.py` exercises all of it.
- **Transparent heuristics, not trained models:** the "AI" ranking (component 15)
  is an interpretable weighted/logistic score over path features, and the UEBA
  signals are rule-based. Both are structured so you can drop in a trained model
  or live telemetry without changing the interfaces. They are labelled as such in
  the code.
- **Integration seams (no-op offline, live when configured):** Kafka ingestion,
  Neo4j backend, SIEM / TheHive / Grafana push, and OpenCTI enrichment all
  activate from environment variables (`.env.example`) and otherwise return a
  clear "not configured" status.
- **Data is synthetic.** Replace the `collect_*` functions in `module1_ingestion/
  collectors.py` with real connectors (Qualys/Nessus, Okta/AD, AWS Config, your
  CTI feed) and the rest of the platform works unchanged.
