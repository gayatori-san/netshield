# NetShield — Architecture & Implementation Plan

**Project:** NetShield — Network Attack Detection System
**Context:** Open Elective (Cyber Security & Laws) mini-project
**Status:** Phase 2 deliverable — architecture contract, review before implementation
**Date:** 2026-10-22

---

## 1. Design Goals & Non-Goals

### Goals
1. **Modular** — every stage (capture → features → detection → scoring → storage → API → UI) is an independently testable unit with a documented contract.
2. **Honest** — the system reports *observable evidence*, never "attack confirmed". Severity is derived by a visible, auditable formula. Insufficient evidence is stated, not hidden.
3. **Safe by default** — PCAP/synthetic workflow is the primary path; live capture requires explicit interface selection + privileges; response actions are opt-in, lab-scoped, and never touch a real firewall unless explicitly unlocked.
4. **Explainable** — a student can open any file and understand it. No magic, no framework magic, no ML.

### Non-Goals (explicitly out of scope, stated so we don't drift)
- Payload inspection / IDS signature matching (no Suricata/Snort rules).
- Machine learning classification.
- Distributed processing, message brokers, cloud databases.
- Multi-tenant auth (single-analyst local tool; no login system).
- Attack traffic generation of any kind (we never *send* malicious traffic — the synthetic generator emits **benign-shaped** traffic only, used to drive the detectors).

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          AUTHORIZED INPUT SOURCES                               │
│                                                                                 │
│   ┌──────────────┐   ┌──────────────────┐   ┌───────────────────────────────┐   │
│   │ PCAP FILE    │   │ SYNTHETIC FIXTURE│   │ LIVE CAPTURE (opt-in, priv.) │   │
│   │ (.pcap/.cap) │   │ (tools/generate)  │   │ iface chosen by analyst      │   │
│   └──────┬───────┘   └────────┬─────────┘   └──────────────┬────────────────┘   │
└──────────┼────────────────────┼────────────────────────────┼────────────────────┘
           │                    │                            │
           └──────────────┬─────┴────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ① CAPTURE & PARSING            netshield/capture/                              │
│                                                                                 │
│   pcap.py  ── rdpcap() → iterates packets, tolerates malformed/empty files      │
│   live.py  ── scapy AsyncSniffer thread; privilege precheck; hard stop          │
│   sources.py ── uniform iterator yielding PacketRecord dataclasses             │
│                                                                                 │
│   Emits: PacketRecord(ts, src, dst, sport, dport, proto, flags, size, source)   │
│   Drops (counts, never crashes): truncated frames, non-IP, undecodable L4        │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ② PROCESSING PIPELINE        netshield/pipeline.py                             │
│                                                                                 │
│   PacketSource (queue.Queue)  →  ProcessingPipeline (single worker thread)      │
│   Producer/consumer decoupling so capture speed never starves the detectors    │
│   Bounded queue → backpressure, not unbounded memory growth                    │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ③ FEATURE EXTRACTION         netshield/features/                               │
│                                                                                 │
│   extract.py     — per-packet → FlowKey (5-tuple) → FlowState (counters)        │
│   aggregation.py — SlidingWindow: per-source distinct dst ports/hosts           │
│                    per-(src,dst) conn attempts, sensitive-port hits            │
│                    Per-second rate buckets → rolling baseline (EWMA)            │
│                    Protocol counters, top-src/top-dst, TCP state tracking       │
│                                                                                 │
│   Emits: FeatureSnapshot (stats) + calls detectors' update() per packet        │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ④ DETECTION ENGINE           netshield/detectors/                              │
│                                                                                 │
│   base.py        — Detector protocol: update(pkt) → flush(now) → list[Alert]    │
│   port_scan.py  — distinct dst ports/hosts per source within window            │
│   suspicious.py  — repeated conn attempts, sensitive ports, rate anomaly        │
│   spike.py      — absolute packet-rate + rolling-baseline deviation            │
│   dedup.py      — fingerprint-based suppression (no duplicate alerts)          │
│                                                                                 │
│   Emits: raw Alert candidates (rule_id, evidence, window, timestamps)           │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ⑤ THREAT SCORING             netshield/scoring/                                │
│                                                                                 │
│   scorer.py   score = rule_base + volume_bonus + frequency_bonus  (clamp 0..100)│
│   severity.py low (<34) / medium (34–66) / high (≥67); evidence gate caps at    │
│               medium when evidence_sufficient == False                          │
│                                                                                 │
│   Emits: Alert(severity, score, reasons[], evidence{}, evidence_sufficient)     │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ⑥ INCIDENT STORE             netshield/storage/                                │
│                                                                                 │
│   schema.sql   incidents, packets, traffic_buckets, response_actions, settings │
│   db.py        connection mgmt (WAL), schema init, migrations                   │
│   repositories.py — incident CRUD, filters, ack/resolve, CSV export, retention  │
│                                                                                 │
│   Dedup enforced by UNIQUE(fingerprint) + INSERT OR IGNORE                     │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ⑦ FLASK API                  netshield/api/                                    │
│                                                                                 │
│   app.py       app factory, error handlers, JSON envelope, static serving      │
│   routes.py    /api/overview /api/traffic /api/alerts /api/incidents          │
│                /api/alerts/<id>/ack|resolve /api/settings /api/capture/*      │
│                /api/response /api/export/incidents.csv                         │
│   validation.py — query-param parsing, bounds, 400 responses                   │
│                                                                                 │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ⑧ LIVE WEB DASHBOARD         dashboard/                                       │
│                                                                                 │
│   index.html  Overview │ Live Traffic │ Alerts │ Incidents │ Settings          │
│   css/        blue+white shell, dark navy monitoring surface                  │
│   js/         api.js (fetch wrapper), views/*.js, charts.js (Chart.js)         │
│                                                                                 │
│   Live updates: 2-second polling (setInterval + fetch) — no Socket.IO          │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ⑨ ANALYST WORKFLOW (loop back to ⑥)                                           │
│                                                                                 │
│   Review alert → inspect evidence + timeline → Acknowledge → Investigate →      │
│   Resolve (with analyst notes)  ──►  status persisted  ──►  dashboard reflects  │
│   Optional safe response action (lab-scoped, opt-in)                            │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Data-flow contract (what crosses each boundary)

| Boundary | Payload | Direction |
|---|---|---|
| capture → pipeline | `PacketRecord` dataclass | producer → queue |
| pipeline → features | `PacketRecord` | in-process call |
| features → detectors | `PacketRecord` + `FeatureSnapshot` | in-process call |
| detectors → scoring | `AlertCandidate` | list return |
| scoring → storage | `Alert` (scored) | in-process call |
| storage → API | `dict` rows (JSON-safe) | DB read |
| API → dashboard | JSON over HTTP | polling fetch |

---

## 3. Directory Tree

```
netshield/
├── netshield/                     # importable package (pip install -e .)
│   ├── __init__.py                # version, package exports
│   ├── models.py                  # PacketRecord, AlertCandidate, Alert, FeatureSnapshot
│   ├── config/
│   │   ├── __init__.py
│   │   ├── settings.py            # loads thresholds.yaml + env, dataclass Config
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── pcap.py                # PCAP reading (PcapSource)
│   │   ├── live.py                # LiveSource (scapy AsyncSniffer, privilege checks)
│   │   └── sources.py             # PacketSource protocol, Normalizer → PacketRecord
│   ├── features/
│   │   ├── __init__.py
│   │   ├── extract.py             # FlowKey, FlowState, FlowExtractor
│   │   └── aggregation.py         # SlidingWindow, EWMA baseline, counters
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── base.py                # Detector protocol + registry
│   │   ├── port_scan.py
│   │   ├── suspicious.py
│   │   ├── spike.py
│   │   └── dedup.py               # fingerprint + suppression window
│   ├── scoring/
│   │   ├── __init__.py
│   │   ├── scorer.py              # transparent additive score
│   │   └── severity.py            # severity bands + evidence gate
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── db.py                  # connection, schema init, WAL
│   │   ├── schema.sql
│   │   └── repositories.py        # incident/packet/bucket/response CRUD
│   ├── pipeline.py                # queue + worker + detector fan-out + flush loop
│   ├── api/
│   │   ├── __init__.py
│   │   ├── app.py                 # create_app()
│   │   ├── routes.py              # blueprint with all /api routes
│   │   ├── validation.py          # param parsing / bounds
│   │   └── errors.py              # JSON error envelope + handlers
│   └── responses.py               # safe response: simulated + lab-gated real
├── dashboard/
│   ├── index.html
│   ├── css/styles.css
│   └── js/{api.js, charts.js, overview.js, traffic.js, alerts.js, incidents.js, settings.js}
├── tests/
│   ├── conftest.py                # temp-db fixture, config fixture
│   ├── unit/
│   │   ├── test_capture_pcap.py
│   │   ├── test_features.py
│   │   ├── test_detector_port_scan.py
│   │   ├── test_detector_suspicious.py
│   │   ├── test_detector_spike.py
│   │   ├── test_dedup.py
│   │   ├── test_scoring.py
│   │   ├── test_storage.py
│   │   ├── test_api.py
│   │   ├── test_dashboard_filters.py
│   │   └── test_responses.py
│   └── fixtures/                  # generated + committed .pcap files
├── tools/
│   ├── generate_fixtures.py       # deterministic synthetic traffic generator
│   └── demo.py                    # scripted demonstration run
├── config/
│   ├── thresholds.yaml            # all tunable detection thresholds
├── data/                          # sqlite db + pcaps (gitignored)
├── docs/
│   ├── ARCHITECTURE.md            # this document
│   ├── THREAT_MODEL.md            # Phase 10
│   ├── DEMO_SCRIPT.md             # Phase 10
│   └── VIVA_QUESTIONS.md          # Phase 10
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
└── pyproject.toml
```

---

## 4. Module Contracts (the API each component promises)

### 4.1 `models.py`
```python
@dataclass(frozen=True, slots=True)
class PacketRecord:
    timestamp: float          # epoch seconds (UTC)
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str             # TCP | UDP | ICMP | OTHER
    flags: str | None         # TCP flags, e.g. "SA"
    tcp_state: str | None     # SYN | SYN_ACK | ACK | RST | FIN | None
    size: int                 # bytes on wire
    source: str               # "pcap:<path>" | "live:<iface>" | "synthetic:<name>"
```

```python
@dataclass
class AlertCandidate:
    rule_id: str              # e.g. "PORT_SCAN"
    title: str
    src_ip: str | None
    dst_ip: str | None
    window_start: float
    window_end: float
    evidence: dict            # rule-specific, JSON-serialisable
    facts: dict               # counts/thresholds used to reach the decision
```

```python
@dataclass
class Alert:
    id: str
    fingerprint: str
    rule_id: str
    title: str
    severity: str             # low | medium | high
    score: int                # 0..100
    reasons: list[str]        # human-readable justification
    evidence: dict
    facts: dict
    evidence_sufficient: bool
    src_ip: str | None
    dst_ip: str | None
    detected_at: float
    window_start: float
    window_end: float
    status: str               # new | acknowledged | resolved
    analyst_notes: str | None
```

### 4.2 Detector protocol (`detectors/base.py`)
```python
class Detector(Protocol):
    rule_id: str
    def update(self, pkt: PacketRecord, snap: FeatureSnapshot) -> None: ...
    def flush(self, now: float) -> list[AlertCandidate]: ...
```
Deterministic: same packet sequence → same candidates. No I/O, no clock reads other than the `now` argument. This is what makes unit testing honest.

### 4.3 Capture source protocol (`capture/sources.py`)
```python
class PacketSource(Protocol):
    def start(self) -> None: ...
    def packets(self) -> Iterator[PacketRecord]: ...
    def stop(self) -> None: ...
    def status(self) -> CaptureStatus: ...
```

### 4.4 Storage (`storage/repositories.py`)
```python
class IncidentRepository:
    def insert_alert(self, alert: Alert) -> bool          # False if duplicate fingerprint
    def list_incidents(self, **filters) -> tuple[list[dict], int]
    def get_incident(self, incident_id: str) -> dict | None
    def acknowledge(self, incident_id: str, note: str | None) -> dict | None
    def resolve(self, incident_id: str, note: str | None) -> dict | None
    def add_packet(self, pkt: PacketRecord) -> None
    def traffic_series(self, bucket_seconds: int) -> list[dict]
    def protocol_counts(self) -> dict[str, int]
    def top_endpoints(self, n: int) -> dict[str, list[dict]]
    def export_csv(self, **filters) -> str
    def prune(self, retention_days: int) -> int
```

### 4.5 API routes
| Method | Path | Purpose | Notes |
|---|---|---|---|
| GET | `/api/health` | liveness | no auth, no data |
| GET | `/api/overview` | monitoring status, counters, severity counts, top endpoints | single aggregated payload |
| GET | `/api/traffic` | recent packet/flow list | `?page=&per_page=&src=&dst=&proto=&q=` |
| GET | `/api/alerts` | alerts list | `?severity=&rule=&status=&from=&to=&q=` |
| GET | `/api/alerts/<id>` | alert detail + evidence + timeline | |
| POST | `/api/alerts/<id>/ack` | acknowledge | body: `{note?}` |
| POST | `/api/alerts/<id>/resolve` | resolve | body: `{note?}` |
| GET | `/api/incidents` | history search | `?q=&status=&severity=&page=` |
| GET | `/api/incidents/<id>` | detail | |
| GET | `/api/export/incidents.csv` | CSV export | honours same filters |
| GET | `/api/settings` | current thresholds + capture status | |
| PUT | `/api/settings` | update thresholds | validated, persisted |
| POST | `/api/capture/start` | start PCAP or live analysis | body: `{mode, path?, iface?}` |
| POST | `/api/capture/stop` | stop monitoring | idempotent |
| GET | `/api/capture/status` | capture state + counters | |
| POST | `/api/response` | safe response action | lab-gated, simulated by default |
| GET | `/api/response` | response action log | |

All responses use one envelope:
```json
{ "ok": true, "data": {...}, "meta": {...} }
{ "ok": false, "error": { "code": "invalid_parameter", "message": "...", "detail": {...} } }
```

---

## 5. Feature Checklist (mapped to implementation phases)

### Capture & parsing
- [x] PCAP reader with malformed-frame tolerance (scapy `rdpcap` + per-packet try/except)
- [x] Empty PCAP handled gracefully (0 packets, no crash, clear status)
- [x] Non-IP / undecodable packets counted as `skipped`, not fatal
- [x] Live capture with explicit interface, privilege precheck, hard stop
- [x] Clear capture status: `idle | reading_pcap | live | error | stopped`
- [x] Permission-denied surfaced with actionable remedy (`setcap` / `sudo` instructions)
- [x] Source label on every packet (`pcap:` / `live:` / `synthetic:`)

### Feature extraction
- [x] 5-tuple flow key; per-flow packet/byte counters
- [x] TCP state classification per packet (SYN, SYN-ACK, ACK, RST, FIN)
- [x] Half-open count (SYN without matching SYN-ACK) — labelled an *inference*, not proof
- [x] Sliding window per source: distinct destination ports, distinct destination hosts
- [x] Connection-attempt counter per (src, dst_port)
- [x] Sensitive-port hit counter
- [x] Per-second packet/byte rate buckets + EWMA rolling baseline
- [x] Protocol distribution counters
- [x] Top-N source and destination address tables
- [x] Windowed eviction (bounded memory) with configurable window size

### Detection rules
- [x] **R1 Port scan (ports):** ≥ `distinct_port_threshold` distinct dst ports from one src to one dst within `port_scan_window` → alert
- [x] **R2 Port scan (hosts):** ≥ `distinct_host_threshold` distinct dst hosts from one src within window → alert
- [x] **R3 Repeated connection attempts:** ≥ `repeat_attempt_threshold` conn attempts to same (src,dst_port) within window
- [x] **R4 Sensitive port access:** connection to a configured sensitive port (22, 23, 3389, 3306, 5432, 445, …) → alert
- [x] **R5 Unusual connection rate:** source's connection rate exceeds `conn_rate_threshold` (per window) **and** is ≥ `conn_rate_multiplier`× the source's own baseline
- [x] **R6 Absolute traffic spike:** packet rate in second bucket ≥ `spike_absolute_pps` → alert
- [x] **R7 Baseline deviation spike:** packet rate ≥ `spike_baseline_ratio`× EWMA baseline **and** ≥ `spike_min_pps` → alert
- [x] **R8 Half-open pattern:** ≥ `half_open_threshold` SYN-without-SYN-ACK from one source → alert (explicitly labelled *inferred*)
- [x] All thresholds configurable via `config/thresholds.yaml`
- [x] Isolated single connection never flagged
- [x] Duplicate alert suppression via fingerprint + suppression window

### Threat scoring
- [x] `score = clamp(rule_base + volume_bonus + frequency_bonus, 0, 100)`
- [x] `volume_bonus = min(30, floor(volume_ratio × 30))`
- [x] `frequency_bonus = min(20, (recurrence_count − 1) × 5)`
- [x] Severity bands: low < 34 ≤ medium < 67 ≤ high
- [x] Evidence gate: `evidence_sufficient == False` → severity capped at **medium**
- [x] `reasons[]` explains the score in plain language
- [x] `facts{}` records exact threshold vs observed values
- [x] No confidence percentages, no accuracy claims

### Storage
- [x] SQLite schema: `incidents`, `packets`, `traffic_buckets`, `response_actions`, `settings`
- [x] `UNIQUE(fingerprint)` + `INSERT OR IGNORE` → duplicate suppression
- [x] WAL mode for concurrent read (API) + write (pipeline)
- [x] Indexes: `incidents(detected_at)`, `incidents(severity)`, `incidents(status)`, `packets(ts)`
- [x] Packet payload is **not** stored — metadata only (privacy)
- [x] Retention pruning (delete packets older than N days; incidents retained)
- [x] CSV export with formula-injection guard (prefix `'` on leading `=`,`+`,`-`,`@`)

### API
- [x] Single JSON envelope for success and error
- [x] Input validation with 400 + field-level details
- [x] 404 for missing incident; 409 for invalid state transition
- [x] Pagination with sane `per_page` bounds (max 500)
- [x] Filters: severity, rule, status, date range, free-text
- [x] Endpoints listed in §4.5

### Dashboard
- [x] Blue/white application shell, dark navy monitoring surface
- [x] Overview: status, packets processed, traffic rate, severity counts, recent incidents, traffic-over-time, protocol pie, top src/dst
- [x] Live traffic: recent flows, filter + pagination, no payload exposed
- [x] Alerts: severity badges, rule, evidence, timeline, ack/resolve, filters
- [x] Incidents: search, detail, status, notes, CSV export
- [x] Settings: thresholds, interface selection, PCAP mode, retention, safe-response config
- [x] 2-second polling for live panels
- [x] Explicit "DEMONSTRATION DATA" badge on synthetic-sourced data
- [x] Empty states that state *why* there is no data (never fake numbers)

### Safety
- [x] Live capture requires explicit iface selection in Settings
- [x] `safe_response.enabled` default **false**
- [x] Real firewall path requires root **and** `allow_firewall_changes: true` **and** target inside lab CIDR allow-list **and** explicit confirm
- [x] Default simulated response = in-memory block list affecting *displayed* traffic only
- [x] No attack-traffic generation anywhere in the codebase
- [x] Explicit stop-monitoring action, always available
- [x] README + threat model state IP-blocking limitations (NAT/CGNAT, spoofing, IPv6 privacy)

### Testing
- [x] Valid + malformed packet inputs
- [x] Port-scan thresholds (below / at / above)
- [x] Normal traffic vs spike (false-positive regression)
- [x] Repeated connection patterns
- [x] Threat scoring bands + evidence gate
- [x] SQLite persistence + dedup + retention
- [x] API validation and error handling
- [x] Dashboard filtering
- [x] Duplicate alert suppression
- [x] Empty PCAP + missing capture permissions
- [x] No network-touching tests — synthetic fixtures only

---

## 6. Detection Rule Specifications (initial thresholds)

All values live in `config/thresholds.yaml` and are editable at runtime via Settings.

```yaml
detection:
  port_scan:
    window_seconds: 60
    distinct_port_threshold: 15     # R1 distinct dst ports, same dst
    distinct_host_threshold: 20     # R2 distinct dst hosts
    min_packets_per_target: 10      # guards against trivial/truncated captures
  suspicious:
    window_seconds: 60
    repeat_attempt_threshold: 15    # R3 attempts to same (src, dst_port)
    conn_rate_threshold: 60         # R5 connections per window
    conn_rate_multiplier: 3.0       # × source's own baseline
    half_open_threshold: 20         # R8 SYN w/o SYN-ACK
    sensitive_ports: [22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200]
  spike:
    window_seconds: 10
    spike_absolute_pps: 500         # R6 packets/sec in bucket
    spike_baseline_ratio: 3.0       # R7 multiple of EWMA baseline
    spike_min_pps: 100              # floor so a low baseline can't trigger R7
    baseline_alpha: 0.3             # EWMA smoothing factor
  dedup:
    suppression_seconds: 300        # same fingerprint within window → suppressed
```

**Initial threshold rationale (defend this in the viva):**
- `distinct_port_threshold: 15` — typical admin services + a few apps sit below 15 distinct ports per host per minute; service-discovery tools and scanners exceed it. Deliberately conservative to favour low false positives over recall.
- `spike_absolute_pps: 500` — one full-speed TCP handshake storm on a laptop exceeds this; ordinary browsing does not.
- `spike_min_pps: 100` — a ratio alone is meaningless when the baseline is 2 pps (2×3 = 6 pps would be "a spike"). The floor prevents that class of false positive.
- `half_open_threshold: 20` — SYN-without-SYN-ACK is an *inference* (asymmetric capture, dropped packets, firewall drops all look identical), so the bar is set high and the alert is labelled accordingly.

---

## 7. Threat Scoring Model

```
score = clamp( rule_base + volume_bonus + frequency_bonus, 0, 100 )

rule_base:      PORT_SCAN_PORTS=40  PORT_SCAN_HOSTS=40
                REPEATED_CONNECTIONS=30  SENSITIVE_PORT=25
                CONN_RATE_ANOMALY=30  TRAFFIC_SPIKE=35
                BASELINE_DEVIATION=45  HALF_OPEN_PATTERN=35

volume_bonus:   min(30, floor(observed/required × 30))
                e.g. 30 ports against a threshold of 15 → ratio 2.0 → +30
frequency_bonus:min(20, (occurrences_in_window − 1) × 5)

severity:       score < 34              → low
                34 ≤ score < 67         → medium
                score ≥ 67              → high

evidence gate:  if evidence_sufficient is False → severity = min(severity, medium)
```

**Evidence sufficiency rules**
| Rule | Sufficient when |
|---|---|
| PORT_SCAN_PORTS | distinct ports ≥ threshold AND packets to target ≥ `min_packets_per_target` |
| PORT_SCAN_HOSTS | distinct hosts ≥ threshold AND packets ≥ threshold |
| REPEATED_CONNECTIONS | attempts ≥ threshold AND attempts spread over ≥ 2 distinct source ports (else it's one busy app) |
| SENSITIVE_PORT | single connection → **insufficient** by itself (needs corroboration) unless the source is internal + port is admin-exposed |
| CONN_RATE_ANOMALY | rate ≥ threshold AND ≥ multiplier×baseline AND baseline has ≥ 3 samples (a baseline from 1 sample is not a baseline) |
| TRAFFIC_SPIKE | absolute rate exceeded — sufficient as a *rate* observation; the alert title must not say "DDoS" |
| BASELINE_DEVIATION | ratio + floor both met AND baseline samples ≥ 3 |
| HALF_OPEN_PATTERN | **insufficient** for attack attribution by construction (asymmetric capture) — capped at medium, labelled as inference |

**Example reasons[] strings** (auto-generated, so the UI never needs hand-written text):
- `"Distinct destination ports 30 ≥ threshold 15 within 60s window"`
- `"Volume ratio 2.0× threshold contributed +30 score"`
- `"Baseline sample count 3 meets minimum for rate comparison"`
- `"Evidence insufficient: SYN/SYN-ACK asymmetry may be capture loss, not attack"`

---

## 8. SQLite Schema (draft — implemented in Phase 6)

```sql
CREATE TABLE IF NOT EXISTS incidents (
  id                 TEXT PRIMARY KEY,
  fingerprint        TEXT NOT NULL UNIQUE,
  rule_id            TEXT NOT NULL,
  title              TEXT NOT NULL,
  severity           TEXT NOT NULL CHECK (severity IN ('low','medium','high')),
  score              INTEGER NOT NULL,
  reasons_json       TEXT NOT NULL,
  evidence_json      TEXT NOT NULL,
  facts_json         TEXT NOT NULL,
  evidence_sufficient INTEGER NOT NULL,
  src_ip             TEXT,
  dst_ip             TEXT,
  detected_at        REAL NOT NULL,
  window_start       REAL NOT NULL,
  window_end         REAL NOT NULL,
  status             TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','acknowledged','resolved')),
  analyst_notes      TEXT,
  data_origin        TEXT NOT NULL DEFAULT 'real',   -- real | demonstration
  created_at         REAL NOT NULL,
  updated_at         REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inc_detected ON incidents(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_inc_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_inc_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_inc_rule     ON incidents(rule_id);

CREATE TABLE IF NOT EXISTS packets (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        REAL NOT NULL,
  src_ip    TEXT NOT NULL,
  dst_ip    TEXT NOT NULL,
  src_port  INTEGER,
  dst_port  INTEGER,
  protocol  TEXT NOT NULL,
  flags     TEXT,
  tcp_state TEXT,
  size      INTEGER NOT NULL,
  origin    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pkt_ts ON packets(ts DESC);

CREATE TABLE IF NOT EXISTS traffic_buckets (
  bucket_ts  INTEGER PRIMARY KEY,   -- epoch seconds
  packets    INTEGER NOT NULL,
  bytes      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS response_actions (
  id         TEXT PRIMARY KEY,
  incident_id TEXT,
  target_ip  TEXT NOT NULL,
  action     TEXT NOT NULL,        -- simulated_block | firewall_insert
  applied    INTEGER NOT NULL,
  reason     TEXT,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
```

**Privacy decision:** the `packets` table stores metadata only — no payload bytes, no DNS query names beyond the standard port, no MAC addresses. This is both a privacy control and a storage control (payload capture of real traffic is where a monitoring tool most often becomes a liability).

---

## 9. Implementation Plan (Phases 3–10) with Exit Criteria

| Phase | Deliverable | Exit criteria (verifiable) |
|---|---|---|
| **3** | venv, `requirements.txt` (pinned), `.env.example`, `config/thresholds.yaml`, `pyproject.toml`, `.gitignore` | `pip install -r requirements.txt` succeeds on Python 3.14; `thresholds.yaml` loads into a `Config` dataclass; `.env.example` documents every env var |
| **4** | `capture/pcap.py`, `capture/sources.py`, `features/extract.py`, `features/aggregation.py` | Fixture generator produces 4 PCAPs (normal, port-scan, spike, malformed+empty); parser tests pass incl. malformed and empty inputs; feature tests assert exact counters |
| **5** | `detectors/*` + `scoring/*` (scoring scaffold) | Each rule has its own test file asserting **below threshold → no alert**, **at/above → alert**, **false-positive case → no alert** |
| **6** | `storage/db.py`, `schema.sql`, `repositories.py`; full scorer wired | Persistence tests pass; duplicate insert returns False; severity bands and evidence gate asserted; CSV export opens in a spreadsheet |
| **7** | `api/app.py`, `routes.py`, `validation.py`, `errors.py` | Every endpoint returns the envelope; invalid params → 400 with field detail; missing incident → 404; API test suite passes |
| **8** | `dashboard/*` wired to real API | Every panel renders from an API response; **no hardcoded sample data in the monitoring surface**; empty states explain why empty |
| **9** | `capture/live.py`, `responses.py`, capture control endpoints, Settings UI | Live capture starts/stops on an explicit iface; permission denial produces the actionable error; simulated response blocks *displayed* traffic; real firewall path refuses non-lab targets |
| **10** | Integration, full `pytest` run, README, THREAT_MODEL, DEMO_SCRIPT, VIVA_QUESTIONS, screenshots | `pytest` green with a real report; documented known limitations; screenshots of the running dashboard |

**Working rules for every phase**
1. Write the module → write its test → run the test → **paste the actual output**.
2. Never claim a passing test that was not executed.
3. Report known limitations as they are discovered, not at the end.
4. Stop after each phase for your review.

---

## 10. Safety & Authorization Model

| Control | Implementation | Where enforced |
|---|---|---|
| No unauthorized capture | Live capture only starts with an explicitly selected interface; the UI states the operator asserts authorization | `api/routes.py` `/api/capture/start` + dashboard confirmation dialog |
| Least-privilege capture | Recommend `setcap cap_net_raw+eip` on the venv interpreter instead of running the whole app as root | `capture/live.py` privilege probe + README |
| No attack traffic | No packet *generation* of malicious traffic; the fixture generator produces benign traffic shapes only (a scan pattern and a rate spike are *simulated as observations*, never sent to a third party) | `tools/generate_fixtures.py` — documented as offline file generation |
| No external scanning | Nothing in the codebase sends traffic to a remote host | Whole codebase; documented in threat model |
| Response opt-in | `safe_response.enabled: false` by default; simulated mode affects only display | `netshield/responses.py` |
| Real firewall gate | Requires root + explicit flag + lab CIDR allow-list + confirm token; refuses any other target | `responses.py::FirewallResponder` |
| Stop always available | `/api/capture/stop` is idempotent and reachable at all times | `api/routes.py` |
| Honest labelling | `data_origin` column (`real` / `demonstration`); dashboard badge | storage + dashboard |

**Lab topology used for the demo (no college LAN):** `127.0.0.1` loopback with two local sockets, plus the offline PCAP fixtures. Traffic observed is only what this machine generates.

---

## 11. Known Limitations (carried forward to README/threat model)

1. Heuristic patterns do not prove an attack — a scan pattern also matches legitimate inventory scanners, uptime monitors, and vulnerability scanners.
2. Packet metadata alone cannot prove a connection "failed"; half-open inference is confounded by asymmetric capture and dropped packets.
3. A traffic spike does not establish a DDoS — a backup job, video call, CDN fetch, or local `curl` loop looks identical from rate alone.
4. IP blocking is weak attribution and weak containment — NAT/CGNAT shared addresses, IPv6 privacy extensions, and spoofable sources all undermine it. The app therefore treats blocking as an *analyst-disciplined lab exercise*, not a control.
5. Live capture on a Wi-Fi NIC without switch mirroring observes only this host's traffic.
6. Single-process, in-memory feature windows — no horizontal scale, and windows reset on restart.
7. No payload inspection → no signature-based detection, no TLS/hostname visibility.
8. Clock skew or deliberate timestamp manipulation in a PCAP could distort the sliding windows.

---

## 12. Open Questions for Review

1. **Scope of the "sensitive ports" list** — proposed defaults in §6. Keep, or add college-relevant services (e.g. `8080`, `3000`, `5432`)?
2. **Sensitive-port severity** — a single connection to port 22 is currently *insufficient evidence* and is capped at medium. Acceptable, or should it be logged as `low` without an incident row?
3. **Retention default** — propose 7 days for packets, incidents retained indefinitely. Acceptable for the syllabus?
4. **Demo dataset** — propose a synthetic scenario set: `normal_day.pcap`, `port_scan_lab.pcap`, `traffic_spike_lab.pcap`, `malformed.pcap`, `empty.pcap`. Good coverage for a 5-minute demo?

---

**Next phase (3) — on approval:** create the virtualenv, pin `requirements.txt` to the versions verified in Phase 1, write `.env.example`, and author `config/thresholds.yaml` exactly as specified in §6.
