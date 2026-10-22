# NetShield

An educational network attack-detection system. It reads packet **metadata** from a
PCAP file, a labelled offline demo, or a live interface, applies seven transparent
heuristic rules, scores the observations, stores incidents in SQLite, and presents
them in a local web dashboard.

NetShield is a teaching tool, not a production IDS. It reports *observable evidence*
("one source contacted 40 ports in 60 seconds"), never "an attack happened", and it
never sends traffic.

![Overview after the built-in demo](docs/screenshots/overview-demo.png)

## What it does

- Parses PCAP/PCAPNG captures with `scapy`; malformed and non-IP packets are counted
  and skipped, never fatal.
- Extracts per-source sliding-window features: distinct destination ports and hosts,
  unanswered SYNs, connection rate, per-second packet rate, EWMA baselines.
- Runs seven independent detectors and a visible scoring formula.
- Suppresses duplicates twice: an in-memory suppression window and a
  `UNIQUE(fingerprint)` database constraint.
- Persists incidents with evidence, facts, a plain-language score rationale, and an
  event timeline (created / acknowledged / resolved).
- Serves a local JSON API and a four-page dashboard: Overview, Alerts, Traffic,
  Settings. All panels render from API responses; there is no hardcoded sample data.
- Supports a **simulated** response action and an opt-in, lab-scoped `iptables` path.
- Labels synthetic runs as `demonstration` everywhere; the UI shows a badge.

## Honest limitations (read this first)

1. Heuristics do not prove intent. A port scan also matches an inventory scanner, an
   uptime monitor, or a vulnerability assessment.
2. "Unanswered SYN" cannot distinguish a closed service from asymmetric capture.
3. A packet-rate spike is not a DDoS. Backups, video calls, and file transfers look
   identical from rate alone.
4. IP blocking is weak containment: NAT/CGNAT, spoofing, and IPv6 privacy addresses
   all undermine attribution. The real-firewall path is a lab exercise, not a control.
5. A Wi-Fi NIC without switch mirroring sees only this host's traffic.
6. Windows live capture is not supported by the recommended setup; PCAP replay and the
   demo work everywhere.
7. Feature windows and the simulated block list live in memory and reset on restart.
8. There is no authentication. The server binds to loopback by default for this reason.

## Quick start

Requirements: Python 3.11+ (tested on 3.14.7), Linux or macOS. `libpcap` is needed by
`scapy` for live capture; PCAP replay and the demo do not need it.

```bash
cd netshield
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt

python run.py
```

Open <http://127.0.0.1:5000/>.

Command-line options:

```bash
python run.py --port 8080
python run.py --debug
python run.py --no-demo-pace     # run the demo scenario as fast as possible
```

Configuration is `config/thresholds.toml` plus `NETSHIELD_*` environment variables.
See `.env.example` for every variable. Changes made on the Settings page apply to the
current session; edit the TOML file to persist them.

## Three input modes

| Mode | What happens | Requirements |
|---|---|---|
| **PCAP replay** | Upload or pick a capture from `data/pcap` or `tests/fixtures`. Processed as fast as the pipeline allows. | none |
| **Demo** | 60 seconds of deterministic, labelled synthetic traffic: port scan, host sweep, repeated SYNs, UDP spike. | none |
| **Live capture** | `scapy` sniffs one explicitly selected interface. | root or `CAP_NET_RAW`; explicit authorization confirmation |

Live capture options, in order of preference:

```bash
# Preferred: grant only the capability, not full root.
sudo setcap cap_net_raw+eip "$(readlink -f .venv/bin/python)"
./.venv/bin/python run.py

# Fallback: run the whole app as root (not recommended).
sudo ./.venv/bin/python run.py
```

The dashboard probes capture capability and shows the actionable error if permission
is missing.

## The seven rules

| ID | Observation | Default threshold |
|---|---|---|
| `PORT_SCAN_PORTS` | Distinct destination ports from one source to one host (connection attempts only) | 15 ports / 60 s, at least 10 attempts |
| `PORT_SCAN_HOSTS` | Distinct destination hosts from one source | 20 hosts / 60 s |
| `REPEATED_CONNECTIONS` | Unanswered TCP SYNs to one destination service | 15 / 60 s |
| `SENSITIVE_PORT` | Connection attempts to an administrative/service port | 1 attempt alerts; 2+ is sufficient evidence |
| `CONN_RATE_ANOMALY` | TCP connections from one source | 300 / 60 s (sufficient only at 3x its own baseline) |
| `TRAFFIC_SPIKE` | Packets in a one-second bucket | 500 pps |
| `BASELINE_DEVIATION` | Rate vs. the capture's own EWMA baseline | 3x baseline, at least 100 pps, 3+ baseline samples |

Scoring:

```text
score = clamp(rule_base + volume_bonus + frequency_bonus, 0, 100)
severity: low < 34 <= medium < 67 <= high
evidence gate: insufficient evidence caps severity at medium
```

Every alert stores the reasons, the exact observed-vs-required values, a fingerprint,
`data_origin`, and a status. Full specifications and worked fixture numbers are in
[`docs/RULES.md`](docs/RULES.md).

## Screenshots

| Alerts | Alert evidence |
|---|---|
| ![Alerts list](docs/screenshots/alerts.png) | ![Alert drawer](docs/screenshots/alert-detail.png) |

| Traffic | Settings |
|---|---|
| ![Traffic](docs/screenshots/traffic.png) | ![Settings](docs/screenshots/settings.png) |

## Safe response

The default is `safe_response.enabled = false`. When enabled:

- `simulate_block` / `simulate_unblock` only mark an address as blocked in the
  dashboard (in-memory, max 500 entries, no host change).
- `firewall_block` / `firewall_unblock` additionally require
  `allow_firewall_changes = true`, root, a target inside the configured lab CIDRs,
  and the exact confirmation token (`BLOCK <ip>` / `UNBLOCK <ip>`). The action inserts
  or deletes one `iptables INPUT` rule and is logged in `response_actions`.

This is deliberately difficult to trigger. See
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Privacy

Only packet metadata is stored: timestamp, addresses, ports, protocol, TCP flags,
size, and source/origin. Payloads, DNS names, and MAC addresses are never stored.
CSV export prefixes spreadsheet formula characters to prevent formula injection.

## Project layout

```text
netshield/                 Python package
  config/                  settings dataclasses + TOML loader
  capture/                 pcap, live, and synthetic sources
  features/                flow extraction and sliding-window aggregation
  detectors/               five detector modules + dedup
  scoring/                 additive scorer and severity bands
  storage/                 SQLite schema, connection management, repositories
  api/                     Flask app factory, JSON routes, validation, errors
  dashboard/               Jinja shell, CSS, JS, vendored Chart.js
  pipeline.py              producer/worker pipeline
  responses.py             gated simulated/firewall response service
config/thresholds.toml     all detection thresholds
run.py                     entry point
tests/                     190 tests (unit + integration) and PCAP fixtures
tools/generate_fixtures.py deterministic offline fixture generator
docs/                      architecture, rules, runbook, demo script, threat model
```

## Tests

```bash
. .venv/bin/activate
python -m pytest
```

Expected: `190 passed`. The suite covers PCAP tolerance, feature counters, each rule
below/at/above threshold, false-positive regressions, scoring and the evidence gate,
deduplication, SQLite persistence and retention, the full API contract, response
gating, and dashboard rendering/security headers. No test opens a live capture or
sends network traffic.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — as-built design, data flow, contracts
- [`docs/RULES.md`](docs/RULES.md) — rule specs, scoring, fixture-verified examples
- [`docs/RUNBOOK.md`](docs/RUNBOOK.md) — install, operate, troubleshoot, reset
- [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) — 10-minute classroom walkthrough
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — assets, abuse cases, controls
- [`docs/VIVA_QUESTIONS.md`](docs/VIVA_QUESTIONS.md) — likely questions with answers

## Academic context

Built for the *Cyber Security & Laws* open elective as a network attack detection
mini-project. The design emphasises modularity, testability, explainability, and
authorization boundaries over detection coverage. It does not generate attack
traffic and must only be pointed at traffic the operator is authorized to observe.

The code is provided for coursework and review. No license is granted beyond what
your institution's policy allows; add one before redistributing.
