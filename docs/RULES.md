# NetShield detection rules

This document is the reference for what NetShield detects, why the threshold was
chosen, and what the alert does **not** mean. Every number here is produced by the
code in `netshield/detectors/` and the defaults in `config/thresholds.toml`.

## Inputs and vocabulary

Only packet metadata is used: timestamp, source/destination address, source/destination
port, protocol, TCP flags/state, and size.

A packet is a **connection attempt** when:

- TCP with state `SYN` (a bare SYN, no ACK), or
- UDP.

Replies (SYN-ACK, ACK, RST, FIN) are never counted as scan evidence. This single
decision prevents the classic student-project error where the *victim* of a scan is
flagged as the scanner because it answers every probe.

"Unanswered SYN" means a SYN for which no SYN-ACK from the same destination was
observed. It is an inference: the service may have refused the connection, a firewall
may have dropped it, or the reply may simply not have been captured.

## Rule summary

| Rule ID | Detector | Observation | Default | Evidence sufficient when |
|---|---|---|---|---|
| `PORT_SCAN_PORTS` | `port_scan.py` | Distinct destination ports from one `(src, dst)` pair | 15 ports / 60 s, at least 10 attempts | Threshold and attempt minimum both met |
| `PORT_SCAN_HOSTS` | `port_scan.py` | Distinct destination hosts from one source | 20 hosts / 60 s | Threshold met (attempt count at least threshold) |
| `REPEATED_CONNECTIONS` | `suspicious.py` | Unanswered SYNs to one `(src, dst, dport)` | 15 / 60 s | **Never** - asymmetry is ambiguous |
| `SENSITIVE_PORT` | `suspicious.py` | SYNs from one source to one sensitive port | 1 attempt alerts | 2 or more attempts |
| `CONN_RATE_ANOMALY` | `suspicious.py` | TCP connections from one source in the window | 300 / 60 s | Requires 3+ baseline samples and >= 3x the source's own baseline |
| `TRAFFIC_SPIKE` | `spike.py` | Packets in one wall-clock second | 500 pps | Rate threshold met |
| `BASELINE_DEVIATION` | `spike.py` | Rate vs. this capture's EWMA baseline | 3x baseline and >= 100 pps, 3+ samples | Ratio, floor, and sample minimum all met |

There is no eighth "half-open" rule. It was merged into `REPEATED_CONNECTIONS` because
both described the same observable and produced duplicate alerts from one event.

## Scoring

```text
score = clamp(rule_base + volume_bonus + frequency_bonus, 0, 100)

rule_base (RULE_BASE in scoring/scorer.py):
  PORT_SCAN_PORTS 40   PORT_SCAN_HOSTS 40   REPEATED_CONNECTIONS 30
  SENSITIVE_PORT 25    CONN_RATE_ANOMALY 30  TRAFFIC_SPIKE 45
  BASELINE_DEVIATION 40

volume_bonus    = min(30, floor(observed / required * 30))
frequency_bonus = min(20, (recurrence_count - 1) * 5)

severity: score < 34 low | 34..66 medium | >= 67 high
evidence gate: insufficient evidence caps at medium, never raises severity
```

`recurrence_count` counts prior alerts from the same source within 600 seconds, capped
by the bonus formula. The alert stores the exact terms in `facts` (`base`,
`volume_bonus`, `frequency_bonus`) and renders each term in `reasons`, so the score can
be recomputed by hand.

## Duplicate suppression

Two layers:

1. **In-memory** (`detectors/dedup.py`): an ongoing pattern is emitted once per
   `suppression_seconds` (default 300). Suppression keys on rule + source + destination,
   so a sliding window crossing a time-bucket boundary cannot duplicate the incident.
2. **SQLite** `UNIQUE(fingerprint)`: the durable backstop. The fingerprint is
   `sha256(rule|src|dst|bucket(window_end))[:32]`; a genuinely new 5-minute bucket can
   be stored after the suppression window, while a restart cannot replay an old row.

## Worked examples from the committed fixtures

Reproduced by replaying each fixture through the real pipeline (fast mode, scratch
database). Scores are stable for these fixtures.

### `normal_day.pcap` - 308 packets, 0 alerts

Mixed browsing, DNS, and short TCP flows below every threshold. This is the
false-positive regression case: any alert here is a bug.

### `port_scan_lab.pcap` - 166 packets, 2 alerts

| Rule | Observed | Required | Base | Volume | Frequency | Score | Severity | Sufficient |
|---|---|---|---|---|---|---|---|---|
| `PORT_SCAN_PORTS` | 21 ports | 15 | 40 | +30 | 0 | **70** | high | yes |
| `SENSITIVE_PORT` | 1 x port 21 | 1 | 25 | +6 | +5 | **36** | medium | no |

`203.0.113.50` contacts 21 ports on `10.0.0.10` with bare SYNs and no replies. The scan
alert is high because the volume bonus is capped at 30. The FTP attempt is only one
attempt, so it is explicitly marked insufficient and capped at medium.

### `suspicious_lab.pcap` - 76 packets, 2 alerts

| Rule | Observed | Required | Base | Volume | Frequency | Score | Severity | Sufficient |
|---|---|---|---|---|---|---|---|---|
| `REPEATED_CONNECTIONS` | 16 unanswered SYNs | 15 | 30 | +30 | +5 | **65** | medium | no |
| `SENSITIVE_PORT` | 1 x SSH | 1 | 25 | +6 | 0 | **31** | low | no |

The repeated-SYN alert would score high arithmetically, but the evidence gate holds it
at medium. That is intentional: a pcap that saw only one direction of the handshake
cannot distinguish "service down" from "capture loss".

### `host_sweep_lab.pcap` - 80 packets, 1 alert

| Rule | Observed | Required | Base | Volume | Frequency | Score | Severity | Sufficient |
|---|---|---|---|---|---|---|---|---|
| `PORT_SCAN_HOSTS` | 21 hosts | 20 | 40 | +30 | 0 | **70** | high | yes |

`198.51.100.77` sends one SYN to port 443 on 21 hosts. This is also what a load-balancer
health check or a discovery tool produces, hence "possible host sweep".

### `traffic_spike_lab.pcap` - 1,282 packets, 1 alert

| Rule | Observed | Required | Base | Volume | Frequency | Score | Severity | Sufficient |
|---|---|---|---|---|---|---|---|---|
| `TRAFFIC_SPIKE` | 600 pps | 500 | 45 | +30 | 0 | **75** | high | yes |

One second holds 600 datagrams from `10.0.0.66`. The alert is about rate, not intent.

### Built-in demo - 1,310 packets, 5 alerts

| Rule | Observed | Score | Severity | Sufficient |
|---|---|---|---|---|
| `PORT_SCAN_PORTS` | 40 ports from `203.0.113.50` | 70 | high | yes |
| `PORT_SCAN_HOSTS` | 30 hosts from `203.0.113.77` | 70 | high | yes |
| `SENSITIVE_PORT` | 20 SSH SYNs from `10.0.0.66` | 49 | medium | yes |
| `REPEATED_CONNECTIONS` | 20 unanswered SYNs from `10.0.0.66` | 65 | medium | no |
| `TRAFFIC_SPIKE` | 600 pps from `10.0.0.99` | 75 | high | yes |

The demo is deterministic in content (seed 1337) and takes about 45 seconds with default
pacing. All five alerts carry `data_origin = demonstration`.

## Threshold rationale (viva-ready)

- **15 ports / 60 s** - ordinary client and server activity stays well below this;
  service discovery and scanners exceed it. Conservative by design: prefer a missed scan
  over flagging a normal host.
- **20 hosts / 60 s** - distinguishes a sweep from a client talking to a few servers.
- **10 attempts per target** - stops a truncated or tiny capture from producing a scan
  alert from three stray SYNs.
- **15 unanswered SYNs** - high enough to tolerate a lossy capture, low enough to catch
  a short SSH brute-force burst.
- **300 connections / 60 s** - a busy browser or package manager is below it; only the
  ratio test makes it meaningful. Rate alone is explicitly insufficient evidence.
- **500 pps** - exceeds ordinary browsing on a laptop; a local flood or a busy backup
  can reach it.
- **3x + 100 pps floor** - a ratio against a 2 pps baseline is meaningless; the floor
  prevents 6 pps from being called a spike.
- **300 s suppression** - long enough to keep one scan from becoming dozens of rows,
  short enough to record a genuinely new wave after five minutes.

## Known false positives

| Pattern | Looks like | Why it fires |
|---|---|---|
| Vulnerability scanner / inventory agent | Port scan, host sweep | It really is contacting many ports/hosts |
| Uptime monitor with retries | Repeated connections | SYNs may be unanswered during an outage |
| Backup, video call, CDN fetch | Traffic spike | High packet rate is indistinguishable from a flood |
| Browser opening many tabs | Connection-rate anomaly | Many short-lived TCP connections; baseline may be immature |
| Asymmetric capture (one direction only) | Repeated connections | SYN-ACKs are not in the capture |

Read the alert's `reasons`, `facts`, and `evidence_sufficient` before acting. The score
is a triage aid, not a probability.

## Adding a rule

1. Implement a detector with `update(pkt)` and `flush(now)`; keep it pure and
   deterministic (no I/O, no clock reads).
2. Emit an `AlertCandidate` with `evidence`, `facts` (`observed`, `required`,
   `metric`, `window_seconds`, `evidence_sufficient`), and a title in
   `RULE_TITLES`.
3. Add a base weight in `scoring/scorer.py`.
4. Add thresholds to `config/thresholds.toml` and the settings dataclasses.
5. Write below/at/above threshold tests plus a false-positive regression test.
6. Document the rule in this file and in `ARCHITECTURE.md`.
