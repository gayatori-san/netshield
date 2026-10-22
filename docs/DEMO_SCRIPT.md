# NetShield classroom demo script

A 10-minute walkthrough for the Cyber Security & Laws open elective. It uses only the
built-in labelled demo, so it needs no root, no network traffic, and no attack tools.

## Before the session (2 minutes)

Configure Firebase and create the demo account first (README -> Authentication), then:

```bash
cd netshield
. .venv/bin/activate
NETSHIELD_DB_PATH=/tmp/netshield-demo.db python run.py
```

Open <http://127.0.0.1:5000/> and sign in. A scratch database keeps the demo counts
predictable. If a previous run left data, stop the server and delete
`/tmp/netshield-demo.db*`. Use an account with the `admin` claim if you plan to
demonstrate response actions; other operators can capture and triage but receive
`403 forbidden` for `/api/response`.

Checklist (after sign-in):

- The top bar shows the operator chip and **Sign out**.
- Overview shows "no capture yet" and the origin badge says "origin unknown".
- Alerts is empty with a reason, not a fake table.
- Browser zoom is 100%; the layout also works at 1024 px and on a phone (nav collapses).

## 0:00 - Framing (1 minute)

> "This is a network attack detection system, not a firewall. It observes packet
> metadata, applies seven explainable rules, and produces incidents an analyst can
> triage. It never sends traffic and never claims an attack is certain."

State the authorization rule: only observe traffic you are authorised to capture. The
demo avoids the question entirely by using synthetic records in memory.

## 1:00 - Empty state (1 minute)

Point at the Overview cards: packets, alerts, current rate, open incidents. Explain that
zeros are real zeros from the API, not placeholders. Show that the origin badge refuses
to guess before any capture.

## 2:00 - Start the demo (1 minute)

1. Capture panel -> **Demo**.
2. Start.
3. Point out the status pill (`running · demo`) and the **"demonstration data"** badge.
4. While it runs, explain the scenario: normal traffic, a 40-port scan, a 30-host
   sweep, 20 SSH attempts, a 600-packet UDP burst. Nothing leaves the machine.

![Empty overview](screenshots/overview-empty.png)

## 3:00 - Watch detection (2 minutes)

Wait for completion (about 45 seconds; the source is paced in real time). The shell
footer counts packets and alerts; the traffic chart and protocol doughnut populate.

Expected result on a clean database: **about 1,310 packets, 5 incidents**.

| Rule | Source | Score | Severity | Evidence sufficient |
|---|---|---|---|---|
| Port scan (ports) | `203.0.113.50` | 70 | high | yes |
| Host sweep | `203.0.113.77` | 70 | high | yes |
| Sensitive port (SSH) | `10.0.0.66` | 49 | medium | yes |
| Repeated connections | `10.0.0.66` | 65 | medium | **no** |
| Traffic spike | `10.0.0.99` | 75 | high | yes |

If a count differs by a row or two, check that the database was fresh and that a
previous capture was stopped. The demo content is deterministic; wall-clock pacing can
change the exact packet count slightly, not the rules that fire.

![Populated overview](screenshots/overview-demo.png)

## 5:00 - Triage one incident (2 minutes)

1. Open **Alerts**.
2. Point out severity chips, rule title, source, score, and time.
3. Open the port-scan row.
4. Walk through the drawer top to bottom:
   - **Summary**: what was observed, not "attack confirmed".
   - **Reasons**: each scoring term, e.g. `Volume 21/15 ... contributed +30`.
   - **Evidence**: distinct ports, sample ports, attempt count, and the note that
     legitimate scanners look the same.
   - **Timeline**: created event; acknowledge adds an event.
5. Acknowledge with a note such as "lab demo - expected". Status becomes
   `acknowledged`; the open count drops.
6. Resolve the incident to show the second transition and the notes retained.

![Alert detail](screenshots/alert-detail.png)

Key line for the viva: the repeated-SSH alert scores 65 but is capped at medium because
`evidence_sufficient` is false. The gate is in `scoring/severity.py` and is tested.

## 7:00 - Filters and export (1 minute)

1. Try the status filter `acknowledged`; the URL changes, so the view is bookmarkable.
2. Search for `10.0.0.66`; two incidents remain.
3. Export CSV and open it. Point out that the export honours the active filters and
   that leading `=`, `+`, `-`, `@` are prefixed to prevent formula injection.

## 8:00 - Traffic view (1 minute)

1. Open **Traffic**.
2. Filter protocol `TCP`; page through.
3. Note the columns: timestamp, source, destination, ports, protocol, flags, size,
   origin. There is deliberately no payload column.
4. Mention retention: 7 days by default, pruned during capture.

![Traffic](screenshots/traffic.png)

## 9:00 - Safety and response (1 minute)

1. Open **Settings**.
2. Show the read-only deployment card (bind address, database, host/port env).
3. Try an invalid threshold (low >= medium). The field error comes from the server, not
   just HTML validation.
4. Explain the response model: simulation is in-memory; the firewall path needs four
   independent gates plus an exact token. Do not enable it during the demo unless asked.
5. Close on limitations: heuristics, NAT/spoofing, asymmetric capture, no payload
   inspection. Authentication is required; accounts are provisioned in Firebase and
   only admins may apply real firewall actions.

![Settings](screenshots/settings.png)

## 10:00 - Questions

Fallback material: `docs/RULES.md` for threshold rationale and
`docs/VIVA_QUESTIONS.md` for likely questions.

## Recovery

| Problem | Fast fix |
|---|---|
| Demo finished before the audience looked | Start it again; a new run adds incidents, so use a fresh DB for exact counts |
| No packets appear | Check the pill is `running`, not `error`; open the browser console |
| Wrong counts | Reused database, or a capture was still running when demo started |
| Port 5000 busy | `python run.py --port 5001` |
| Live capture requested | Switch to the demo; live needs `CAP_NET_RAW`, an interface, and a confirmation |
