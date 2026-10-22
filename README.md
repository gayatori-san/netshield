# NetShield — Network Defense Web App

NetShield is an educational web-based intrusion detection prototype built with Flask, SQLite, Scapy, and Chart.js. It includes a responsive dashboard, a synthetic safe demo, heuristic alert detection, alert triage, and offline PCAP uploads.

## Live deployment (Render)

This repository is ready for a Python web service deployment.

1. Sign in to [Render](https://render.com/) and create a **New Web Service**.
2. Connect this repository: `gayatori-san/netshield`.
3. Use the repository root as **Root Directory** (leave it blank).
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn app:app`
6. Deploy. Open the generated `onrender.com` URL and click **Run synthetic demo**.

The `Procfile` also declares the Gunicorn start command for compatible hosts.

## Run locally

Python 3.10+ is recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

## Features

- Responsive web dashboard with event counts, alert counts, and severity chart.
- Synthetic sample generation for safe end-to-end demonstration. It sends no packets.
- Offline PCAP upload in the browser (PCAP/PCAPNG/CAP, maximum 32 MB).
- Heuristics for possible port scans and unusually high event rates.
- Alert status workflow: open, acknowledged, and resolved.
- Health endpoint at `/api/health`.

## Deployment and storage notes

The hosted demo uses SQLite. On the included Render-style web service, the default database file is local to the service instance; deployments and restarts may reset data depending on the host's filesystem policy. For durable production data, migrate the store to managed PostgreSQL. On Vercel, the app selects `/tmp/netshield.db` because serverless filesystems are ephemeral; it should be treated as a demo, not persistent storage.

A PCAP upload is processed by the server, not by the visitor's computer. Files are held in memory, and NetShield does not enable live capture or blocking.

## Detection limitations and safety

- This project is a learning prototype, not a production IDS/SIEM.
- Heuristic rules can generate false positives and false negatives.
- A traffic spike alone does not prove a DDoS attack.
- Live packet capture, active probing, and firewall blocking are not enabled.
- Upload only traffic captures that you own or have explicit permission to analyze. PCAP files may contain sensitive information.
- No accuracy claim is made without evaluation using a labelled dataset.

## Architecture

Browser dashboard → Flask API → heuristic engine → SQLite alert/event store. Uploaded PCAP bytes are parsed offline with Scapy and passed into the same detection engine.
