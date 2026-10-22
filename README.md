# NetShield — Network Attack Detection System

Educational IDS mini-project using Python, Scapy, Flask, SQLite and Chart.js.

## Features
- Responsive dashboard and JSON API
- Synthetic demonstration event generator (metadata only; no packets sent)
- Offline PCAP parsing with Scapy
- Heuristic detection for possible port scans and traffic spikes
- SQLite event and alert storage
- Alert acknowledgement and resolution
- Basic automated test

## Run
Python 3.10+ recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 and click **Run synthetic demo**.

Windows activation: `.venv\\Scripts\\activate`.

## PCAP analysis
Enter the full path to a PCAP file on the computer running the Flask process. It is parsed offline. Scapy must be installed.

## Tests
```bash
pytest -q
```

## Architecture
PCAP or synthetic event metadata → parsing → detection heuristics → SQLite → Flask API → dashboard.

## Safety and limitations
- This is a starter IDS prototype, not a production security tool.
- Detection uses simple heuristics and can generate false positives and false negatives.
- A traffic spike alone does not prove a DDoS attack.
- Live packet capture and firewall blocking are not enabled.
- Use only systems and traffic you own or have explicit permission to inspect.
- PCAP files can contain sensitive data; handle them responsibly.
- No detection accuracy claim is made without evaluation against a labelled dataset.

## Next improvements
Improve alert deduplication, add flow aggregation and protocol charts, add more tests, and only then consider optional authorized live capture with explicit interface selection and a stop control.
