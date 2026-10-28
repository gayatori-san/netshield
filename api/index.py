"""Vercel-compatible, stateless NetShield demo API.

This deployment profile deliberately does not start live capture, use iptables,
or write to SQLite. Vercel functions are short-lived and their filesystem is
ephemeral. The full local/Render app remains available through run.py / wsgi.py.
"""
from __future__ import annotations

import io
import time
from collections import defaultdict
from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
MAX_PACKETS = 20000


def response(data, status=200):
    return jsonify({"ok": status < 400, "data": data} if status < 400 else {"ok": False, "error": data}), status


@app.get("/")
@app.get("/api")
@app.get("/api/")
def index():
    return response({"service": "NetShield Vercel API", "status": "ok", "mode": "stateless-demo"})


@app.get("/health")
@app.get("/api/health")
def health():
    return response({"status": "ok", "service": "netshield", "mode": "vercel-demo", "time": int(time.time())})


def demo_result():
    return {
        "mode": "demonstration",
        "generated_at": int(time.time()),
        "summary": {"packets": 1842, "sources": 14, "destinations": 37, "alerts": 3},
        "alerts": [
            {"id": "DEMO-001", "severity": "high", "title": "Port-scan-like activity",
             "evidence": "One source contacted 24 distinct destination ports in 60 seconds.",
             "score": 78, "status": "demonstration"},
            {"id": "DEMO-002", "severity": "medium", "title": "Traffic-rate spike",
             "evidence": "Observed packet rate rose above the configured illustrative baseline.",
             "score": 54, "status": "demonstration"},
            {"id": "DEMO-003", "severity": "low", "title": "Sensitive-port contact",
             "evidence": "Traffic touched a sensitive service port; this alone does not prove malicious intent.",
             "score": 28, "status": "demonstration"}
        ],
        "notice": "Synthetic demonstration data. It is not live traffic or proof of an attack."
    }


@app.get("/demo")
@app.get("/api/demo")
def demo():
    return response(demo_result())


@app.post("/analyze")
@app.post("/api/analyze")
def analyze_pcap():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return response("Attach a .pcap, .pcapng, or .cap file.", 400)
    if not uploaded.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        return response("Unsupported file type. Use PCAP or PCAPNG.", 400)
    raw = uploaded.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        return response("Upload exceeds the 2 MB demo limit.", 413)
    if not raw:
        return response("The uploaded capture is empty.", 400)

    try:
        from scapy.all import IP, TCP, UDP, rdpcap
        packets = rdpcap(io.BytesIO(raw), count=MAX_PACKETS)
    except Exception:
        return response("Could not parse this capture. Check that it is a valid PCAP/PCAPNG file.", 400)

    src_ports = defaultdict(set)
    src_hosts = defaultdict(set)
    src_syn = defaultdict(int)
    packet_count = 0
    for packet in packets:
        if IP not in packet:
            continue
        packet_count += 1
        ip = packet[IP]
        src_hosts[ip.src].add(ip.dst)
        if TCP in packet:
            tcp = packet[TCP]
            src_ports[ip.src].add(int(tcp.dport))
            if int(tcp.flags) & 0x02 and not (int(tcp.flags) & 0x10):
                src_syn[ip.src] += 1
        elif UDP in packet:
            src_ports[ip.src].add(int(packet[UDP].dport))

    alerts = []
    for source, ports in src_ports.items():
        if len(ports) >= 15:
            alerts.append({
                "id": "PCAP-" + str(len(alerts) + 1),
                "severity": "high" if len(ports) >= 25 else "medium",
                "title": "Port-scan-like activity",
                "evidence": f"{source} contacted {len(ports)} distinct destination ports in this capture.",
                "score": min(95, 40 + len(ports)),
                "status": "pcap-analysis"
            })
        if len(src_hosts[source]) >= 20:
            alerts.append({
                "id": "PCAP-" + str(len(alerts) + 1),
                "severity": "medium",
                "title": "Multi-host contact pattern",
                "evidence": f"{source} contacted {len(src_hosts[source])} distinct destination hosts.",
                "score": min(85, 30 + len(src_hosts[source])),
                "status": "pcap-analysis"
            })
    return response({
        "mode": "pcap-analysis",
        "summary": {"packets": packet_count, "sources": len(src_ports),
                    "destinations": len({dst for hosts in src_hosts.values() for dst in hosts}),
                    "alerts": len(alerts), "packets_examined_limit": MAX_PACKETS},
        "alerts": alerts[:100],
        "notice": "Heuristic evidence only; this does not prove an attack. The upload is processed in memory and is not saved by this function."
    })


@app.errorhandler(413)
def too_large(_error):
    return response("Upload too large for the Vercel demo endpoint.", 413)


@app.errorhandler(500)
def server_error(_error):
    return response("Unexpected server error.", 500)
