from flask import Flask, jsonify, request
import io
from collections import defaultdict

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
MAX_PACKETS = 20000

@app.post("/")
@app.post("/api/analyze")
def analyze():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"ok": False, "error": "Attach a .pcap, .pcapng, or .cap file."}), 400
    if not uploaded.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        return jsonify({"ok": False, "error": "Unsupported file type. Use PCAP or PCAPNG."}), 400
    raw = uploaded.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        return jsonify({"ok": False, "error": "Upload exceeds the 2 MB demo limit."}), 413
    if not raw:
        return jsonify({"ok": False, "error": "The uploaded capture is empty."}), 400
    try:
        from scapy.all import IP, TCP, UDP, rdpcap
        packets = rdpcap(io.BytesIO(raw), count=MAX_PACKETS)
    except Exception:
        return jsonify({"ok": False, "error": "Could not parse this capture. Check that it is a valid PCAP/PCAPNG file."}), 400

    src_ports, src_hosts = defaultdict(set), defaultdict(set)
    packet_count = 0
    for packet in packets:
        if IP not in packet:
            continue
        packet_count += 1
        ip = packet[IP]
        src_hosts[ip.src].add(ip.dst)
        if TCP in packet:
            src_ports[ip.src].add(int(packet[TCP].dport))
        elif UDP in packet:
            src_ports[ip.src].add(int(packet[UDP].dport))

    alerts = []
    for source, ports in src_ports.items():
        if len(ports) >= 15:
            alerts.append({"id": "PCAP-" + str(len(alerts) + 1), "severity": "high" if len(ports) >= 25 else "medium", "title": "Port-scan-like activity", "evidence": f"{source} contacted {len(ports)} distinct destination ports in this capture.", "score": min(95, 40 + len(ports)), "status": "pcap-analysis"})
        hosts = src_hosts[source]
        if len(hosts) >= 20:
            alerts.append({"id": "PCAP-" + str(len(alerts) + 1), "severity": "medium", "title": "Multi-host contact pattern", "evidence": f"{source} contacted {len(hosts)} distinct destination hosts.", "score": min(85, 30 + len(hosts)), "status": "pcap-analysis"})

    data = {
        "mode": "pcap-analysis",
        "summary": {"packets": packet_count, "sources": len(src_ports), "destinations": len({dst for hosts in src_hosts.values() for dst in hosts}), "alerts": len(alerts), "packets_examined_limit": MAX_PACKETS},
        "alerts": alerts[:100],
        "notice": "Heuristic evidence only; this does not prove an attack. The upload is processed in memory and is not saved by this function."
    }
    return jsonify({"ok": True, "data": data})

@app.errorhandler(413)
def too_large(_error):
    return jsonify({"ok": False, "error": "Upload too large for the Vercel demo endpoint."}), 413
