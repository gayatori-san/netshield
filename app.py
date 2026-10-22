import os
import tempfile
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from netshield.core import Store, Engine, demo_events, read_pcap_bytes

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB upload limit

# /tmp is writable on common serverless platforms but ephemeral.
# For durable deployed alert history, use a managed database in a later iteration.
db_path = os.getenv("NETSHIELD_DB", "/tmp/netshield.db" if os.getenv("VERCEL") else "netshield.db")
store = Store(db_path)
engine = Engine(store)


@app.route("/")
def home():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify(ok=True, service="NetShield", mode="safe-demo")


@app.get("/api/overview")
def overview():
    return jsonify(store.overview())


@app.get("/api/alerts")
def alerts():
    return jsonify(store.alerts())


@app.post("/api/demo")
def demo():
    n = engine.process(demo_events())
    return jsonify(ok=True, events_processed=n, message="Synthetic metadata only; no packets sent.")


@app.post("/api/alerts/<int:aid>")
def status(aid):
    s = (request.get_json(silent=True) or {}).get("status")
    if s not in {"open", "acknowledged", "resolved"}:
        return jsonify(error="Invalid status"), 400
    if not store.status(aid, s):
        return jsonify(error="Alert not found"), 404
    return jsonify(ok=True)


@app.post("/api/pcap")
def pcap():
    """Analyze an uploaded PCAP file entirely on the server, offline."""
    uploaded = request.files.get("pcap")
    if uploaded is None or not uploaded.filename:
        return jsonify(error="Choose a PCAP file to analyze."), 400
    filename = uploaded.filename.lower()
    if not (filename.endswith(".pcap") or filename.endswith(".pcapng") or filename.endswith(".cap")):
        return jsonify(error="Upload a .pcap, .pcapng, or .cap file."), 400
    data = uploaded.read(app.config["MAX_CONTENT_LENGTH"] + 1)
    if not data:
        return jsonify(error="The uploaded file is empty."), 400
    if len(data) > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify(error="The PCAP is larger than the 32 MB upload limit."), 413
    try:
        events = read_pcap_bytes(data)
    except Exception as e:
        return jsonify(error=str(e)), 400
    n = engine.process(events)
    return jsonify(ok=True, packets_processed=len(events), alerts_created=n)


@app.errorhandler(413)
def too_large(_error):
    return jsonify(error="Upload too large. The maximum file size is 32 MB."), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
