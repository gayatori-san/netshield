from flask import Flask, jsonify
import time

app = Flask(__name__)

@app.get("/")
@app.get("/api/demo")
def demo():
    data = {
        "mode": "demonstration",
        "generated_at": int(time.time()),
        "summary": {"packets": 1842, "sources": 14, "destinations": 37, "alerts": 3},
        "alerts": [
            {"id": "DEMO-001", "severity": "high", "title": "Port-scan-like activity", "evidence": "One source contacted 24 distinct destination ports in 60 seconds.", "score": 78, "status": "demonstration"},
            {"id": "DEMO-002", "severity": "medium", "title": "Traffic-rate spike", "evidence": "Observed packet rate rose above the configured illustrative baseline.", "score": 54, "status": "demonstration"},
            {"id": "DEMO-003", "severity": "low", "title": "Sensitive-port contact", "evidence": "Traffic touched a sensitive service port; this alone does not prove malicious intent.", "score": 28, "status": "demonstration"}
        ],
        "notice": "Synthetic demonstration data. It is not live traffic or proof of an attack."
    }
    return jsonify({"ok": True, "data": data})
