from flask import Flask, jsonify
import time

app = Flask(__name__)

@app.get("/")
@app.get("/api/health")
def health():
    return jsonify({"ok": True, "data": {"status": "ok", "service": "netshield", "mode": "vercel-demo", "time": int(time.time())}})
