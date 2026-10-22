from flask import Flask, jsonify, render_template, request
from netshield.core import Store, Engine, demo_events, read_pcap
app=Flask(__name__)
store=Store()
engine=Engine(store)
@app.route("/")
def home(): return render_template("index.html")
@app.get("/api/overview")
def overview(): return jsonify(store.overview())
@app.get("/api/alerts")
def alerts(): return jsonify(store.alerts())
@app.post("/api/demo")
def demo():
    n=engine.process(demo_events())
    return jsonify(ok=True,events_processed=n,message="Synthetic metadata only; no packets sent.")
@app.post("/api/alerts/<int:aid>")
def status(aid):
    s=(request.get_json(silent=True) or {}).get("status")
    if s not in {"open","acknowledged","resolved"}: return jsonify(error="Invalid status"),400
    if not store.status(aid,s): return jsonify(error="Alert not found"),404
    return jsonify(ok=True)
@app.post("/api/pcap")
def pcap():
    path=(request.get_json(silent=True) or {}).get("path","")
    try: events=read_pcap(path)
    except Exception as e: return jsonify(error=str(e)),400
    n=engine.process(events)
    return jsonify(ok=True,packets_processed=len(events),alerts_created=n)
if __name__=="__main__": app.run(host="127.0.0.1",port=5000,debug=False)
