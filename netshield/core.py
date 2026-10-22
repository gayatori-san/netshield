import os, sqlite3, time
from collections import defaultdict, deque
from datetime import datetime, timezone

def stamp(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

class Store:
    def __init__(self,path=None):
        self.path=path or os.getenv("NETSHIELD_DB","netshield.db")
        with self.db() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts REAL,src TEXT,dst TEXT,port INTEGER,proto TEXT,mode TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,created TEXT,src TEXT,dst TEXT,type TEXT,severity TEXT,title TEXT,evidence TEXT,status TEXT DEFAULT 'open',mode TEXT)""")
    def db(self):
        c=sqlite3.connect(self.path); c.row_factory=sqlite3.Row; return c
    def event(self,e):
        with self.db() as c: c.execute("INSERT INTO events(ts,src,dst,port,proto,mode) VALUES(?,?,?,?,?,?)",(e.get("timestamp",0),e.get("src_ip"),e.get("dst_ip"),e.get("dst_port"),e.get("protocol","OTHER"),e.get("source_mode","pcap")))
    def add(self,e):
        with self.db() as c:
            c.execute("INSERT INTO alerts(created,src,dst,type,severity,title,evidence,mode) VALUES(?,?,?,?,?,?,?,?)",(stamp(),e.get("src_ip"),e.get("dst_ip"),e["type"],e["severity"],e["title"],e["evidence"],e.get("source_mode","pcap")))
    def alerts(self):
        with self.db() as c: return [dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 200")]
    def status(self,aid,s):
        with self.db() as c: return c.execute("UPDATE alerts SET status=? WHERE id=?",(s,aid)).rowcount>0
    def overview(self):
        with self.db() as c:
            events=c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
            total=c.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"]
            opened=c.execute("SELECT COUNT(*) n FROM alerts WHERE status='open'").fetchone()["n"]
            sev={r["severity"]:r["n"] for r in c.execute("SELECT severity,COUNT(*) n FROM alerts GROUP BY severity")}
            return dict(events=events,total=total,opened=opened,severity=sev)

class Engine:
    def __init__(self,store):
        self.store=store; self.src_windows=defaultdict(deque); self.all=deque()
        self.scan_ports=int(os.getenv("SCAN_UNIQUE_PORTS","12")); self.scan_secs=20
        self.spike_count=int(os.getenv("SPIKE_PACKETS_PER_WINDOW","150")); self.spike_secs=10
    def process(self,events):
        made=0
        for e in events:
            e.setdefault("source_mode","pcap"); e.setdefault("timestamp",0)
            self.store.event(e); t=float(e["timestamp"]); src=e.get("src_ip") or "unknown"
            w=self.src_windows[src]; w.append((t,e.get("dst_port"),e.get("dst_ip")))
            while w and t-w[0][0]>self.scan_secs: w.popleft()
            ports={x[1] for x in w if x[1] is not None}
            if len(ports)>=self.scan_ports:
                self.store.add(dict(**e,type="port_scan",severity="high",title="Possible port scan",evidence=f"{len(ports)} distinct destination ports from one source within {self.scan_secs}s; heuristic only.")); made+=1; w.clear()
            self.all.append(t)
            while self.all and t-self.all[0]>self.spike_secs: self.all.popleft()
            if len(self.all)>=self.spike_count:
                self.store.add(dict(**e,type="traffic_spike",severity="medium",title="Unusual traffic spike",evidence=f"{len(self.all)} events in {self.spike_secs}s; benign bursts can trigger this.")); made+=1; self.all.clear()
        return made

def demo_events():
    t=time.time(); out=[]
    for i in range(8): out.append(dict(timestamp=t+i*.03,src_ip="192.0.2.10",dst_ip="198.51.100.20",dst_port=443,protocol="TCP",source_mode="synthetic_demo"))
    for i,p in enumerate(range(20,36)): out.append(dict(timestamp=t+1+i*.2,src_ip="192.0.2.99",dst_ip="198.51.100.40",dst_port=p,protocol="TCP",source_mode="synthetic_demo"))
    for i in range(30): out.append(dict(timestamp=t+6+i*.01,src_ip="192.0.2.55",dst_ip="198.51.100.55",dst_port=80,protocol="TCP",source_mode="synthetic_demo"))
    return out

def read_pcap(path):
    if not path or not os.path.isfile(path): raise ValueError("PCAP file not found on the machine running NetShield.")
    try: from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError: raise ValueError("Scapy is missing. Run pip install -r requirements.txt.")
    try: packets=rdpcap(path)
    except Exception as e: raise ValueError("Could not read PCAP: "+str(e))
    out=[]
    for p in packets:
        if IP not in p: continue
        proto,port="OTHER",None
        if TCP in p: proto,port="TCP",int(p[TCP].dport)
        elif UDP in p: proto,port="UDP",int(p[UDP].dport)
        out.append(dict(timestamp=float(p.time),src_ip=p[IP].src,dst_ip=p[IP].dst,dst_port=port,protocol=proto,source_mode="pcap"))
    return out
