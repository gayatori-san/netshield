# NetShield runbook

Operational instructions for running, demonstrating, and troubleshooting NetShield.

## 1. Install

```bash
cd netshield
python3 --version                 # 3.11 or newer; tested on 3.14.7
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
```

`requirements.txt` pins `scapy==2.8.0` and `Flask==3.1.3`; the dev file adds
`pytest==9.1.1`. Live capture additionally needs `libpcap`; PCAP replay and the demo do
not.

## 2. Run

```bash
python run.py                      # http://127.0.0.1:5000/
python run.py --port 8080
python run.py --debug              # verbose Flask logging
python run.py --no-demo-pace       # demo as fast as possible
```

The server prints a banner with the URL and database path, warns if bound beyond
loopback, and never enables the reloader (it would orphan sniffer threads).

Environment overrides: `NETSHIELD_HOST`, `NETSHIELD_PORT`, `NETSHIELD_DB_PATH`,
`NETSHIELD_CONFIG`, `NETSHIELD_QUEUE_MAXSIZE`, `NETSHIELD_DEMO_DURATION`,
`NETSHIELD_SECRET_KEY`, `NETSHIELD_DEBUG`. See `.env.example`.

## 3. Capture modes

### PCAP replay

1. Overview -> Capture -> select **PCAP file**.
2. Either choose a file from the dropdown (`data/pcap` or `tests/fixtures`) or upload
   one (`.pcap`, `.pcapng`, `.cap`, max 25 MiB).
3. Start. Replay runs as fast as the pipeline allows; the status pill shows `running`
   and ends as `completed` (or `stopped` if you stop it early).

Allowed upload path is fixed: `data/pcap`. Arbitrary filesystem paths are rejected,
symlinks are resolved, and the file signature is checked before ingestion.

### Demo

1. Select **Demo**, start, and wait about 45 seconds.
2. Expect roughly 1,310 packets and 5 incidents, all labelled `demonstration` in the
   origin badge and on each alert.
3. Stop at any time; the synthetic source stops immediately.

### Live capture

Preferred (capability only):

```bash
sudo setcap cap_net_raw+eip "$(readlink -f .venv/bin/python)"
./.venv/bin/python run.py
```

Fallback:

```bash
sudo ./.venv/bin/python run.py
```

Then choose an interface, confirm authorization, and start. On Wi-Fi without switch
mirroring you see only this host's traffic.

Remove the capability later with:

```bash
sudo setcap -r "$(readlink -f .venv/bin/python)"
```

## 4. Daily operation

- **Overview** refreshes every 2.5 s; the top bar polls capture status every 2 s.
  Polling pauses while the browser tab is hidden.
- **Alerts** holds all incidents (the planned separate "Incidents" page is merged into
  this one). Filters are URL parameters, so a filtered view can be bookmarked.
  Acknowledge and resolve add timeline events and an optional note.
- **Traffic** shows packet metadata with filters and pagination. A blocked target is
  marked in the table.
- **Settings** changes apply to the current session. Edit `config/thresholds.toml` to
  persist them; restart after editing.

### Retention

Packets older than `retention.packet_days` (default 7) are deleted during a running
capture every `retention.prune_interval_seconds` (default 300). Incidents are retained.
Adjust both in the TOML file.

### Backup

SQLite runs in WAL mode. To copy safely:

```bash
sqlite3 data/netshield.db ".backup '/tmp/netshield-backup.db'"
```

Do not copy only the `.db` file while a capture is writing; also include `-wal` and
`-shm` or use `.backup`.

### Reset

```bash
# Stop the server first.
rm -f data/netshield.db data/netshield.db-wal data/netshield.db-shm
python run.py
```

Uploaded PCAPs live in `data/pcap/` and are safe to delete when not analysing them.

## 5. Safe response

Default configuration disables everything:

```toml
[safe_response]
enabled = false
allow_firewall_changes = false
allowed_cidrs = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

To demonstrate simulation, set `enabled = true` and restart. Simulated blocks are
in-memory only (max 500) and disappear on restart; they change the dashboard, not the
host.

Real firewall changes additionally require `allow_firewall_changes = true`, root, a
target inside `allowed_cidrs`, and the confirmation token shown in the UI:

```text
BLOCK 10.0.0.66
UNBLOCK 10.0.0.66
```

The API inserts/deletes exactly one `iptables INPUT` rule. Verify and clean up manually:

```bash
sudo iptables -S INPUT | grep 10.0.0.66
sudo iptables -D INPUT -s 10.0.0.66 -j DROP
```

The app logs every attempt in `response_actions`, including refusals.

## 6. Verification checklist

```bash
curl -s http://127.0.0.1:5000/api/health
curl -s http://127.0.0.1:5000/api/overview | head -c 400
curl -sI http://127.0.0.1:5000/ | grep -Ei 'content-security|x-frame|x-content'
. .venv/bin/activate && python -m pytest
```

Expected: `{"ok": true, ...}`, a CSP header without `unsafe-inline`, and
`190 passed`.

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `PermissionError: [Errno 1] Operation not permitted` on live start | No `CAP_NET_RAW` | `setcap` command above, or run with `sudo` |
| `can_capture: false` on `/api/interfaces` | Same as above | Same as above |
| `Address already in use` | Another server on the port | `python run.py --port 5001`, or stop the other process |
| `a capture is already running; stop it first` (HTTP 409) | One pipeline per process | Stop the current capture; mode changes need a stop first |
| Live capture shows no packets | Wrong interface, or Wi-Fi without mirroring | Pick the active interface; expect only local traffic |
| Upload rejected as unsupported | Extension or signature check | Use `.pcap`, `.pcapng`, or `.cap` from a real capture |
| Upload rejected as unreadable | Truncated/renamed file | Open it in Wireshark/`tcpdump -r` first |
| `database is locked` | Long write plus external reader holding a lock | Close external SQLite tools; retry |
| Alerts appear then vanish from a filter | Status filter is `new` and you acknowledged them | Clear the status filter |
| Settings save says thresholds apply next capture | A capture is running | Stop and start, or accept the next-run behaviour |
| Blocks do nothing to real traffic | Simulation mode | Only `firewall_block` touches `iptables`, and it is lab-gated |
| Firewall action returns 403 | Feature off, non-root, non-lab IP, or bad token | Check each gate; the error names the failing one |
| Dashboard page blank | CSP or JS load failure | Check the browser console; assets are served from `/static/`, no CDN |
| Demo overlaps with old rows | Same database reused | Expected; use `--no-demo-pace` with a scratch DB for a clean count |
| SQLite file grows | Packets are retained for 7 days | Lower `retention.packet_days`; prune runs during capture |

## 8. Log locations

The app logs to stdout/stderr only; there is no log file. For a durable run:

```bash
python run.py 2>&1 | tee netshield.log
```

`*.log` is gitignored. Flask's development server is single-process and not intended for
exposure; do not bind `0.0.0.0` on an untrusted network (there is no authentication).

## 9. Upgrade / reinstall

```bash
git pull
. .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
python run.py
```

The schema uses `CREATE TABLE IF NOT EXISTS`; there are no destructive migrations. If
you change the schema manually, use a fresh database file.
