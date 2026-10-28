## Vercel deployment profile

A separate **stateless demo profile** is included for Vercel:

- `public/index.html` — standalone responsive dashboard.
- `api/index.py` — short-lived Flask serverless API with health, clearly labelled synthetic demo data, and in-memory PCAP/PCAPNG heuristic analysis.
- `vercel.json` — rewrites API calls to the Python function.
- `requirements.txt` — includes Flask and Scapy, required by the Vercel profile.

### Deploy to Vercel

1. Import `gayatori-san/netshield` into Vercel.
2. Use the repository root as the project root and let Vercel detect Python from `api/index.py`.
3. Deploy, then test `/api/health`, the synthetic demo, and a small authorised PCAP file.
4. If Vercel's current Python runtime or account limits differ, follow the deployment build log; keep the capture below 2 MB for this demo endpoint.

### Important difference from the full app

Vercel mode is deliberately **not** the full long-running IDS. It does not start live NIC capture, execute firewall/iptables actions, or persist incidents to SQLite. Serverless filesystem and process memory are not durable. The original local/Render application, Firebase authentication, full detector pipeline, and SQLite-backed history remain in the repository for environments designed for a long-running service. Do not expose the full application as an unauthenticated public API.
