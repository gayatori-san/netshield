# Viva preparation

Likely questions with answers grounded in the implementation. File references point to
the code that supports each answer.

## Architecture

**1. Walk me through the pipeline.**
Capture source -> bounded queue -> worker thread -> feature aggregation -> detectors ->
scorer/dedup -> SQLite -> Flask JSON API -> dashboard. The producer and worker are
separate so a fast PCAP cannot starve detection, and the queue is bounded so a slow
worker cannot exhaust memory (`netshield/pipeline.py`).

**2. Why a single worker thread?**
Detection state is in-memory and order-sensitive (sliding windows, EWMA baselines).
One consumer gives deterministic ordering without locks around every detector. Scaling
out would require partitioning by source or a shared state store, which is out of scope.

**3. Why SQLite?**
Zero-install, single file, transactional, and supports WAL for concurrent reads while
the worker writes. A teaching project does not need a server database
(`netshield/storage/db.py`).

**4. Why Flask and not FastAPI/Django?**
Small surface, familiar to students, no async complexity. The app needs a handful of
JSON routes and static files, not an ORM or admin site.

**5. Why polling instead of WebSockets/Socket.IO?**
Two-second polling is simpler, survives restarts, and is easy to explain. At this data
volume the overhead is irrelevant. `api.js` pauses polling when the tab is hidden.

**6. Why server-rendered Jinja shells with client-side rendering?**
The shells are static and safe (autoescaped), while all monitoring data comes from the
JSON API. That satisfies "no hardcoded sample data" and keeps one source of truth
(`netshield/dashboard/templates/`, `static/js/`).

**7. Why TOML instead of YAML?**
`tomllib` is in the standard library on Python 3.11+, while PyYAML is a compiled
dependency that can fail to install on a student laptop. The format still supports
comments and sections (`config/thresholds.toml`, `netshield/config/settings.py`).

## Detection

**8. What is the difference between a packet and a connection attempt?**
A TCP SYN without ACK, or a UDP datagram, is an attempt. SYN-ACK, ACK, RST, and FIN are
responses. Port-scan evidence counts attempts only; otherwise the victim, which sends
one reply per probed port, looks like the scanner (`models.py`,
`detectors/port_scan.py`).

**9. Why merge the half-open rule into repeated connections?**
Both described SYNs without SYN-ACK. Keeping both produced two alerts from one
observation without independent evidence. One rule, one caveat
(`detectors/suspicious.py`).

**10. How does the port-scan detector avoid flagging a small capture?**
It requires both the distinct-port threshold (15) and a minimum of 10 attempts to the
target. A truncated capture with three SYNs cannot fire (`PortScanConfig`).

**11. How does the host-sweep detector differ?**
It groups by source across all destinations (20 distinct hosts / 60 s) rather than by
one source-destination pair.

**12. How is "unanswered SYN" computed, and why is it insufficient evidence?**
SYNs and SYN-ACKs are counted per `(src, dst, dport)`; the difference is "unanswered".
Asymmetric capture, a firewall drop, and a closed service are indistinguishable from
metadata, so the alert is always marked insufficient and capped at medium.

**13. Why is a single SSH attempt only low/medium?**
One connection to an administrative port is routine. It alerts with
`evidence_sufficient = false`; two or more attempts become sufficient. The score still
reflects volume and recurrence (`SENSITIVE_PORT` in `detectors/suspicious.py`).

**14. How does the connection-rate rule work?**
It counts TCP SYNs per source in a 60-second window. Reaching 300 alerts, but it is only
sufficient when the source has at least three baseline samples and the rate is at least
3x its own EWMA baseline. A high rate alone is normal for busy clients.

**15. Explain the two spike rules.**
`TRAFFIC_SPIKE` is absolute (500 pps in a one-second bucket). `BASELINE_DEVIATION` is
relative (3x the capture's EWMA baseline) but requires at least 100 pps and three
baseline samples, so a 2 pps baseline cannot make 6 pps look like a flood.

**16. Why one-second buckets?**
They make the threshold easy to reason about and to demonstrate. The trade-off is that
a burst split across a second boundary can be missed; the EWMA rule partly compensates.

**17. What happens to detector state on restart?**
Windows, baselines, and the simulated block list reset. Persisted incidents remain.
That is a documented limitation; a production system would rebuild baselines from
stored buckets.

## Scoring and deduplication

**18. How is the score calculated?**
`clamp(base + volume_bonus + frequency_bonus, 0, 100)`. Base is per rule, volume is
`min(30, floor(observed/required*30))`, frequency is `min(20, (recurrence-1)*5)`.
Severity bands are low < 34 <= medium < 67 <= high. Every term is stored in `facts` and
rendered in `reasons` (`scoring/scorer.py`).

**19. What is the evidence gate?**
If `evidence_sufficient` is false, severity is capped at medium. The gate can only lower
severity, never raise it (`scoring/severity.py`). The repeated-SSH demo alert scores 65
but stays medium because of this.

**20. Is the score a probability?**
No. It is an additive triage weight. The UI never shows confidence percentages and the
docs state there are no accuracy claims.

**21. How are duplicate alerts prevented?**
In-memory suppression for 300 seconds keyed on rule + source + destination, plus
`UNIQUE(fingerprint)` in SQLite. The fingerprint includes a 5-minute bucket, so a new
wave after the window can be stored, while a restart cannot duplicate a row
(`detectors/dedup.py`, `storage/schema.sql`).

**22. Why key suppression on rule+addresses rather than the fingerprint?**
A sliding window can cross a bucket boundary mid-pattern; the fingerprint changes and a
naive check would emit a second incident. The identity key fixes that, and there is a
regression test for it.

## Storage and API

**23. What is stored for each packet?**
Timestamp, source/destination address and port, protocol, TCP flags/state, size, origin,
and ingestion time. No payloads, DNS names, or MAC addresses. This is a privacy and
retention decision (`schema.sql`).

**24. How does the API report errors?**
One envelope: `{ok: false, error: {code, message, detail}}` with 400 for validation, 404
for missing incidents, 409 for busy capture or invalid state, 403 for refused responses,
502 for firewall failures (`api/errors.py`).

**25. How are query parameters validated?**
A `ParamReader` bounds integers, limits text length, and restricts enums; `per_page` is
capped at 500. Unknown or repeated parameters are rejected rather than silently ignored
(`api/validation.py`).

**26. How is the CSV export made safe?**
The writer quotes fields and prefixes a leading `=`, `+`, `-`, or `@` with an
apostrophe to stop spreadsheet formula execution. It honours the same filters as the
list view.

**27. Can a user request an arbitrary file to parse?**
No. The path is resolved and must remain inside `data/pcap` or `tests/fixtures`;
uploads are restricted by extension, size, server-generated name, and capture
signature (`api/routes.py`).

## Security and safety

**28. How is the dashboard protected against XSS?**
Jinja autoescaping, `textContent`/`escapeHtml` for API data, and a CSP with
`script-src 'self'` and no `unsafe-inline`. Chart.js is vendored locally, so there is no
CDN trust (`api/app.py`, `dashboard/templates/`).

**29. What stops the response feature from blocking a random IP?**
Seven checks for a real action: feature enabled, valid IP, target inside configured lab
CIDRs, real changes allowed, root, `iptables` present, and an exact confirmation token.
Simulation only needs the first two. Simulation never
touches the host (`responses.py`).

**30. Why is IP blocking described as weak?**
NAT/CGNAT hides many hosts behind one address, sources can be spoofed, and IPv6 privacy
addresses rotate. Blocking is containment theatre unless the network path is controlled.
The tool treats it as a lab exercise, not a control.

**31. What is the biggest security weakness?**
Coarse authorization and account lifecycle, not missing authentication. Any signed-in
operator can control capture and triage, and a compromised admin account can change host
firewall rules. Mitigations are deliberate Firebase account provisioning, TLS, Bearer
tokens for writes, an admin custom claim for firewall actions, rate limiting, and
fail-closed verification. A stricter deployment would add per-user roles and audit.

**32. What about capturing other people's traffic?**
The tool cannot verify authorization. The UI requires an explicit confirmation, the
docs state the legal/ethical rule, and the recommended workflow uses PCAP or synthetic
data. This is a policy control with a technical reminder, not a guarantee.

## Testing and limitations

**33. How many tests and what do they cover?**
268 tests: PCAP tolerance, feature counters, each rule below/at/above threshold,
false-positive regressions, scoring and the gate, dedup, storage, API contract, response
gates, dashboard pages/headers, and Firebase authentication (mocked): redirects,
missing/expired/revoked tokens, session cookies, write-token enforcement, admin claims,
fail-closed outages, and rate limiting. No test opens a live capture or sends traffic.

**34. Give an example of a false-positive test.**
`normal_day.pcap` (308 packets of ordinary traffic) must produce zero incidents.
Another test asserts that a lone connection is never flagged as a port scan.

**35. What are the main limitations?**
Heuristics are not proof; asymmetric capture confuses failed connections; a rate spike
is not a DDoS; no payload inspection; in-memory state resets; Wi-Fi sees only local
traffic; coarse authorization; IPv4/IPv6 blocking is unreliable. Full list in README and
`docs/THREAT_MODEL.md`.

**36. What would you improve with more time?**
Per-source baselines persisted across restarts, a proper incident workflow with
assignment, IPv6-aware lab policies, configurable rule enable/disable, structured
logging/metrics, per-user RBAC and audit, and PCAP-bounded streaming
instead of loading the whole file.

**37. Why not machine learning?**
The project's goal is explainability and testability. An ML model would add training
data, drift, and unexplainable decisions, and would not improve the pedagogical point:
that evidence must be inspectable. Heuristics plus a visible score are defensible in a
viva.
