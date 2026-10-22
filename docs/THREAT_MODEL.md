# NetShield threat model

Scope: the NetShield application as shipped in this repository, run locally for
coursework. It is a single-user teaching tool with no authentication and no cloud
components. This document states what it protects, what it does not, and which controls
are enforced where.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Captured packet metadata | Can reveal who talked to whom, when, and on which ports |
| Incident records and analyst notes | Coursework evidence; may contain IPs and observations |
| Host firewall state | The response feature can insert `iptables` rules |
| Capture privileges | Sniffing requires `CAP_NET_RAW` or root |
| Integrity of displayed evidence | A fake incident or fake "blocked" badge would mislead an analyst |
| Availability of the local service | A crash or resource exhaustion ends the demo |

Non-assets: there are no user accounts, passwords, API keys, or payment data. Packet
payloads are never captured or stored by NetShield.

## 2. Actors and trust boundaries

| Actor | Trust |
|---|---|
| Local operator running the server | Trusted; has filesystem and process control |
| Browser on the same machine | Trusted-ish; the server has no auth, so any local process can call the API |
| Anyone who can reach the bound port | **Untrusted** if the operator binds beyond loopback |
| Uploaded PCAP file | Untrusted input |
| Observed network traffic | Untrusted data; fields may be spoofed or malformed |
| Synthetic demo traffic | Trusted code, but must be labelled so it is not mistaken for evidence |

Trust boundaries: browser -> HTTP API, upload file -> PCAP parser, packet -> detector,
detector output -> SQLite, incident text -> CSV and HTML.

## 3. Threats and controls

### T1. Presenting demo data as real evidence

**Threat:** a viewer believes synthetic incidents were observed on the network.

**Controls:** the synthetic source is explicitly labelled; the pipeline sets
`data_origin = demonstration` on every alert and packet; the UI shows a
"demonstration data" badge and per-row tags; the demo page text says no packets are
sent. `packets.origin`, `incidents.data_origin`, and `data_origin` are separate from
capture state.

**Residual:** a screenshot can be cropped. The badge is a UI-level control.

### T2. Unauthorized capture

**Threat:** the tool is pointed at traffic the operator is not authorized to observe.

**Controls:** no capture starts automatically; live mode requires an explicit interface
and `confirm_authorization: true`; the server binds to `127.0.0.1` by default and warns
when that changes; README, runbook, and demo script state the authorization rule.
The recommended privilege model is `setcap cap_net_raw` on the interpreter, not a
root-owned web server.

**Residual:** technical controls cannot grant legal authorization. This is a policy and
ethics control, and the tool cannot verify it.

### T3. Abusing the response feature

**Threat:** an attacker (or a mistaken operator) uses the app to block arbitrary hosts,
including the operator's own gateway or a public service.

**Controls (all must pass, in `responses.py`):**

1. `safe_response.enabled = true` (default false).
2. Target parses as an IP and is inside `safe_response.allowed_cidrs` (RFC 1918/loopback by default).
3. For real changes: `allow_firewall_changes = true`.
4. For real changes: effective UID 0.
5. For real changes: `iptables` exists.
6. For real changes: `confirm_token` equals exactly `BLOCK <ip>` or `UNBLOCK <ip>`.

Simulated actions pass gates 1-2 only; real actions must pass all six.

Every attempt is recorded in `response_actions` with mode and applied flag. Simulated
blocks are capped at 500 and affect display only.

**Residual:** root plus the explicit flag is a deliberate, documented escape hatch.
An operator who enables all gates can still block a lab address. The app refuses
non-lab targets, but "lab" is defined by configuration.

### T4. Malicious upload

**Threat:** a crafted file causes code execution, path traversal, or resource
exhaustion.

**Controls:** extension allow-list (`.pcap`, `.pcapng`, `.cap`), `secure_filename`,
server-generated destination name inside `data/pcap`, 25 MiB request limit, capture
signature check before ingestion, deletion of rejected files, `scapy` parsing inside
per-packet exception handling, and a 200,000-packet cap per run. Capture paths supplied
to the API are resolved and must stay inside `data/pcap` or `tests/fixtures`.

**Residual:** a very large but valid PCAP up to the upload limit is intentionally
processable; that is a local denial-of-service vector for the operator only.

### T5. Stored/reflected XSS through captured fields

**Threat:** packet fields or analyst notes contain `<script>` and execute in the
dashboard.

**Controls:** Jinja autoescaping for templates; incident data is fetched as JSON and
inserted with `textContent` or escaped via `escapeHtml` before `innerHTML`; the CSP is
`script-src 'self'` with no `unsafe-inline`, so inline event handlers and injected
scripts do not run. No CDN scripts are loaded.

**Residual:** a compromised local static file would bypass CSP. The repository is the
trust boundary.

### T6. CSV formula injection

**Threat:** a value beginning with `=`, `+`, `-`, or `@` executes when the export is
opened in a spreadsheet.

**Controls:** `export_csv` prefixes such leading characters with an apostrophe, applies
quoted CSV writer escaping, and honours the same filters as the UI. Verified by tests.

### T7. SQL injection

**Threat:** filters or notes alter SQL.

**Controls:** all queries use SQLite parameters; filter values are validated and
bounded (`per_page` max 500, enums for severity/status/rule, text length limits); sort
order is fixed in code, never taken from the request.

### T8. Exposure of an unauthenticated admin surface

**Threat:** anyone on the LAN starts captures, changes thresholds, or triggers response
actions.

**Controls:** default bind is loopback; `run.py` prints a warning when binding beyond
loopback; the README and UI state there is no login. There is no CSRF token because
there are no cookies or sessions that grant authority; the API is same-origin and
loopback-only by default.

**Residual:** if bound to `0.0.0.0`, any reachable client has full control. This is
documented as unsupported for shared networks.

### T9. Misleading detection output

**Threat:** a heuristic alert is treated as proof and used to accuse a host.

**Controls:** titles use "possible"; every alert carries `evidence_sufficient`,
observed-vs-required facts, and the rule's caveat; the evidence gate caps ambiguous
alerts at medium; `docs/RULES.md` lists known false positives; no accuracy percentages
or confidence scores are shown.

**Residual:** human interpretation. The tool cannot prevent overconfidence.

### T10. Privacy leakage through retention

**Threat:** packet metadata accumulates beyond the exercise.

**Controls:** metadata only (no payload, DNS names, or MAC addresses); packet retention
defaults to 7 days and is pruned during capture; incidents are retained deliberately as
coursework evidence; the database path and uploads are gitignored.

**Residual:** incidents and notes are kept indefinitely by design. Operators should
delete the database after the exercise if the addresses are sensitive.

### T11. Privilege escalation through capture setup

**Threat:** running the whole web app as root exposes more than needed.

**Controls:** the runbook recommends `setcap cap_net_raw+eip` on the venv interpreter
and documents how to remove it. The app itself does not modify capabilities, sudoers,
or system services.

**Residual:** `setcap` on a Python interpreter lets any code run by that interpreter
sniff packets. Use a dedicated venv, not the system Python.

### T12. Command injection in the firewall path

**Threat:** the target IP is interpolated into a shell command.

**Controls:** the target is parsed with `ipaddress.ip_address` and normalised; the
`iptables` path is fixed; the command is executed as an argv list with `shell=False`;
the confirmation token must match the exact normalised command.

## 4. Data flow summary

```text
untrusted pcap/live packet
  -> parser (bounded, per-packet try/except), metadata only
  -> bounded queue (10,000)
  -> detectors/scorer (pure, in-memory)
  -> SQLite (parameterised, WAL, UNIQUE fingerprint)
  -> JSON API (validated query params, envelope)
  -> dashboard (Jinja autoescape, CSP self-only, textContent/escapeHtml)
  -> optional CSV (formula-injection guard)
  -> optional response (four gates + token, lab CIDR only)
```

## 5. Out of scope

- Multi-user authentication, RBAC, audit of who did what.
- TLS termination; run behind a local reverse proxy if remote access is ever required.
- Payload-level IDS, malware detection, TLS inspection.
- Distributed capture, high-availability, long-term forensic storage.
- Windows live capture and non-Linux firewall backends.
- Protection of the host from a malicious local operator; that actor already has root or
  the filesystem.

## 6. Deployment guidance

1. Keep the default loopback bind. If a demo needs another machine, use an SSH tunnel,
   not `0.0.0.0`.
2. Use a scratch database for demos and delete it afterwards.
3. Leave `safe_response.enabled = false` unless the exercise specifically covers
   response, and never enable firewall changes outside a disposable lab VM.
4. Grant capture capability to the venv interpreter only, and remove it after the
   exercise.
5. Treat every alert as a hypothesis; read `evidence_sufficient` and the reasons first.
6. Review `data/pcap` and the database before sharing the project directory.
