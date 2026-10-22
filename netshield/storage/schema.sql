-- NetShield schema.
--
-- Design notes:
-- * incidents.fingerprint is UNIQUE: the durable half of duplicate suppression.
-- * packets stores metadata only. Payloads, DNS names and MAC addresses are
--   deliberately not stored: capturing real payloads creates a privacy and
--   retention liability that a teaching tool does not need.
-- * data_origin distinguishes real capture data from the labelled synthetic
--   demonstration so the dashboard never presents demo data as live evidence.

CREATE TABLE IF NOT EXISTS incidents (
  id                  TEXT PRIMARY KEY,
  fingerprint         TEXT NOT NULL UNIQUE,
  rule_id             TEXT NOT NULL,
  title               TEXT NOT NULL,
  severity            TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
  score               INTEGER NOT NULL,
  reasons_json        TEXT NOT NULL,
  evidence_json       TEXT NOT NULL,
  facts_json          TEXT NOT NULL,
  evidence_sufficient INTEGER NOT NULL,
  src_ip              TEXT,
  dst_ip              TEXT,
  detected_at         REAL NOT NULL,
  window_start        REAL NOT NULL,
  window_end          REAL NOT NULL,
  status              TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'acknowledged', 'resolved')),
  analyst_notes       TEXT,
  data_origin         TEXT NOT NULL DEFAULT 'real' CHECK (data_origin IN ('real', 'demonstration')),
  created_at          REAL NOT NULL,
  updated_at          REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_inc_detected ON incidents(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_inc_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_inc_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_inc_rule     ON incidents(rule_id);

CREATE TABLE IF NOT EXISTS incident_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  event_type  TEXT NOT NULL,
  detail      TEXT,
  created_at  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_event_incident ON incident_events(incident_id, created_at);

CREATE TABLE IF NOT EXISTS packets (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        REAL NOT NULL,
  src_ip    TEXT NOT NULL,
  dst_ip    TEXT NOT NULL,
  src_port  INTEGER,
  dst_port  INTEGER,
  protocol  TEXT NOT NULL,
  flags     TEXT,
  tcp_state TEXT,
  size      INTEGER NOT NULL,
  origin    TEXT NOT NULL,
  ingested_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pkt_ts   ON packets(ts DESC);
CREATE INDEX IF NOT EXISTS idx_pkt_src  ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_pkt_dst  ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_pkt_proto ON packets(protocol);
CREATE INDEX IF NOT EXISTS idx_pkt_ingested ON packets(ingested_at);

CREATE TABLE IF NOT EXISTS traffic_buckets (
  bucket_ts INTEGER PRIMARY KEY,
  packets   INTEGER NOT NULL,
  bytes     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS response_actions (
  id          TEXT PRIMARY KEY,
  incident_id TEXT,
  target_ip   TEXT NOT NULL,
  action      TEXT NOT NULL,
  applied     INTEGER NOT NULL,
  mode        TEXT NOT NULL,
  reason      TEXT,
  created_at  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_response_created ON response_actions(created_at DESC);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
