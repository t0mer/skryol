-- Skryol initial schema. All timestamps are RFC3339 UTC strings.

CREATE TABLE assets (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL CHECK (type IN ('ip','fqdn','domain','cidr')),
    value       TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    rescan      INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (type, value)
);

CREATE TABLE shodan_keys (
    id              TEXT PRIMARY KEY,
    label           TEXT NOT NULL DEFAULT '',
    ciphertext      TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    rate_per_second REAL NOT NULL DEFAULT 1.0,
    query_credits   INTEGER NOT NULL DEFAULT 0,
    scan_credits    INTEGER NOT NULL DEFAULT 0,
    plan            TEXT NOT NULL DEFAULT '',
    health          TEXT NOT NULL DEFAULT 'unknown',
    last_error      TEXT NOT NULL DEFAULT '',
    last_used_at    TEXT,
    last_checked_at TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE scans (
    id            TEXT PRIMARY KEY,
    asset_id      TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT NOT NULL DEFAULT 'ok' CHECK (status IN ('ok','partial','failed')),
    score         INTEGER,
    grade         TEXT NOT NULL DEFAULT '',
    highest_cvss  REAL NOT NULL DEFAULT 0,
    cve_count     INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    open_ports_count INTEGER NOT NULL DEFAULT 0,
    score_delta   INTEGER,
    raw_json      TEXT NOT NULL DEFAULT '{}',
    error         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_scans_asset ON scans(asset_id, started_at);

CREATE TABLE findings (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_ip   TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL CHECK (kind IN ('port','cve','weakness','screenshot','smb_share','mqtt_topic','service','cert')),
    severity    TEXT NOT NULL DEFAULT '',
    cvss        REAL NOT NULL DEFAULT 0,
    key         TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_asset_kind ON findings(asset_id, kind);

CREATE TABLE score_history (
    id       TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    at       TEXT NOT NULL,
    score    INTEGER NOT NULL,
    grade    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_score_history_asset ON score_history(asset_id, at);

CREATE TABLE diffs (
    id           TEXT PRIMARY KEY,
    asset_id     TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    from_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
    to_scan_id   TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL
);
CREATE INDEX idx_diffs_asset ON diffs(asset_id, created_at);

CREATE TABLE channels (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL CHECK (type IN ('shoutrrr','greenapi','whatsapp_web')),
    label       TEXT NOT NULL DEFAULT '',
    ciphertext  TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    needs_credentials INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE alert_rules (
    id              TEXT PRIMARY KEY,
    scope           TEXT NOT NULL CHECK (scope IN ('global','asset')),
    asset_id        TEXT REFERENCES assets(id) ON DELETE CASCADE,
    condition       TEXT NOT NULL,
    params_json     TEXT NOT NULL DEFAULT '{}',
    enabled         INTEGER NOT NULL DEFAULT 1,
    cooldown_seconds INTEGER NOT NULL DEFAULT 3600,
    severity        TEXT NOT NULL DEFAULT 'info',
    label           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE alert_channel_map (
    rule_id    TEXT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, channel_id)
);

CREATE TABLE alert_events (
    id          TEXT PRIMARY KEY,
    rule_id     TEXT REFERENCES alert_rules(id) ON DELETE SET NULL,
    asset_id    TEXT REFERENCES assets(id) ON DELETE SET NULL,
    condition   TEXT NOT NULL,
    fired_at    TEXT NOT NULL,
    dedup_key   TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    delivered_json TEXT NOT NULL DEFAULT '{}',
    severity    TEXT NOT NULL DEFAULT 'info'
);
CREATE INDEX idx_alert_events_rule ON alert_events(rule_id, fired_at);
CREATE INDEX idx_alert_events_dedup ON alert_events(dedup_key, fired_at);

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE tokens (
    id          TEXT PRIMARY KEY,
    label       TEXT NOT NULL DEFAULT '',
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    data_json   TEXT NOT NULL DEFAULT '{}',
    updated_at  TEXT NOT NULL
);
INSERT INTO settings(id, data_json, updated_at) VALUES (1, '{}', '1970-01-01T00:00:00Z');
