-- ─────────────────────────────────────────────────────────────────────────────
-- SOC Platform — PostgreSQL schema
-- Runs once on first container start via docker-entrypoint-initdb.d
-- ─────────────────────────────────────────────────────────────────────────────

\c socdb;

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- fuzzy text search on IPs/usernames

-- ─── log_events ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS log_events (
    event_id     UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    username     TEXT         NOT NULL,
    source_ip    INET         NOT NULL,
    event_type   TEXT         NOT NULL,   -- login_success | login_failed | file_access | …
    geo_country  CHAR(2),
    hostname     TEXT,
    label        SMALLINT     NOT NULL DEFAULT 0 CHECK (label IN (0,1)),
    bytes_read   BIGINT       DEFAULT 0,
    is_sensitive SMALLINT     DEFAULT 0,
    mfa_used     TEXT,
    metadata     JSONB        DEFAULT '{}'
);

CREATE INDEX idx_log_events_timestamp  ON log_events (timestamp DESC);
CREATE INDEX idx_log_events_source_ip  ON log_events (source_ip);
CREATE INDEX idx_log_events_username   ON log_events (username);
CREATE INDEX idx_log_events_event_type ON log_events (event_type);
CREATE INDEX idx_log_events_label      ON log_events (label);
CREATE INDEX idx_log_events_country    ON log_events (geo_country);

-- ─── threats ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threats (
    threat_id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    detected_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    event_id            UUID         REFERENCES log_events(event_id) ON DELETE SET NULL,
    source_ip           INET         NOT NULL,
    username            TEXT         NOT NULL,
    anomaly_score       NUMERIC(6,2) NOT NULL CHECK (anomaly_score BETWEEN 0 AND 100),
    threat_category     TEXT         NOT NULL,
    primary_confidence  NUMERIC(5,4) NOT NULL CHECK (primary_confidence BETWEEN 0 AND 1),
    severity            TEXT         NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    mitre_techniques    TEXT[]       DEFAULT '{}',
    rule_matches        JSONB        DEFAULT '[]',
    is_resolved         BOOLEAN      NOT NULL DEFAULT FALSE,
    resolved_at         TIMESTAMPTZ
);

CREATE INDEX idx_threats_detected_at    ON threats (detected_at DESC);
CREATE INDEX idx_threats_severity       ON threats (severity);
CREATE INDEX idx_threats_category       ON threats (threat_category);
CREATE INDEX idx_threats_source_ip      ON threats (source_ip);
CREATE INDEX idx_threats_username       ON threats (username);
CREATE INDEX idx_threats_anomaly_score  ON threats (anomaly_score DESC);
CREATE INDEX idx_threats_unresolved     ON threats (is_resolved) WHERE is_resolved = FALSE;

-- ─── alerts ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    threat_id       UUID         REFERENCES threats(threat_id) ON DELETE CASCADE,
    severity        TEXT         NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    title           TEXT         NOT NULL,
    description     TEXT,
    source_ip       INET         NOT NULL,
    username        TEXT         NOT NULL,
    category        TEXT         NOT NULL,
    actions_taken   TEXT[]       DEFAULT '{}',
    action_results  JSONB        DEFAULT '[]',
    status          TEXT         NOT NULL DEFAULT 'open'
                                 CHECK (status IN ('open','acknowledged','resolved')),
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX idx_alerts_severity   ON alerts (severity);
CREATE INDEX idx_alerts_status     ON alerts (status);
CREATE INDEX idx_alerts_category   ON alerts (category);
CREATE INDEX idx_alerts_open       ON alerts (status) WHERE status = 'open';

-- ─── response_actions ────────────────────────────────────────────────────────
-- Immutable audit log of every SOAR action ever executed
CREATE TABLE IF NOT EXISTS response_actions (
    action_id    UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    executed_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    alert_id     UUID         REFERENCES alerts(alert_id) ON DELETE SET NULL,
    action_type  TEXT         NOT NULL,
    target       TEXT         NOT NULL,
    status       TEXT         NOT NULL CHECK (status IN ('success','failed','simulated','skipped')),
    duration_ms  NUMERIC(10,2),
    message      TEXT,
    metadata     JSONB        DEFAULT '{}'
);

CREATE INDEX idx_actions_executed_at ON response_actions (executed_at DESC);
CREATE INDEX idx_actions_alert_id    ON response_actions (alert_id);
CREATE INDEX idx_actions_type        ON response_actions (action_type);
CREATE INDEX idx_actions_target      ON response_actions (target);

-- ─── blocked_ips ─────────────────────────────────────────────────────────────
-- Active firewall blocks (populated by block_ip action)
CREATE TABLE IF NOT EXISTS blocked_ips (
    id            SERIAL       PRIMARY KEY,
    ip_address    INET         NOT NULL UNIQUE,
    blocked_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ,
    reason        TEXT,
    blocked_by    TEXT,        -- rule name that triggered the block
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_blocked_ips_active ON blocked_ips (ip_address) WHERE is_active = TRUE;
CREATE INDEX idx_blocked_ips_expiry ON blocked_ips (expires_at) WHERE is_active = TRUE;

-- ─── disabled_accounts ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS disabled_accounts (
    id                   SERIAL       PRIMARY KEY,
    username             TEXT         NOT NULL UNIQUE,
    disabled_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    reason               TEXT,
    force_password_reset BOOLEAN      NOT NULL DEFAULT TRUE,
    is_active_disable    BOOLEAN      NOT NULL DEFAULT TRUE,
    re_enabled_at        TIMESTAMPTZ
);

-- ─── Seed: demo data so the dashboard has something to show immediately ───────
-- (idempotent — uses ON CONFLICT DO NOTHING)

INSERT INTO log_events (event_id, timestamp, username, source_ip, event_type, geo_country, hostname, label)
VALUES
    ('00000000-0000-0000-0000-000000000001', NOW() - INTERVAL '2 hours',  'alice',  '10.0.1.15',       'login_success', 'US', 'workstation-alice', 0),
    ('00000000-0000-0000-0000-000000000002', NOW() - INTERVAL '90 minutes','bob',   '10.0.1.22',       'file_access',   'US', 'server-01',         0),
    ('00000000-0000-0000-0000-000000000003', NOW() - INTERVAL '1 hour',   'alice',  '185.220.101.15',  'login_failed',  'RU', 'server-01',         1),
    ('00000000-0000-0000-0000-000000000004', NOW() - INTERVAL '45 minutes','carol', '203.0.113.42',    'admin_access',  'CN', 'server-02',         1)
ON CONFLICT DO NOTHING;

-- ─── Views ────────────────────────────────────────────────────────────────────

-- Recent open alerts with threat details (used by GET /api/v1/alerts)
CREATE OR REPLACE VIEW v_open_alerts AS
SELECT
    a.alert_id, a.created_at, a.severity, a.title,
    a.description, a.source_ip, a.username, a.category,
    a.actions_taken, a.status,
    t.anomaly_score, t.mitre_techniques, t.primary_confidence
FROM alerts a
LEFT JOIN threats t ON a.threat_id = t.threat_id
WHERE a.status = 'open'
ORDER BY a.created_at DESC;

-- Dashboard stats summary (used by GET /api/v1/stats)
CREATE OR REPLACE VIEW v_dashboard_stats AS
SELECT
    (SELECT COUNT(*)                    FROM log_events)             AS total_logs,
    (SELECT COUNT(*)                    FROM threats)                AS total_threats,
    (SELECT COUNT(*)                    FROM alerts)                 AS total_alerts,
    (SELECT COUNT(*)                    FROM alerts WHERE status='open') AS open_alerts,
    (SELECT COUNT(*) FROM threats WHERE severity='CRITICAL')        AS critical_count,
    (SELECT COUNT(*) FROM threats WHERE severity='HIGH')            AS high_count,
    (SELECT COUNT(*) FROM blocked_ips   WHERE is_active=TRUE)       AS active_blocks,
    (SELECT COUNT(*) FROM disabled_accounts WHERE is_active_disable=TRUE) AS disabled_accounts;

COMMENT ON TABLE log_events        IS 'Raw ingested log events from Filebeat/Kafka/simulator';
COMMENT ON TABLE threats           IS 'ML-detected threat records with classification results';
COMMENT ON TABLE alerts            IS 'Security alerts dispatched to SOC analysts';
COMMENT ON TABLE response_actions  IS 'Immutable audit log of all SOAR actions';
COMMENT ON TABLE blocked_ips       IS 'Currently active IP firewall blocks';
COMMENT ON TABLE disabled_accounts IS 'Currently disabled user accounts';
