-- Spectre schema v1. Timestamps are RFC 3339 UTC text; identifiers are UUID text.

CREATE TABLE investigations (
    id              TEXT PRIMARY KEY NOT NULL,
    target_type     TEXT NOT NULL CHECK (target_type IN ('username', 'email', 'phone', 'domain')),
    target_value    TEXT NOT NULL,
    purpose         TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'partially_completed', 'failed', 'cancelled')),
    progress        REAL NOT NULL DEFAULT 0,
    providers_json  TEXT NOT NULL DEFAULT '[]',
    metrics_json    TEXT,
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    completed_at    TEXT
);
CREATE INDEX idx_investigations_created_at ON investigations (created_at DESC);
CREATE INDEX idx_investigations_target ON investigations (target_type, target_value);

CREATE TABLE investigation_targets (
    id                TEXT PRIMARY KEY NOT NULL,
    investigation_id  TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
    target_type       TEXT NOT NULL,
    normalized_value  TEXT NOT NULL,
    role              TEXT NOT NULL CHECK (role IN ('primary', 'derived')),
    created_at        TEXT NOT NULL
);
CREATE INDEX idx_investigation_targets_value ON investigation_targets (target_type, normalized_value);
CREATE INDEX idx_investigation_targets_investigation ON investigation_targets (investigation_id);

CREATE TABLE investigation_errors (
    id                TEXT PRIMARY KEY NOT NULL,
    investigation_id  TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
    provider_id       TEXT NOT NULL,
    code              TEXT NOT NULL,
    message           TEXT NOT NULL,
    occurred_at       TEXT NOT NULL
);
CREATE INDEX idx_investigation_errors_investigation ON investigation_errors (investigation_id);

CREATE TABLE findings (
    id                   TEXT PRIMARY KEY NOT NULL,
    investigation_id     TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
    provider_id          TEXT NOT NULL,
    kind                 TEXT NOT NULL,
    title                TEXT NOT NULL,
    summary              TEXT,
    confidence           REAL NOT NULL,
    category             TEXT NOT NULL,
    rationale_json       TEXT NOT NULL DEFAULT '[]',
    verification_status  TEXT NOT NULL,
    data_json            TEXT NOT NULL,
    discovered_at        TEXT NOT NULL
);
CREATE INDEX idx_findings_investigation ON findings (investigation_id, discovered_at);
CREATE INDEX idx_findings_kind ON findings (kind);
CREATE INDEX idx_findings_provider ON findings (provider_id);

CREATE TABLE finding_sources (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id     TEXT NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    provider_id    TEXT NOT NULL,
    provider_name  TEXT NOT NULL,
    url            TEXT,
    method         TEXT NOT NULL,
    retrieved_at   TEXT NOT NULL
);
CREATE INDEX idx_finding_sources_finding ON finding_sources (finding_id);

CREATE TABLE profiles (
    id                TEXT PRIMARY KEY NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    investigation_id  TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
    platform          TEXT NOT NULL,
    username          TEXT NOT NULL,
    profile_url       TEXT NOT NULL,
    display_name      TEXT,
    platform_verified INTEGER NOT NULL DEFAULT 0,
    confidence        REAL NOT NULL,
    discovered_at     TEXT NOT NULL
);
CREATE INDEX idx_profiles_platform_username ON profiles (platform, username COLLATE NOCASE);
CREATE INDEX idx_profiles_investigation ON profiles (investigation_id);

CREATE TABLE identities (
    id                TEXT PRIMARY KEY NOT NULL,
    investigation_id  TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
    kind              TEXT NOT NULL,
    label             TEXT NOT NULL,
    value             TEXT NOT NULL,
    platform          TEXT,
    finding_id        TEXT,
    is_target         INTEGER NOT NULL DEFAULT 0,
    verified          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_identities_investigation ON identities (investigation_id);
CREATE INDEX idx_identities_value ON identities (kind, value);

CREATE TABLE identity_relationships (
    id                     TEXT PRIMARY KEY NOT NULL,
    investigation_id       TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
    source_identity        TEXT NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    target_identity        TEXT NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    relationship           TEXT NOT NULL,
    confidence             REAL NOT NULL,
    category               TEXT NOT NULL,
    evidence_json          TEXT NOT NULL,
    verified               INTEGER NOT NULL DEFAULT 0,
    investigator_decision  TEXT CHECK (investigator_decision IN ('confirmed', 'rejected')),
    decided_at             TEXT
);
CREATE INDEX idx_relationships_investigation ON identity_relationships (investigation_id);
CREATE INDEX idx_relationships_category ON identity_relationships (category);

CREATE TABLE email_addresses (
    id                    TEXT PRIMARY KEY NOT NULL,
    email                 TEXT NOT NULL UNIQUE,
    verification_status   TEXT NOT NULL,
    verification_method   TEXT,
    attestation           TEXT,
    verified_at           TEXT,
    last_breach_check_at  TEXT,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);

CREATE TABLE phone_numbers (
    id                    TEXT PRIMARY KEY NOT NULL,
    e164                  TEXT NOT NULL UNIQUE,
    country_calling_code  INTEGER NOT NULL,
    region_code           TEXT,
    number_type           TEXT NOT NULL,
    verification_status   TEXT NOT NULL,
    created_at            TEXT NOT NULL
);

CREATE TABLE domains (
    id                     TEXT PRIMARY KEY NOT NULL,
    domain                 TEXT NOT NULL UNIQUE,
    verification_status    TEXT NOT NULL,
    verification_method    TEXT,
    challenge_value        TEXT,
    challenge_record_name  TEXT,
    verified_at            TEXT,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL
);

CREATE TABLE breach_incidents (
    name           TEXT PRIMARY KEY NOT NULL,
    title          TEXT NOT NULL,
    domain         TEXT,
    breach_date    TEXT,
    pwn_count      INTEGER NOT NULL DEFAULT 0,
    incident_json  TEXT NOT NULL,
    fetched_at     TEXT NOT NULL
);
CREATE INDEX idx_breach_incidents_domain ON breach_incidents (domain);
CREATE INDEX idx_breach_incidents_date ON breach_incidents (breach_date);

CREATE TABLE breach_exposures (
    id           TEXT PRIMARY KEY NOT NULL,
    email_id     TEXT NOT NULL REFERENCES email_addresses (id) ON DELETE CASCADE,
    breach_name  TEXT NOT NULL REFERENCES breach_incidents (name) ON DELETE CASCADE,
    checked_at   TEXT NOT NULL,
    UNIQUE (email_id, breach_name)
);
CREATE INDEX idx_breach_exposures_email ON breach_exposures (email_id);

CREATE TABLE provider_configs (
    provider_id            TEXT PRIMARY KEY NOT NULL,
    enabled                INTEGER NOT NULL DEFAULT 1,
    rate_limit_per_minute  INTEGER,
    updated_at             TEXT NOT NULL
);

-- Audit events intentionally have no foreign key: they outlive deleted
-- investigations and never contain passwords, hashes, or API keys.
CREATE TABLE audit_events (
    id                TEXT PRIMARY KEY NOT NULL,
    investigation_id  TEXT,
    event_type        TEXT NOT NULL,
    detail_json       TEXT NOT NULL DEFAULT '{}',
    created_at        TEXT NOT NULL
);
CREATE INDEX idx_audit_events_created ON audit_events (created_at DESC);
CREATE INDEX idx_audit_events_investigation ON audit_events (investigation_id);

CREATE TABLE engine_settings (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    settings_json  TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
