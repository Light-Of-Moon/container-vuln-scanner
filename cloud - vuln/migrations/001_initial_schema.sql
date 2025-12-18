-- =============================================================================
-- Container Vulnerability Scanner - Database Schema
-- =============================================================================
-- Principal Architect: Production-grade PostgreSQL schema
-- Version: 1.0.0
-- 
-- DEPLOYMENT NOTES:
-- 1. Run as database owner or superuser
-- 2. Ensure pg_trgm extension is enabled for text search (optional)
-- 3. Consider table partitioning for high-volume deployments (>1M scans)
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";      -- UUID generation
CREATE EXTENSION IF NOT EXISTS "pg_trgm";        -- Trigram text search (optional)

-- =============================================================================
-- ENUM TYPES
-- =============================================================================

-- Scan lifecycle states
DO $$ BEGIN
    CREATE TYPE scan_status AS ENUM (
        'pending',      -- Queued, waiting for worker
        'pulling',      -- Pulling Docker image
        'scanning',     -- Trivy scan in progress
        'parsing',      -- Processing Trivy JSON output
        'completed',    -- Scan finished successfully
        'failed'        -- Scan failed
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- CVE severity levels (NVD standard)
DO $$ BEGIN
    CREATE TYPE severity_level AS ENUM (
        'CRITICAL',     -- CVSS 9.0-10.0
        'HIGH',         -- CVSS 7.0-8.9
        'MEDIUM',       -- CVSS 4.0-6.9
        'LOW',          -- CVSS 0.1-3.9
        'UNKNOWN'       -- No CVSS score available
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Compliance classification
DO $$ BEGIN
    CREATE TYPE compliance_status AS ENUM (
        'compliant',        -- No Critical/High vulnerabilities
        'non_compliant',    -- Has Critical or High vulnerabilities
        'pending_review'    -- Only Medium/Low (needs manual review)
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- =============================================================================
-- PRIMARY TABLE: vulnerability_scans
-- =============================================================================

CREATE TABLE IF NOT EXISTS vulnerability_scans (
    -- Primary Key & Identifiers
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    idempotency_key         VARCHAR(64) UNIQUE,
    
    -- Image Identification
    image_name              VARCHAR(255) NOT NULL,
    image_tag               VARCHAR(128) NOT NULL DEFAULT 'latest',
    image_digest            VARCHAR(128),
    registry                VARCHAR(255) NOT NULL DEFAULT 'docker.io',
    
    -- Scan Lifecycle State
    status                  scan_status NOT NULL DEFAULT 'pending',
    error_message           TEXT,
    error_code              VARCHAR(64),
    retry_count             INTEGER NOT NULL DEFAULT 0 
                            CHECK (retry_count >= 0 AND retry_count <= 10),
    
    -- Raw Scan Data (JSONB for flexibility)
    raw_report              JSONB,
    image_metadata          JSONB,
    
    -- Intelligence Metrics (Indexed for fast queries)
    critical_count          INTEGER NOT NULL DEFAULT 0 CHECK (critical_count >= 0),
    high_count              INTEGER NOT NULL DEFAULT 0 CHECK (high_count >= 0),
    medium_count            INTEGER NOT NULL DEFAULT 0 CHECK (medium_count >= 0),
    low_count               INTEGER NOT NULL DEFAULT 0 CHECK (low_count >= 0),
    unknown_count           INTEGER NOT NULL DEFAULT 0 CHECK (unknown_count >= 0),
    total_vulnerabilities   INTEGER NOT NULL DEFAULT 0 CHECK (total_vulnerabilities >= 0),
    fixable_count           INTEGER NOT NULL DEFAULT 0 CHECK (fixable_count >= 0),
    unfixable_count         INTEGER NOT NULL DEFAULT 0 CHECK (unfixable_count >= 0),
    
    -- Risk Scoring
    risk_score              INTEGER NOT NULL DEFAULT 0 CHECK (risk_score >= 0),
    max_cvss_score          FLOAT,
    avg_cvss_score          FLOAT,
    
    -- Compliance Flags
    is_compliant            BOOLEAN NOT NULL DEFAULT FALSE,
    compliance_status       compliance_status NOT NULL DEFAULT 'pending_review',
    
    -- Timing Metrics
    scan_duration           FLOAT,
    pull_duration           FLOAT,
    analysis_duration       FLOAT,
    
    -- Audit Timestamps
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Worker Metadata
    worker_id               VARCHAR(64),
    trivy_version           VARCHAR(32)
);

-- Table comment
COMMENT ON TABLE vulnerability_scans IS 'Primary table for container vulnerability scan results';

-- Column comments
COMMENT ON COLUMN vulnerability_scans.idempotency_key IS 'Hash of (image_name + tag + timestamp_bucket) for deduplication';
COMMENT ON COLUMN vulnerability_scans.raw_report IS 'Complete Trivy JSON output (preserved for audit)';
COMMENT ON COLUMN vulnerability_scans.risk_score IS 'Weighted risk score: Critical=100, High=50, Medium=10, Low=1';
COMMENT ON COLUMN vulnerability_scans.is_compliant IS 'True if no Critical/High CVEs found';

-- =============================================================================
-- INDEXES: vulnerability_scans
-- =============================================================================

-- Single column indexes for common filters
CREATE INDEX IF NOT EXISTS ix_scans_image_name ON vulnerability_scans (image_name);
CREATE INDEX IF NOT EXISTS ix_scans_status ON vulnerability_scans (status);
CREATE INDEX IF NOT EXISTS ix_scans_created_at ON vulnerability_scans (created_at);
CREATE INDEX IF NOT EXISTS ix_scans_risk_score ON vulnerability_scans (risk_score);
CREATE INDEX IF NOT EXISTS ix_scans_is_compliant ON vulnerability_scans (is_compliant);
CREATE INDEX IF NOT EXISTS ix_scans_critical_count ON vulnerability_scans (critical_count);
CREATE INDEX IF NOT EXISTS ix_scans_image_digest ON vulnerability_scans (image_digest);
CREATE INDEX IF NOT EXISTS ix_scans_idempotency ON vulnerability_scans (idempotency_key);

-- Composite index for historical trend queries
-- Query pattern: "Show me all scans for nginx:latest over the past 30 days"
CREATE INDEX IF NOT EXISTS ix_scans_image_history 
    ON vulnerability_scans (image_name, image_tag, created_at DESC);

-- Composite index for compliance dashboards
-- Query pattern: "Show me all non-compliant images with critical vulnerabilities"
CREATE INDEX IF NOT EXISTS ix_scans_compliance_filter 
    ON vulnerability_scans (is_compliant, critical_count DESC, created_at DESC);

-- Partial index for failed scans (retry queue)
-- Only indexes rows where status = 'failed' AND retry_count < 3
CREATE INDEX IF NOT EXISTS ix_scans_retry_queue 
    ON vulnerability_scans (status, retry_count, created_at)
    WHERE status = 'failed' AND retry_count < 3;

-- Partial index for pending scans (worker pickup queue)
CREATE INDEX IF NOT EXISTS ix_scans_pending_queue 
    ON vulnerability_scans (status, created_at)
    WHERE status = 'pending';

-- GIN index for JSONB queries on raw_report
-- Enables: SELECT * FROM vulnerability_scans WHERE raw_report @> '{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1234"}]}]}'
CREATE INDEX IF NOT EXISTS ix_scans_raw_report_gin 
    ON vulnerability_scans USING GIN (raw_report jsonb_path_ops);

-- =============================================================================
-- TABLE: vulnerability_details (Denormalized for fast CVE lookups)
-- =============================================================================

CREATE TABLE IF NOT EXISTS vulnerability_details (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id                 UUID NOT NULL REFERENCES vulnerability_scans(id) ON DELETE CASCADE,
    
    -- CVE identification
    vulnerability_id        VARCHAR(64) NOT NULL,
    
    -- Affected package
    package_name            VARCHAR(255) NOT NULL,
    package_version         VARCHAR(64) NOT NULL,
    fixed_version           VARCHAR(64),
    
    -- Severity
    severity                severity_level NOT NULL,
    cvss_score              FLOAT,
    
    -- Flags
    is_fixable              BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Timestamps
    published_date          TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE vulnerability_details IS 'Denormalized vulnerability details for fast CVE lookups';

-- Indexes for vulnerability_details
CREATE INDEX IF NOT EXISTS ix_vuln_scan_id ON vulnerability_details (scan_id);
CREATE INDEX IF NOT EXISTS ix_vuln_cve_id ON vulnerability_details (vulnerability_id);
CREATE INDEX IF NOT EXISTS ix_vuln_severity ON vulnerability_details (severity);
CREATE INDEX IF NOT EXISTS ix_vuln_cvss ON vulnerability_details (cvss_score);
CREATE INDEX IF NOT EXISTS ix_vuln_package ON vulnerability_details (package_name);
CREATE INDEX IF NOT EXISTS ix_vuln_fixable ON vulnerability_details (is_fixable);

-- Composite index for CVE impact analysis
-- Query pattern: "Find all images affected by CVE-2024-XXXX"
CREATE INDEX IF NOT EXISTS ix_vuln_cve_lookup 
    ON vulnerability_details (vulnerability_id, severity);

-- Composite index for package analysis
CREATE INDEX IF NOT EXISTS ix_vuln_package_lookup 
    ON vulnerability_details (package_name, package_version);

-- =============================================================================
-- TABLE: scan_audit_logs (State transition audit trail)
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_audit_logs (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id                 UUID NOT NULL REFERENCES vulnerability_scans(id) ON DELETE CASCADE,
    
    -- State transition
    previous_status         scan_status,
    new_status              scan_status NOT NULL,
    
    -- Context
    message                 TEXT,
    metadata                JSONB,
    
    -- Actor
    triggered_by            VARCHAR(128),
    
    -- Timestamp
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE scan_audit_logs IS 'Audit trail for scan state transitions';

-- Indexes for audit logs
CREATE INDEX IF NOT EXISTS ix_audit_scan_id ON scan_audit_logs (scan_id);
CREATE INDEX IF NOT EXISTS ix_audit_created_at ON scan_audit_logs (created_at);
CREATE INDEX IF NOT EXISTS ix_audit_scan_timeline ON scan_audit_logs (scan_id, created_at);

-- =============================================================================
-- FUNCTIONS: Auto-update updated_at timestamp
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for vulnerability_scans
DROP TRIGGER IF EXISTS trg_scans_updated_at ON vulnerability_scans;
CREATE TRIGGER trg_scans_updated_at
    BEFORE UPDATE ON vulnerability_scans
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- FUNCTIONS: Calculate risk score (can be used in triggers or queries)
-- =============================================================================

CREATE OR REPLACE FUNCTION calculate_risk_score(
    p_critical INTEGER,
    p_high INTEGER,
    p_medium INTEGER,
    p_low INTEGER
) RETURNS INTEGER AS $$
BEGIN
    -- Defense University Risk Scoring Formula:
    -- Critical=100, High=50, Medium=10, Low=1
    RETURN (p_critical * 100) + (p_high * 50) + (p_medium * 10) + (p_low * 1);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- FUNCTIONS: Determine compliance status
-- =============================================================================

CREATE OR REPLACE FUNCTION determine_compliance_status(
    p_critical INTEGER,
    p_high INTEGER,
    p_medium INTEGER,
    p_low INTEGER
) RETURNS compliance_status AS $$
BEGIN
    IF p_critical > 0 OR p_high > 0 THEN
        RETURN 'non_compliant';
    ELSIF p_medium > 0 OR p_low > 0 THEN
        RETURN 'pending_review';
    ELSE
        RETURN 'compliant';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- VIEW: Latest scan per image (for dashboard)
-- =============================================================================

CREATE OR REPLACE VIEW latest_scans AS
SELECT DISTINCT ON (image_name, image_tag)
    id,
    image_name,
    image_tag,
    registry,
    status,
    risk_score,
    is_compliant,
    compliance_status,
    critical_count,
    high_count,
    medium_count,
    low_count,
    total_vulnerabilities,
    fixable_count,
    scan_duration,
    created_at,
    completed_at
FROM vulnerability_scans
WHERE status = 'completed'
ORDER BY image_name, image_tag, created_at DESC;

COMMENT ON VIEW latest_scans IS 'Latest completed scan for each unique image:tag combination';

-- =============================================================================
-- VIEW: Vulnerability summary statistics
-- =============================================================================

CREATE OR REPLACE VIEW vulnerability_statistics AS
SELECT
    COUNT(*) AS total_scans,
    COUNT(*) FILTER (WHERE status = 'completed') AS completed_scans,
    COUNT(*) FILTER (WHERE status = 'failed') AS failed_scans,
    COUNT(*) FILTER (WHERE is_compliant = TRUE) AS compliant_scans,
    COUNT(*) FILTER (WHERE critical_count > 0) AS scans_with_critical,
    AVG(risk_score) FILTER (WHERE status = 'completed') AS avg_risk_score,
    SUM(total_vulnerabilities) FILTER (WHERE status = 'completed') AS total_vulnerabilities_found,
    SUM(critical_count) FILTER (WHERE status = 'completed') AS total_critical_cves,
    SUM(high_count) FILTER (WHERE status = 'completed') AS total_high_cves,
    AVG(scan_duration) FILTER (WHERE status = 'completed') AS avg_scan_duration
FROM vulnerability_scans
WHERE created_at >= NOW() - INTERVAL '30 days';

COMMENT ON VIEW vulnerability_statistics IS 'Aggregated vulnerability statistics for the past 30 days';

-- =============================================================================
-- GRANTS (Adjust based on your role setup)
-- =============================================================================

-- Uncomment and modify based on your PostgreSQL role configuration:
-- GRANT SELECT, INSERT, UPDATE, DELETE ON vulnerability_scans TO scanner_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON vulnerability_details TO scanner_app;
-- GRANT SELECT, INSERT ON scan_audit_logs TO scanner_app;
-- GRANT SELECT ON latest_scans TO scanner_app;
-- GRANT SELECT ON vulnerability_statistics TO scanner_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO scanner_app;
