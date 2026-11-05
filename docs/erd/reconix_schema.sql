-- Reconix ERD V3 (Final), written as PostgreSQL DDL.
-- Source: docs/erd/reconix-erd-v3-final.md (16 tables, 13 enums).
-- A readable copy of the schema the Alembic migrations make (up to revision b7c1d2e3f4a5),
-- checked to give the same columns, constraints, indexes and enums. To change the database,
-- add a migration in services/api/alembic/versions/ and update this file; never the reverse.
-- Load it into an empty database: psql -f docs/erd/reconix_schema.sql
-- It has no alembic_version table: on a database the API will manage, run
-- `alembic -c services/api/alembic.ini stamp head` afterwards.

BEGIN;

-- 1. Enums -----------------------------------------------------------------------------------

CREATE TYPE session_status AS ENUM ('ACTIVE', 'CLOSED');
CREATE TYPE assessment_status AS ENUM ('DRAFT', 'ACTIVE', 'COMPLETED', 'CANCELLED');
CREATE TYPE manifests_status AS ENUM ('DRAFT', 'APPROVED', 'REJECTED');
CREATE TYPE tool_run_status AS ENUM
    ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT', 'CANCELLED');
CREATE TYPE action_status AS ENUM
    ('PENDING', 'APPROVED', 'REJECTED', 'COMPLETED', 'FAILED', 'CANCELLED', 'BLOCKED');
CREATE TYPE risk_level AS ENUM ('LOW', 'MEDIUM', 'HIGH');
CREATE TYPE validation_status AS ENUM ('CONFIRMED', 'UNCONFIRMED', 'INCONCLUSIVE');
CREATE TYPE approval_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED');
CREATE TYPE finding_status AS ENUM ('OPEN', 'FALSE_POSITIVE', 'FIXED');
CREATE TYPE agent_runs_status AS ENUM
    ('RUNNING', 'WAITING_APPROVAL', 'COMPLETED', 'FAILED', 'CANCELLED');
CREATE TYPE severity_status AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE');
CREATE TYPE provider_type AS ENUM
    ('RECONIX', 'OPENAI', 'ANTHROPIC', 'DEEPSEEK', 'OLLAMA', 'OPENAI_API_COMPATIBLE');
CREATE TYPE report_status AS ENUM ('GENERATING', 'READY', 'FAILED');

-- 2. Tables ----------------------------------------------------------------------------------

-- 2.1 One chat session from the web, the CLI or VS Code.
CREATE TABLE sessions (
    session_id      UUID           NOT NULL DEFAULT gen_random_uuid(),
    interface       VARCHAR(20)    NOT NULL,                     -- web, cli or vscode
    session_status  session_status NOT NULL DEFAULT 'ACTIVE',
    created_at      TIMESTAMPTZ    NOT NULL DEFAULT now(),
    closed_at       TIMESTAMPTZ,                                 -- set when the session closes
    CONSTRAINT pk_sessions PRIMARY KEY (session_id)
);

-- 2.2 The chat messages in a session.
CREATE TABLE messages (
    message_id      UUID         NOT NULL DEFAULT gen_random_uuid(),
    sequence_no     INTEGER      NOT NULL,
    role            VARCHAR(20)  NOT NULL,                       -- user, assistant or system
    content_masked  TEXT         NOT NULL,                       -- secrets are masked
    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    session_id      UUID         NOT NULL,
    CONSTRAINT pk_messages PRIMARY KEY (message_id),
    CONSTRAINT fk_messages_session_id_sessions
        FOREIGN KEY (session_id) REFERENCES sessions (session_id),
    CONSTRAINT uq_messages_session_id_sequence_no UNIQUE (session_id, sequence_no)
);

-- 2.3 One security test. Each session has at most one assessment.
CREATE TABLE assessments (
    assessment_id      UUID              NOT NULL DEFAULT gen_random_uuid(),
    engagement_code    VARCHAR(50)       NOT NULL,               -- e.g. RCX-2026-0042
    name               VARCHAR(200)      NOT NULL,
    type               VARCHAR(60)       NOT NULL,               -- e.g. web_url, network
    assessment_status  assessment_status NOT NULL DEFAULT 'DRAFT',
    created_by         VARCHAR(100)      NOT NULL,
    created_at         TIMESTAMPTZ       NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ       NOT NULL DEFAULT now(),
    session_id         UUID              NOT NULL,
    CONSTRAINT pk_assessments PRIMARY KEY (assessment_id),
    CONSTRAINT fk_assessments_session_id_sessions
        FOREIGN KEY (session_id) REFERENCES sessions (session_id),
    CONSTRAINT uq_assessments_engagement_code UNIQUE (engagement_code),
    CONSTRAINT uq_assessments_session_id UNIQUE (session_id)
);

-- 2.4 The approved scope: what may be tested, and how.
CREATE TABLE scope_manifests (
    manifest_id       UUID             NOT NULL DEFAULT gen_random_uuid(),
    version           INTEGER          NOT NULL DEFAULT 1,
    manifests_status  manifests_status NOT NULL DEFAULT 'DRAFT',
    max_risk          risk_level       NOT NULL DEFAULT 'LOW',
    allowed_tools     JSONB            NOT NULL DEFAULT '[]'::jsonb,  -- e.g. ["nmap", "nuclei", "zap"]
    allowed_actions   JSONB            NOT NULL DEFAULT '[]'::jsonb,  -- e.g. ["discovery", "scan"]
    allowed_methods   JSONB            NOT NULL DEFAULT '[]'::jsonb,  -- e.g. ["GET", "HEAD"]
    allowed_ports     JSONB            NOT NULL DEFAULT '[]'::jsonb,  -- e.g. [22, 80, 443]; empty: no limit
    starts_at         TIMESTAMPTZ,                               -- start of the test window
    ends_at           TIMESTAMPTZ,                               -- end of the test window
    limitations       TEXT,                                      -- e.g. quiet hours
    decided_by        VARCHAR(100),
    decided_at        TIMESTAMPTZ,
    reject_reason     TEXT,                                      -- only when REJECTED
    session_id        UUID             NOT NULL,
    assessment_id     UUID,                                      -- empty while draft
    CONSTRAINT pk_scope_manifests PRIMARY KEY (manifest_id),
    CONSTRAINT fk_scope_manifests_session_id_sessions
        FOREIGN KEY (session_id) REFERENCES sessions (session_id),
    CONSTRAINT fk_scope_manifests_assessment_id_assessments
        FOREIGN KEY (assessment_id) REFERENCES assessments (assessment_id),
    CONSTRAINT uq_scope_manifests_session_id_version UNIQUE (session_id, version),
    CONSTRAINT uq_scope_manifests_assessment_id UNIQUE (assessment_id)
);

-- 2.5 The targets inside a scope manifest.
CREATE TABLE scope_targets (
    scope_target_id  UUID         NOT NULL DEFAULT gen_random_uuid(),
    type             VARCHAR(20)  NOT NULL,                      -- domain, ip, cidr, url or path
    value            TEXT         NOT NULL,                      -- e.g. shop.acme.test
    excluded         BOOLEAN      NOT NULL DEFAULT false,        -- true = must not be tested
    manifest_id      UUID         NOT NULL,
    CONSTRAINT pk_scope_targets PRIMARY KEY (scope_target_id),
    CONSTRAINT fk_scope_targets_manifest_id_scope_manifests
        FOREIGN KEY (manifest_id) REFERENCES scope_manifests (manifest_id)
);

-- 2.6 The AI model settings.
CREATE TABLE llm_providers (
    llm_provider_id    UUID          NOT NULL DEFAULT gen_random_uuid(),
    provider_type      provider_type NOT NULL,
    display_name       VARCHAR(100)  NOT NULL,
    base_url           TEXT,                                     -- empty for the built-in provider
    api_key_encrypted  BYTEA,                                    -- never shown
    api_key_last4      VARCHAR(4),                               -- for display
    model_name         VARCHAR(100)  NOT NULL,
    is_active          BOOLEAN       NOT NULL DEFAULT false,
    created_by         VARCHAR(100)  NOT NULL,
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT pk_llm_providers PRIMARY KEY (llm_provider_id)
);

-- Only one active provider.
CREATE UNIQUE INDEX uq_llm_providers_one_active ON llm_providers (is_active) WHERE is_active;

-- 2.7 One run of the AI agent.
CREATE TABLE agent_runs (
    agent_run_id       UUID              NOT NULL DEFAULT gen_random_uuid(),
    model_name         VARCHAR(100)      NOT NULL,               -- copy of the model used
    checkpoint_id      TEXT,                                     -- for resume
    agent_runs_status  agent_runs_status NOT NULL DEFAULT 'RUNNING',
    started_at         TIMESTAMPTZ       NOT NULL DEFAULT now(),
    plan               JSONB,                                    -- steps the agent plans
    finished_at        TIMESTAMPTZ,
    session_id         UUID              NOT NULL,
    assessment_id      UUID,                                     -- empty before an assessment exists
    llm_provider_id    UUID              NOT NULL,
    CONSTRAINT pk_agent_runs PRIMARY KEY (agent_run_id),
    CONSTRAINT fk_agent_runs_session_id_sessions
        FOREIGN KEY (session_id) REFERENCES sessions (session_id),
    CONSTRAINT fk_agent_runs_assessment_id_assessments
        FOREIGN KEY (assessment_id) REFERENCES assessments (assessment_id),
    CONSTRAINT fk_agent_runs_llm_provider_id_llm_providers
        FOREIGN KEY (llm_provider_id) REFERENCES llm_providers (llm_provider_id)
);

-- 2.8 A tool command the agent wants to run.
CREATE TABLE actions (
    action_id         UUID          NOT NULL DEFAULT gen_random_uuid(),
    tool              VARCHAR(100)  NOT NULL,                    -- e.g. nmap
    args              JSONB         NOT NULL DEFAULT '[]'::jsonb,
    target            TEXT          NOT NULL,                    -- host or URL
    purpose           TEXT          NOT NULL,                    -- discovery, scan or validation
    risk_level        risk_level,                                -- empty when blocked
    action_status     action_status NOT NULL DEFAULT 'PENDING',
    guardrail_report  JSONB         NOT NULL DEFAULT '{}'::jsonb, -- result of each safety check
    source            VARCHAR(30)   NOT NULL DEFAULT 'agent',
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    assessment_id     UUID          NOT NULL,
    manifest_id       UUID          NOT NULL,                    -- scope version in force
    agent_run_id      UUID          NOT NULL,
    CONSTRAINT pk_actions PRIMARY KEY (action_id),
    CONSTRAINT fk_actions_assessment_id_assessments
        FOREIGN KEY (assessment_id) REFERENCES assessments (assessment_id),
    CONSTRAINT fk_actions_manifest_id_scope_manifests
        FOREIGN KEY (manifest_id) REFERENCES scope_manifests (manifest_id),
    CONSTRAINT fk_actions_agent_run_id_agent_runs
        FOREIGN KEY (agent_run_id) REFERENCES agent_runs (agent_run_id)
);

-- 2.12 A security issue found in an assessment (before evidences, which point to it).
CREATE TABLE findings (
    finding_id         UUID              NOT NULL DEFAULT gen_random_uuid(),
    code               VARCHAR(100)      NOT NULL,               -- e.g. RCX-001
    title              TEXT              NOT NULL,
    target             TEXT              NOT NULL,               -- host or URL affected
    description        TEXT              NOT NULL,
    severity_status    severity_status   NOT NULL DEFAULT 'UNKNOWN',
    cvss_score         NUMERIC(3, 1),                            -- 0.0 to 10.0
    cwe_ids            JSONB             NOT NULL DEFAULT '[]'::jsonb,
    owasp_id           JSONB             NOT NULL DEFAULT '[]'::jsonb,
    cve_ids            JSONB             NOT NULL DEFAULT '[]'::jsonb,
    impact             TEXT,
    remediation        TEXT,
    validation_status  validation_status NOT NULL DEFAULT 'UNCONFIRMED', -- same as newest validation run
    finding_status     finding_status    NOT NULL DEFAULT 'OPEN',
    reviewed_by        VARCHAR(100),
    reviewed_at        TIMESTAMPTZ,
    dedupe_key         VARCHAR(255)      NOT NULL,
    created_at         TIMESTAMPTZ       NOT NULL DEFAULT now(),
    assessment_id      UUID              NOT NULL,
    CONSTRAINT pk_findings PRIMARY KEY (finding_id),
    CONSTRAINT fk_findings_assessment_id_assessments
        FOREIGN KEY (assessment_id) REFERENCES assessments (assessment_id),
    CONSTRAINT uq_findings_assessment_id_dedupe_key UNIQUE (assessment_id, dedupe_key)
);

-- 2.15 A report for an assessment. A new version is made each time.
CREATE TABLE reports (
    report_id          UUID          NOT NULL DEFAULT gen_random_uuid(),
    version            INTEGER       NOT NULL DEFAULT 1,
    report_status      report_status NOT NULL DEFAULT 'GENERATING',
    executive_summary  TEXT,
    methodology        TEXT,
    snapshot           JSONB         NOT NULL,                   -- frozen copy of the findings
    snapshot_hash      VARCHAR(64)   NOT NULL,                   -- SHA-256 of the snapshot
    exports            JSONB         NOT NULL DEFAULT '{}'::jsonb, -- e.g. {"pdf": "..."}
    generated_by       VARCHAR(100)  NOT NULL,
    generated_at       TIMESTAMPTZ,                              -- set when READY
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    assessment_id      UUID          NOT NULL,
    manifest_id        UUID          NOT NULL,
    CONSTRAINT pk_reports PRIMARY KEY (report_id),
    CONSTRAINT fk_reports_assessment_id_assessments
        FOREIGN KEY (assessment_id) REFERENCES assessments (assessment_id),
    CONSTRAINT fk_reports_manifest_id_scope_manifests
        FOREIGN KEY (manifest_id) REFERENCES scope_manifests (manifest_id),
    CONSTRAINT uq_reports_assessment_id_version UNIQUE (assessment_id, version)
);

-- 2.10 A person's yes or no on something risky. Each approval is used once.
-- evidence_id's foreign key is added after evidences (approvals -> evidences -> tool_runs ->
-- approvals is a cycle).
CREATE TABLE approvals (
    approval_id            UUID            NOT NULL DEFAULT gen_random_uuid(),
    kind                   VARCHAR(20)     NOT NULL,  -- scope, action, disclosure, configuration or review
    subject_snapshot       JSONB           NOT NULL,             -- masked copy of what was approved
    subject_hash           VARCHAR(64)     NOT NULL,             -- SHA-256 of the snapshot
    risk_level             risk_level,
    approval_status        approval_status NOT NULL DEFAULT 'PENDING',
    config_change          JSONB,                                -- only for configuration approvals
    confirmation_verified  BOOLEAN         NOT NULL DEFAULT false, -- true when the user typed it
    reason                 TEXT,
    decided_by             VARCHAR(100),
    requested_at           TIMESTAMPTZ     NOT NULL DEFAULT now(),
    decided_at             TIMESTAMPTZ,
    consumed_at            TIMESTAMPTZ,                          -- set when used
    action_id              UUID,                                 -- action approvals
    manifest_id            UUID,                                 -- scope approvals
    evidence_id            UUID,                                 -- disclosure approvals
    report_id              UUID,                                 -- review approvals
    CONSTRAINT pk_approvals PRIMARY KEY (approval_id),
    CONSTRAINT fk_approvals_action_id_actions
        FOREIGN KEY (action_id) REFERENCES actions (action_id),
    CONSTRAINT fk_approvals_manifest_id_scope_manifests
        FOREIGN KEY (manifest_id) REFERENCES scope_manifests (manifest_id),
    CONSTRAINT fk_approvals_report_id_reports
        FOREIGN KEY (report_id) REFERENCES reports (report_id)
);

-- 2.9 One try at running an action.
CREATE TABLE tool_runs (
    tool_run_id      UUID            NOT NULL DEFAULT gen_random_uuid(),
    attempt_no       INTEGER         NOT NULL DEFAULT 1,
    tool_run_status  tool_run_status NOT NULL DEFAULT 'PENDING',
    exit_code        INTEGER,
    error            TEXT,                                       -- why it failed
    masked_count     INTEGER         NOT NULL DEFAULT 0,         -- secrets masked in output
    request_count    INTEGER         NOT NULL DEFAULT 0,         -- requests sent to the target
    output_masked    TEXT,
    job_token_id     UUID            NOT NULL,                   -- stops a token being used twice
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    action_id        UUID            NOT NULL,
    approval_id      UUID,                                       -- empty when no approval is needed
    CONSTRAINT pk_tool_runs PRIMARY KEY (tool_run_id),
    CONSTRAINT fk_tool_runs_action_id_actions
        FOREIGN KEY (action_id) REFERENCES actions (action_id),
    CONSTRAINT fk_tool_runs_approval_id_approvals
        FOREIGN KEY (approval_id) REFERENCES approvals (approval_id),
    CONSTRAINT uq_tool_runs_action_id_attempt_no UNIQUE (action_id, attempt_no),
    CONSTRAINT uq_tool_runs_job_token_id UNIQUE (job_token_id),
    CONSTRAINT uq_tool_runs_approval_id UNIQUE (approval_id)
);

-- 2.11 Proof collected by a tool run.
CREATE TABLE evidences (
    evidence_id  UUID         NOT NULL DEFAULT gen_random_uuid(),
    kind         VARCHAR(50)  NOT NULL,                          -- e.g. http_response, screenshot
    content      TEXT,                                           -- masked text
    file_path    TEXT,                                           -- stored file
    location     TEXT,                                           -- URL, host:port or line
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    finding_id   UUID,                                           -- empty until linked
    tool_run_id  UUID         NOT NULL,
    CONSTRAINT pk_evidences PRIMARY KEY (evidence_id),
    CONSTRAINT fk_evidences_finding_id_findings
        FOREIGN KEY (finding_id) REFERENCES findings (finding_id),
    CONSTRAINT fk_evidences_tool_run_id_tool_runs
        FOREIGN KEY (tool_run_id) REFERENCES tool_runs (tool_run_id)
);

ALTER TABLE approvals ADD CONSTRAINT fk_approvals_evidence_id_evidences
    FOREIGN KEY (evidence_id) REFERENCES evidences (evidence_id);

-- 2.13 Join table: which tool runs found which findings.
CREATE TABLE finding_sources (
    finding_id   UUID NOT NULL,
    tool_run_id  UUID NOT NULL,
    CONSTRAINT pk_finding_sources PRIMARY KEY (finding_id, tool_run_id),
    CONSTRAINT fk_finding_sources_finding_id_findings
        FOREIGN KEY (finding_id) REFERENCES findings (finding_id),
    CONSTRAINT fk_finding_sources_tool_run_id_tool_runs
        FOREIGN KEY (tool_run_id) REFERENCES tool_runs (tool_run_id)
);

-- 2.14 A check that a finding is real.
CREATE TABLE validation_runs (
    validation_run_id  UUID              NOT NULL DEFAULT gen_random_uuid(),
    method             VARCHAR(30)       NOT NULL,               -- e.g. poc, manual_review
    validation_status  validation_status NOT NULL,
    reason             TEXT,
    reviewed_by        VARCHAR(100),
    reviewed_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ       NOT NULL DEFAULT now(),
    finding_id         UUID              NOT NULL,
    tool_run_id        UUID,                                     -- empty for a manual review
    CONSTRAINT pk_validation_runs PRIMARY KEY (validation_run_id),
    CONSTRAINT fk_validation_runs_finding_id_findings
        FOREIGN KEY (finding_id) REFERENCES findings (finding_id),
    CONSTRAINT fk_validation_runs_tool_run_id_tool_runs
        FOREIGN KEY (tool_run_id) REFERENCES tool_runs (tool_run_id)
);

-- 2.16 Join table: which assessments a report covers.
CREATE TABLE report_assessments (
    assessment_id  UUID NOT NULL,
    report_id      UUID NOT NULL,
    CONSTRAINT pk_report_assessments PRIMARY KEY (assessment_id, report_id),
    CONSTRAINT fk_report_assessments_assessment_id_assessments
        FOREIGN KEY (assessment_id) REFERENCES assessments (assessment_id),
    CONSTRAINT fk_report_assessments_report_id_reports
        FOREIGN KEY (report_id) REFERENCES reports (report_id)
);

-- 3. Indexes (not in the ERD; the same ones the migrations create, for common lookups) -------

CREATE INDEX ix_assessments_assessment_status ON assessments (assessment_status);
CREATE INDEX ix_scope_targets_manifest_id ON scope_targets (manifest_id);
CREATE INDEX ix_agent_runs_assessment_id ON agent_runs (assessment_id);
CREATE INDEX ix_actions_action_status ON actions (action_status);
CREATE INDEX ix_actions_assessment_id ON actions (assessment_id);
CREATE INDEX ix_approvals_approval_status ON approvals (approval_status);
CREATE INDEX ix_evidences_finding_id ON evidences (finding_id);
CREATE INDEX ix_evidences_tool_run_id ON evidences (tool_run_id);
CREATE INDEX ix_findings_finding_status ON findings (finding_status);
CREATE INDEX ix_findings_severity_status ON findings (severity_status);
CREATE INDEX ix_validation_runs_finding_id ON validation_runs (finding_id);

COMMIT;
