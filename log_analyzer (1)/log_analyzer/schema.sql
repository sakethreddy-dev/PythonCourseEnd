-- =====================================================================
-- System Log Intelligence Analyzer - MySQL schema
-- Safe to run many times: every statement uses IF NOT EXISTS / INSERT IGNORE.
-- You can run this whole file in MySQL Workbench (File > Open SQL Script,
-- then press the lightning-bolt button) OR let `python init_db.py` do it.
-- =====================================================================

CREATE DATABASE IF NOT EXISTS log_analyzer
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE log_analyzer;

-- ---------------------------------------------------------------------
-- 1. log_files : one row per uploaded file (import history)
--    file_sha256 is UNIQUE so the exact same file cannot be imported twice.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_files (
    file_id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    original_name     VARCHAR(255) NOT NULL,
    file_sha256       CHAR(64)     NOT NULL,
    file_size         INT UNSIGNED NOT NULL,
    uploaded_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    total_lines       INT UNSIGNED NOT NULL DEFAULT 0,
    parsed_lines      INT UNSIGNED NOT NULL DEFAULT 0,
    rejected_lines    INT UNSIGNED NOT NULL DEFAULT 0,
    duplicate_events  INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (file_id),
    UNIQUE KEY uq_file_sha256 (file_sha256)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 2. event_types : lookup table (event type -> category)
--    Keeps text out of the big log_events table and gives us a JOIN target.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_types (
    type_id      TINYINT UNSIGNED NOT NULL AUTO_INCREMENT,
    type_code    VARCHAR(30)  NOT NULL,
    category     ENUM('AUTHENTICATION','SYSTEM') NOT NULL,
    description  VARCHAR(150) NOT NULL,
    PRIMARY KEY (type_id),
    UNIQUE KEY uq_type_code (type_code)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 3. log_events : the parsed log records (the main table)
--    event_hash is UNIQUE: it stops the same log line being stored twice
--    even if it appears in two different (overlapping) files.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_events (
    event_id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    file_id          INT UNSIGNED    NOT NULL,
    type_id          TINYINT UNSIGNED NOT NULL,
    event_time       DATETIME        NOT NULL,
    username         VARCHAR(64)     NULL,
    ip_address       VARCHAR(45)     NULL,
    service          VARCHAR(64)     NULL,
    severity         ENUM('INFO','WARNING','ERROR','CRITICAL') NOT NULL DEFAULT 'INFO',
    message          VARCHAR(1000)   NOT NULL,
    error_signature  VARCHAR(255)    NULL,
    event_hash       CHAR(64)        NOT NULL,
    line_number      INT UNSIGNED    NOT NULL,
    PRIMARY KEY (event_id),
    UNIQUE KEY uq_event_hash (event_hash),
    KEY idx_event_time (event_time),
    KEY idx_ip (ip_address),
    KEY idx_username (username),
    KEY idx_type_time (type_id, event_time),
    KEY idx_signature (error_signature),
    KEY idx_file (file_id),
    CONSTRAINT fk_events_file FOREIGN KEY (file_id)
        REFERENCES log_files (file_id) ON DELETE CASCADE,
    CONSTRAINT fk_events_type FOREIGN KEY (type_id)
        REFERENCES event_types (type_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 4. rejected_lines : lines the parser could not understand
--    (malformed lines are kept for review instead of crashing the import)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rejected_lines (
    reject_id    INT UNSIGNED NOT NULL AUTO_INCREMENT,
    file_id      INT UNSIGNED NOT NULL,
    line_number  INT UNSIGNED NOT NULL,
    raw_line     VARCHAR(1000) NOT NULL,
    reason       VARCHAR(100)  NOT NULL,
    PRIMARY KEY (reject_id),
    KEY idx_reject_file (file_id),
    CONSTRAINT fk_reject_file FOREIGN KEY (file_id)
        REFERENCES log_files (file_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 5. detection_rules : the investigation rules and their thresholds
--    Change `threshold` here (or on the website's Rules page) to tune them.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_code    VARCHAR(30)  NOT NULL,
    title        VARCHAR(100) NOT NULL,
    description  VARCHAR(300) NOT NULL,
    threshold    INT UNSIGNED NOT NULL DEFAULT 1,
    enabled      TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (rule_code)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 6. investigation_flags : which events were flagged by which rule
--    Rebuilt from scratch after every import / threshold change.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS investigation_flags (
    flag_id     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    event_id    BIGINT UNSIGNED NOT NULL,
    rule_code   VARCHAR(30)     NOT NULL,
    reason      VARCHAR(255)    NOT NULL,
    flagged_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (flag_id),
    UNIQUE KEY uq_event_rule (event_id, rule_code),
    KEY idx_flag_rule (rule_code),
    CONSTRAINT fk_flag_event FOREIGN KEY (event_id)
        REFERENCES log_events (event_id) ON DELETE CASCADE,
    CONSTRAINT fk_flag_rule FOREIGN KEY (rule_code)
        REFERENCES detection_rules (rule_code)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Seed data (reference data the application needs)
-- ---------------------------------------------------------------------
INSERT IGNORE INTO event_types (type_code, category, description) VALUES
    ('LOGIN_SUCCESS', 'AUTHENTICATION', 'Successful login'),
    ('LOGIN_FAILED',  'AUTHENTICATION', 'Failed login attempt'),
    ('SYSTEM_ERROR',  'SYSTEM',         'System or application error'),
    ('SYSTEM_WARNING','SYSTEM',         'System or application warning'),
    ('SYSTEM_INFO',   'SYSTEM',         'Informational system message');

INSERT IGNORE INTO detection_rules (rule_code, title, description, threshold, enabled) VALUES
    ('IP_FAILURES',
     'Repeated failures from one IP',
     'Failed logins from an IP address that has this many failed logins or more.',
     5, 1),
    ('USER_FAILURES',
     'Repeated failures for one account',
     'Failed logins for a username that has this many failed logins or more.',
     5, 1),
    ('SUCCESS_AFTER_FAILURES',
     'Success from a failing IP',
     'Successful login from an IP that also has this many failed logins or more.',
     5, 1),
    ('FREQUENT_ERROR',
     'Frequently occurring error',
     'System errors whose message pattern occurs this many times or more.',
     3, 1),
    ('CRITICAL_EVENT',
     'Critical severity event',
     'Any event logged with CRITICAL or FATAL severity (threshold not used).',
     1, 1);
