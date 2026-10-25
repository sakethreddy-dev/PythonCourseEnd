-- =====================================================================
-- OPTIONAL hand-written demo rows (use this INSTEAD of uploading files,
-- or in addition). Run schema.sql first, then this file in MySQL Workbench.
-- After running it, open the website and press "Re-run analysis"
-- (the flags are calculated by the application, not stored here).
-- =====================================================================
USE log_analyzer;

-- INSERT: a pseudo "file" that owns these rows (file_id 1000 is just a marker)
INSERT IGNORE INTO log_files
    (file_id, original_name, file_sha256, file_size, total_lines, parsed_lines, rejected_lines)
VALUES
    (1000, 'manual_demo_rows.sql', SHA2('manual_demo_rows.sql', 256), 0, 17, 17, 0);

SET @ok   = (SELECT type_id FROM event_types WHERE type_code = 'LOGIN_SUCCESS');
SET @fail = (SELECT type_id FROM event_types WHERE type_code = 'LOGIN_FAILED');
SET @err  = (SELECT type_id FROM event_types WHERE type_code = 'SYSTEM_ERROR');
SET @info = (SELECT type_id FROM event_types WHERE type_code = 'SYSTEM_INFO');

INSERT IGNORE INTO log_events
    (file_id, type_id, event_time, username, ip_address, service, severity,
     message, error_signature, event_hash, line_number)
VALUES
 (1000, @ok,   '2026-10-20 09:01:12', 'alice', '10.0.0.5',      'sshd', 'INFO',    'Accepted password for alice from 10.0.0.5 port 50122 ssh2', NULL, SHA2('demo-01',256), 1),
 (1000, @ok,   '2026-10-20 09:15:40', 'bob',   '10.0.0.9',      'sshd', 'INFO',    'Accepted password for bob from 10.0.0.9 port 50310 ssh2',   NULL, SHA2('demo-02',256), 2),
 (1000, @fail, '2026-10-20 10:02:03', 'bob',   '10.0.0.9',      'sshd', 'WARNING', 'Failed password for bob from 10.0.0.9 port 50411 ssh2',     NULL, SHA2('demo-03',256), 3),
 (1000, @ok,   '2026-10-20 10:02:30', 'bob',   '10.0.0.9',      'sshd', 'INFO',    'Accepted password for bob from 10.0.0.9 port 50412 ssh2',   NULL, SHA2('demo-04',256), 4),
 -- six failures from one outside IP (will be flagged with the default threshold of 5)
 (1000, @fail, '2026-10-21 02:10:01', 'root',  '203.0.113.99',  'sshd', 'WARNING', 'Failed password for root from 203.0.113.99 port 40001 ssh2',  NULL, SHA2('demo-05',256), 5),
 (1000, @fail, '2026-10-21 02:10:05', 'admin', '203.0.113.99',  'sshd', 'WARNING', 'Failed password for admin from 203.0.113.99 port 40002 ssh2', NULL, SHA2('demo-06',256), 6),
 (1000, @fail, '2026-10-21 02:10:09', 'root',  '203.0.113.99',  'sshd', 'WARNING', 'Failed password for root from 203.0.113.99 port 40003 ssh2',  NULL, SHA2('demo-07',256), 7),
 (1000, @fail, '2026-10-21 02:10:14', 'test',  '203.0.113.99',  'sshd', 'WARNING', 'Failed password for test from 203.0.113.99 port 40004 ssh2',  NULL, SHA2('demo-08',256), 8),
 (1000, @fail, '2026-10-21 02:10:20', 'root',  '203.0.113.99',  'sshd', 'WARNING', 'Failed password for root from 203.0.113.99 port 40005 ssh2',  NULL, SHA2('demo-09',256), 9),
 (1000, @fail, '2026-10-21 02:10:26', 'admin', '203.0.113.99',  'sshd', 'WARNING', 'Failed password for admin from 203.0.113.99 port 40006 ssh2', NULL, SHA2('demo-10',256), 10),
 (1000, @ok,   '2026-10-21 02:11:02', 'admin', '203.0.113.99',  'sshd', 'INFO',    'Accepted password for admin from 203.0.113.99 port 40007 ssh2', NULL, SHA2('demo-11',256), 11),
 -- errors (the same pattern 4 times -> "frequent error" with the default threshold of 3)
 (1000, @err,  '2026-10-21 11:00:00', NULL, NULL, 'db', 'ERROR', 'Database connection timeout after 30s (host=db01, attempt 1)', 'db: database connection timeout after Ns (host=dbN, attempt N)', SHA2('demo-12',256), 12),
 (1000, @err,  '2026-10-21 11:05:00', NULL, NULL, 'db', 'ERROR', 'Database connection timeout after 30s (host=db01, attempt 2)', 'db: database connection timeout after Ns (host=dbN, attempt N)', SHA2('demo-13',256), 13),
 (1000, @err,  '2026-10-21 11:09:00', NULL, NULL, 'db', 'ERROR', 'Database connection timeout after 45s (host=db01, attempt 1)', 'db: database connection timeout after Ns (host=dbN, attempt N)', SHA2('demo-14',256), 14),
 (1000, @err,  '2026-10-22 08:30:00', NULL, NULL, 'db', 'ERROR', 'Database connection timeout after 60s (host=db01, attempt 3)', 'db: database connection timeout after Ns (host=dbN, attempt N)', SHA2('demo-15',256), 15),
 (1000, @err,  '2026-10-22 13:00:00', NULL, NULL, 'mail', 'ERROR', 'Failed to send notification email to user id=77', 'mail: failed to send notification email to user id=N', SHA2('demo-16',256), 16),
 (1000, @info, '2026-10-22 06:00:00', NULL, NULL, 'app', 'INFO', 'Application started, version 2.4.1', NULL, SHA2('demo-17',256), 17);

-- Quick check after running:
SELECT t.type_code, COUNT(*) AS n
FROM log_events e JOIN event_types t ON t.type_id = e.type_id
WHERE e.file_id = 1000
GROUP BY t.type_code;
