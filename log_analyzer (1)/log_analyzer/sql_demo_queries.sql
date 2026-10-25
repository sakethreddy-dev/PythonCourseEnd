-- =====================================================================
-- SQL DEMO QUERIES  (run these in MySQL Workbench after importing logs)
-- Each block says which SQL concept it demonstrates - handy for your viva.
-- =====================================================================
USE log_analyzer;

-- ---------------------------------------------------------------------
-- 1. SELECT with LIMIT / ORDER BY : the 10 newest events
-- ---------------------------------------------------------------------
SELECT event_id, event_time, username, ip_address, message
FROM log_events
ORDER BY event_time DESC
LIMIT 10;

-- ---------------------------------------------------------------------
-- 2. WHERE : failed logins for one user, or from one IP range
-- ---------------------------------------------------------------------
SELECT event_time, username, ip_address
FROM log_events
WHERE ip_address LIKE '203.0.113.%'
  AND event_time >= '2026-10-20';

-- ---------------------------------------------------------------------
-- 3. Aggregate functions : COUNT, MIN, MAX over the whole table
-- ---------------------------------------------------------------------
SELECT COUNT(*)        AS total_records,
       MIN(event_time) AS first_event,
       MAX(event_time) AS last_event,
       COUNT(DISTINCT ip_address) AS distinct_ips
FROM log_events;

-- ---------------------------------------------------------------------
-- 4. JOIN + GROUP BY : events per type and category
--    (event_types is the lookup table; log_events only stores type_id)
-- ---------------------------------------------------------------------
SELECT t.category, t.type_code, COUNT(*) AS events
FROM log_events e
JOIN event_types t ON t.type_id = e.type_id
GROUP BY t.category, t.type_code
ORDER BY events DESC;

-- ---------------------------------------------------------------------
-- 5. GROUP BY + HAVING : IP addresses with repeated failed logins
--    (this is exactly the "suspicious IP" rule; 5 = default threshold)
-- ---------------------------------------------------------------------
SELECT e.ip_address,
       COUNT(*)                   AS failures,
       COUNT(DISTINCT e.username) AS usernames_tried,
       MIN(e.event_time)          AS first_seen,
       MAX(e.event_time)          AS last_seen
FROM log_events e
JOIN event_types t ON t.type_id = e.type_id
WHERE t.type_code = 'LOGIN_FAILED'
GROUP BY e.ip_address
HAVING COUNT(*) >= 5
ORDER BY failures DESC;

-- ---------------------------------------------------------------------
-- 6. Frequent errors : group similar messages by error_signature
-- ---------------------------------------------------------------------
SELECT error_signature, COUNT(*) AS occurrences, MAX(event_time) AS last_seen
FROM log_events
WHERE error_signature IS NOT NULL
GROUP BY error_signature
ORDER BY occurrences DESC;

-- ---------------------------------------------------------------------
-- 7. Daily activity : GROUP BY on a date + conditional SUM
-- ---------------------------------------------------------------------
SELECT DATE(e.event_time)                    AS day,
       SUM(t.type_code = 'LOGIN_SUCCESS')    AS successes,
       SUM(t.type_code = 'LOGIN_FAILED')     AS failures,
       SUM(t.type_code = 'SYSTEM_ERROR')     AS errors
FROM log_events e
JOIN event_types t ON t.type_id = e.type_id
GROUP BY DATE(e.event_time)
ORDER BY day;

-- ---------------------------------------------------------------------
-- 8. Three-table JOIN : flagged events with the rule and the source file
-- ---------------------------------------------------------------------
SELECT f.rule_code, r.title, e.event_time, e.ip_address, e.username,
       lf.original_name AS source_file, f.reason
FROM investigation_flags f
JOIN detection_rules r ON r.rule_code = f.rule_code
JOIN log_events e      ON e.event_id  = f.event_id
JOIN log_files  lf     ON lf.file_id  = e.file_id
ORDER BY e.event_time DESC
LIMIT 20;

-- ---------------------------------------------------------------------
-- 9. LEFT JOIN : how many events each rule flagged (including rules with 0)
-- ---------------------------------------------------------------------
SELECT r.rule_code, r.threshold, COUNT(f.flag_id) AS flagged_events
FROM detection_rules r
LEFT JOIN investigation_flags f ON f.rule_code = r.rule_code
GROUP BY r.rule_code, r.threshold;

-- ---------------------------------------------------------------------
-- 10. Subquery : IPs that failed repeatedly AND later logged in successfully
-- ---------------------------------------------------------------------
SELECT DISTINCT s.ip_address, s.username, s.event_time AS login_time
FROM log_events s
JOIN event_types st ON st.type_id = s.type_id AND st.type_code = 'LOGIN_SUCCESS'
WHERE s.ip_address IN (
        SELECT e.ip_address
        FROM log_events e
        JOIN event_types t ON t.type_id = e.type_id AND t.type_code = 'LOGIN_FAILED'
        GROUP BY e.ip_address
        HAVING COUNT(*) >= 5);

-- ---------------------------------------------------------------------
-- 11. INSERT : add your own event by hand
--     (event_hash must be unique; SHA2() makes one)
-- ---------------------------------------------------------------------
INSERT INTO log_events
    (file_id, type_id, event_time, username, ip_address, service, severity, message, event_hash, line_number)
SELECT (SELECT MIN(file_id) FROM log_files),
       (SELECT type_id FROM event_types WHERE type_code = 'LOGIN_FAILED'),
       NOW(), 'viva_demo', '192.0.2.200', 'sshd', 'WARNING',
       'Failed password for viva_demo from 192.0.2.200 port 22 ssh2',
       SHA2(CONCAT('viva-demo-', NOW()), 256), 0
WHERE EXISTS (SELECT 1 FROM log_files);

-- ---------------------------------------------------------------------
-- 12. UPDATE : change a threshold (then press "Re-run analysis" on the site)
-- ---------------------------------------------------------------------
UPDATE detection_rules SET threshold = 3 WHERE rule_code = 'IP_FAILURES';

-- ---------------------------------------------------------------------
-- 13. DELETE : remove one import and all of its events
--     (ON DELETE CASCADE removes log_events, rejected_lines and flags too)
-- ---------------------------------------------------------------------
-- DELETE FROM log_files WHERE file_id = 1;     -- uncomment to try

-- ---------------------------------------------------------------------
-- 14. Prove the duplicate protection works : this MUST return no rows
-- ---------------------------------------------------------------------
SELECT event_hash, COUNT(*) AS copies
FROM log_events
GROUP BY event_hash
HAVING COUNT(*) > 1;

-- ---------------------------------------------------------------------
-- 15. Show the indexes MySQL is using
-- ---------------------------------------------------------------------
SHOW INDEX FROM log_events;
EXPLAIN SELECT * FROM log_events WHERE ip_address = '203.0.113.45';
