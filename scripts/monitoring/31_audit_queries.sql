-- ============================================================
-- DITTEAU DATA GOVERNANCE - AUDIT QUERIES
-- ============================================================
-- Purpose: Compliance audit and monitoring queries
-- Run As: GOVERNANCE_ADMIN_ROLE or IR_ANALYST_ROLE
-- Run Order: On-demand (monthly audits, compliance reviews)
-- Dependencies: All governance scripts must be run first
-- ============================================================

USE ROLE GOVERNANCE_ADMIN_ROLE;
USE DATABASE DITTEAU_DATA;
USE SCHEMA GOVERNANCE;
USE WAREHOUSE GOVERNANCE_WH;

-- ============================================================
-- SECTION 1: POLICY COVERAGE AUDITS
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- Audit 1: Unmasked PII Columns (HIGH PRIORITY)
-- ─────────────────────────────────────────────────────────
-- Find columns that likely contain PII but don't have masking policies

SELECT 
    '🚨 UNMASKED PII COLUMNS' AS audit_name,
    COUNT(*) AS issue_count,
    'HIGH' AS priority,
    CURRENT_TIMESTAMP() AS audit_timestamp;

SELECT 
    schema_name,
    table_name,
    column_name,
    suggested_pii_type,
    suggested_masking_policy,
    data_type
FROM GOVERNANCE.V_POTENTIAL_SENSITIVE_COLUMNS
WHERE has_masking_policy = 'NO - NEEDS REVIEW'
ORDER BY 
    CASE suggested_pii_type
        WHEN 'SSN' THEN 1
        WHEN 'DOB' THEN 2
        WHEN 'EMAIL' THEN 3
        WHEN 'PHONE' THEN 4
        WHEN 'FINANCIAL' THEN 5
        ELSE 6
    END,
    schema_name, 
    table_name, 
    column_name;

-- Action Items:
-- □ Review each column listed above
-- □ Apply appropriate masking policy
-- □ Update documentation
-- □ Re-run this audit to verify

-- ─────────────────────────────────────────────────────────
-- Audit 2: Untagged PII Columns
-- ─────────────────────────────────────────────────────────
-- Find PII columns that aren't tagged

SELECT 
    '⚠️ UNTAGGED PII COLUMNS' AS audit_name,
    COUNT(*) AS issue_count,
    'MEDIUM' AS priority,
    CURRENT_TIMESTAMP() AS audit_timestamp;

SELECT 
    schema_name,
    table_name,
    column_name,
    suggested_pii_type,
    has_masking_policy,
    tagged_as_pii
FROM GOVERNANCE.V_POTENTIAL_SENSITIVE_COLUMNS
WHERE tagged_as_pii = 'NO - NEEDS TAGGING'
ORDER BY schema_name, table_name, column_name;

-- Action Items:
-- □ Apply CONTAINS_PII = 'TRUE' tag to each column
-- □ Apply SENSITIVITY_LEVEL tag
-- □ Apply COMPLIANCE_TYPE tag
-- □ Update documentation

-- ─────────────────────────────────────────────────────────
-- Audit 3: Tables Without Any Governance
-- ─────────────────────────────────────────────────────────
-- Find tables with no tags, masking, or row access policies

SELECT 
    '📋 UNGOVERNED TABLES' AS audit_name,
    COUNT(*) AS issue_count,
    'MEDIUM' AS priority,
    CURRENT_TIMESTAMP() AS audit_timestamp;

SELECT 
    schema_name,
    table_name,
    column_count,
    compliance_status,
    has_tags,
    has_masking,
    masked_column_count,
    has_row_access
FROM GOVERNANCE.V_GOVERNANCE_COVERAGE_REPORT
WHERE compliance_status = 'NEEDS_REVIEW'
ORDER BY schema_name, table_name;

-- Action Items:
-- □ Review each table's data
-- □ Determine if PII is present
-- □ Apply appropriate policies
-- □ Apply table-level tags

-- ─────────────────────────────────────────────────────────
-- Audit 4: Tables With Tags But No Policies
-- ─────────────────────────────────────────────────────────
-- Tables are tagged but missing masking or row access policies

SELECT 
    '🏷️ TAGGED BUT UNPROTECTED' AS audit_name,
    COUNT(*) AS issue_count,
    'MEDIUM' AS priority,
    CURRENT_TIMESTAMP() AS audit_timestamp;

SELECT 
    schema_name,
    table_name,
    column_count,
    has_tags,
    has_masking,
    masked_column_count,
    has_row_access
FROM GOVERNANCE.V_GOVERNANCE_COVERAGE_REPORT
WHERE compliance_status = 'TAGGED_ONLY'
ORDER BY schema_name, table_name;

-- Action Items:
-- □ Review tagged columns
-- □ Apply masking policies where needed
-- □ Consider row access policies
-- □ Document reasons if policies not needed

-- ============================================================
-- SECTION 2: ACCESS PATTERN AUDITS
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- Audit 5: Unusual Access Patterns
-- ─────────────────────────────────────────────────────────
-- Users with unusually high query counts (potential data mining)

SELECT 
    '🔍 HIGH VOLUME USERS' AS audit_name,
    COUNT(*) AS user_count,
    'INFO' AS priority,
    CURRENT_TIMESTAMP() AS audit_timestamp;

SELECT 
    USER_NAME,
    ROLE_NAME,
    SCHEMA_NAME,
    query_count,
    days_active,
    total_rows_returned,
    last_access,
    CASE 
        WHEN query_count > 1000 THEN '🚨 VERY HIGH'
        WHEN query_count > 500 THEN '⚠️ HIGH'
        WHEN query_count > 100 THEN '📊 MODERATE'
        ELSE '✓ NORMAL'
    END AS access_level
FROM GOVERNANCE.V_RECENT_ACCESS_PATTERNS
WHERE SCHEMA_NAME IN ('DETERGE', 'DISTRIBUTE')
ORDER BY query_count DESC
LIMIT 20;

-- Action Items:
-- □ Review users with VERY HIGH access
-- □ Verify legitimate business need
-- □ Check if automated processes
-- □ Document approved high-volume use cases

-- ─────────────────────────────────────────────────────────
-- Audit 6: Access to Sensitive Tables by Role
-- ─────────────────────────────────────────────────────────
-- Which roles are accessing tables with PII

WITH sensitive_tables AS (
    SELECT DISTINCT 
        OBJECT_SCHEMA AS schema_name,
        OBJECT_NAME AS table_name
    FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
    WHERE TAG_DATABASE = 'DITTEAU_DATA'
        AND TAG_SCHEMA = 'GOVERNANCE'
        AND TAG_NAME = 'CONTAINS_PII'
        AND TAG_VALUE = 'TRUE'
        AND OBJECT_DELETED IS NULL
)
SELECT 
    '🔐 SENSITIVE TABLE ACCESS' AS audit_name,
    COUNT(DISTINCT qh.USER_NAME) AS unique_users,
    COUNT(DISTINCT qh.ROLE_NAME) AS unique_roles,
    'INFO' AS priority,
    CURRENT_TIMESTAMP() AS audit_timestamp;

WITH sensitive_tables AS (
    SELECT DISTINCT 
        OBJECT_SCHEMA AS schema_name,
        OBJECT_NAME AS table_name
    FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
    WHERE TAG_DATABASE = 'DITTEAU_DATA'
        AND TAG_SCHEMA = 'GOVERNANCE'
        AND TAG_NAME = 'CONTAINS_PII'
        AND TAG_VALUE = 'TRUE'
        AND OBJECT_DELETED IS NULL
)
SELECT 
    st.schema_name,
    st.table_name,
    qh.ROLE_NAME,
    COUNT(DISTINCT qh.USER_NAME) AS user_count,
    COUNT(*) AS query_count,
    MAX(qh.START_TIME) AS last_access
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY qh
JOIN sensitive_tables st
    ON qh.SCHEMA_NAME = st.schema_name
WHERE qh.DATABASE_NAME = 'DITTEAU_DATA'
    AND qh.START_TIME >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
    AND qh.QUERY_TYPE IN ('SELECT', 'COPY', 'INSERT', 'UPDATE')
GROUP BY st.schema_name, st.table_name, qh.ROLE_NAME
ORDER BY query_count DESC;

-- Action Items:
-- □ Verify appropriate role access
-- □ Check for unexpected roles
-- □ Review access justifications
-- □ Update role access matrix

-- ─────────────────────────────────────────────────────────
-- Audit 7: After-Hours Access to PII
-- ─────────────────────────────────────────────────────────
-- Access to sensitive data outside business hours (configurable)

SELECT 
    '🌙 AFTER-HOURS PII ACCESS' AS audit_name,
    COUNT(*) AS query_count,
    'MEDIUM' AS priority,
    CURRENT_TIMESTAMP() AS audit_timestamp;

WITH sensitive_tables AS (
    SELECT DISTINCT 
        OBJECT_SCHEMA AS schema_name,
        OBJECT_NAME AS table_name
    FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
    WHERE TAG_DATABASE = 'DITTEAU_DATA'
        AND TAG_SCHEMA = 'GOVERNANCE'
        AND TAG_NAME = 'CONTAINS_PII'
        AND TAG_VALUE = 'TRUE'
        AND OBJECT_DELETED IS NULL
)
SELECT 
    qh.USER_NAME,
    qh.ROLE_NAME,
    st.table_name,
    qh.START_TIME,
    HOUR(qh.START_TIME) AS access_hour,
    DAYNAME(qh.START_TIME) AS access_day,
    qh.QUERY_TEXT
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY qh
JOIN sensitive_tables st
    ON qh.SCHEMA_NAME = st.schema_name
WHERE qh.DATABASE_NAME = 'DITTEAU_DATA'
    AND qh.START_TIME >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
    AND qh.QUERY_TYPE = 'SELECT'
    AND (
        HOUR(qh.START_TIME) < 6  -- Before 6 AM
        OR HOUR(qh.START_TIME) >= 22  -- After 10 PM
        OR DAYNAME(qh.START_TIME) IN ('Sat', 'Sun')  -- Weekends
    )
ORDER BY qh.START_TIME DESC
LIMIT 50;

-- Action Items:
-- □ Review after-hours access patterns
-- □ Verify legitimate business need
-- □ Check for automated processes
-- □ Consider alerting for unusual patterns

-- ============================================================
-- SECTION 3: COMPLIANCE VERIFICATION AUDITS
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- Audit 8: FERPA Compliance Check
-- ─────────────────────────────────────────────────────────
-- Verify all FERPA-protected data has appropriate controls

SELECT 
    '🎓 FERPA COMPLIANCE STATUS' AS audit_name,
    COUNT(*) AS total_tables,
    SUM(CASE WHEN has_masking = 'YES' OR has_row_access = 'YES' THEN 1 ELSE 0 END) AS protected_tables,
    CURRENT_TIMESTAMP() AS audit_timestamp;

WITH ferpa_tables AS (
    SELECT DISTINCT
        OBJECT_SCHEMA AS schema_name,
        OBJECT_NAME AS table_name
    FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
    WHERE TAG_DATABASE = 'DITTEAU_DATA'
        AND TAG_SCHEMA = 'GOVERNANCE'
        AND TAG_NAME = 'COMPLIANCE_TYPE'
        AND TAG_VALUE = 'FERPA'
        AND OBJECT_DELETED IS NULL
)
SELECT 
    gc.schema_name,
    gc.table_name,
    gc.has_masking,
    gc.masked_column_count,
    gc.has_row_access,
    gc.compliance_status,
    CASE 
        WHEN gc.has_masking = 'YES' OR gc.has_row_access = 'YES' THEN '✓ PROTECTED'
        ELSE '⚠️ NEEDS PROTECTION'
    END AS ferpa_status
FROM ferpa_tables ft
JOIN GOVERNANCE.V_GOVERNANCE_COVERAGE_REPORT gc
    ON ft.schema_name = gc.schema_name
    AND ft.table_name = gc.table_name
ORDER BY ferpa_status, schema_name, table_name;

-- Action Items:
-- □ Review tables marked NEEDS PROTECTION
-- □ Apply masking policies to FERPA data
-- □ Apply row access policies
-- □ Document FERPA compliance measures

-- ─────────────────────────────────────────────────────────
-- Audit 9: SSN Protection Verification
-- ─────────────────────────────────────────────────────────
-- Verify all SSN columns are masked

SELECT 
    '🔒 SSN MASKING STATUS' AS audit_name,
    COUNT(*) AS ssn_columns_found,
    SUM(CASE WHEN policy_name = 'SSN_MASK' THEN 1 ELSE 0 END) AS ssn_columns_masked,
    CURRENT_TIMESTAMP() AS audit_timestamp;

SELECT 
    c.TABLE_SCHEMA AS schema_name,
    c.TABLE_NAME AS table_name,
    c.COLUMN_NAME AS column_name,
    CASE 
        WHEN mp.POLICY_NAME = 'SSN_MASK' THEN '✓ MASKED'
        ELSE '🚨 UNMASKED'
    END AS masking_status,
    mp.POLICY_NAME AS current_policy
FROM DITTEAU_DATA.INFORMATION_SCHEMA.COLUMNS c
LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES mp
    ON c.TABLE_CATALOG = mp.REF_DATABASE_NAME
    AND c.TABLE_SCHEMA = mp.REF_SCHEMA_NAME
    AND c.TABLE_NAME = mp.REF_ENTITY_NAME
    AND c.COLUMN_NAME = mp.REF_COLUMN_NAME
    AND mp.POLICY_KIND = 'MASKING_POLICY'
WHERE c.TABLE_SCHEMA IN ('DEPOSIT', 'DETERGE', 'DISTRIBUTE')
    AND (
        LOWER(c.COLUMN_NAME) LIKE '%ssn%'
        OR LOWER(c.COLUMN_NAME) LIKE '%social%security%'
    )
ORDER BY masking_status, schema_name, table_name;

-- Action Items:
-- □ Apply SSN_MASK to all UNMASKED columns
-- □ Verify masking works by testing as different roles
-- □ Document any exceptions

-- ─────────────────────────────────────────────────────────
-- Audit 10: Email and DOB Protection
-- ─────────────────────────────────────────────────────────
-- Verify email and DOB columns are protected

SELECT 
    '📧 EMAIL & DOB MASKING STATUS' AS audit_name,
    COUNT(*) AS total_columns,
    SUM(CASE WHEN mp.POLICY_NAME IS NOT NULL THEN 1 ELSE 0 END) AS masked_columns,
    CURRENT_TIMESTAMP() AS audit_timestamp;

SELECT 
    c.TABLE_SCHEMA AS schema_name,
    c.TABLE_NAME AS table_name,
    c.COLUMN_NAME AS column_name,
    CASE 
        WHEN LOWER(c.COLUMN_NAME) LIKE '%email%' THEN 'EMAIL'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%dob%' OR LOWER(c.COLUMN_NAME) LIKE '%birth%' THEN 'DOB'
        ELSE 'OTHER'
    END AS pii_type,
    CASE 
        WHEN mp.POLICY_NAME IS NOT NULL THEN '✓ MASKED'
        ELSE '⚠️ UNMASKED'
    END AS masking_status,
    mp.POLICY_NAME AS current_policy
FROM DITTEAU_DATA.INFORMATION_SCHEMA.COLUMNS c
LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES mp
    ON c.TABLE_CATALOG = mp.REF_DATABASE_NAME
    AND c.TABLE_SCHEMA = mp.REF_SCHEMA_NAME
    AND c.TABLE_NAME = mp.REF_ENTITY_NAME
    AND c.COLUMN_NAME = mp.REF_COLUMN_NAME
    AND mp.POLICY_KIND = 'MASKING_POLICY'
WHERE c.TABLE_SCHEMA IN ('DETERGE', 'DISTRIBUTE')
    AND (
        LOWER(c.COLUMN_NAME) LIKE '%email%'
        OR LOWER(c.COLUMN_NAME) LIKE '%dob%'
        OR LOWER(c.COLUMN_NAME) LIKE '%birth%date%'
    )
ORDER BY masking_status, pii_type, schema_name, table_name;

-- Action Items:
-- □ Apply EMAIL_MASK to email columns
-- □ Apply DOB_MASK to birth date columns
-- □ Verify masking behavior per role
-- □ Document any exceptions

-- ============================================================
-- SECTION 4: TAG COMPLIANCE AUDITS
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- Audit 11: Required Tag Coverage
-- ─────────────────────────────────────────────────────────
-- Verify all tables have required tags

SELECT 
    '🏷️ REQUIRED TAG COVERAGE' AS audit_name,
    COUNT(DISTINCT TABLE_NAME) AS total_tables,
    'INFO' AS priority,
    CURRENT_TIMESTAMP() AS audit_timestamp;

WITH all_tables AS (
    SELECT DISTINCT
        TABLE_SCHEMA AS schema_name,
        TABLE_NAME AS table_name
    FROM DITTEAU_DATA.INFORMATION_SCHEMA.TABLES
    WHERE TABLE_SCHEMA IN ('DETERGE', 'DISTRIBUTE')
        AND TABLE_TYPE = 'BASE TABLE'
),
tagged_tables AS (
    SELECT 
        at.schema_name,
        at.table_name,
        MAX(CASE WHEN tr.TAG_NAME = 'SENSITIVITY_LEVEL' THEN 'YES' ELSE 'NO' END) AS has_sensitivity,
        MAX(CASE WHEN tr.TAG_NAME = 'DATA_DOMAIN' THEN 'YES' ELSE 'NO' END) AS has_domain,
        MAX(CASE WHEN tr.TAG_NAME = 'DATA_OWNER' THEN 'YES' ELSE 'NO' END) AS has_owner
    FROM all_tables at
    LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tr
        ON at.schema_name = tr.OBJECT_SCHEMA
        AND at.table_name = tr.OBJECT_NAME
        AND tr.TAG_DATABASE = 'DITTEAU_DATA'
        AND tr.TAG_SCHEMA = 'GOVERNANCE'
        AND tr.OBJECT_DELETED IS NULL
    GROUP BY at.schema_name, at.table_name
)
SELECT 
    schema_name,
    table_name,
    has_sensitivity,
    has_domain,
    has_owner,
    CASE 
        WHEN has_sensitivity = 'YES' AND has_domain = 'YES' AND has_owner = 'YES' 
        THEN '✓ COMPLETE'
        ELSE '⚠️ INCOMPLETE'
    END AS tag_status
FROM tagged_tables
WHERE tag_status = '⚠️ INCOMPLETE'
ORDER BY schema_name, table_name;

-- Action Items:
-- □ Apply SENSITIVITY_LEVEL tag to all tables
-- □ Apply DATA_DOMAIN tag to all tables
-- □ Apply DATA_OWNER tag to all tables
-- □ Update documentation

-- ─────────────────────────────────────────────────────────
-- Audit 12: PII Tag Accuracy
-- ─────────────────────────────────────────────────────────
-- Verify columns tagged as PII actually need masking

SELECT 
    '🎯 PII TAG ACCURACY' AS audit_name,
    COUNT(*) AS pii_tagged_columns,
    SUM(CASE WHEN mp.POLICY_NAME IS NOT NULL THEN 1 ELSE 0 END) AS masked_columns,
    CURRENT_TIMESTAMP() AS audit_timestamp;

SELECT 
    pii.schema_name,
    pii.table_name,
    pii.column_name,
    pii.sensitivity_level,
    pii.compliance_type,
    CASE 
        WHEN mp.POLICY_NAME IS NOT NULL THEN '✓ MASKED'
        ELSE '⚠️ TAGGED BUT NOT MASKED'
    END AS protection_status,
    mp.POLICY_NAME AS applied_policy
FROM GOVERNANCE.V_PII_COLUMNS pii
LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES mp
    ON pii.database_name = mp.REF_DATABASE_NAME
    AND pii.schema_name = mp.REF_SCHEMA_NAME
    AND pii.table_name = mp.REF_ENTITY_NAME
    AND pii.column_name = mp.REF_COLUMN_NAME
    AND mp.POLICY_KIND = 'MASKING_POLICY'
ORDER BY protection_status, schema_name, table_name, column_name;

-- Action Items:
-- □ Review columns TAGGED BUT NOT MASKED
-- □ Apply appropriate masking policy
-- □ Or remove PII tag if incorrect
-- □ Document decisions

-- ============================================================
-- SECTION 5: POLICY EFFECTIVENESS AUDITS
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- Audit 13: Role-Based Query Success Rates
-- ─────────────────────────────────────────────────────────
-- Check if users are being blocked inappropriately

SELECT 
    '📊 QUERY SUCCESS RATES BY ROLE' AS audit_name,
    COUNT(*) AS total_queries,
    CURRENT_TIMESTAMP() AS audit_timestamp;

SELECT 
    ROLE_NAME,
    SCHEMA_NAME,
    COUNT(*) AS total_queries,
    SUM(CASE WHEN ERROR_CODE IS NULL THEN 1 ELSE 0 END) AS successful_queries,
    SUM(CASE WHEN ERROR_CODE IS NOT NULL THEN 1 ELSE 0 END) AS failed_queries,
    ROUND(100.0 * SUM(CASE WHEN ERROR_CODE IS NULL THEN 1 ELSE 0 END) / COUNT(*), 2) AS success_rate_pct,
    -- Common errors
    SUM(CASE WHEN ERROR_MESSAGE ILIKE '%access%denied%' THEN 1 ELSE 0 END) AS access_denied_errors,
    SUM(CASE WHEN ERROR_MESSAGE ILIKE '%policy%' THEN 1 ELSE 0 END) AS policy_errors
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE DATABASE_NAME = 'DITTEAU_DATA'
    AND SCHEMA_NAME IN ('DETERGE', 'DISTRIBUTE')
    AND START_TIME >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
    AND QUERY_TYPE = 'SELECT'
GROUP BY ROLE_NAME, SCHEMA_NAME
ORDER BY failed_queries DESC;

-- Action Items:
-- □ Review roles with high failure rates
-- □ Check if policies are too restrictive
-- □ Verify appropriate access grants
-- □ Update policies if needed

-- ─────────────────────────────────────────────────────────
-- Audit 14: Recently Modified Policies
-- ─────────────────────────────────────────────────────────
-- Track when policies were last changed

SELECT 
    '📝 POLICY CHANGE HISTORY' AS audit_name,
    COUNT(*) AS policy_count,
    CURRENT_TIMESTAMP() AS audit_timestamp;

-- Note: This requires history tracking to be enabled
-- Shows recent changes to governance objects

SELECT 
    QUERY_TYPE,
    USER_NAME,
    ROLE_NAME,
    START_TIME,
    QUERY_TEXT
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE DATABASE_NAME = 'DITTEAU_DATA'
    AND SCHEMA_NAME = 'GOVERNANCE'
    AND START_TIME >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
    AND (
        QUERY_TYPE IN ('CREATE', 'ALTER', 'DROP')
        OR QUERY_TEXT ILIKE '%MASKING%POLICY%'
        OR QUERY_TEXT ILIKE '%ROW%ACCESS%POLICY%'
        OR QUERY_TEXT ILIKE '%TAG%'
    )
ORDER BY START_TIME DESC;

-- Action Items:
-- □ Review recent policy changes
-- □ Verify changes were authorized
-- □ Document change rationale
-- □ Communicate changes to stakeholders

-- ============================================================
-- SECTION 6: MONTHLY SUMMARY REPORT
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- Summary Report: Overall Governance Health
-- ─────────────────────────────────────────────────────────

SELECT '═══════════════════════════════════════════════════' AS divider;
SELECT '    DITTEAU DATA GOVERNANCE - MONTHLY AUDIT REPORT' AS report_title;
SELECT '═══════════════════════════════════════════════════' AS divider;
SELECT '' AS blank_line;

-- Report metadata
SELECT 
    'Audit Period: Last 30 Days' AS period,
    TO_CHAR(DATEADD(DAY, -30, CURRENT_DATE()), 'YYYY-MM-DD') AS start_date,
    TO_CHAR(CURRENT_DATE(), 'YYYY-MM-DD') AS end_date,
    CURRENT_USER() AS auditor,
    CURRENT_ROLE() AS auditor_role;

SELECT '' AS blank_line;
SELECT '───────────────────────────────────────────────────' AS section_divider;
SELECT '1. POLICY COVERAGE' AS section_title;
SELECT '───────────────────────────────────────────────────' AS section_divider;

-- Policy coverage metrics
WITH coverage_stats AS (
    SELECT 
        COUNT(*) AS total_tables,
        SUM(CASE WHEN has_masking = 'YES' THEN 1 ELSE 0 END) AS tables_with_masking,
        SUM(CASE WHEN has_row_access = 'YES' THEN 1 ELSE 0 END) AS tables_with_row_access,
        SUM(CASE WHEN has_tags = 'YES' THEN 1 ELSE 0 END) AS tables_with_tags,
        SUM(CASE WHEN compliance_status = 'COMPLIANT' THEN 1 ELSE 0 END) AS compliant_tables,
        SUM(masked_column_count) AS total_masked_columns
    FROM GOVERNANCE.V_GOVERNANCE_COVERAGE_REPORT
)
SELECT 
    total_tables AS total_tables,
    compliant_tables AS compliant_tables,
    ROUND(100.0 * compliant_tables / NULLIF(total_tables, 0), 1) || '%' AS compliance_rate,
    tables_with_masking AS tables_with_masking,
    total_masked_columns AS total_masked_columns,
    tables_with_row_access AS tables_with_row_access,
    tables_with_tags AS tables_with_tags
FROM coverage_stats;

SELECT '' AS blank_line;
SELECT '───────────────────────────────────────────────────' AS section_divider;
SELECT '2. HIGH-PRIORITY ISSUES' AS section_title;
SELECT '───────────────────────────────────────────────────' AS section_divider;

-- Critical issues count
SELECT 
    'Unmasked PII Columns' AS issue_type,
    COUNT(*) AS count,
    '🚨 HIGH' AS priority
FROM GOVERNANCE.V_POTENTIAL_SENSITIVE_COLUMNS
WHERE has_masking_policy = 'NO - NEEDS REVIEW'
UNION ALL
SELECT 
    'Ungoverned Tables',
    COUNT(*),
    '⚠️ MEDIUM'
FROM GOVERNANCE.V_GOVERNANCE_COVERAGE_REPORT
WHERE compliance_status = 'NEEDS_REVIEW'
UNION ALL
SELECT 
    'Untagged PII Columns',
    COUNT(*),
    '⚠️ MEDIUM'
FROM GOVERNANCE.V_POTENTIAL_SENSITIVE_COLUMNS
WHERE tagged_as_pii = 'NO - NEEDS TAGGING';

SELECT '' AS blank_line;
SELECT '───────────────────────────────────────────────────' AS section_divider;
SELECT '3. ACCESS PATTERNS' AS section_title;
SELECT '───────────────────────────────────────────────────' AS section_divider;

-- Access summary
WITH access_stats AS (
    SELECT 
        COUNT(DISTINCT USER_NAME) AS unique_users,
        COUNT(DISTINCT ROLE_NAME) AS unique_roles,
        SUM(query_count) AS total_queries,
        SUM(total_rows_returned) AS total_rows_accessed
    FROM GOVERNANCE.V_RECENT_ACCESS_PATTERNS
)
SELECT * FROM access_stats;

SELECT '' AS blank_line;
SELECT '───────────────────────────────────────────────────' AS section_divider;
SELECT '4. RECOMMENDATIONS' AS section_title;
SELECT '───────────────────────────────────────────────────' AS section_divider;

SELECT 
    '☐ Review and apply masking to unmasked PII columns' AS recommendation
UNION ALL
SELECT '☐ Apply tags to all ungoverned tables'
UNION ALL
SELECT '☐ Verify high-volume user access is legitimate'
UNION ALL
SELECT '☐ Update governance documentation'
UNION ALL
SELECT '☐ Schedule quarterly governance review';

SELECT '' AS blank_line;
SELECT '═══════════════════════════════════════════════════' AS divider;
SELECT '                 END OF AUDIT REPORT' AS footer;
SELECT '═══════════════════════════════════════════════════' AS divider;

-- ============================================================
-- SECTION 7: EXPORT RESULTS FOR REPORTING
-- ============================================================

/*
To export audit results for external reporting:

1. Run desired audit queries above
2. Export results to CSV via Snowflake UI
3. Create summary dashboard in Excel/PowerBI
4. Archive results for compliance records

Recommended exports:
- V_POTENTIAL_SENSITIVE_COLUMNS (unmasked PII)
- V_GOVERNANCE_COVERAGE_REPORT (overall compliance)
- V_RECENT_ACCESS_PATTERNS (access monitoring)
- Monthly summary report (section 6)
*/

-- ============================================================
-- SECTION 8: AUTOMATED MONITORING (OPTIONAL)
-- ============================================================

/*
Consider setting up automated monitoring:

1. Create Snowflake tasks to run key audits daily/weekly
2. Send email alerts for critical issues
3. Log results to audit table for trending
4. Create dashboards in Snowsight or external BI tool

Example task (requires setup):

CREATE OR REPLACE TASK GOVERNANCE.DAILY_PII_CHECK
    WAREHOUSE = GOVERNANCE_WH
    SCHEDULE = 'USING CRON 0 8 * * * America/New_York'
AS
    SELECT COUNT(*) AS unmasked_pii_count
    FROM GOVERNANCE.V_POTENTIAL_SENSITIVE_COLUMNS
    WHERE has_masking_policy = 'NO - NEEDS REVIEW';
*/

-- ============================================================
-- END OF AUDIT QUERIES
-- ============================================================

/*
AUDIT QUERIES READY TO USE

Audits Included:
---------------
Policy Coverage (Audits 1-4):
✓ Unmasked PII columns
✓ Untagged PII columns
✓ Ungoverned tables
✓ Tagged but unprotected tables

Access Patterns (Audits 5-7):
✓ Unusual access patterns
✓ Sensitive table access by role
✓ After-hours PII access

Compliance (Audits 8-10):
✓ FERPA compliance status
✓ SSN protection verification
✓ Email and DOB protection

Tag Compliance (Audits 11-12):
✓ Required tag coverage
✓ PII tag accuracy

Policy Effectiveness (Audits 13-14):
✓ Query success rates by role
✓ Policy change history

Monthly Report (Section 6):
✓ Comprehensive governance health summary

Usage Instructions:
------------------
1. Run monthly (first week of each month)
2. Review all HIGH priority issues first
3. Address MEDIUM priority issues
4. Document findings and actions taken
5. Export results for compliance records
6. Share summary with governance committee

Quick Monthly Audit:
-------------------
Run these queries in order for monthly review:

@scripts/monitoring/51_audit_queries.sql

Or run specific sections as needed.

Next Steps:
----------
□ Schedule monthly audit in calendar
□ Create audit results template
□ Assign action items from findings
□ Update governance documentation
□ Communicate results to stakeholders
*/
