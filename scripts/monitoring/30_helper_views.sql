-- ============================================================
-- DITTEAU DATA GOVERNANCE - HELPER VIEWS & MONITORING
-- ============================================================
-- Purpose: Create views for monitoring governance policies and compliance
-- Run As: GOVERNANCE_ADMIN_ROLE
-- Run Order: 7 (After policies are created)
-- Dependencies: All previous scripts
-- ============================================================

USE ROLE GOVERNANCE_ADMIN_ROLE;
USE DATABASE DITTEAU_DATA;
USE SCHEMA GOVERNANCE;

-- ============================================================
-- SECTION 1: MASKING POLICY MONITORING VIEWS
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- View 1: All Masking Policy Applications
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_MASKING_POLICY_REFERENCES AS
SELECT 
    POLICY_DB AS policy_database,
    POLICY_SCHEMA AS policy_schema,
    POLICY_NAME AS policy_name,
    POLICY_KIND AS policy_kind,
    REF_DATABASE_NAME AS table_database,
    REF_SCHEMA_NAME AS table_schema,
    REF_ENTITY_NAME AS table_name,
    REF_ENTITY_DOMAIN AS entity_type,
    REF_COLUMN_NAME AS column_name,
    POLICY_STATUS AS policy_status,
    TAG_DATABASE,
    TAG_SCHEMA,
    TAG_NAME
FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
WHERE POLICY_KIND = 'MASKING_POLICY'
    AND POLICY_DB = 'DITTEAU_DATA'
    AND POLICY_SCHEMA = 'GOVERNANCE'
ORDER BY table_schema, table_name, column_name
COMMENT = 'Shows all masking policy applications across the database';

-- ─────────────────────────────────────────────────────────
-- View 2: Masking Policy Summary by Schema
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_MASKING_POLICY_SUMMARY AS
SELECT 
    REF_SCHEMA_NAME AS schema_name,
    POLICY_NAME AS policy_name,
    COUNT(DISTINCT REF_ENTITY_NAME) AS tables_count,
    COUNT(DISTINCT REF_COLUMN_NAME) AS columns_count,
    LISTAGG(DISTINCT REF_ENTITY_NAME, ', ') WITHIN GROUP (ORDER BY REF_ENTITY_NAME) AS affected_tables
FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
WHERE POLICY_KIND = 'MASKING_POLICY'
    AND POLICY_DB = 'DITTEAU_DATA'
    AND POLICY_SCHEMA = 'GOVERNANCE'
GROUP BY schema_name, policy_name
ORDER BY schema_name, policy_name
COMMENT = 'Summary of masking policy usage by schema';

-- ============================================================
-- SECTION 2: ROW ACCESS POLICY MONITORING VIEWS
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- View 3: All Row Access Policy Applications
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_ROW_ACCESS_POLICY_REFERENCES AS
SELECT 
    POLICY_DB AS policy_database,
    POLICY_SCHEMA AS policy_schema,
    POLICY_NAME AS policy_name,
    POLICY_KIND AS policy_kind,
    REF_DATABASE_NAME AS table_database,
    REF_SCHEMA_NAME AS table_schema,
    REF_ENTITY_NAME AS table_name,
    REF_ENTITY_DOMAIN AS entity_type,
    REF_ARG_COLUMN_NAMES AS filter_columns,
    POLICY_STATUS AS policy_status
FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
WHERE POLICY_KIND = 'ROW_ACCESS_POLICY'
    AND POLICY_DB = 'DITTEAU_DATA'
    AND POLICY_SCHEMA = 'GOVERNANCE'
ORDER BY table_schema, table_name
COMMENT = 'Shows all row access policy applications across the database';

-- ─────────────────────────────────────────────────────────
-- View 4: Row Access Policy Summary
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_ROW_ACCESS_POLICY_SUMMARY AS
SELECT 
    REF_SCHEMA_NAME AS schema_name,
    POLICY_NAME AS policy_name,
    COUNT(DISTINCT REF_ENTITY_NAME) AS tables_count,
    LISTAGG(DISTINCT REF_ENTITY_NAME, ', ') WITHIN GROUP (ORDER BY REF_ENTITY_NAME) AS affected_tables
FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
WHERE POLICY_KIND = 'ROW_ACCESS_POLICY'
    AND POLICY_DB = 'DITTEAU_DATA'
    AND POLICY_SCHEMA = 'GOVERNANCE'
GROUP BY schema_name, policy_name
ORDER BY schema_name, policy_name
COMMENT = 'Summary of row access policy usage by schema';

-- ============================================================
-- SECTION 3: TAG MONITORING VIEWS
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- View 5: All Tagged Objects
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_TAGGED_OBJECTS AS
SELECT 
    TAG_DATABASE AS tag_database,
    TAG_SCHEMA AS tag_schema,
    TAG_NAME AS tag_name,
    TAG_VALUE AS tag_value,
    OBJECT_DATABASE AS object_database,
    OBJECT_SCHEMA AS object_schema,
    OBJECT_NAME AS object_name,
    COLUMN_NAME AS column_name,
    DOMAIN AS object_type,
    OBJECT_DELETED AS is_deleted
FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
WHERE TAG_DATABASE = 'DITTEAU_DATA'
    AND TAG_SCHEMA = 'GOVERNANCE'
    AND OBJECT_DELETED IS NULL
ORDER BY object_schema, object_name, column_name, tag_name
COMMENT = 'Shows all tag applications across tables and columns';

-- ─────────────────────────────────────────────────────────
-- View 6: Tag Coverage by Schema
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_TAG_COVERAGE_SUMMARY AS
SELECT 
    OBJECT_SCHEMA AS schema_name,
    TAG_NAME AS tag_name,
    COUNT(DISTINCT OBJECT_NAME) AS tables_count,
    COUNT(DISTINCT COLUMN_NAME) AS columns_count,
    COUNT(DISTINCT CASE WHEN COLUMN_NAME IS NULL THEN OBJECT_NAME END) AS table_level_tags,
    COUNT(DISTINCT CASE WHEN COLUMN_NAME IS NOT NULL THEN OBJECT_NAME END) AS column_level_tags
FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
WHERE TAG_DATABASE = 'DITTEAU_DATA'
    AND TAG_SCHEMA = 'GOVERNANCE'
    AND OBJECT_DELETED IS NULL
GROUP BY schema_name, tag_name
ORDER BY schema_name, tag_name
COMMENT = 'Summary of tag coverage by schema';

-- ─────────────────────────────────────────────────────────
-- View 7: PII Tagged Columns
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_PII_COLUMNS AS
SELECT 
    OBJECT_DATABASE AS database_name,
    OBJECT_SCHEMA AS schema_name,
    OBJECT_NAME AS table_name,
    COLUMN_NAME AS column_name,
    TAG_VALUE AS contains_pii,
    -- Get sensitivity level if tagged
    (SELECT TAG_VALUE 
     FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tr2
     WHERE tr2.OBJECT_DATABASE = tr.OBJECT_DATABASE
       AND tr2.OBJECT_SCHEMA = tr.OBJECT_SCHEMA
       AND tr2.OBJECT_NAME = tr.OBJECT_NAME
       AND tr2.COLUMN_NAME = tr.COLUMN_NAME
       AND tr2.TAG_NAME = 'SENSITIVITY_LEVEL'
       AND tr2.OBJECT_DELETED IS NULL
     LIMIT 1) AS sensitivity_level,
    -- Get compliance type if tagged
    (SELECT TAG_VALUE 
     FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tr3
     WHERE tr3.OBJECT_DATABASE = tr.OBJECT_DATABASE
       AND tr3.OBJECT_SCHEMA = tr.OBJECT_SCHEMA
       AND tr3.OBJECT_NAME = tr.OBJECT_NAME
       AND tr3.COLUMN_NAME = tr3.COLUMN_NAME
       AND tr3.TAG_NAME = 'COMPLIANCE_TYPE'
       AND tr3.OBJECT_DELETED IS NULL
     LIMIT 1) AS compliance_type
FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tr
WHERE TAG_DATABASE = 'DITTEAU_DATA'
    AND TAG_SCHEMA = 'GOVERNANCE'
    AND TAG_NAME = 'CONTAINS_PII'
    AND TAG_VALUE = 'TRUE'
    AND COLUMN_NAME IS NOT NULL
    AND OBJECT_DELETED IS NULL
ORDER BY schema_name, table_name, column_name
COMMENT = 'All columns tagged as containing PII with their sensitivity levels';

-- ============================================================
-- SECTION 4: POTENTIAL SENSITIVE COLUMNS DETECTION
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- View 8: Potential Sensitive Columns Needing Review
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_POTENTIAL_SENSITIVE_COLUMNS AS
SELECT 
    c.TABLE_CATALOG AS database_name,
    c.TABLE_SCHEMA AS schema_name,
    c.TABLE_NAME AS table_name,
    c.COLUMN_NAME AS column_name,
    c.DATA_TYPE AS data_type,
    CASE 
        WHEN LOWER(c.COLUMN_NAME) LIKE '%ssn%' 
            OR LOWER(c.COLUMN_NAME) LIKE '%social%security%' 
            THEN 'SSN'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%email%' 
            THEN 'EMAIL'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%dob%' 
            OR LOWER(c.COLUMN_NAME) LIKE '%birth%date%'
            OR LOWER(c.COLUMN_NAME) LIKE '%birthdate%'
            THEN 'DOB'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%phone%' 
            OR LOWER(c.COLUMN_NAME) LIKE '%mobile%'
            OR LOWER(c.COLUMN_NAME) LIKE '%telephone%'
            THEN 'PHONE'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%address%' 
            OR LOWER(c.COLUMN_NAME) LIKE '%street%'
            OR LOWER(c.COLUMN_NAME) LIKE '%addr%'
            THEN 'ADDRESS'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%salary%' 
            OR LOWER(c.COLUMN_NAME) LIKE '%wage%' 
            OR LOWER(c.COLUMN_NAME) LIKE '%income%'
            OR LOWER(c.COLUMN_NAME) LIKE '%amount%'
            THEN 'FINANCIAL'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%student%id%' 
            THEN 'STUDENT_ID'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%password%'
            OR LOWER(c.COLUMN_NAME) LIKE '%pwd%'
            THEN 'PASSWORD'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%name%'
            AND c.TABLE_SCHEMA IN ('DETERGE', 'DISTRIBUTE')
            THEN 'NAME'
        ELSE 'REVIEW'
    END AS suggested_pii_type,
    CASE 
        WHEN LOWER(c.COLUMN_NAME) LIKE '%ssn%' THEN 'SSN_MASK'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%email%' THEN 'EMAIL_MASK'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%dob%' OR LOWER(c.COLUMN_NAME) LIKE '%birth%' THEN 'DOB_MASK'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%phone%' THEN 'PHONE_MASK'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%address%' THEN 'ADDRESS_MASK'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%amount%' THEN 'FINANCIAL_AMOUNT_MASK'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%student%id%' THEN 'STUDENT_ID_MASK'
        WHEN LOWER(c.COLUMN_NAME) LIKE '%name%' THEN 'NAME_MASK'
        ELSE 'REVIEW_NEEDED'
    END AS suggested_masking_policy,
    -- Check if already masked
    CASE 
        WHEN mp.POLICY_NAME IS NOT NULL THEN 'YES (' || mp.POLICY_NAME || ')'
        ELSE 'NO - NEEDS REVIEW'
    END AS has_masking_policy,
    -- Check if tagged as PII
    CASE 
        WHEN tg.TAG_VALUE = 'TRUE' THEN 'YES'
        ELSE 'NO - NEEDS TAGGING'
    END AS tagged_as_pii
FROM DITTEAU_DATA.INFORMATION_SCHEMA.COLUMNS c
LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES mp
    ON c.TABLE_CATALOG = mp.REF_DATABASE_NAME
    AND c.TABLE_SCHEMA = mp.REF_SCHEMA_NAME
    AND c.TABLE_NAME = mp.REF_ENTITY_NAME
    AND c.COLUMN_NAME = mp.REF_COLUMN_NAME
    AND mp.POLICY_KIND = 'MASKING_POLICY'
    AND mp.POLICY_SCHEMA = 'GOVERNANCE'
LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tg
    ON c.TABLE_CATALOG = tg.OBJECT_DATABASE
    AND c.TABLE_SCHEMA = tg.OBJECT_SCHEMA
    AND c.TABLE_NAME = tg.OBJECT_NAME
    AND c.COLUMN_NAME = tg.COLUMN_NAME
    AND tg.TAG_NAME = 'CONTAINS_PII'
    AND tg.OBJECT_DELETED IS NULL
WHERE c.TABLE_SCHEMA IN ('DEPOSIT', 'DETERGE', 'DISTRIBUTE')
    AND (
        LOWER(c.COLUMN_NAME) LIKE '%ssn%'
        OR LOWER(c.COLUMN_NAME) LIKE '%social%'
        OR LOWER(c.COLUMN_NAME) LIKE '%email%'
        OR LOWER(c.COLUMN_NAME) LIKE '%dob%'
        OR LOWER(c.COLUMN_NAME) LIKE '%birth%'
        OR LOWER(c.COLUMN_NAME) LIKE '%phone%'
        OR LOWER(c.COLUMN_NAME) LIKE '%address%'
        OR LOWER(c.COLUMN_NAME) LIKE '%salary%'
        OR LOWER(c.COLUMN_NAME) LIKE '%amount%'
        OR LOWER(c.COLUMN_NAME) LIKE '%student%id%'
        OR LOWER(c.COLUMN_NAME) LIKE '%password%'
        OR (LOWER(c.COLUMN_NAME) LIKE '%name%' AND c.TABLE_SCHEMA IN ('DETERGE', 'DISTRIBUTE'))
    )
ORDER BY 
    CASE WHEN mp.POLICY_NAME IS NULL THEN 0 ELSE 1 END,  -- Unmasked first
    c.TABLE_SCHEMA, 
    c.TABLE_NAME, 
    c.COLUMN_NAME
COMMENT = 'Identifies columns that may contain PII and need masking policies or tags';

-- ============================================================
-- SECTION 5: ACCESS PATTERN MONITORING VIEWS
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- View 9: Recent Query Access Patterns
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_RECENT_ACCESS_PATTERNS AS
SELECT 
    USER_NAME,
    ROLE_NAME,
    DATABASE_NAME,
    SCHEMA_NAME,
    COUNT(*) AS query_count,
    COUNT(DISTINCT DATE_TRUNC('DAY', START_TIME)) AS days_active,
    MIN(START_TIME) AS first_access,
    MAX(START_TIME) AS last_access,
    SUM(TOTAL_ELAPSED_TIME) / 1000 AS total_seconds,
    SUM(ROWS_PRODUCED) AS total_rows_returned
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE DATABASE_NAME = 'DITTEAU_DATA'
    AND SCHEMA_NAME IN ('DEPOSIT', 'DETERGE', 'DISTRIBUTE')
    AND START_TIME >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
    AND QUERY_TYPE NOT IN ('SHOW', 'DESCRIBE', 'USE')
GROUP BY USER_NAME, ROLE_NAME, DATABASE_NAME, SCHEMA_NAME
ORDER BY query_count DESC
COMMENT = 'Shows user access patterns over the last 30 days';

-- ─────────────────────────────────────────────────────────
-- View 10: Table Access Frequency
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_TABLE_ACCESS_FREQUENCY AS
WITH table_queries AS (
    SELECT 
        qh.DATABASE_NAME,
        qh.SCHEMA_NAME,
        obj.VALUE:objectName::STRING AS table_name,
        qh.ROLE_NAME,
        COUNT(*) AS access_count,
        COUNT(DISTINCT qh.USER_NAME) AS unique_users,
        MAX(qh.START_TIME) AS last_accessed
    FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY qh,
         LATERAL FLATTEN(INPUT => qh.QUERY_PARAMETERIZED_HASH) obj
    WHERE qh.DATABASE_NAME = 'DITTEAU_DATA'
        AND qh.SCHEMA_NAME IN ('DEPOSIT', 'DETERGE', 'DISTRIBUTE')
        AND qh.START_TIME >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
        AND obj.VALUE:objectName::STRING IS NOT NULL
    GROUP BY 1, 2, 3, 4
)
SELECT 
    SCHEMA_NAME,
    table_name,
    ROLE_NAME,
    access_count,
    unique_users,
    last_accessed
FROM table_queries
WHERE table_name IS NOT NULL
ORDER BY access_count DESC
COMMENT = 'Shows which tables are accessed most frequently by role';

-- ============================================================
-- SECTION 6: COMPLIANCE REPORTING VIEWS
-- ============================================================

-- ─────────────────────────────────────────────────────────
-- View 11: Governance Coverage Report
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW V_GOVERNANCE_COVERAGE_REPORT AS
WITH all_tables AS (
    SELECT 
        TABLE_CATALOG AS database_name,
        TABLE_SCHEMA AS schema_name,
        TABLE_NAME AS table_name,
        COUNT(*) AS column_count
    FROM DITTEAU_DATA.INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA IN ('DETERGE', 'DISTRIBUTE')
    GROUP BY 1, 2, 3
),
tagged_tables AS (
    SELECT DISTINCT
        OBJECT_DATABASE AS database_name,
        OBJECT_SCHEMA AS schema_name,
        OBJECT_NAME AS table_name
    FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
    WHERE TAG_DATABASE = 'DITTEAU_DATA'
        AND TAG_SCHEMA = 'GOVERNANCE'
        AND OBJECT_DELETED IS NULL
),
masked_tables AS (
    SELECT DISTINCT
        REF_DATABASE_NAME AS database_name,
        REF_SCHEMA_NAME AS schema_name,
        REF_ENTITY_NAME AS table_name,
        COUNT(DISTINCT REF_COLUMN_NAME) AS masked_columns
    FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
    WHERE POLICY_KIND = 'MASKING_POLICY'
        AND POLICY_DB = 'DITTEAU_DATA'
        AND POLICY_SCHEMA = 'GOVERNANCE'
    GROUP BY 1, 2, 3
),
row_policy_tables AS (
    SELECT DISTINCT
        REF_DATABASE_NAME AS database_name,
        REF_SCHEMA_NAME AS schema_name,
        REF_ENTITY_NAME AS table_name
    FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
    WHERE POLICY_KIND = 'ROW_ACCESS_POLICY'
        AND POLICY_DB = 'DITTEAU_DATA'
        AND POLICY_SCHEMA = 'GOVERNANCE'
)
SELECT 
    a.schema_name,
    a.table_name,
    a.column_count,
    CASE WHEN t.table_name IS NOT NULL THEN 'YES' ELSE 'NO' END AS has_tags,
    CASE WHEN m.table_name IS NOT NULL THEN 'YES' ELSE 'NO' END AS has_masking,
    COALESCE(m.masked_columns, 0) AS masked_column_count,
    CASE WHEN r.table_name IS NOT NULL THEN 'YES' ELSE 'NO' END AS has_row_access,
    CASE 
        WHEN t.table_name IS NOT NULL 
            AND (m.table_name IS NOT NULL OR r.table_name IS NOT NULL)
        THEN 'COMPLIANT'
        WHEN t.table_name IS NOT NULL 
        THEN 'TAGGED_ONLY'
        ELSE 'NEEDS_REVIEW'
    END AS compliance_status
FROM all_tables a
LEFT JOIN tagged_tables t 
    ON a.database_name = t.database_name
    AND a.schema_name = t.schema_name
    AND a.table_name = t.table_name
LEFT JOIN masked_tables m
    ON a.database_name = m.database_name
    AND a.schema_name = m.schema_name
    AND a.table_name = m.table_name
LEFT JOIN row_policy_tables r
    ON a.database_name = r.database_name
    AND a.schema_name = r.schema_name
    AND a.table_name = r.table_name
ORDER BY 
    CASE compliance_status 
        WHEN 'NEEDS_REVIEW' THEN 1
        WHEN 'TAGGED_ONLY' THEN 2
        WHEN 'COMPLIANT' THEN 3
    END,
    schema_name,
    table_name
COMMENT = 'Overall governance coverage showing which tables have tags, masking, and row access policies';

-- ============================================================
-- SECTION 7: GRANT ACCESS TO VIEWS
-- ============================================================

-- Allow data engineers and analysts to see governance monitoring views
GRANT SELECT ON ALL VIEWS IN SCHEMA DITTEAU_DATA.GOVERNANCE TO ROLE DATA_ENGINEER_ROLE;
GRANT SELECT ON ALL VIEWS IN SCHEMA DITTEAU_DATA.GOVERNANCE TO ROLE IR_ANALYST_ROLE;

-- Future views
GRANT SELECT ON FUTURE VIEWS IN SCHEMA DITTEAU_DATA.GOVERNANCE TO ROLE DATA_ENGINEER_ROLE;
GRANT SELECT ON FUTURE VIEWS IN SCHEMA DITTEAU_DATA.GOVERNANCE TO ROLE IR_ANALYST_ROLE;

-- ============================================================
-- SECTION 8: VERIFICATION
-- ============================================================

-- Show all views created
SHOW VIEWS IN SCHEMA GOVERNANCE;

-- Test each view
SELECT 'V_MASKING_POLICY_REFERENCES' AS view_name, COUNT(*) AS row_count FROM V_MASKING_POLICY_REFERENCES
UNION ALL
SELECT 'V_MASKING_POLICY_SUMMARY', COUNT(*) FROM V_MASKING_POLICY_SUMMARY
UNION ALL
SELECT 'V_ROW_ACCESS_POLICY_REFERENCES', COUNT(*) FROM V_ROW_ACCESS_POLICY_REFERENCES
UNION ALL
SELECT 'V_ROW_ACCESS_POLICY_SUMMARY', COUNT(*) FROM V_ROW_ACCESS_POLICY_SUMMARY
UNION ALL
SELECT 'V_TAGGED_OBJECTS', COUNT(*) FROM V_TAGGED_OBJECTS
UNION ALL
SELECT 'V_TAG_COVERAGE_SUMMARY', COUNT(*) FROM V_TAG_COVERAGE_SUMMARY
UNION ALL
SELECT 'V_PII_COLUMNS', COUNT(*) FROM V_PII_COLUMNS
UNION ALL
SELECT 'V_POTENTIAL_SENSITIVE_COLUMNS', COUNT(*) FROM V_POTENTIAL_SENSITIVE_COLUMNS
UNION ALL
SELECT 'V_RECENT_ACCESS_PATTERNS', COUNT(*) FROM V_RECENT_ACCESS_PATTERNS
UNION ALL
SELECT 'V_TABLE_ACCESS_FREQUENCY', COUNT(*) FROM V_TABLE_ACCESS_FREQUENCY
UNION ALL
SELECT 'V_GOVERNANCE_COVERAGE_REPORT', COUNT(*) FROM V_GOVERNANCE_COVERAGE_REPORT;

-- ============================================================
-- SECTION 9: USAGE EXAMPLES
-- ============================================================

/*
-- Example 1: Find all tables without masking policies
SELECT * FROM V_POTENTIAL_SENSITIVE_COLUMNS
WHERE has_masking_policy = 'NO - NEEDS REVIEW'
ORDER BY schema_name, table_name;

-- Example 2: Check governance coverage
SELECT 
    schema_name,
    compliance_status,
    COUNT(*) AS table_count
FROM V_GOVERNANCE_COVERAGE_REPORT
GROUP BY schema_name, compliance_status
ORDER BY schema_name, compliance_status;

-- Example 3: Find all PII columns
SELECT 
    schema_name,
    table_name,
    column_name,
    sensitivity_level,
    compliance_type
FROM V_PII_COLUMNS
ORDER BY schema_name, table_name;

-- Example 4: Check which users accessed sensitive data recently
SELECT 
    USER_NAME,
    ROLE_NAME,
    query_count,
    last_access
FROM V_RECENT_ACCESS_PATTERNS
WHERE SCHEMA_NAME = 'DISTRIBUTE'
ORDER BY last_access DESC;

-- Example 5: Audit masking policy application
SELECT 
    policy_name,
    table_schema,
    table_name,
    column_name,
    policy_status
FROM V_MASKING_POLICY_REFERENCES
WHERE table_schema = 'DISTRIBUTE'
ORDER BY table_name, column_name;

-- Example 6: Find tables with row access policies
SELECT 
    schema_name,
    table_name,
    policy_name,
    filter_columns
FROM V_ROW_ACCESS_POLICY_REFERENCES
ORDER BY schema_name, table_name;

-- Example 7: Tag coverage by schema
SELECT * FROM V_TAG_COVERAGE_SUMMARY
ORDER BY schema_name, tag_name;
*/

-- ============================================================
-- SECTION 10: NEXT STEPS
-- ============================================================

/*
HELPER VIEWS CREATED

Views Created:
-------------
✓ V_MASKING_POLICY_REFERENCES - All masking policy applications
✓ V_MASKING_POLICY_SUMMARY - Masking policy summary by schema
✓ V_ROW_ACCESS_POLICY_REFERENCES - All row access policy applications
✓ V_ROW_ACCESS_POLICY_SUMMARY - Row access policy summary
✓ V_TAGGED_OBJECTS - All tag applications
✓ V_TAG_COVERAGE_SUMMARY - Tag coverage by schema
✓ V_PII_COLUMNS - All columns tagged as PII
✓ V_POTENTIAL_SENSITIVE_COLUMNS - Columns needing review
✓ V_RECENT_ACCESS_PATTERNS - User access patterns
✓ V_TABLE_ACCESS_FREQUENCY - Table access frequency
✓ V_GOVERNANCE_COVERAGE_REPORT - Overall compliance status

Next Steps:
-----------
1. Review V_POTENTIAL_SENSITIVE_COLUMNS to find unmasked PII
2. Check V_GOVERNANCE_COVERAGE_REPORT for tables needing governance
3. Apply policies using application scripts:
   @scripts/application/41_apply_to_deterge.sql
   @scripts/application/42_apply_to_distribute.sql
4. Monitor access patterns using V_RECENT_ACCESS_PATTERNS
5. Create monthly audit process using these views
6. Document monthly audit procedures
7. Set up alerting for unmasked PII (optional)

Monthly Audit Queries:
---------------------
-- Run these monthly:
SELECT * FROM V_POTENTIAL_SENSITIVE_COLUMNS WHERE has_masking_policy LIKE 'NO%';
SELECT * FROM V_GOVERNANCE_COVERAGE_REPORT WHERE compliance_status = 'NEEDS_REVIEW';
SELECT * FROM V_RECENT_ACCESS_PATTERNS ORDER BY query_count DESC LIMIT 20;
*/

-- ============================================================
-- END OF SCRIPT
-- ============================================================
