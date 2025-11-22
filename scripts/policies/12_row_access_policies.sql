-- ============================================================
-- DITTEAU DATA GOVERNANCE - ROW ACCESS POLICIES
-- ============================================================
-- Purpose: Create row-level access control policies
-- Run As: GOVERNANCE_ADMIN_ROLE
-- Run Order: 5 (After masking policies)
-- Dependencies: 00_governance_schema.sql, 01_roles_and_grants.sql, 10_tags.sql, 20_masking_policies.sql
-- ============================================================

USE ROLE GOVERNANCE_ADMIN_ROLE;
USE DATABASE DITTEAU_DATA;
USE SCHEMA GOVERNANCE;

-- ============================================================
-- SECTION 1: ENROLLMENT STATUS ROW ACCESS POLICY
-- ============================================================

CREATE OR REPLACE ROW ACCESS POLICY ENROLLMENT_ROW_ACCESS 
AS (ENROLLMENT_STATUS STRING) RETURNS BOOLEAN ->
    CASE
        -- Admins, IR, and Engineers see all data
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN', 
                                 'IR_ANALYST_ROLE', 'DATA_ENGINEER_ROLE',
                                 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN TRUE
        
        -- Enrollment analysts see prospective, admitted, enrolled, and deposited students
        WHEN CURRENT_ROLE() IN ('ENROLLMENT_ANALYST_ROLE')
            AND UPPER(ENROLLMENT_STATUS) IN ('PROSPECTIVE', 'ADMITTED', 'ENROLLED', 'DEPOSITED', 'APPLIED')
            THEN TRUE
        
        -- Registrar sees enrolled, graduated, and withdrawn students
        WHEN CURRENT_ROLE() IN ('REGISTRAR_ANALYST_ROLE')
            AND UPPER(ENROLLMENT_STATUS) IN ('ENROLLED', 'GRADUATED', 'WITHDRAWN', 'LEAVE_OF_ABSENCE', 'COMPLETED')
            THEN TRUE
        
        -- Financial aid sees admitted and enrolled students (need to process aid)
        WHEN CURRENT_ROLE() IN ('FINANCIAL_AID_ANALYST_ROLE')
            AND UPPER(ENROLLMENT_STATUS) IN ('ADMITTED', 'ENROLLED', 'DEPOSITED')
            THEN TRUE
        
        -- General analysts see enrolled students only
        WHEN CURRENT_ROLE() IN ('DATA_ANALYST_ROLE')
            AND UPPER(ENROLLMENT_STATUS) = 'ENROLLED'
            THEN TRUE
        
        ELSE FALSE
    END
    COMMENT = 'Filter rows based on enrollment status - different visibility by department';

-- ============================================================
-- SECTION 2: ACTIVE RECORDS ONLY POLICY
-- ============================================================

CREATE OR REPLACE ROW ACCESS POLICY ACTIVE_RECORDS_ONLY 
AS (IS_ACTIVE BOOLEAN) RETURNS BOOLEAN ->
    CASE
        -- Admins and engineers see all records including inactive/deleted
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN', 
                                 'DATA_ENGINEER_ROLE', 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN TRUE
        
        -- All analysts only see active records
        WHEN CURRENT_ROLE() IN ('DATA_ANALYST_ROLE', 'ENROLLMENT_ANALYST_ROLE', 
                                 'IR_ANALYST_ROLE', 'FINANCIAL_AID_ANALYST_ROLE', 
                                 'REGISTRAR_ANALYST_ROLE')
            AND IS_ACTIVE = TRUE
            THEN TRUE
        
        ELSE FALSE
    END
    COMMENT = 'Filter out inactive/deleted records for end users - engineers see all for debugging';

-- ============================================================
-- SECTION 3: CURRENT ACADEMIC YEAR ACCESS POLICY
-- ============================================================

CREATE OR REPLACE ROW ACCESS POLICY CURRENT_AY_ACCESS 
AS (ACADEMIC_YEAR STRING) RETURNS BOOLEAN ->
    CASE
        -- Admins, IR, and engineers see all academic years
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN', 
                                 'IR_ANALYST_ROLE', 'DATA_ENGINEER_ROLE',
                                 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN TRUE
        
        -- Other analysts see current year + 2 prior years (3 years total)
        -- Adjust the -2 to change how many years back analysts can see
        WHEN CURRENT_ROLE() IN ('ENROLLMENT_ANALYST_ROLE', 'REGISTRAR_ANALYST_ROLE', 
                                 'FINANCIAL_AID_ANALYST_ROLE', 'DATA_ANALYST_ROLE')
            AND ACADEMIC_YEAR >= TO_CHAR(DATEADD(YEAR, -2, CURRENT_DATE()), 'YYYY')
            THEN TRUE
        
        ELSE FALSE
    END
    COMMENT = 'Limit analysts to current academic year plus 2 prior years - IR/Engineers see all history';

-- ============================================================
-- SECTION 4: TERM-BASED ACCESS POLICY
-- ============================================================

CREATE OR REPLACE ROW ACCESS POLICY CURRENT_TERM_ACCESS 
AS (TERM_CODE STRING) RETURNS BOOLEAN ->
    CASE
        -- Admins, IR, and engineers see all terms
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN', 
                                 'IR_ANALYST_ROLE', 'DATA_ENGINEER_ROLE',
                                 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN TRUE
        
        -- Analysts see recent terms (customize based on your term code format)
        -- This example assumes term codes like '202401', '202402', '202403'
        -- Adjust logic based on your institution's term code format
        WHEN CURRENT_ROLE() IN ('ENROLLMENT_ANALYST_ROLE', 'REGISTRAR_ANALYST_ROLE', 
                                 'FINANCIAL_AID_ANALYST_ROLE', 'DATA_ANALYST_ROLE')
            AND TERM_CODE >= TO_CHAR(DATEADD(MONTH, -24, CURRENT_DATE()), 'YYYYMM')
            THEN TRUE
        
        ELSE FALSE
    END
    COMMENT = 'Limit analysts to recent terms (24 months) - IR/Engineers see all terms';

-- ============================================================
-- SECTION 5: DEPARTMENT-BASED ACCESS POLICY
-- ============================================================
-- Use this if you need to restrict access by department/college

CREATE OR REPLACE ROW ACCESS POLICY DEPARTMENT_ACCESS 
AS (DEPARTMENT_CODE STRING) RETURNS BOOLEAN ->
    CASE
        -- Admins, IR, and engineers see all departments
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN', 
                                 'IR_ANALYST_ROLE', 'DATA_ENGINEER_ROLE',
                                 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN TRUE
        
        -- Registrar and enrollment see all departments
        WHEN CURRENT_ROLE() IN ('REGISTRAR_ANALYST_ROLE', 'ENROLLMENT_ANALYST_ROLE')
            THEN TRUE
        
        -- Financial aid sees all departments (need for aid processing)
        WHEN CURRENT_ROLE() IN ('FINANCIAL_AID_ANALYST_ROLE')
            THEN TRUE
        
        -- General analysts see all (uncomment and customize if you need restrictions)
        WHEN CURRENT_ROLE() IN ('DATA_ANALYST_ROLE')
            THEN TRUE
        
        -- Example: Restrict specific custom roles to specific departments
        -- WHEN CURRENT_ROLE() = 'BUSINESS_SCHOOL_ANALYST_ROLE'
        --     AND DEPARTMENT_CODE IN ('ACCT', 'FIN', 'MGMT', 'MKTG')
        --     THEN TRUE
        
        ELSE FALSE
    END
    COMMENT = 'Optional department-based access control - customize for specific departmental roles';

-- ============================================================
-- SECTION 6: FERPA COMPLIANCE POLICY
-- ============================================================
-- Restrict access based on FERPA consent flags

CREATE OR REPLACE ROW ACCESS POLICY FERPA_CONSENT_ACCESS 
AS (FERPA_CONSENT BOOLEAN) RETURNS BOOLEAN ->
    CASE
        -- Admins and registrar see all records regardless of consent
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN', 
                                 'REGISTRAR_ANALYST_ROLE')
            THEN TRUE
        
        -- Engineers see all for development/testing
        WHEN CURRENT_ROLE() IN ('DATA_ENGINEER_ROLE', 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN TRUE
        
        -- Analysts only see students who have given FERPA consent for directory info
        WHEN CURRENT_ROLE() IN ('ENROLLMENT_ANALYST_ROLE', 'IR_ANALYST_ROLE', 
                                 'FINANCIAL_AID_ANALYST_ROLE', 'DATA_ANALYST_ROLE')
            AND (FERPA_CONSENT = TRUE OR FERPA_CONSENT IS NULL)  -- NULL = assume consent
            THEN TRUE
        
        ELSE FALSE
    END
    COMMENT = 'FERPA consent-based access - analysts only see students who have given directory info consent';

-- ============================================================
-- SECTION 7: PROGRAM TYPE ACCESS POLICY
-- ============================================================
-- Filter by program type (undergraduate, graduate, etc.)

CREATE OR REPLACE ROW ACCESS POLICY PROGRAM_TYPE_ACCESS 
AS (PROGRAM_TYPE STRING) RETURNS BOOLEAN ->
    CASE
        -- Admins, IR, and engineers see all program types
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN', 
                                 'IR_ANALYST_ROLE', 'DATA_ENGINEER_ROLE',
                                 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN TRUE
        
        -- Most roles see all program types
        WHEN CURRENT_ROLE() IN ('REGISTRAR_ANALYST_ROLE', 'ENROLLMENT_ANALYST_ROLE',
                                 'FINANCIAL_AID_ANALYST_ROLE', 'DATA_ANALYST_ROLE')
            THEN TRUE
        
        -- Example: Create specialized roles for specific program types
        -- WHEN CURRENT_ROLE() = 'UNDERGRAD_ANALYST_ROLE'
        --     AND UPPER(PROGRAM_TYPE) = 'UNDERGRADUATE'
        --     THEN TRUE
        
        -- WHEN CURRENT_ROLE() = 'GRADUATE_ANALYST_ROLE'
        --     AND UPPER(PROGRAM_TYPE) IN ('GRADUATE', 'DOCTORAL')
        --     THEN TRUE
        
        ELSE FALSE
    END
    COMMENT = 'Optional program type filtering - customize for specialized roles if needed';

-- ============================================================
-- SECTION 8: VERIFICATION
-- ============================================================

-- Show all row access policies created
SHOW ROW ACCESS POLICIES IN SCHEMA GOVERNANCE;

-- Describe each policy to review logic
DESCRIBE ROW ACCESS POLICY ENROLLMENT_ROW_ACCESS;
DESCRIBE ROW ACCESS POLICY ACTIVE_RECORDS_ONLY;
DESCRIBE ROW ACCESS POLICY CURRENT_AY_ACCESS;
DESCRIBE ROW ACCESS POLICY CURRENT_TERM_ACCESS;
DESCRIBE ROW ACCESS POLICY DEPARTMENT_ACCESS;
DESCRIBE ROW ACCESS POLICY FERPA_CONSENT_ACCESS;
DESCRIBE ROW ACCESS POLICY PROGRAM_TYPE_ACCESS;

-- ============================================================
-- SECTION 9: TESTING TEMPLATE
-- ============================================================

/*
-- Create test table with row access policy columns
CREATE OR REPLACE TABLE GOVERNANCE.TEST_ROW_ACCESS (
    STUDENT_ID VARCHAR,
    STUDENT_NAME VARCHAR,
    ENROLLMENT_STATUS VARCHAR,
    IS_ACTIVE BOOLEAN,
    ACADEMIC_YEAR VARCHAR,
    TERM_CODE VARCHAR,
    DEPARTMENT_CODE VARCHAR,
    FERPA_CONSENT BOOLEAN,
    PROGRAM_TYPE VARCHAR
);

-- Insert test data covering different scenarios
INSERT INTO GOVERNANCE.TEST_ROW_ACCESS VALUES
    ('S001', 'John Doe', 'ENROLLED', TRUE, '2024', '202403', 'MATH', TRUE, 'UNDERGRADUATE'),
    ('S002', 'Jane Smith', 'ADMITTED', TRUE, '2024', '202403', 'ENG', TRUE, 'UNDERGRADUATE'),
    ('S003', 'Bob Johnson', 'PROSPECTIVE', TRUE, '2024', '202403', 'BIOL', NULL, 'UNDERGRADUATE'),
    ('S004', 'Alice Williams', 'GRADUATED', TRUE, '2023', '202303', 'HIST', TRUE, 'UNDERGRADUATE'),
    ('S005', 'Charlie Brown', 'WITHDRAWN', FALSE, '2023', '202301', 'PSYC', FALSE, 'UNDERGRADUATE'),
    ('S006', 'Diana Prince', 'ENROLLED', TRUE, '2024', '202403', 'MBA', TRUE, 'GRADUATE'),
    ('S007', 'Eve Adams', 'ENROLLED', TRUE, '2022', '202203', 'COMP', TRUE, 'UNDERGRADUATE');

-- Apply row access policies to test table
ALTER TABLE GOVERNANCE.TEST_ROW_ACCESS
    ADD ROW ACCESS POLICY ENROLLMENT_ROW_ACCESS ON (ENROLLMENT_STATUS);

ALTER TABLE GOVERNANCE.TEST_ROW_ACCESS
    ADD ROW ACCESS POLICY ACTIVE_RECORDS_ONLY ON (IS_ACTIVE);

ALTER TABLE GOVERNANCE.TEST_ROW_ACCESS
    ADD ROW ACCESS POLICY CURRENT_AY_ACCESS ON (ACADEMIC_YEAR);

-- Test as each role
USE ROLE GOVERNANCE_ADMIN_ROLE;
SELECT * FROM GOVERNANCE.TEST_ROW_ACCESS;
-- Expected: All 7 rows visible

USE ROLE IR_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_ROW_ACCESS;
-- Expected: All 7 rows visible (IR has full access)

USE ROLE ENROLLMENT_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_ROW_ACCESS;
-- Expected: Only PROSPECTIVE, ADMITTED, ENROLLED students (S001, S002, S003, S006)
-- Should filter out GRADUATED and WITHDRAWN
-- Should only show active records
-- Should show recent academic years only

USE ROLE REGISTRAR_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_ROW_ACCESS;
-- Expected: Only ENROLLED, GRADUATED, WITHDRAWN students
-- Should show S001, S004, S005 (active status), S006
-- Should filter out PROSPECTIVE and ADMITTED

USE ROLE FINANCIAL_AID_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_ROW_ACCESS;
-- Expected: Only ADMITTED and ENROLLED students (S001, S002, S006)
-- Should filter out PROSPECTIVE, GRADUATED, WITHDRAWN

USE ROLE DATA_ENGINEER_ROLE;
SELECT * FROM GOVERNANCE.TEST_ROW_ACCESS;
-- Expected: All 7 rows (engineers have full access for debugging)

-- Test combinations
USE ROLE ENROLLMENT_ANALYST_ROLE;
SELECT ENROLLMENT_STATUS, COUNT(*) 
FROM GOVERNANCE.TEST_ROW_ACCESS 
GROUP BY ENROLLMENT_STATUS;
-- Expected: Only see counts for PROSPECTIVE, ADMITTED, ENROLLED

-- Clean up test table when done
-- DROP TABLE GOVERNANCE.TEST_ROW_ACCESS;
*/

-- ============================================================
-- SECTION 10: APPLICATION EXAMPLES
-- ============================================================

/*
-- Example applications to actual tables
-- These will be done in scripts/application/4X_apply_to_*.sql files

-- Apply enrollment status filtering to student dimension
ALTER TABLE DITTEAU_DATA.DISTRIBUTE.DIM_STUDENT
    ADD ROW ACCESS POLICY DITTEAU_DATA.GOVERNANCE.ENROLLMENT_ROW_ACCESS 
    ON (ENROLLMENT_STATUS);

ALTER TABLE DITTEAU_DATA.DISTRIBUTE.DIM_STUDENT
    ADD ROW ACCESS POLICY DITTEAU_DATA.GOVERNANCE.ACTIVE_RECORDS_ONLY 
    ON (IS_ACTIVE);

ALTER TABLE DITTEAU_DATA.DISTRIBUTE.DIM_STUDENT
    ADD ROW ACCESS POLICY DITTEAU_DATA.GOVERNANCE.CURRENT_AY_ACCESS 
    ON (CURRENT_ACADEMIC_YEAR);

-- Apply to enrollment fact table
ALTER TABLE DITTEAU_DATA.DISTRIBUTE.FACT_ENROLLMENT
    ADD ROW ACCESS POLICY DITTEAU_DATA.GOVERNANCE.CURRENT_AY_ACCESS 
    ON (ACADEMIC_YEAR);

ALTER TABLE DITTEAU_DATA.DISTRIBUTE.FACT_ENROLLMENT
    ADD ROW ACCESS POLICY DITTEAU_DATA.GOVERNANCE.CURRENT_TERM_ACCESS 
    ON (TERM_CODE);

-- Apply to course registrations
ALTER TABLE DITTEAU_DATA.DETERGE.INT_COURSE_REGISTRATIONS
    ADD ROW ACCESS POLICY DITTEAU_DATA.GOVERNANCE.CURRENT_TERM_ACCESS 
    ON (TERM_CODE);
*/

-- ============================================================
-- SECTION 11: POLICY CUSTOMIZATION NOTES
-- ============================================================

/*
CUSTOMIZATION CHECKLIST:
-----------------------

For each policy, review and customize:

1. ENROLLMENT_ROW_ACCESS:
   ☐ Review enrollment status codes used at your institution
   ☐ Which roles should see which statuses?
   ☐ Add any custom enrollment statuses
   ☐ Consider leave of absence, deferred, etc.

2. ACTIVE_RECORDS_ONLY:
   ☐ Define what "active" means at your institution
   ☐ Should deleted records be hidden from all analysts?
   ☐ How to handle soft-deleted records?

3. CURRENT_AY_ACCESS:
   ☐ How many years back should analysts see? (currently 2)
   ☐ Adjust DATEADD parameter as needed
   ☐ Consider fiscal year vs academic year

4. CURRENT_TERM_ACCESS:
   ☐ Review your term code format
   ☐ Adjust date logic for your format
   ☐ How many months/terms back? (currently 24 months)

5. DEPARTMENT_ACCESS:
   ☐ Do you need department-based restrictions?
   ☐ Create specialized roles if needed
   ☐ Define department code groupings

6. FERPA_CONSENT_ACCESS:
   ☐ How does your institution track FERPA consent?
   ☐ Should NULL = consent or no consent?
   ☐ Which roles bypass consent requirements?

7. PROGRAM_TYPE_ACCESS:
   ☐ Do you need to separate undergrad/graduate access?
   ☐ Create specialized roles if needed
   ☐ Review program type codes

ENROLLMENT STATUS CODES:
-----------------------
Common codes to consider (adjust for your institution):
- PROSPECTIVE: Inquiry, not yet applied
- APPLIED: Application submitted
- ADMITTED: Accepted for admission
- DEPOSITED: Accepted and deposited
- ENROLLED: Currently enrolled
- GRADUATED: Completed program
- WITHDRAWN: Withdrawn from institution
- LEAVE_OF_ABSENCE: Temporarily not enrolled
- DEFERRED: Admission deferred to future term
- DENIED: Application denied
- CANCELLED: Enrollment cancelled

TESTING REMINDERS:
------------------
- Test EACH policy with EACH role
- Test combinations of policies on same table
- Verify counts match expectations
- Test edge cases (NULL values, unusual statuses)
- Document expected row counts per role
- Get sign-off from departments before production
*/

-- ============================================================
-- SECTION 12: COMBINING MULTIPLE POLICIES
-- ============================================================

/*
COMBINING POLICIES ON ONE TABLE:
--------------------------------

You can apply MULTIPLE row access policies to a single table.
The policies are combined with AND logic - a row is visible only if
ALL policies return TRUE.

Example:
ALTER TABLE DISTRIBUTE.DIM_STUDENT
    ADD ROW ACCESS POLICY ENROLLMENT_ROW_ACCESS ON (ENROLLMENT_STATUS);
    -- AND (applied separately)
ALTER TABLE DISTRIBUTE.DIM_STUDENT
    ADD ROW ACCESS POLICY ACTIVE_RECORDS_ONLY ON (IS_ACTIVE);
    -- AND (applied separately)
ALTER TABLE DISTRIBUTE.DIM_STUDENT
    ADD ROW ACCESS POLICY CURRENT_AY_ACCESS ON (CURRENT_ACADEMIC_YEAR);

Result: A row is visible only if:
  - The role has access to that enrollment status
  - AND the record is active
  - AND the academic year is within the allowed range

IMPORTANT: Test carefully when combining policies!
The combination might be more restrictive than intended.
*/

-- ============================================================
-- SECTION 13: REMOVING ROW ACCESS POLICIES
-- ============================================================

/*
To remove a row access policy from a table:

ALTER TABLE DITTEAU_DATA.DISTRIBUTE.DIM_STUDENT
    DROP ROW ACCESS POLICY ENROLLMENT_ROW_ACCESS;

To remove ALL row access policies from a table:

ALTER TABLE DITTEAU_DATA.DISTRIBUTE.DIM_STUDENT
    DROP ALL ROW ACCESS POLICIES;

To drop a policy entirely (must remove from all tables first):

DROP ROW ACCESS POLICY DITTEAU_DATA.GOVERNANCE.ENROLLMENT_ROW_ACCESS;
*/

-- ============================================================
-- SECTION 14: NEXT STEPS
-- ============================================================

/*
ROW ACCESS POLICIES CREATED

Policies Created:
----------------
✓ ENROLLMENT_ROW_ACCESS - Filter by enrollment status
✓ ACTIVE_RECORDS_ONLY - Show only active records
✓ CURRENT_AY_ACCESS - Limit to recent academic years
✓ CURRENT_TERM_ACCESS - Limit to recent terms
✓ DEPARTMENT_ACCESS - Optional department filtering
✓ FERPA_CONSENT_ACCESS - FERPA consent filtering
✓ PROGRAM_TYPE_ACCESS - Optional program type filtering

Next Steps:
-----------
1. Review and customize each policy for your institution
2. Verify enrollment status codes match your codes
3. Create test table and test each policy
4. Test combinations of policies
5. Run 50_helper_views.sql to create monitoring views
6. Apply policies to actual tables using application scripts
7. Document policy decisions and test results
8. Get departmental sign-off on access levels

Testing Command:
---------------
-- Create and test policies on test table (see Section 9 above)

Application Commands:
--------------------
-- After testing is complete:
@scripts/application/41_apply_to_deterge.sql
@scripts/application/42_apply_to_distribute.sql

Monitoring Commands:
-------------------
-- After policies are applied, monitor usage:
SELECT * FROM GOVERNANCE.V_ROW_ACCESS_POLICY_REFERENCES;
*/

-- ============================================================
-- END OF SCRIPT
-- ============================================================
