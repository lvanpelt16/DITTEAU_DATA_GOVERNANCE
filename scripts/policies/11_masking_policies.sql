-- ============================================================
-- DITTEAU DATA GOVERNANCE - MASKING POLICIES
-- ============================================================
-- Purpose: Create masking policies for PII protection
-- Run As: GOVERNANCE_ADMIN_ROLE
-- Run Order: 4 (After tags setup)
-- Dependencies: 00_governance_schema.sql, 01_roles_and_grants.sql, 10_tags.sql
-- ============================================================

USE ROLE GOVERNANCE_ADMIN_ROLE;
USE DATABASE DITTEAU_DATA_GOVERNANCE;
USE SCHEMA GOVERNANCE;

-- ============================================================
-- SECTION 1: SSN MASKING POLICY
-- ============================================================

CREATE OR REPLACE MASKING POLICY SSN_MASK AS (VAL STRING) RETURNS STRING ->
    CASE
        -- Full access for governance and admin roles
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN') 
            THEN VAL
        
        -- Full access for Financial Aid and Registrar (need for verification)
        WHEN CURRENT_ROLE() IN ('FINANCIAL_AID_ANALYST_ROLE', 'REGISTRAR_ANALYST_ROLE')
            THEN VAL
        
        -- Data engineers see last 4 digits for testing/debugging
        WHEN CURRENT_ROLE() IN ('DATA_ENGINEER_ROLE', 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN 'XXX-XX-' || RIGHT(VAL, 4)
        
        -- All other roles see fully masked
        ELSE 'XXX-XX-XXXX'
    END
    COMMENT = 'Mask Social Security Numbers - Full access for FA/Registrar, partial for engineers, masked for others';

-- ============================================================
-- SECTION 2: EMAIL MASKING POLICY
-- ============================================================

CREATE OR REPLACE MASKING POLICY EMAIL_MASK AS (VAL STRING) RETURNS STRING ->
    CASE
        -- Admins and governance see all
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN')
            THEN VAL
        
        -- Department analysts see full email (needed for outreach/communication)
        WHEN CURRENT_ROLE() IN ('ENROLLMENT_ANALYST_ROLE', 'REGISTRAR_ANALYST_ROLE', 
                                 'IR_ANALYST_ROLE', 'FINANCIAL_AID_ANALYST_ROLE')
            THEN VAL
        
        -- Data engineers see domain only for data quality checks
        WHEN CURRENT_ROLE() IN ('DATA_ENGINEER_ROLE', 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN REGEXP_REPLACE(VAL, '^[^@]+', '***')
        
        -- Others see masked
        ELSE '***@***.***'
    END
    COMMENT = 'Mask email addresses - Full for analysts, domain only for engineers, masked for others';

-- ============================================================
-- SECTION 3: DATE OF BIRTH MASKING POLICY
-- ============================================================

CREATE OR REPLACE MASKING POLICY DOB_MASK AS (VAL DATE) RETURNS DATE ->
    CASE
        -- Full access for admins and specific analysts who need exact age
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN', 
                                 'FINANCIAL_AID_ANALYST_ROLE', 'REGISTRAR_ANALYST_ROLE')
            THEN VAL
        
        -- IR analysts see year only (sufficient for cohort analysis and age calculations)
        WHEN CURRENT_ROLE() IN ('IR_ANALYST_ROLE', 'ENROLLMENT_ANALYST_ROLE', 'DATA_ANALYST_ROLE')
            THEN DATE_FROM_PARTS(YEAR(VAL), 1, 1)
        
        -- Engineers see year only for testing
        WHEN CURRENT_ROLE() IN ('DATA_ENGINEER_ROLE', 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN DATE_FROM_PARTS(YEAR(VAL), 1, 1)
        
        -- Others see NULL
        ELSE NULL
    END
    COMMENT = 'Mask dates of birth - Full for FA/Registrar, year only for IR/Enrollment, NULL for others';

-- ============================================================
-- SECTION 4: PHONE NUMBER MASKING POLICY
-- ============================================================

CREATE OR REPLACE MASKING POLICY PHONE_MASK AS (VAL STRING) RETURNS STRING ->
    CASE
        -- Full access for roles that need to contact students
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN',
                                 'ENROLLMENT_ANALYST_ROLE', 'REGISTRAR_ANALYST_ROLE',
                                 'FINANCIAL_AID_ANALYST_ROLE')
            THEN VAL
        
        -- Show area code only for IR (geographic analysis)
        WHEN CURRENT_ROLE() IN ('IR_ANALYST_ROLE')
            THEN CASE 
                WHEN VAL REGEXP '\\d{3}-\\d{3}-\\d{4}' 
                THEN REGEXP_REPLACE(VAL, '(\\d{3})-\\d{3}-\\d{4}', '\\1-XXX-XXXX')
                WHEN VAL REGEXP '\\(\\d{3}\\)\\s*\\d{3}-\\d{4}'
                THEN REGEXP_REPLACE(VAL, '(\\(\\d{3}\\))\\s*\\d{3}-\\d{4}', '\\1 XXX-XXXX')
                ELSE 'XXX-XXX-XXXX'
            END
        
        -- Engineers see format for data quality
        WHEN CURRENT_ROLE() IN ('DATA_ENGINEER_ROLE', 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN CASE 
                WHEN VAL REGEXP '\\d{3}-\\d{3}-\\d{4}' THEN 'XXX-XXX-XXXX (formatted)'
                WHEN VAL REGEXP '\\(\\d{3}\\)' THEN '(XXX) XXX-XXXX (formatted)'
                ELSE 'XXXXXXXXXX (unformatted)'
            END
        
        ELSE 'XXX-XXX-XXXX'
    END
    COMMENT = 'Mask phone numbers - Full for outreach roles, area code for IR, format indicator for engineers';

-- ============================================================
-- SECTION 5: ADDRESS MASKING POLICY
-- ============================================================

CREATE OR REPLACE MASKING POLICY ADDRESS_MASK AS (VAL STRING) RETURNS STRING ->
    CASE
        -- Full access for admins and registrar (official records)
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN', 
                                 'REGISTRAR_ANALYST_ROLE', 'FINANCIAL_AID_ANALYST_ROLE')
            THEN VAL
        
        -- Show city/state only for analysts (geographic analysis)
        WHEN CURRENT_ROLE() IN ('IR_ANALYST_ROLE', 'ENROLLMENT_ANALYST_ROLE', 'DATA_ANALYST_ROLE')
            THEN CASE
                -- Try to extract city, state from common formats
                WHEN VAL LIKE '%,%,%' THEN REGEXP_REPLACE(VAL, '^[^,]+,\\s*(.*)$', '*** \\1')
                WHEN VAL LIKE '%,%' THEN REGEXP_REPLACE(VAL, '^[^,]+,\\s*(.*)$', '*** \\1')
                ELSE '*** (Address)'
            END
        
        -- Engineers see indicator only
        WHEN CURRENT_ROLE() IN ('DATA_ENGINEER_ROLE', 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN '*** (Address Present)'
        
        ELSE '***'
    END
    COMMENT = 'Mask street addresses - Full for Registrar/FA, city/state for analysts, indicator for engineers';

-- ============================================================
-- SECTION 6: FINANCIAL AMOUNT MASKING POLICY
-- ============================================================

CREATE OR REPLACE MASKING POLICY FINANCIAL_AMOUNT_MASK AS (VAL NUMBER) RETURNS NUMBER ->
    CASE
        -- Full access for admins and financial aid (need exact amounts)
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN', 
                                 'FINANCIAL_AID_ANALYST_ROLE')
            THEN VAL
        
        -- Registrar sees rounded amounts (context for academic decisions)
        WHEN CURRENT_ROLE() IN ('REGISTRAR_ANALYST_ROLE')
            THEN ROUND(VAL, -2)  -- Round to nearest hundred
        
        -- IR sees rounded amounts for aggregate analysis
        WHEN CURRENT_ROLE() IN ('IR_ANALYST_ROLE')
            THEN ROUND(VAL, -2)  -- Round to nearest hundred
        
        -- Engineers see rounded for testing
        WHEN CURRENT_ROLE() IN ('DATA_ENGINEER_ROLE', 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN ROUND(VAL, -3)  -- Round to nearest thousand
        
        -- Others see NULL
        ELSE NULL
    END
    COMMENT = 'Mask financial amounts - Full for FA, rounded for IR/Registrar, NULL for others';

-- ============================================================
-- SECTION 7: STUDENT ID MASKING POLICY
-- ============================================================
-- Note: This is for cases where you want to partially mask student IDs
-- In most cases, student IDs are not considered PII and don't need masking

CREATE OR REPLACE MASKING POLICY STUDENT_ID_MASK AS (VAL STRING) RETURNS STRING ->
    CASE
        -- Full access for most roles (student IDs are typically not PII)
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN',
                                 'REGISTRAR_ANALYST_ROLE', 'ENROLLMENT_ANALYST_ROLE',
                                 'FINANCIAL_AID_ANALYST_ROLE', 'IR_ANALYST_ROLE',
                                 'DATA_ANALYST_ROLE')
            THEN VAL
        
        -- Data engineers see partial for joins/testing
        WHEN CURRENT_ROLE() IN ('DATA_ENGINEER_ROLE', 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN 'ID_' || RIGHT(VAL, 4)
        
        ELSE 'XXXXXXXX'
    END
    COMMENT = 'Mask student IDs - Full for analysts, partial for engineers (rarely used - IDs typically not PII)';

-- ============================================================
-- SECTION 8: NAME MASKING POLICY (OPTIONAL)
-- ============================================================
-- Use this if you need to mask student names in certain contexts

CREATE OR REPLACE MASKING POLICY NAME_MASK AS (VAL STRING) RETURNS STRING ->
    CASE
        -- Full access for roles that work directly with students
        WHEN CURRENT_ROLE() IN ('GOVERNANCE_ADMIN_ROLE', 'DITTEAU_DATA_ADMIN',
                                 'REGISTRAR_ANALYST_ROLE', 'ENROLLMENT_ANALYST_ROLE',
                                 'FINANCIAL_AID_ANALYST_ROLE')
            THEN VAL
        
        -- IR sees initials only (sufficient for data validation)
        WHEN CURRENT_ROLE() IN ('IR_ANALYST_ROLE', 'DATA_ANALYST_ROLE')
            THEN CASE
                WHEN VAL LIKE '% %' THEN LEFT(VAL, 1) || '. ' || LEFT(SPLIT_PART(VAL, ' ', 2), 1) || '.'
                ELSE LEFT(VAL, 1) || '.'
            END
        
        -- Engineers see indicator
        WHEN CURRENT_ROLE() IN ('DATA_ENGINEER_ROLE', 'DBT_CLOUD_PROD_ROLE', 'DBT_CLOUD_DEV_ROLE')
            THEN 'Student ' || RIGHT(VAL, 1)
        
        ELSE '***'
    END
    COMMENT = 'Mask student names - Full for student-facing roles, initials for IR, masked for others';

-- ============================================================
-- SECTION 9: VERIFICATION
-- ============================================================

-- Show all masking policies created
SHOW MASKING POLICIES IN SCHEMA GOVERNANCE;

-- Describe each policy to review logic
DESCRIBE MASKING POLICY SSN_MASK;
DESCRIBE MASKING POLICY EMAIL_MASK;
DESCRIBE MASKING POLICY DOB_MASK;
DESCRIBE MASKING POLICY PHONE_MASK;
DESCRIBE MASKING POLICY ADDRESS_MASK;
DESCRIBE MASKING POLICY FINANCIAL_AMOUNT_MASK;
DESCRIBE MASKING POLICY STUDENT_ID_MASK;
DESCRIBE MASKING POLICY NAME_MASK;

-- ============================================================
-- SECTION 10: TESTING TEMPLATE
-- ============================================================

/*
-- Create test table to verify masking
CREATE OR REPLACE TABLE GOVERNANCE.TEST_MASKING (
    STUDENT_ID VARCHAR,
    STUDENT_NAME VARCHAR,
    SSN VARCHAR,
    EMAIL VARCHAR,
    DOB DATE,
    PHONE VARCHAR,
    ADDRESS VARCHAR,
    FINANCIAL_AID_AMOUNT NUMBER(10,2)
);

-- Insert test data
INSERT INTO GOVERNANCE.TEST_MASKING VALUES
    ('S12345', 'John Doe', '123-45-6789', 'john.doe@university.edu', '2000-01-15', '555-123-4567', '123 Main St, Springfield, IL 62701', 15000.00),
    ('S67890', 'Jane Smith', '987-65-4321', 'jane.smith@university.edu', '1999-12-31', '555-987-6543', '456 Oak Ave, Chicago, IL 60601', 22500.50);

-- Apply masking policies to test table
ALTER TABLE GOVERNANCE.TEST_MASKING
    MODIFY COLUMN SSN SET MASKING POLICY SSN_MASK;

ALTER TABLE GOVERNANCE.TEST_MASKING
    MODIFY COLUMN EMAIL SET MASKING POLICY EMAIL_MASK;

ALTER TABLE GOVERNANCE.TEST_MASKING
    MODIFY COLUMN DOB SET MASKING POLICY DOB_MASK;

ALTER TABLE GOVERNANCE.TEST_MASKING
    MODIFY COLUMN PHONE SET MASKING POLICY PHONE_MASK;

ALTER TABLE GOVERNANCE.TEST_MASKING
    MODIFY COLUMN ADDRESS SET MASKING POLICY ADDRESS_MASK;

ALTER TABLE GOVERNANCE.TEST_MASKING
    MODIFY COLUMN FINANCIAL_AID_AMOUNT SET MASKING POLICY FINANCIAL_AMOUNT_MASK;

ALTER TABLE GOVERNANCE.TEST_MASKING
    MODIFY COLUMN STUDENT_NAME SET MASKING POLICY NAME_MASK;

-- Test as each role
USE ROLE GOVERNANCE_ADMIN_ROLE;
SELECT * FROM GOVERNANCE.TEST_MASKING;
-- Expected: Full visibility of all fields

USE ROLE DATA_ENGINEER_ROLE;
SELECT * FROM GOVERNANCE.TEST_MASKING;
-- Expected: SSN=XXX-XX-6789, EMAIL=***@university.edu, DOB=2000-01-01, etc.

USE ROLE IR_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_MASKING;
-- Expected: SSN=XXX-XX-XXXX, EMAIL=full, DOB=2000-01-01, NAME=J. D., etc.

USE ROLE REGISTRAR_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_MASKING;
-- Expected: Full SSN, EMAIL, DOB, NAME; Address full; Amount rounded

USE ROLE ENROLLMENT_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_MASKING;
-- Expected: SSN masked, EMAIL full, DOB year only, NAME full

USE ROLE FINANCIAL_AID_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_MASKING;
-- Expected: Full access to all fields including exact financial amounts

-- Clean up test table when done
-- DROP TABLE GOVERNANCE.TEST_MASKING;
*/

-- ============================================================
-- SECTION 11: APPLICATION EXAMPLES
-- ============================================================

/*
-- Example applications to actual tables
-- These will be done in scripts/application/4X_apply_to_*.sql files

-- Apply to student dimension table (apply to all environments)
-- PROD
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN SSN SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SSN_MASK;
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN EMAIL SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.EMAIL_MASK;
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN BIRTH_DATE SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DOB_MASK;
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN PHONE_NUMBER SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.PHONE_MASK;
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN HOME_ADDRESS SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.ADDRESS_MASK;

-- TEST
ALTER TABLE DITTEAU_DATA_TEST.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN SSN SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SSN_MASK;
ALTER TABLE DITTEAU_DATA_TEST.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN EMAIL SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.EMAIL_MASK;
ALTER TABLE DITTEAU_DATA_TEST.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN BIRTH_DATE SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DOB_MASK;
ALTER TABLE DITTEAU_DATA_TEST.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN PHONE_NUMBER SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.PHONE_MASK;
ALTER TABLE DITTEAU_DATA_TEST.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN HOME_ADDRESS SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.ADDRESS_MASK;

-- DEV
ALTER TABLE DITTEAU_DATA_DEV.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN SSN SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SSN_MASK;
ALTER TABLE DITTEAU_DATA_DEV.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN EMAIL SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.EMAIL_MASK;
ALTER TABLE DITTEAU_DATA_DEV.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN BIRTH_DATE SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DOB_MASK;
ALTER TABLE DITTEAU_DATA_DEV.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN PHONE_NUMBER SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.PHONE_MASK;
ALTER TABLE DITTEAU_DATA_DEV.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN HOME_ADDRESS SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.ADDRESS_MASK;

-- Apply to financial aid fact table (all environments)
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.FACT_FINANCIAL_AID
    MODIFY COLUMN AID_AMOUNT SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.FINANCIAL_AMOUNT_MASK;
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.FACT_FINANCIAL_AID
    MODIFY COLUMN EFC_AMOUNT SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.FINANCIAL_AMOUNT_MASK;

ALTER TABLE DITTEAU_DATA_TEST.DISTRIBUTE.FACT_FINANCIAL_AID
    MODIFY COLUMN AID_AMOUNT SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.FINANCIAL_AMOUNT_MASK;
ALTER TABLE DITTEAU_DATA_TEST.DISTRIBUTE.FACT_FINANCIAL_AID
    MODIFY COLUMN EFC_AMOUNT SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.FINANCIAL_AMOUNT_MASK;

ALTER TABLE DITTEAU_DATA_DEV.DISTRIBUTE.FACT_FINANCIAL_AID
    MODIFY COLUMN AID_AMOUNT SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.FINANCIAL_AMOUNT_MASK;
ALTER TABLE DITTEAU_DATA_DEV.DISTRIBUTE.FACT_FINANCIAL_AID
    MODIFY COLUMN EFC_AMOUNT SET MASKING POLICY DITTEAU_DATA_GOVERNANCE.GOVERNANCE.FINANCIAL_AMOUNT_MASK;
*/

-- ============================================================
-- SECTION 12: POLICY CUSTOMIZATION NOTES
-- ============================================================

/*
CUSTOMIZATION CHECKLIST:
-----------------------

For each policy, review and customize:

1. SSN_MASK:
   ☐ Who needs full SSN access? (currently: FA, Registrar)
   ☐ Should engineers see last 4 or nothing?
   ☐ Any other roles need access?

2. EMAIL_MASK:
   ☐ Which roles need email for communication?
   ☐ Should any role see domain only?
   ☐ Geographic restrictions needed?

3. DOB_MASK:
   ☐ Who needs exact birthdate? (currently: FA, Registrar)
   ☐ Is year sufficient for IR analytics?
   ☐ Should enrollment see exact dates?

4. PHONE_MASK:
   ☐ Who needs phone for outreach?
   ☐ Should IR see area codes for analysis?
   ☐ Format validation needed?

5. ADDRESS_MASK:
   ☐ Who needs full addresses?
   ☐ Is city/state sufficient for analysts?
   ☐ International address handling needed?

6. FINANCIAL_AMOUNT_MASK:
   ☐ Who needs exact amounts? (currently: FA only)
   ☐ What rounding level for IR? (currently: hundreds)
   ☐ Should registrar see exact amounts?

7. STUDENT_ID_MASK:
   ☐ Are student IDs considered PII at your institution?
   ☐ If not, remove this policy or keep for special cases
   ☐ What partial format works for engineers?

8. NAME_MASK:
   ☐ Do you need to mask names?
   ☐ Are initials sufficient for IR?
   ☐ Consider FERPA requirements

TESTING REMINDERS:
------------------
- Test EACH policy with EACH role
- Document expected vs actual results
- Test edge cases (NULL values, empty strings, unusual formats)
- Verify performance impact on large tables
- Get sign-off from compliance before production
*/

-- ============================================================
-- SECTION 13: NEXT STEPS
-- ============================================================

/*
MASKING POLICIES CREATED

Policies Created:
----------------
✓ SSN_MASK - Social Security Number masking
✓ EMAIL_MASK - Email address masking
✓ DOB_MASK - Date of birth masking
✓ PHONE_MASK - Phone number masking
✓ ADDRESS_MASK - Address masking
✓ FINANCIAL_AMOUNT_MASK - Financial data masking
✓ STUDENT_ID_MASK - Student ID partial masking
✓ NAME_MASK - Student name masking

Next Steps:
-----------
1. Review and customize each policy for your institution
2. Create test table and test each policy
3. Run 30_row_access_policies.sql to create row-level policies
4. Run 50_helper_views.sql to create monitoring views
5. Apply policies to actual tables using application scripts
6. Document policy decisions and test results
7. Get compliance/security team sign-off

Testing Command:
---------------
-- Create and test policies on test table (see Section 10 above)

Application Commands:
--------------------
-- After testing is complete:
@scripts/application/41_apply_to_deterge.sql
@scripts/application/42_apply_to_distribute.sql
*/

-- ============================================================
-- END OF SCRIPT
-- ============================================================
