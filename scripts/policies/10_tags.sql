-- ============================================================
-- DITTEAU DATA GOVERNANCE - TAG TAXONOMY
-- ============================================================
-- Purpose: Create classification tags for data governance
-- Run As: GOVERNANCE_ADMIN_ROLE
-- Run Order: 3 (After roles setup)
-- Dependencies: 00_governance_schema.sql, 01_roles_and_grants.sql
-- ============================================================

USE ROLE GOVERNANCE_ADMIN_ROLE;
USE DATABASE DITTEAU_DATA_GOVERNANCE;
USE SCHEMA GOVERNANCE;

-- ============================================================
-- SECTION 1: DATA SENSITIVITY CLASSIFICATION
-- ============================================================

CREATE TAG IF NOT EXISTS SENSITIVITY_LEVEL
    ALLOWED_VALUES 'PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'
    COMMENT = 'Data sensitivity classification level';

/*
SENSITIVITY_LEVEL Values:
--------------------------
PUBLIC: Can be freely shared externally (no restrictions)
INTERNAL: For institutional use only (not public)
CONFIDENTIAL: Sensitive data requiring authorization (limited access)
RESTRICTED: Highly sensitive (PII, FERPA, financial) requiring strict controls
*/

-- ============================================================
-- SECTION 2: REGULATORY COMPLIANCE CLASSIFICATION
-- ============================================================

CREATE TAG IF NOT EXISTS COMPLIANCE_TYPE
    ALLOWED_VALUES 'FERPA', 'PII', 'FINANCIAL', 'PHI', 'NONE'
    COMMENT = 'Regulatory compliance requirement type';

/*
COMPLIANCE_TYPE Values:
-----------------------
FERPA: Family Educational Rights and Privacy Act (student records)
PII: Personally Identifiable Information (general)
FINANCIAL: Financial data requiring special handling
PHI: Protected Health Information (HIPAA)
NONE: No specific compliance requirement
*/

-- ============================================================
-- SECTION 3: PII INDICATOR
-- ============================================================

CREATE TAG IF NOT EXISTS CONTAINS_PII
    ALLOWED_VALUES 'TRUE', 'FALSE'
    COMMENT = 'Indicates if column contains Personally Identifiable Information';

/*
CONTAINS_PII Values:
--------------------
TRUE: Column contains PII requiring masking/protection
FALSE: Column does not contain PII

Examples of PII:
- Social Security Numbers
- Email addresses
- Phone numbers
- Street addresses
- Dates of birth
- Student names (when combined with other identifiers)
*/

-- ============================================================
-- SECTION 4: BUSINESS DOMAIN CLASSIFICATION
-- ============================================================

CREATE TAG IF NOT EXISTS DATA_DOMAIN
    ALLOWED_VALUES 'ENROLLMENT', 'ACADEMIC', 'FINANCIAL_AID', 'HR', 'INSTITUTIONAL_RESEARCH', 'FINANCE', 'ADVANCEMENT', 'GENERAL'
    COMMENT = 'Business domain or functional area';

/*
DATA_DOMAIN Values:
-------------------
ENROLLMENT: Admissions, recruitment, application data
ACADEMIC: Course enrollments, grades, academic records
FINANCIAL_AID: Aid awards, FAFSA, financial eligibility
HR: Employee data, payroll (future)
INSTITUTIONAL_RESEARCH: Analytics, reporting, compliance reporting
FINANCE: Student accounts, billing, payments
ADVANCEMENT: Alumni, donors (future)
GENERAL: Cross-domain or administrative data
*/

-- ============================================================
-- SECTION 5: DATA OWNERSHIP
-- ============================================================

CREATE TAG IF NOT EXISTS DATA_OWNER
    ALLOWED_VALUES 'REGISTRAR', 'FINANCIAL_AID', 'ADMISSIONS', 'IR', 'FINANCE', 'HR', 'IT', 'ADVANCEMENT', 'MULTIPLE'
    COMMENT = 'Department or role responsible for data governance';

/*
DATA_OWNER Values:
------------------
REGISTRAR: Registrar's Office
FINANCIAL_AID: Financial Aid Office
ADMISSIONS: Admissions/Enrollment Office
IR: Institutional Research Office
FINANCE: Finance/Bursar's Office
HR: Human Resources
IT: Information Technology
ADVANCEMENT: Alumni Relations/Development
MULTIPLE: Shared ownership across departments
*/

-- ============================================================
-- SECTION 6: RETENTION PERIOD (OPTIONAL)
-- ============================================================

CREATE TAG IF NOT EXISTS RETENTION_PERIOD
    ALLOWED_VALUES '1_YEAR', '3_YEARS', '5_YEARS', '7_YEARS', 'PERMANENT', 'INDEFINITE'
    COMMENT = 'Data retention period per institutional policy';

/*
RETENTION_PERIOD Values:
------------------------
1_YEAR: Retain for 1 year after last use
3_YEARS: Retain for 3 years (typical for operational data)
5_YEARS: Retain for 5 years (typical for academic records)
7_YEARS: Retain for 7 years (typical for financial records)
PERMANENT: Retain permanently (degree records, transcripts)
INDEFINITE: No defined retention period (to be determined)
*/

-- ============================================================
-- SECTION 7: DATA QUALITY INDICATOR
-- ============================================================

CREATE TAG IF NOT EXISTS DATA_QUALITY_TIER
    ALLOWED_VALUES 'GOLD', 'SILVER', 'BRONZE', 'UNVERIFIED'
    COMMENT = 'Data quality and trustworthiness tier';

/*
DATA_QUALITY_TIER Values:
--------------------------
GOLD: Highest quality - Production-ready, fully tested, documented
SILVER: Good quality - Cleaned and conformed, some testing
BRONZE: Raw quality - Minimally processed, may contain issues
UNVERIFIED: Quality unknown - Requires validation
*/

-- ============================================================
-- SECTION 8: VERIFICATION
-- ============================================================

-- Show all tags
SHOW TAGS IN SCHEMA DITTEAU_DATA.GOVERNANCE;

-- Verify tag allowed values
DESCRIBE TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SENSITIVITY_LEVEL;
DESCRIBE TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.COMPLIANCE_TYPE;
DESCRIBE TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.CONTAINS_PII;
DESCRIBE TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DATA_DOMAIN;
DESCRIBE TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DATA_OWNER;
DESCRIBE TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.RETENTION_PERIOD;
DESCRIBE TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DATA_QUALITY_TIER;

-- ============================================================
-- SECTION 9: EXAMPLE TAG APPLICATIONS
-- ============================================================

/*
-- These are examples - actual applications happen in 
-- scripts/application/4X_apply_to_*.sql files

-- Example 1: Tag a student demographics table (PROD environment)
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.DIM_STUDENT
    SET TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SENSITIVITY_LEVEL = 'RESTRICTED',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.COMPLIANCE_TYPE = 'FERPA',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DATA_DOMAIN = 'ACADEMIC',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DATA_OWNER = 'REGISTRAR';

-- Example 2: Tag a specific PII column (SSN)
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN SSN
    SET TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SENSITIVITY_LEVEL = 'RESTRICTED',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.COMPLIANCE_TYPE = 'FERPA',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.CONTAINS_PII = 'TRUE';

-- Example 3: Tag an email column
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.DIM_STUDENT
    MODIFY COLUMN EMAIL
    SET TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SENSITIVITY_LEVEL = 'CONFIDENTIAL',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.CONTAINS_PII = 'TRUE';

-- Example 4: Tag a financial aid table
ALTER TABLE DITTEAU_DATA_PROD.DISTRIBUTE.FACT_FINANCIAL_AID
    SET TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SENSITIVITY_LEVEL = 'RESTRICTED',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.COMPLIANCE_TYPE = 'FERPA',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DATA_DOMAIN = 'FINANCIAL_AID',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DATA_OWNER = 'FINANCIAL_AID',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.RETENTION_PERIOD = '7_YEARS';

-- Example 5: Tag staging/intermediate models (apply same tags across all environments)
ALTER TABLE DITTEAU_DATA_PROD.DETERGE.INT_STUDENTS
    SET TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DATA_QUALITY_TIER = 'SILVER',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SENSITIVITY_LEVEL = 'RESTRICTED';
ALTER TABLE DITTEAU_DATA_TEST.DETERGE.INT_STUDENTS
    SET TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DATA_QUALITY_TIER = 'SILVER',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SENSITIVITY_LEVEL = 'RESTRICTED';
ALTER TABLE DITTEAU_DATA_DEV.DETERGE.INT_STUDENTS
    SET TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.DATA_QUALITY_TIER = 'SILVER',
            DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SENSITIVITY_LEVEL = 'RESTRICTED';
*/

-- ============================================================
-- SECTION 10: TAG USAGE GUIDELINES
-- ============================================================

/*
TAGGING BEST PRACTICES:
-----------------------

1. Tag at Multiple Levels:
   - Table level: General classification
   - Column level: Specific sensitivity

2. Required Tags for All Tables:
   - SENSITIVITY_LEVEL (always required)
   - DATA_DOMAIN (always required)
   - DATA_OWNER (always required)

3. Required Tags for PII Columns:
   - SENSITIVITY_LEVEL = RESTRICTED or CONFIDENTIAL
   - COMPLIANCE_TYPE = FERPA or PII
   - CONTAINS_PII = TRUE

4. Tag Inheritance:
   - Column tags override table tags
   - More specific beats more general

5. Tag Review Schedule:
   - New tables: Tag immediately upon creation
   - Existing tables: Quarterly review
   - PII columns: Monthly audit

6. Tag Consistency:
   - Use same tags for similar data across tables
   - Document exceptions and reasoning
   - Maintain tag taxonomy as institutional standard

TAGGING WORKFLOW:
-----------------

Step 1: dbt Model Creation
   └─> Model built in DETERGE or DISTRIBUTE

Step 2: Initial Tagging (Automated via dbt meta)
   └─> Table-level tags applied via post-hook

Step 3: Column-Level Tagging (Manual in Governance Workspace)
   └─> PII columns tagged with specific classifications

Step 4: Verification
   └─> Query tag references view to confirm

Step 5: Apply Policies
   └─> Masking/row access policies reference tags
*/

-- ============================================================
-- SECTION 11: NEXT STEPS
-- ============================================================

/*
TAG TAXONOMY SETUP COMPLETE

Tags Created:
-------------
✓ SENSITIVITY_LEVEL: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
✓ COMPLIANCE_TYPE: FERPA, PII, FINANCIAL, PHI, NONE
✓ CONTAINS_PII: TRUE, FALSE
✓ DATA_DOMAIN: ENROLLMENT, ACADEMIC, FINANCIAL_AID, HR, IR, FINANCE, ADVANCEMENT, GENERAL
✓ DATA_OWNER: REGISTRAR, FINANCIAL_AID, ADMISSIONS, IR, FINANCE, HR, IT, ADVANCEMENT, MULTIPLE
✓ RETENTION_PERIOD: 1_YEAR, 3_YEARS, 5_YEARS, 7_YEARS, PERMANENT, INDEFINITE
✓ DATA_QUALITY_TIER: GOLD, SILVER, BRONZE, UNVERIFIED

Next Steps:
-----------
1. Run 20_masking_policies.sql to create masking policies
2. Run 30_row_access_policies.sql to create row access policies
3. Run 50_helper_views.sql to create monitoring views
4. Begin applying tags to existing tables
5. Document tagging standards for your institution

Testing Tags:
-------------

-- View all tag definitions
SHOW TAGS IN SCHEMA DITTEAU_DATA_GOVERNANCE.GOVERNANCE;

-- Check tag values
DESCRIBE TAG DITTEAU_DATA_GOVERNANCE.GOVERNANCE.SENSITIVITY_LEVEL;

-- Once tags are applied, query tag references
SELECT * FROM DITTEAU_DATA_GOVERNANCE.GOVERNANCE.V_TAGGED_OBJECTS
WHERE TAG_NAME = 'SENSITIVITY_LEVEL';
*/

-- ============================================================
-- END OF SCRIPT
-- ============================================================

