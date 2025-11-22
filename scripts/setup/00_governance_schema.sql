-- ============================================================
-- DITTEAU DATA GOVERNANCE - SCHEMA SETUP
-- ============================================================
-- Purpose: Create governance schema and foundational objects
-- Run As: ACCOUNTADMIN
-- Run Order: 1 (First script to run)
-- ============================================================

USE ROLE ACCOUNTADMIN;

-- ============================================================
-- SECTION 1: CREATE GOVERNANCE SCHEMA
-- ============================================================

-- Create database if not exists (should already exist)
CREATE DATABASE IF NOT EXISTS DITTEAU_DATA
    COMMENT = 'Ditteau Data unified data platform';

-- Create governance schema
CREATE SCHEMA IF NOT EXISTS DITTEAU_DATA.GOVERNANCE
    COMMENT = 'Data governance policies, tags, masking, row access, and helper views';

-- ============================================================
-- SECTION 2: CREATE GOVERNANCE ROLE
-- ============================================================

-- Create governance admin role
CREATE ROLE IF NOT EXISTS GOVERNANCE_ADMIN_ROLE
    COMMENT = 'Role for managing data governance policies, tags, and security';

-- Grant schema access
GRANT USAGE ON DATABASE DITTEAU_DATA TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT ALL ON SCHEMA DITTEAU_DATA.GOVERNANCE TO ROLE GOVERNANCE_ADMIN_ROLE;

-- Grant ability to create governance objects
GRANT CREATE TAG ON SCHEMA DITTEAU_DATA.GOVERNANCE TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT CREATE MASKING POLICY ON SCHEMA DITTEAU_DATA.GOVERNANCE TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT CREATE ROW ACCESS POLICY ON SCHEMA DITTEAU_DATA.GOVERNANCE TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT CREATE VIEW ON SCHEMA DITTEAU_DATA.GOVERNANCE TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT CREATE TABLE ON SCHEMA DITTEAU_DATA.GOVERNANCE TO ROLE GOVERNANCE_ADMIN_ROLE;

-- Grant ability to APPLY governance objects (critical!)
GRANT APPLY MASKING POLICY ON ACCOUNT TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT APPLY ROW ACCESS POLICY ON ACCOUNT TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT APPLY TAG ON ACCOUNT TO ROLE GOVERNANCE_ADMIN_ROLE;

-- Grant access to account usage for monitoring
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE GOVERNANCE_ADMIN_ROLE;

-- ============================================================
-- SECTION 3: GRANT ACCESS TO OTHER SCHEMAS
-- ============================================================

-- Governance admin needs to see all schemas to apply policies
GRANT USAGE ON SCHEMA DITTEAU_DATA.DEPOSIT TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT USAGE ON SCHEMA DITTEAU_DATA.DETERGE TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT USAGE ON SCHEMA DITTEAU_DATA.DISTRIBUTE TO ROLE GOVERNANCE_ADMIN_ROLE;

-- Grant SELECT on all tables (needed to apply policies)
GRANT SELECT ON ALL TABLES IN SCHEMA DITTEAU_DATA.DEPOSIT TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT SELECT ON ALL TABLES IN SCHEMA DITTEAU_DATA.DETERGE TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT SELECT ON ALL TABLES IN SCHEMA DITTEAU_DATA.DISTRIBUTE TO ROLE GOVERNANCE_ADMIN_ROLE;

-- Grant on future tables
GRANT SELECT ON FUTURE TABLES IN SCHEMA DITTEAU_DATA.DEPOSIT TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT SELECT ON FUTURE TABLES IN SCHEMA DITTEAU_DATA.DETERGE TO ROLE GOVERNANCE_ADMIN_ROLE;
GRANT SELECT ON FUTURE TABLES IN SCHEMA DITTEAU_DATA.DISTRIBUTE TO ROLE GOVERNANCE_ADMIN_ROLE;

-- ============================================================
-- SECTION 4: GRANT GOVERNANCE ROLE TO USERS
-- ============================================================

-- Grant governance admin role to appropriate users
-- IMPORTANT: Replace with your actual usernames

-- Example grants (uncomment and customize):
-- GRANT ROLE GOVERNANCE_ADMIN_ROLE TO USER LVANPELT;
-- GRANT ROLE GOVERNANCE_ADMIN_ROLE TO USER DATA_GOVERNANCE_LEAD;
-- GRANT ROLE GOVERNANCE_ADMIN_ROLE TO USER SECURITY_ADMIN;

-- Grant to SYSADMIN for administrative access
GRANT ROLE GOVERNANCE_ADMIN_ROLE TO ROLE SYSADMIN;

-- ============================================================
-- SECTION 5: CREATE WAREHOUSES FOR GOVERNANCE WORK
-- ============================================================

--  Create dedicated warehouse for governance operations
CREATE WAREHOUSE IF NOT EXISTS GOVERNANCE_WH
    WAREHOUSE_SIZE = 'XSMALL'
    AUTO_SUSPEND = 60
    AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE
    COMMENT = 'Warehouse for governance policy management and auditing';

-- Grant warehouse usage to governance admin
GRANT USAGE ON WAREHOUSE GOVERNANCE_WH TO ROLE GOVERNANCE_ADMIN_ROLE;

-- ============================================================
-- SECTION 6: VERIFICATION
-- ============================================================

-- Verify schema creation
SHOW SCHEMAS IN DATABASE DITTEAU_DATA;

-- Verify role creation
SHOW ROLES LIKE 'GOVERNANCE_ADMIN_ROLE';

-- Verify grants to governance role
SHOW GRANTS TO ROLE GOVERNANCE_ADMIN_ROLE;

-- ============================================================
-- SECTION 7: NEXT STEPS
-- ============================================================

/*
SETUP COMPLETE

Next Steps:
-----------
1. Grant GOVERNANCE_ADMIN_ROLE to appropriate users (Section 4)
2. Run 01_roles_and_grants.sql to set up data layer roles
3. Run 10_tags.sql to create tag taxonomy
4. Run 12_masking_policies.sql to create masking policies
5. Run 13_row_access_policies.sql to create row access policies

Testing:
--------
-- Switch to governance role and verify access
USE ROLE GOVERNANCE_ADMIN_ROLE;
USE DATABASE DITTEAU_DATA;
USE SCHEMA GOVERNANCE;
USE WAREHOUSE GOVERNANCE_WH;

-- Should succeed
SELECT CURRENT_ROLE(), CURRENT_DATABASE(), CURRENT_SCHEMA(), CURRENT_WAREHOUSE();

-- Verify you can see other schemas
SHOW SCHEMAS IN DATABASE DITTEAU_DATA;
SHOW TABLES IN SCHEMA DITTEAU_DATA.DEPOSIT;
SHOW TABLES IN SCHEMA DITTEAU_DATA.DETERGE;
SHOW TABLES IN SCHEMA DITTEAU_DATA.DISTRIBUTE;
*/

-- ============================================================
-- END OF SCRIPT
-- ============================================================
