# Ditteau Data Governance Implementation Guide

## Quick Start Guide

This guide walks you through implementing governance for Ditteau Data from scratch.

## Prerequisites

- [ ] Snowflake ACCOUNTADMIN or SECURITYADMIN access
- [ ] Understanding of FERPA requirements
- [ ] List of users and their required access levels
- [ ] Institutional data classification policy

## Implementation Timeline

**Week 1: Foundation**
- Days 1-2: Set up schemas and roles
- Days 3-5: Create tag taxonomy and document policies

**Week 2: Core Policies**
- Days 1-3: Create masking policies
- Days 4-5: Create row access policies and test

**Week 3: Application**
- Days 1-2: Apply to DETERGE layer
- Days 3-4: Apply to DISTRIBUTE layer
- Day 5: Testing and verification

**Week 4: Monitoring & Documentation**
- Days 1-2: Set up monitoring views
- Days 3-4: Document procedures
- Day 5: Team training

## Step-by-Step Implementation

### Phase 1: Initial Setup (Days 1-2)

#### Step 1.1: Create Governance Schema

```sql
-- In Snowflake UI, run:
USE ROLE ACCOUNTADMIN;
@scripts/setup/00_governance_schema.sql
```

**Verification:**
```sql
SHOW SCHEMAS IN DATABASE DITTEAU_DATA;
-- Should see: GOVERNANCE schema

SHOW ROLES LIKE 'GOVERNANCE%';
-- Should see: GOVERNANCE_ADMIN_ROLE
```

#### Step 1.2: Grant GOVERNANCE_ADMIN_ROLE to Users

Edit `scripts/setup/00_governance_schema.sql` Section 4:

```sql
-- Replace with your actual username
GRANT ROLE GOVERNANCE_ADMIN_ROLE TO USER YOUR_USERNAME;
GRANT ROLE GOVERNANCE_ADMIN_ROLE TO USER GOVERNANCE_LEAD;
```

Run the grants:
```sql
USE ROLE ACCOUNTADMIN;
GRANT ROLE GOVERNANCE_ADMIN_ROLE TO USER <your_username>;
```

**Verification:**
```sql
SHOW GRANTS TO USER <your_username>;
-- Should include GOVERNANCE_ADMIN_ROLE
```

#### Step 1.3: Set Up Role Hierarchy

```sql
USE ROLE ACCOUNTADMIN;
@scripts/setup/01_roles_and_grants.sql
```

**Customize:**
1. Edit Section 5 of `01_roles_and_grants.sql`
2. Add your institutional users to appropriate roles
3. Run the customized grants

**Verification:**
```sql
-- Test switching to governance role
USE ROLE GOVERNANCE_ADMIN_ROLE;
USE WAREHOUSE GOVERNANCE_WH;
SELECT CURRENT_ROLE(), CURRENT_WAREHOUSE();
-- Should show GOVERNANCE_ADMIN_ROLE, GOVERNANCE_WH

-- Verify access to schemas
SHOW SCHEMAS IN DATABASE DITTEAU_DATA;
-- Should see: DEPOSIT, DETERGE, DISTRIBUTE, GOVERNANCE
```

### Phase 2: Create Tag Taxonomy (Days 3-5)

#### Step 2.1: Create Tags

```sql
USE ROLE GOVERNANCE_ADMIN_ROLE;
USE DATABASE DITTEAU_DATA;
USE SCHEMA GOVERNANCE;

@scripts/policies/10_tags.sql
```

**Verification:**
```sql
SHOW TAGS IN SCHEMA GOVERNANCE;
-- Should see: SENSITIVITY_LEVEL, COMPLIANCE_TYPE, CONTAINS_PII, etc.

DESCRIBE TAG SENSITIVITY_LEVEL;
-- Should show allowed values: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
```

#### Step 2.2: Document Institutional Classification Policy

Create a document that maps your institutional data to sensitivity levels:

| Data Type | Example | Sensitivity Level | Compliance Type |
|-----------|---------|-------------------|-----------------|
| Student SSN | 123-45-6789 | RESTRICTED | FERPA |
| Student Email | student@edu | CONFIDENTIAL | FERPA |
| Student Name | John Doe | CONFIDENTIAL | FERPA |
| Course Code | MATH-101 | INTERNAL | NONE |
| Aggregate Enrollment | 1,500 students | PUBLIC | NONE |

Save this in `docs/data_classification_policy.md`

### Phase 3: Create Masking Policies (Week 2, Days 1-3)

#### Step 3.1: Review and Customize Masking Logic

Open `scripts/policies/20_masking_policies.sql` and review each policy:

**Key Decision Points:**
1. **SSN_MASK**: Who needs full SSN access?
   - Registrar? ✓
   - Financial Aid? ✓
   - IR? Usually NO (aggregate only)
   - Data Engineers? Last 4 digits for testing

2. **EMAIL_MASK**: Who needs email access?
   - Most analysts: YES
   - External reporting: NO

3. **DOB_MASK**: Who needs exact birth date?
   - Financial Aid: YES (age calculations)
   - IR: Year only (cohort analysis)
   - Registrar: YES

**Customize the policies** to match your institution's needs.

#### Step 3.2: Create Masking Policies

```sql
USE ROLE GOVERNANCE_ADMIN_ROLE;
@scripts/policies/20_masking_policies.sql
```

**Verification:**
```sql
SHOW MASKING POLICIES IN SCHEMA GOVERNANCE;
-- Should see: SSN_MASK, EMAIL_MASK, DOB_MASK, PHONE_MASK, etc.

DESCRIBE MASKING POLICY SSN_MASK;
-- Review the policy definition
```

#### Step 3.3: Test Masking Policies

Create a test table:

```sql
USE ROLE GOVERNANCE_ADMIN_ROLE;

-- Create test table
CREATE OR REPLACE TABLE GOVERNANCE.TEST_MASKING (
    STUDENT_ID VARCHAR,
    SSN VARCHAR,
    EMAIL VARCHAR,
    DOB DATE
);

-- Insert test data
INSERT INTO GOVERNANCE.TEST_MASKING VALUES
    ('12345', '123-45-6789', 'student@university.edu', '2000-01-15'),
    ('67890', '987-65-4321', 'another@university.edu', '1999-12-31');

-- Apply masking policies
ALTER TABLE GOVERNANCE.TEST_MASKING
    MODIFY COLUMN SSN SET MASKING POLICY SSN_MASK;

ALTER TABLE GOVERNANCE.TEST_MASKING
    MODIFY COLUMN EMAIL SET MASKING POLICY EMAIL_MASK;

ALTER TABLE GOVERNANCE.TEST_MASKING
    MODIFY COLUMN DOB SET MASKING POLICY DOB_MASK;

-- Test as different roles
USE ROLE GOVERNANCE_ADMIN_ROLE;
SELECT * FROM GOVERNANCE.TEST_MASKING;
-- Should see: Full SSN, Full Email, Full DOB

USE ROLE DATA_ENGINEER_ROLE;
SELECT * FROM GOVERNANCE.TEST_MASKING;
-- Should see: XXX-XX-6789 (last 4 of SSN), ***@***, NULL

USE ROLE IR_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_MASKING;
-- Should see: NULL (SSN), Full Email, 2000-01-01 (year only)

USE ROLE REGISTRAR_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_MASKING;
-- Should see: Full SSN, Full Email, Full DOB
```

**If masking doesn't work as expected:**
1. Review the CASE WHEN logic in the policy
2. Check `SHOW GRANTS TO ROLE <role_name>`
3. Verify you're using the correct role names in the policy

### Phase 4: Create Row Access Policies (Week 2, Days 4-5)

#### Step 4.1: Create Row Access Policies

```sql
USE ROLE GOVERNANCE_ADMIN_ROLE;
@scripts/policies/30_row_access_policies.sql
```

**Verification:**
```sql
SHOW ROW ACCESS POLICIES IN SCHEMA GOVERNANCE;
-- Should see: ENROLLMENT_ROW_ACCESS, ACTIVE_RECORDS_ONLY, etc.
```

#### Step 4.2: Test Row Access Policies

```sql
-- Create test table
CREATE OR REPLACE TABLE GOVERNANCE.TEST_ROW_ACCESS (
    STUDENT_ID VARCHAR,
    ENROLLMENT_STATUS VARCHAR,
    IS_ACTIVE BOOLEAN
);

-- Insert test data
INSERT INTO GOVERNANCE.TEST_ROW_ACCESS VALUES
    ('12345', 'ENROLLED', TRUE),
    ('23456', 'ADMITTED', TRUE),
    ('34567', 'PROSPECTIVE', TRUE),
    ('45678', 'WITHDRAWN', TRUE),
    ('56789', 'GRADUATED', TRUE),
    ('67890', 'ENROLLED', FALSE);

-- Apply row access policy
ALTER TABLE GOVERNANCE.TEST_ROW_ACCESS
    ADD ROW ACCESS POLICY ENROLLMENT_ROW_ACCESS ON (ENROLLMENT_STATUS);

-- Test as different roles
USE ROLE IR_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_ROW_ACCESS;
-- Should see: All rows (IR has full access)

USE ROLE ENROLLMENT_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_ROW_ACCESS;
-- Should see: Only PROSPECTIVE, ADMITTED, ENROLLED

USE ROLE REGISTRAR_ANALYST_ROLE;
SELECT * FROM GOVERNANCE.TEST_ROW_ACCESS;
-- Should see: Only ENROLLED, GRADUATED, WITHDRAWN
```

### Phase 5: Apply to Production Tables (Week 3)

#### Step 5.1: Identify PII Columns

Run the helper query:

```sql
USE ROLE GOVERNANCE_ADMIN_ROLE;
@scripts/monitoring/50_helper_views.sql

-- Find potential sensitive columns
SELECT * FROM GOVERNANCE.V_POTENTIAL_SENSITIVE_COLUMNS
ORDER BY SCHEMA_NAME, TABLE_NAME;
```

Create a spreadsheet tracking:
- Table name
- Column name
- Suggested policy
- Applied? (Y/N)
- Applied date

#### Step 5.2: Apply to DETERGE Layer

```sql
USE ROLE GOVERNANCE_ADMIN_ROLE;
@scripts/application/41_apply_to_deterge.sql
```

**Note:** This script is a template. Customize for your actual tables.

#### Step 5.3: Apply to DISTRIBUTE Layer

```sql
USE ROLE GOVERNANCE_ADMIN_ROLE;
@scripts/application/42_apply_to_distribute.sql
```

#### Step 5.4: Verify Application

```sql
-- Check masking policy applications
SELECT * FROM GOVERNANCE.V_MASKING_POLICY_REFERENCES
WHERE REF_SCHEMA_NAME IN ('DETERGE', 'DISTRIBUTE')
ORDER BY REF_SCHEMA_NAME, REF_ENTITY_NAME, REF_COLUMN_NAME;

-- Check row access policy applications
SELECT * FROM GOVERNANCE.V_ROW_ACCESS_POLICY_REFERENCES
WHERE REF_SCHEMA_NAME IN ('DETERGE', 'DISTRIBUTE')
ORDER BY REF_SCHEMA_NAME, REF_ENTITY_NAME;

-- Check tag applications
SELECT * FROM GOVERNANCE.V_TAGGED_OBJECTS
WHERE OBJECT_SCHEMA IN ('DETERGE', 'DISTRIBUTE')
ORDER BY OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME;
```

### Phase 6: End-to-End Testing (Week 3, Day 5)

#### Test Checklist

Create a test script for each analyst role:

```sql
-- ====================
-- IR ANALYST TEST
-- ====================
USE ROLE IR_ANALYST_ROLE;
USE WAREHOUSE ANALYST_WH;

-- Should succeed: Read aggregate data
SELECT 
    COUNT(*) AS student_count,
    AVG(YEAR(birth_date)) AS avg_birth_year
FROM DISTRIBUTE.DIM_STUDENT;

-- Should see masked: SSN should be NULL
SELECT ssn FROM DISTRIBUTE.DIM_STUDENT LIMIT 5;

-- Should see partial: DOB should show year only
SELECT birth_date FROM DISTRIBUTE.DIM_STUDENT LIMIT 5;

-- Document results:
-- ✓ Can query tables
-- ✓ SSN is NULL
-- ✓ DOB shows year only
```

Repeat for each role:
- [ ] IR_ANALYST_ROLE
- [ ] REGISTRAR_ANALYST_ROLE
- [ ] ENROLLMENT_ANALYST_ROLE
- [ ] FINANCIAL_AID_ANALYST_ROLE
- [ ] DATA_ENGINEER_ROLE

### Phase 7: Documentation (Week 4, Days 1-2)

#### Document for Each Role

Create `docs/role_access_matrix.md` with complete access matrix.

#### Create Runbooks

1. **Adding a New Table**: `docs/runbook_new_table.md`
2. **Updating a Policy**: `docs/runbook_update_policy.md`
3. **Granting Access**: `docs/runbook_grant_access.md`
4. **Monthly Audit**: `docs/runbook_monthly_audit.md`

### Phase 8: Team Training (Week 4, Days 3-5)

#### Training Sessions

**Session 1: Data Engineers**
- How to work with masked data
- Testing procedures
- When to notify governance team

**Session 2: Analysts**
- What data they can access
- How to request additional access
- Understanding masked fields

**Session 3: Governance Team**
- Monthly audit procedures
- Handling access requests
- Policy update process

## Ongoing Maintenance

### Weekly Tasks
- [ ] Review new tables/columns in INFORMATION_SCHEMA
- [ ] Check for unapplied policies
- [ ] Monitor access patterns

### Monthly Tasks
- [ ] Run `51_audit_queries.sql`
- [ ] Review `V_POTENTIAL_SENSITIVE_COLUMNS`
- [ ] Update policy application tracking spreadsheet
- [ ] Document any policy changes

### Quarterly Tasks
- [ ] Full compliance review
- [ ] Policy effectiveness assessment
- [ ] Update documentation
- [ ] Conduct audit with compliance team

### Annual Tasks
- [ ] Review all policies against regulatory changes
- [ ] Update role access matrix
- [ ] Refresh team training
- [ ] Document lessons learned

## Troubleshooting Guide

### Issue: Policy Not Applying

**Symptoms:** Data appears unmasked when it should be masked

**Solutions:**
1. Check policy exists: `SHOW MASKING POLICIES`
2. Verify role in policy: Check CASE WHEN logic
3. Confirm policy applied: Check `V_MASKING_POLICY_REFERENCES`
4. Restart session: Close and reopen Snowflake UI

### Issue: Access Denied

**Symptoms:** User cannot query table

**Solutions:**
1. Verify role granted: `SHOW GRANTS TO USER <username>`
2. Check schema grants: `SHOW GRANTS ON SCHEMA <schema>`
3. Verify warehouse access: `SHOW GRANTS ON WAREHOUSE <warehouse>`
4. Check row access policy isn't filtering everything

### Issue: Performance Degradation

**Symptoms:** Queries slower after applying policies

**Solutions:**
1. Review row access policy complexity
2. Consider pre-filtering in views
3. Add appropriate indexes
4. Monitor with `QUERY_HISTORY`

## Success Criteria

Your governance implementation is successful when:

- [ ] All PII columns have appropriate masking policies
- [ ] All sensitive tables have appropriate row access policies
- [ ] All tables and columns are tagged
- [ ] Each role can access only their authorized data
- [ ] Masking works correctly for each role
- [ ] Team is trained and documentation is complete
- [ ] Monthly audit process is established
- [ ] Access request process is documented

## Additional Resources

- Snowflake Masking Policies: https://docs.snowflake.com/en/user-guide/security-column-ddm
- Snowflake Row Access Policies: https://docs.snowflake.com/en/user-guide/security-row
- FERPA Guidelines: https://www2.ed.gov/policy/gen/guid/fpco/ferpa/index.html

---

**Document Version:** 1.0  
**Last Updated:** 2025-01-XX  
**Maintained By:** Ditteau Data Governance Team

