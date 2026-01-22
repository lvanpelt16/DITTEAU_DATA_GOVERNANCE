# DITTEAU_DATA_GOVERNANCE
Configuring governance database/roles for a new Ditteau Data client institution

## Environment Structure

This governance framework supports three environments:
- **DITTEAU_DATA_DEV** - Development environment
- **DITTEAU_DATA_TEST** - Testing environment
- **DITTEAU_DATA_PROD** - Production environment

Governance is centralized in a shared **DITTEAU_DATA_GOVERNANCE** database that applies policies across all three environments.

## Warehouse Structure

Each environment has dedicated warehouses:
- **TRANSFORM_DEV/TEST/PROD** - For dbt transformations and data engineering
- **ANALYST_DEV/TEST/PROD** - For analyst queries
- **GOVERNANCE_DEV/TEST/PROD** - For governance policy management and auditing

## Quick Start

1. Run setup scripts in order:
   - `scripts/setup/00_governance_schema.sql` - Create governance database and roles
   - `scripts/setup/01_roles_and_grants.sql` - Set up role hierarchy and grants
2. Create governance policies:
   - `scripts/policies/10_tags.sql` - Create tag taxonomy
   - `scripts/policies/11_masking_policies.sql` - Create masking policies
   - `scripts/policies/12_row_access_policies.sql` - Create row access policies
3. Set up monitoring:
   - `scripts/monitoring/30_helper_views.sql` - Create monitoring views
   - `scripts/monitoring/31_audit_queries.sql` - Run compliance audits

See `docs/implementation_guide.md` for detailed instructions.
