# Migration Governance Policy

All migrations MUST comply with the following rules, enforced at review time.

## Rules

1. **Timestamp prefix required**
   All migration files must begin with a `YYYYMMDDHHММSS` or `YYYYMMDD000000` timestamp prefix.
   Example: `20260221000000_my_feature.sql`

2. **Always use `IF NOT EXISTS`**
   All `CREATE TABLE`, `CREATE SCHEMA`, `CREATE INDEX`, and `CREATE EXTENSION` statements must
   include `IF NOT EXISTS` to guarantee idempotency.

3. **Always prefix schema**
   All object references must include explicit schema qualification.
   Example: `public.users`, `app.orders` — never bare `users` or `orders`.

4. **No test artifacts in migrations**
   Migrations containing `_test`, `_verification`, `_proof`, or `_temp` table names are forbidden
   from being merged to `main`. Only permitted on `staging` during pipeline bootstrapping.

5. **No destructive operations without a transaction block**
   Any migration containing `DROP`, `TRUNCATE`, `ALTER TABLE ... DROP COLUMN`, or `DELETE` must
   wrap the entire statement in a transaction:

   ```sql
   BEGIN;
   DROP TABLE IF EXISTS public.old_table CASCADE;
   COMMIT;
   ```

6. **RLS required on all `app` schema tables**
   Every table created under the `app` schema must have `ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;`
   in the same migration. No exceptions.

7. **No manual dashboard edits**
   The Supabase dashboard SQL editor must not be used for schema changes in staging or production.
   All schema changes must go through `supabase/migrations/` and the CI pipeline.
   Any dashboard change that is not replicated to a migration file will be flagged as drift by CI.

8. **Tenant Isolation Enforcement**
   All future app tables MUST include a mandatory foreign key to the tenant primitive:
   `tenant_id uuid REFERENCES app.tenants(id) NOT NULL`
   This is the non-negotiable anchor for Row-Level Security.
