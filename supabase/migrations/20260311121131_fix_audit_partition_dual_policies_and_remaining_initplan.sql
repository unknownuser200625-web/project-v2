-- =============================================================================
-- MIGRATION: fix_audit_partition_dual_policies_and_remaining_initplan
-- DB VERSION: 20260311121131
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-11
-- PURPOSE:
--   1. Consolidate dual permissive SELECT policies on audit.change_log parent
--      and all 14 child partitions into a single policy with OR logic.
--      Eliminates multiple_permissive_policies WARN on 15 tables.
--   2. Rebuild remaining app table policies (restaurants ×4, users INSERT/UPDATE/
--      DELETE, staff INSERT/UPDATE/DELETE, memberships UPDATE/DELETE, tenants
--      bootstrap INSERT) with explicit (SELECT ...) initPlan wrappers on all
--      auth.jwt() call sites.
--
-- NOTE: The tenants_bootstrap_insert predicate in this migration contains a
--   logic bug (WHERE t.id = id) that is corrected by a subsequent migration:
--   20260311121609_fix_tenants_bootstrap_insert_predicate.sql
--
-- ADVISOR FINDINGS RESOLVED:
--   multiple_permissive_policies: audit.change_log + 14 partitions (×15)
--   auth_rls_initplan: restaurants ×4, users ×3, staff ×3, memberships ×2, tenants ×1
--
-- ROLLBACK:
--   Drop consolidated policies; recreate dual split pair from
--   20260310122331_audit_partition_rls_remediation and baseline_v1.sql
-- =============================================================================

-- ─────────────────────────────────────────────────────────────────
-- 1. AUDIT PARENT TABLE
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "audit_platform_admin_select" ON audit.change_log;
DROP POLICY IF EXISTS "audit_tenant_admin_select"   ON audit.change_log;

CREATE POLICY "audit_select"
  ON audit.change_log FOR SELECT
  TO authenticated
  USING (
    (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
    OR (
      (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
      AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
      AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    )
  );

-- ─────────────────────────────────────────────────────────────────
-- 2. ALL 14 PARTITION TABLES
-- ─────────────────────────────────────────────────────────────────
DO $$
DECLARE
  partition_name text;
BEGIN
  FOR partition_name IN
    SELECT c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_inherits i ON i.inhrelid = c.oid
    JOIN pg_class p ON p.oid = i.inhparent
    JOIN pg_namespace np ON np.oid = p.relnamespace
    WHERE np.nspname = 'audit'
      AND p.relname  = 'change_log'
      AND n.nspname  = 'audit'
      AND c.relkind  = 'r'
  LOOP
    EXECUTE format(
      'DROP POLICY IF EXISTS audit_platform_admin_select ON audit.%I',
      partition_name
    );
    EXECUTE format(
      'DROP POLICY IF EXISTS audit_tenant_admin_select ON audit.%I',
      partition_name
    );
    EXECUTE format($policy$
      CREATE POLICY audit_select
        ON audit.%I FOR SELECT
        TO authenticated
        USING (
          (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
          OR (
            (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
            AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
            AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
          )
        )
    $policy$, partition_name);
  END LOOP;
END;
$$;

-- ─────────────────────────────────────────────────────────────────
-- 3. app.restaurants
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "restaurants_select" ON app.restaurants;
DROP POLICY IF EXISTS "restaurants_insert" ON app.restaurants;
DROP POLICY IF EXISTS "restaurants_update" ON app.restaurants;
DROP POLICY IF EXISTS "restaurants_delete" ON app.restaurants;

CREATE POLICY "restaurants_select"
  ON app.restaurants FOR SELECT
  TO authenticated
  USING (
    deleted_at IS NULL
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
  );

CREATE POLICY "restaurants_insert"
  ON app.restaurants FOR INSERT
  TO authenticated
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

CREATE POLICY "restaurants_update"
  ON app.restaurants FOR UPDATE
  TO authenticated
  USING (
    deleted_at IS NULL
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  )
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

CREATE POLICY "restaurants_delete"
  ON app.restaurants FOR DELETE
  TO authenticated
  USING (
    deleted_at IS NULL
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

-- ─────────────────────────────────────────────────────────────────
-- 4. app.users — INSERT / UPDATE / DELETE
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "users_admin_insert" ON app.users;
DROP POLICY IF EXISTS "users_admin_update" ON app.users;
DROP POLICY IF EXISTS "users_admin_delete" ON app.users;

CREATE POLICY "users_insert"
  ON app.users FOR INSERT
  TO authenticated
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

CREATE POLICY "users_update"
  ON app.users FOR UPDATE
  TO authenticated
  USING (
    deleted_at IS NULL
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  )
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

CREATE POLICY "users_delete"
  ON app.users FOR DELETE
  TO authenticated
  USING (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

-- ─────────────────────────────────────────────────────────────────
-- 5. app.staff — INSERT / UPDATE / DELETE
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "staff_admin_insert" ON app.staff;
DROP POLICY IF EXISTS "staff_admin_update" ON app.staff;
DROP POLICY IF EXISTS "staff_admin_delete" ON app.staff;

CREATE POLICY "staff_insert"
  ON app.staff FOR INSERT
  TO authenticated
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

CREATE POLICY "staff_update"
  ON app.staff FOR UPDATE
  TO authenticated
  USING (
    deleted_at IS NULL
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  )
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

CREATE POLICY "staff_delete"
  ON app.staff FOR DELETE
  TO authenticated
  USING (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

-- ─────────────────────────────────────────────────────────────────
-- 6. app.memberships — UPDATE / DELETE
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "memberships_admin_update" ON app.memberships;
DROP POLICY IF EXISTS "memberships_admin_delete" ON app.memberships;

CREATE POLICY "memberships_update"
  ON app.memberships FOR UPDATE
  TO authenticated
  USING (
    deleted_at IS NULL
    AND revoked_at IS NULL
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  )
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

CREATE POLICY "memberships_delete"
  ON app.memberships FOR DELETE
  TO authenticated
  USING (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

-- ─────────────────────────────────────────────────────────────────
-- 7. app.tenants — bootstrap INSERT
-- NOTE: The NOT EXISTS predicate below contains a logic bug (t.id = id)
--       that is corrected by migration 20260311121609.
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "tenants_platform_admin_bootstrap_insert" ON app.tenants;

CREATE POLICY "tenants_bootstrap_insert"
  ON app.tenants FOR INSERT
  TO authenticated
  WITH CHECK (
    (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
    AND NOT EXISTS (
      SELECT 1 FROM app.tenants t
      WHERE t.id = id
        AND t.deleted_at IS NULL
    )
  );
