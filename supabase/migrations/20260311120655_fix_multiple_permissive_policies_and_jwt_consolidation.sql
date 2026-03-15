-- =============================================================================
-- MIGRATION: fix_multiple_permissive_policies_and_jwt_consolidation
-- DB VERSION: 20260311120655
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-11
-- PURPOSE:
--   1. Consolidate dual permissive SELECT/INSERT policies into single policies
--      with OR logic — eliminates multiple_permissive_policies WARN (×6).
--   2. Align users_self_select to cached pattern.
--   3. Minimise auth.jwt() call sites per policy where possible.
--
-- ADVISOR FINDINGS RESOLVED:
--   multiple_permissive_policies:
--     app.users       authenticated SELECT  (users_admin_select, users_self_select)
--     app.staff       authenticated SELECT  (staff_admin_select, staff_self_select)
--     app.memberships authenticated SELECT  (memberships_admin_select, memberships_self_select)
--     app.memberships authenticated INSERT  (memberships_admin_insert, memberships_platform_admin_bootstrap_insert)
--     app.tenants     authenticated SELECT  (tenants_owner_select, tenants_platform_admin_select)
--     app.tenants     authenticated UPDATE  (tenants_owner_update, tenants_platform_admin_update)
--
-- ROLLBACK:
--   Drop consolidated policies and recreate split versions from:
--   supabase/backups/baseline_schema.sql + 20260310122348_fix_memberships_policy_drift
-- =============================================================================

-- ─────────────────────────────────────────────────────────────────
-- app.users
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "users_admin_select" ON app.users;
DROP POLICY IF EXISTS "users_self_select"  ON app.users;

CREATE POLICY "users_select"
  ON app.users FOR SELECT
  TO authenticated
  USING (
    deleted_at IS NULL
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (
      (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
      OR auth_user_id = (SELECT auth.uid())
    )
  );

-- ─────────────────────────────────────────────────────────────────
-- app.staff
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "staff_admin_select" ON app.staff;
DROP POLICY IF EXISTS "staff_self_select"  ON app.staff;

CREATE POLICY "staff_select"
  ON app.staff FOR SELECT
  TO authenticated
  USING (
    deleted_at IS NULL
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (
      (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
      OR id = (SELECT (auth.jwt() ->> 'staff_id')::uuid)
    )
  );

-- ─────────────────────────────────────────────────────────────────
-- app.memberships — SELECT
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "memberships_admin_select" ON app.memberships;
DROP POLICY IF EXISTS "memberships_self_select"  ON app.memberships;

CREATE POLICY "memberships_select"
  ON app.memberships FOR SELECT
  TO authenticated
  USING (
    deleted_at IS NULL
    AND revoked_at IS NULL
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (
      (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
      OR user_id = (SELECT (auth.jwt() ->> 'user_id')::uuid)
    )
  );

-- ─────────────────────────────────────────────────────────────────
-- app.memberships — INSERT
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "memberships_admin_insert"                    ON app.memberships;
DROP POLICY IF EXISTS "memberships_platform_admin_bootstrap_insert" ON app.memberships;

CREATE POLICY "memberships_insert"
  ON app.memberships FOR INSERT
  TO authenticated
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (
      (
        (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
        AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
      )
      OR (
        (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
        AND NOT EXISTS (
          SELECT 1 FROM app.memberships m
          WHERE m.tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
            AND m.deleted_at IS NULL
            AND m.revoked_at IS NULL
        )
      )
    )
  );

-- ─────────────────────────────────────────────────────────────────
-- app.tenants — SELECT
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "tenants_owner_select"          ON app.tenants;
DROP POLICY IF EXISTS "tenants_platform_admin_select" ON app.tenants;

CREATE POLICY "tenants_select"
  ON app.tenants FOR SELECT
  TO authenticated
  USING (
    (
      (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
    )
    OR
    (
      deleted_at IS NULL
      AND id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
      AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
    )
  );

-- ─────────────────────────────────────────────────────────────────
-- app.tenants — UPDATE
-- ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "tenants_owner_update"          ON app.tenants;
DROP POLICY IF EXISTS "tenants_platform_admin_update" ON app.tenants;

CREATE POLICY "tenants_update"
  ON app.tenants FOR UPDATE
  TO authenticated
  USING (
    (
      (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
    )
    OR
    (
      deleted_at IS NULL
      AND id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
      AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
      AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
    )
  )
  WITH CHECK (
    (
      (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
    )
    OR
    (
      id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
      AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
      AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
    )
  );
