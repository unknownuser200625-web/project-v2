-- =============================================================================
-- MIGRATION: fix_memberships_policy_drift
-- DB VERSION: 20260310122348
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-10
-- PURPOSE:
--   Drop and recreate all app.memberships policies with full constitutional
--   compliance: initPlan cached predicates, is_platform_admin guards,
--   deleted_at IS NULL filters, restored bootstrap INSERT with NOT EXISTS guard.
--   Also restores tenants_platform_admin_bootstrap_insert with NOT EXISTS guard.
--
-- ROLLBACK:
--   Drop all recreated policies and restore prior versions from:
--   supabase/backups/baseline_schema.sql
-- =============================================================================

DROP POLICY IF EXISTS "memberships_admin_select"                    ON app.memberships;
DROP POLICY IF EXISTS "memberships_admin_insert"                    ON app.memberships;
DROP POLICY IF EXISTS "memberships_admin_update"                    ON app.memberships;
DROP POLICY IF EXISTS "memberships_admin_delete"                    ON app.memberships;
DROP POLICY IF EXISTS "memberships_self_select"                     ON app.memberships;
DROP POLICY IF EXISTS "memberships_platform_admin_bootstrap_insert" ON app.memberships;

CREATE POLICY "memberships_admin_select"
  ON app.memberships FOR SELECT
  TO authenticated
  USING (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
    AND deleted_at IS NULL
  );

CREATE POLICY "memberships_self_select"
  ON app.memberships FOR SELECT
  TO authenticated
  USING (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND user_id = (SELECT (auth.jwt() ->> 'user_id')::uuid)
    AND deleted_at IS NULL
    AND revoked_at IS NULL
  );

CREATE POLICY "memberships_admin_insert"
  ON app.memberships FOR INSERT
  TO authenticated
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

CREATE POLICY "memberships_platform_admin_bootstrap_insert"
  ON app.memberships FOR INSERT
  TO authenticated
  WITH CHECK (
    (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND NOT EXISTS (
      SELECT 1 FROM app.memberships m
      WHERE m.tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
        AND m.deleted_at IS NULL
        AND m.revoked_at IS NULL
    )
  );

CREATE POLICY "memberships_admin_update"
  ON app.memberships FOR UPDATE
  TO authenticated
  USING (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
    AND deleted_at IS NULL
  )
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

CREATE POLICY "memberships_admin_delete"
  ON app.memberships FOR DELETE
  TO authenticated
  USING (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
    AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
  );

DROP POLICY IF EXISTS "tenants_platform_admin_insert"           ON app.tenants;
DROP POLICY IF EXISTS "tenants_platform_admin_bootstrap_insert" ON app.tenants;

CREATE POLICY "tenants_platform_admin_bootstrap_insert"
  ON app.tenants FOR INSERT
  TO authenticated
  WITH CHECK (
    (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
    AND NOT EXISTS (
      SELECT 1 FROM app.tenants WHERE deleted_at IS NULL
    )
  );
