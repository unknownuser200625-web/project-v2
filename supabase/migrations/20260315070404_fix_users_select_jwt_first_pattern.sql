-- =============================================================================
-- MIGRATION: fix_users_select_jwt_first_pattern
-- DB VERSION: 20260315070404
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-15
-- SEVERITY: HIGH — constitutional violation (PVD V2 §5.1 JWT-First rule)
--
-- PROBLEM:
--   users_select policy used auth.uid() instead of the constitutionally
--   mandated JWT-first pattern. PVD V2 §5.1 requires all RLS predicates
--   to derive identity exclusively from JWT claims via (SELECT auth.jwt()).
--   auth.uid() is a non-JWT path that bypasses the initPlan optimization
--   and violates the "JWT claims drive tenant isolation" constitutional rule.
--
-- FIX:
--   Replace:  auth_user_id = (SELECT auth.uid())
--   With:     auth_user_id = (SELECT (auth.jwt() ->> 'user_id')::uuid)
--
-- ROLLBACK:
--   DROP POLICY IF EXISTS "users_select" ON app.users;
--   CREATE POLICY "users_select" ON app.users FOR SELECT TO authenticated
--   USING (
--     deleted_at IS NULL
--     AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
--     AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
--     AND (
--       (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
--       OR auth_user_id = (SELECT auth.uid())
--     )
--   );
-- =============================================================================

DROP POLICY IF EXISTS "users_select" ON app.users;

CREATE POLICY "users_select"
  ON app.users FOR SELECT
  TO authenticated
  USING (
    deleted_at IS NULL
    AND (SELECT (auth.jwt() ->> 'is_platform_admin'::text))::boolean IS NOT TRUE
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (
      (SELECT auth.jwt() ->> 'app_role'::text) = 'admin'
      OR auth_user_id = (SELECT (auth.jwt() ->> 'user_id'::text)::uuid)
    )
  );
