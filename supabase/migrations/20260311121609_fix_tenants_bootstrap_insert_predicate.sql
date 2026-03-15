-- =============================================================================
-- MIGRATION: fix_tenants_bootstrap_insert_predicate
-- DB VERSION: 20260311121609
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-11
-- SEVERITY: HIGH — broken bootstrap gate allowed unlimited tenant creation
--
-- ROOT CAUSE:
--   Migration 20260311121131 introduced a broken NOT EXISTS predicate:
--     WHERE t.id = id AND t.deleted_at IS NULL
--   In INSERT context, bare `id` is the NEW row being inserted.
--   t.id = NEW.id: checks whether an existing row has the same UUID as
--   the row being inserted — nearly always FALSE for a fresh UUIDv7.
--   Result: NOT EXISTS always TRUE → bootstrap gate never closes.
--   Platform admin could insert unlimited tenants.
--
-- FIX:
--   NOT EXISTS (SELECT 1 FROM app.tenants WHERE deleted_at IS NULL)
--   Closes after ANY active tenant record exists. Matches original baseline.
--
-- ROLLBACK:
--   DROP POLICY "tenants_bootstrap_insert" ON app.tenants;
--   CREATE POLICY "tenants_bootstrap_insert" ON app.tenants FOR INSERT
--   TO authenticated WITH CHECK (
--     (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
--     AND NOT EXISTS (
--       SELECT 1 FROM app.tenants t WHERE t.id = id AND t.deleted_at IS NULL
--     )
--   );
-- =============================================================================

DROP POLICY IF EXISTS "tenants_bootstrap_insert" ON app.tenants;

CREATE POLICY "tenants_bootstrap_insert"
  ON app.tenants FOR INSERT
  TO authenticated
  WITH CHECK (
    (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
    AND NOT EXISTS (
      SELECT 1 FROM app.tenants
      WHERE deleted_at IS NULL
    )
  );
