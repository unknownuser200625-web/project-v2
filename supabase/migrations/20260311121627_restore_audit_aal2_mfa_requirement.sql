-- =============================================================================
-- MIGRATION: restore_audit_aal2_mfa_requirement
-- DB VERSION: 20260311121627
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-11
-- SEVERITY: HIGH — security regression: MFA gate removed from audit log access
--
-- ROOT CAUSE:
--   Migration 20260311121131 consolidated dual audit SELECT policies but
--   silently dropped the aal2 requirement for tenant admin access.
--   Original audit_tenant_admin_select required:
--     AND (SELECT (auth.jwt() ->> 'aal')::text) = 'aal2'
--   PVD V2 §4.1 + §19.2: audit log access is a high-risk operation
--   requiring TOTP verification. Without aal2, a password-only compromise
--   exposes the full audit trail.
--
-- FIX:
--   Rebuild audit_select on parent + all 14 partitions with aal2 on
--   the tenant admin path. Platform admin path has no aal restriction.
--
-- ROLLBACK:
--   Re-run consolidated policy without aal2 from migration 20260311121131.
-- =============================================================================

-- ── Parent table ─────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "audit_select" ON audit.change_log;

CREATE POLICY "audit_select"
  ON audit.change_log FOR SELECT
  TO authenticated
  USING (
    -- Platform admin: full read for compliance and forensics (no aal restriction)
    (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) = TRUE
    OR (
      -- Tenant admin: own tenant audit only. Requires MFA session (aal2).
      -- PVD V2 §4.1 + §19.2: high-risk operation requiring TOTP verification.
      -- Password-only compromise must NOT expose audit trail.
      (SELECT (auth.jwt() ->> 'app_role')::text) = 'admin'
      AND (SELECT (auth.jwt() ->> 'is_platform_admin')::boolean) IS NOT TRUE
      AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)
      AND (SELECT (auth.jwt() ->> 'aal')::text) = 'aal2'
    )
  );

-- ── All 14 partition tables ───────────────────────────────────────────────────
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
    EXECUTE format('DROP POLICY IF EXISTS audit_select ON audit.%I', partition_name);

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
            AND (SELECT (auth.jwt() ->> 'aal')::text) = 'aal2'
          )
        )
    $policy$, partition_name);
  END LOOP;
END;
$$;
