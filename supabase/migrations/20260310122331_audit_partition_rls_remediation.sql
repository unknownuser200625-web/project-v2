-- =============================================================================
-- MIGRATION: audit_partition_rls_remediation
-- DB VERSION: 20260310122331
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-10
-- PURPOSE:
--   Enable RLS + FORCE RLS on all 14 audit.change_log partition tables.
--   Replicate parent change_log policies onto each partition.
--   PostgreSQL partition tables do NOT inherit RLS from parent tables.
--   This is a constitutional security requirement (PVD V2 §6.2).
--
-- ROLLBACK:
--   For each partition: ALTER TABLE audit.<partition> DISABLE ROW LEVEL SECURITY;
--   DROP POLICY "audit_platform_admin_select" ON audit.<partition>;
--   DROP POLICY "audit_tenant_admin_select"   ON audit.<partition>;
-- =============================================================================

ALTER TABLE audit.change_log_2026_02 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_02 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_03 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_03 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_04 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_04 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_05 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_05 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_06 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_06 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_07 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_07 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_08 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_08 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_09 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_09 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_10 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_10 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_11 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_11 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_12 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2026_12 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2027_01 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2027_01 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2027_02 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2027_02 FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2027_03 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.change_log_2027_03 FORCE ROW LEVEL SECURITY;

DO $$
DECLARE
  partitions TEXT[] := ARRAY[
    'change_log_2026_02','change_log_2026_03','change_log_2026_04',
    'change_log_2026_05','change_log_2026_06','change_log_2026_07',
    'change_log_2026_08','change_log_2026_09','change_log_2026_10',
    'change_log_2026_11','change_log_2026_12','change_log_2027_01',
    'change_log_2027_02','change_log_2027_03'
  ];
  p TEXT;
BEGIN
  FOREACH p IN ARRAY partitions LOOP
    EXECUTE format(
      'CREATE POLICY "audit_platform_admin_select"
       ON audit.%I FOR SELECT TO authenticated
       USING ((SELECT (auth.jwt() ->> ''is_platform_admin'')::boolean) = TRUE)',
      p
    );
    EXECUTE format(
      'CREATE POLICY "audit_tenant_admin_select"
       ON audit.%I FOR SELECT TO authenticated
       USING (
         tenant_id = (SELECT (auth.jwt() ->> ''tenant_id'')::uuid)
         AND (SELECT (auth.jwt() ->> ''app_role'')::text) = ''admin''
         AND (SELECT (auth.jwt() ->> ''is_platform_admin'')::boolean) IS NOT TRUE
         AND (SELECT (auth.jwt() ->> ''aal'')::text) = ''aal2''
       )',
      p
    );
  END LOOP;
END $$;
