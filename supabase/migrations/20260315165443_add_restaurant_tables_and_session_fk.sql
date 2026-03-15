-- =============================================================================
-- MIGRATION: add_restaurant_tables_and_session_fk
-- DB VERSION: 20260315165443
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-15
--
-- PURPOSE:
--   1. Create app.restaurant_tables — physical table/QR-station entity.
--      Required by PVD V2 Step 7 spec but absent from phase5_business_logic_tables.
--   2. Add table_id FK column to app.table_sessions (additive — existing rows
--      remain valid; nullable to preserve backward compatibility).
--
-- RESTAURANT_TABLES SCHEMA:
--   id              uuid PK
--   tenant_id       uuid NOT NULL (RLS isolation key)
--   restaurant_id   uuid NOT NULL FK -> app.restaurants
--   label           text NOT NULL (e.g. "Table 1", "Bar 3")
--   capacity        integer nullable
--   qr_code_token   text UNIQUE nullable (embedded in QR URL)
--   is_active       boolean default true
--   position_x/y    numeric nullable (floor-plan coords)
--   metadata        jsonb
--   standard audit columns (created_at, updated_at, deleted_at)
--
-- RLS CONTRACT:
--   - RLS + FORCE RLS enabled
--   - 4 policies (SELECT/INSERT/UPDATE/DELETE)
--   - All: initPlan cached JWT pattern, is_platform_admin exclusion guard
--   - SELECT: admin + staff (no role filter — staff need to see table layout)
--   - INSERT/UPDATE/DELETE: admin only
--
-- INDEXES:
--   - tenant_id (primary RLS predicate)
--   - restaurant_id
--   - active composite partial (restaurant_id, label)
--   - qr_code_token partial
--   - table_sessions.table_id
--
-- TRIGGERS: updated_at, soft_delete, audit.log_changes
--
-- ROLLBACK:
--   ALTER TABLE app.table_sessions DROP COLUMN IF EXISTS table_id;
--   DROP TABLE IF EXISTS app.restaurant_tables CASCADE;
-- =============================================================================

-- ── 1. app.restaurant_tables ─────────────────────────────────────────────────
CREATE TABLE app.restaurant_tables (
  id              uuid        PRIMARY KEY DEFAULT generate_uuidv7(),
  tenant_id       uuid        NOT NULL REFERENCES app.tenants(id),
  restaurant_id   uuid        NOT NULL REFERENCES app.restaurants(id),
  label           text        NOT NULL CHECK (char_length(trim(label)) > 0),
  capacity        integer     CHECK (capacity IS NULL OR capacity > 0),
  qr_code_token   text        UNIQUE,
  is_active       boolean     NOT NULL DEFAULT true,
  position_x      numeric,
  position_y      numeric,
  metadata        jsonb       NOT NULL DEFAULT '{}',
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  deleted_at      timestamptz,
  CONSTRAINT uq_table_label_per_restaurant
    UNIQUE (restaurant_id, label)
    DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE app.restaurant_tables ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.restaurant_tables FORCE ROW LEVEL SECURITY;

CREATE INDEX idx_restaurant_tables_tenant_id     ON app.restaurant_tables (tenant_id);
CREATE INDEX idx_restaurant_tables_restaurant_id ON app.restaurant_tables (restaurant_id);
CREATE INDEX idx_restaurant_tables_active        ON app.restaurant_tables (restaurant_id, label)
  WHERE deleted_at IS NULL AND is_active = true;
CREATE INDEX idx_restaurant_tables_qr_token      ON app.restaurant_tables (qr_code_token)
  WHERE qr_code_token IS NOT NULL AND deleted_at IS NULL;

CREATE TRIGGER trg_restaurant_tables_updated_at
  BEFORE UPDATE ON app.restaurant_tables
  FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();

CREATE TRIGGER trg_restaurant_tables_soft_delete
  BEFORE DELETE ON app.restaurant_tables
  FOR EACH ROW EXECUTE FUNCTION app.soft_delete();

CREATE TRIGGER trg_restaurant_tables_audit
  AFTER INSERT OR UPDATE OR DELETE ON app.restaurant_tables
  FOR EACH ROW EXECUTE FUNCTION audit.log_changes();

CREATE POLICY restaurant_tables_select ON app.restaurant_tables
  FOR SELECT TO authenticated
  USING (
    deleted_at IS NULL
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  );

CREATE POLICY restaurant_tables_insert ON app.restaurant_tables
  FOR INSERT TO authenticated
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  );

CREATE POLICY restaurant_tables_update ON app.restaurant_tables
  FOR UPDATE TO authenticated
  USING (
    deleted_at IS NULL
    AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  )
  WITH CHECK (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  );

CREATE POLICY restaurant_tables_delete ON app.restaurant_tables
  FOR DELETE TO authenticated
  USING (
    tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  );


-- ── 2. Add table_id to app.table_sessions (additive) ─────────────────────────
ALTER TABLE app.table_sessions
  ADD COLUMN table_id uuid REFERENCES app.restaurant_tables(id);

CREATE INDEX idx_table_sessions_table_id ON app.table_sessions (table_id)
  WHERE table_id IS NOT NULL;
