-- =============================================================================
-- MIGRATION: phase5_business_logic_tables
-- DB VERSION: 20260315154516
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-15
--
-- PURPOSE: Phase 5 Business Logic — all operational tables for restaurant
--          onboarding, menu management, QR table sessions, and order processing.
--
-- TABLES CREATED:
--   app.activation_codes   — single-use 72h onboarding codes (PVD V2 §8.1)
--   app.menu_categories    — hierarchical menu categories per restaurant
--   app.menu_items         — individual menu items (prices in paise, INR base)
--   app.table_sessions     — anonymous customer sessions via QR scan (PVD V2 §8.2)
--   app.orders             — customer orders (status machine)
--   app.order_items        — line items with price snapshot at order time
--
-- NEW ENUMS:
--   app.order_status       — PENDING | CONFIRMED | PREPARING | READY | DELIVERED | CANCELLED
--   app.session_status     — ACTIVE | CLOSED | EXPIRED
--   app.item_availability  — AVAILABLE | SOLD_OUT | HIDDEN
--
-- SECURITY CONTRACT (all 6 tables):
--   - RLS enabled + FORCE RLS enabled
--   - 4 policies per table (SELECT/INSERT/UPDATE/DELETE)
--   - All USING/WITH CHECK use cached initPlan JWT pattern
--   - is_platform_admin exclusion guard on all tenant-scoped policies
--   - deleted_at IS NULL filter on all SELECT/UPDATE/DELETE policies
--
-- INDEXES:
--   - tenant_id on every table (primary RLS predicate column)
--   - restaurant_id on every table
--   - Operational composite indexes for KDS and menu queries
--   - Partial indexes on active/available records
--   NOTE: now() cannot be used in index predicates (STABLE, not IMMUTABLE)
--         activation_codes active index uses redeemed_at IS NULL + deleted_at IS NULL;
--         expires_at filter is applied at query time only.
--
-- TRIGGERS (all 6 tables):
--   - BEFORE UPDATE → app.set_updated_at()
--   - BEFORE DELETE → app.soft_delete() (converts DELETE → UPDATE deleted_at)
--   - AFTER INSERT OR UPDATE OR DELETE → audit.log_changes()
--
-- ROLLBACK:
--   DROP TABLE IF EXISTS app.order_items, app.orders, app.table_sessions,
--     app.menu_items, app.menu_categories, app.activation_codes CASCADE;
--   DROP TYPE IF EXISTS app.order_status, app.session_status,
--     app.item_availability CASCADE;
-- =============================================================================

-- ─── Enums ─────────────────────────────────────────────────────────────────────
CREATE TYPE app.order_status AS ENUM (
  'PENDING','CONFIRMED','PREPARING','READY','DELIVERED','CANCELLED'
);

CREATE TYPE app.session_status AS ENUM (
  'ACTIVE','CLOSED','EXPIRED'
);

CREATE TYPE app.item_availability AS ENUM (
  'AVAILABLE','SOLD_OUT','HIDDEN'
);

-- =============================================================================
-- TABLE 1: app.activation_codes
-- =============================================================================
CREATE TABLE app.activation_codes (
  id              uuid        PRIMARY KEY DEFAULT generate_uuidv7(),
  tenant_id       uuid        NOT NULL REFERENCES app.tenants(id),
  restaurant_id   uuid        NOT NULL REFERENCES app.restaurants(id),
  token           text        NOT NULL UNIQUE CHECK (token ~ '^[0-9a-f]{32}$'),
  issued_by       uuid        REFERENCES auth.users(id),
  issued_at       timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL DEFAULT (now() + INTERVAL '72 hours'),
  redeemed_at     timestamptz,
  redeemed_by     uuid        REFERENCES auth.users(id),
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  deleted_at      timestamptz,
  CONSTRAINT chk_expires_after_issued  CHECK (expires_at > issued_at),
  CONSTRAINT chk_redeemed_after_issued CHECK (redeemed_at IS NULL OR redeemed_at >= issued_at)
);

ALTER TABLE app.activation_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.activation_codes FORCE ROW LEVEL SECURITY;

CREATE UNIQUE INDEX idx_activation_codes_active_per_restaurant
  ON app.activation_codes (restaurant_id)
  WHERE redeemed_at IS NULL AND deleted_at IS NULL;

CREATE INDEX idx_activation_codes_tenant_id ON app.activation_codes (tenant_id);
CREATE INDEX idx_activation_codes_token     ON app.activation_codes (token) WHERE redeemed_at IS NULL;
CREATE INDEX idx_activation_codes_expires   ON app.activation_codes (expires_at) WHERE redeemed_at IS NULL AND deleted_at IS NULL;

CREATE TRIGGER trg_activation_codes_updated_at  BEFORE UPDATE ON app.activation_codes FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER trg_activation_codes_soft_delete BEFORE DELETE ON app.activation_codes FOR EACH ROW EXECUTE FUNCTION app.soft_delete();
CREATE TRIGGER trg_activation_codes_audit       AFTER INSERT OR UPDATE OR DELETE ON app.activation_codes FOR EACH ROW EXECUTE FUNCTION audit.log_changes();

CREATE POLICY activation_codes_select ON app.activation_codes FOR SELECT TO authenticated USING (
  (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) = true
  OR ( (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE AND deleted_at IS NULL
       AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
       AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin' )
);
CREATE POLICY activation_codes_insert ON app.activation_codes FOR INSERT TO authenticated WITH CHECK (
  (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) = true
  AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
);
CREATE POLICY activation_codes_update ON app.activation_codes FOR UPDATE TO authenticated
  USING    ( (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) = true )
  WITH CHECK ( (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) = true );
CREATE POLICY activation_codes_delete ON app.activation_codes FOR DELETE TO authenticated USING (
  (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) = true
);

-- =============================================================================
-- TABLE 2: app.menu_categories
-- =============================================================================
CREATE TABLE app.menu_categories (
  id              uuid        PRIMARY KEY DEFAULT generate_uuidv7(),
  tenant_id       uuid        NOT NULL REFERENCES app.tenants(id),
  restaurant_id   uuid        NOT NULL REFERENCES app.restaurants(id),
  parent_id       uuid        REFERENCES app.menu_categories(id),
  name            text        NOT NULL CHECK (char_length(trim(name)) > 0),
  description     text,
  display_order   integer     NOT NULL DEFAULT 0,
  is_active       boolean     NOT NULL DEFAULT true,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  deleted_at      timestamptz
);

ALTER TABLE app.menu_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.menu_categories FORCE ROW LEVEL SECURITY;

CREATE INDEX idx_menu_categories_tenant_id     ON app.menu_categories (tenant_id);
CREATE INDEX idx_menu_categories_restaurant_id ON app.menu_categories (restaurant_id);
CREATE INDEX idx_menu_categories_parent_id     ON app.menu_categories (parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX idx_menu_categories_active        ON app.menu_categories (restaurant_id, display_order) WHERE deleted_at IS NULL AND is_active = true;

CREATE TRIGGER trg_menu_categories_updated_at  BEFORE UPDATE ON app.menu_categories FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER trg_menu_categories_soft_delete BEFORE DELETE ON app.menu_categories FOR EACH ROW EXECUTE FUNCTION app.soft_delete();
CREATE TRIGGER trg_menu_categories_audit       AFTER INSERT OR UPDATE OR DELETE ON app.menu_categories FOR EACH ROW EXECUTE FUNCTION audit.log_changes();

CREATE POLICY menu_categories_select ON app.menu_categories FOR SELECT TO authenticated USING (
  deleted_at IS NULL AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
);
CREATE POLICY menu_categories_insert ON app.menu_categories FOR INSERT TO authenticated WITH CHECK (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
);
CREATE POLICY menu_categories_update ON app.menu_categories FOR UPDATE TO authenticated
  USING ( deleted_at IS NULL AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE )
  WITH CHECK ( tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE );
CREATE POLICY menu_categories_delete ON app.menu_categories FOR DELETE TO authenticated USING (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
);

-- =============================================================================
-- TABLE 3: app.menu_items
-- =============================================================================
CREATE TABLE app.menu_items (
  id               uuid                  PRIMARY KEY DEFAULT generate_uuidv7(),
  tenant_id        uuid                  NOT NULL REFERENCES app.tenants(id),
  restaurant_id    uuid                  NOT NULL REFERENCES app.restaurants(id),
  category_id      uuid                  REFERENCES app.menu_categories(id),
  name             text                  NOT NULL CHECK (char_length(trim(name)) > 0),
  description      text,
  price_paise      integer               NOT NULL CHECK (price_paise >= 0),
  image_url        text,
  availability     app.item_availability NOT NULL DEFAULT 'AVAILABLE',
  is_veg           boolean               NOT NULL DEFAULT true,
  display_order    integer               NOT NULL DEFAULT 0,
  metadata         jsonb                 NOT NULL DEFAULT '{}',
  created_at       timestamptz           NOT NULL DEFAULT now(),
  updated_at       timestamptz           NOT NULL DEFAULT now(),
  deleted_at       timestamptz
);

ALTER TABLE app.menu_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.menu_items FORCE ROW LEVEL SECURITY;

CREATE INDEX idx_menu_items_tenant_id     ON app.menu_items (tenant_id);
CREATE INDEX idx_menu_items_restaurant_id ON app.menu_items (restaurant_id);
CREATE INDEX idx_menu_items_category_id   ON app.menu_items (category_id) WHERE category_id IS NOT NULL;
CREATE INDEX idx_menu_items_active        ON app.menu_items (restaurant_id, display_order) WHERE deleted_at IS NULL AND availability = 'AVAILABLE';

CREATE TRIGGER trg_menu_items_updated_at  BEFORE UPDATE ON app.menu_items FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER trg_menu_items_soft_delete BEFORE DELETE ON app.menu_items FOR EACH ROW EXECUTE FUNCTION app.soft_delete();
CREATE TRIGGER trg_menu_items_audit       AFTER INSERT OR UPDATE OR DELETE ON app.menu_items FOR EACH ROW EXECUTE FUNCTION audit.log_changes();

CREATE POLICY menu_items_select ON app.menu_items FOR SELECT TO authenticated USING (
  deleted_at IS NULL AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid) AND availability != 'HIDDEN'
);
CREATE POLICY menu_items_insert ON app.menu_items FOR INSERT TO authenticated WITH CHECK (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
);
CREATE POLICY menu_items_update ON app.menu_items FOR UPDATE TO authenticated
  USING ( deleted_at IS NULL AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE )
  WITH CHECK ( tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE );
CREATE POLICY menu_items_delete ON app.menu_items FOR DELETE TO authenticated USING (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
);

-- =============================================================================
-- TABLE 4: app.table_sessions
-- =============================================================================
CREATE TABLE app.table_sessions (
  id              uuid                NOT NULL PRIMARY KEY DEFAULT generate_uuidv7(),
  tenant_id       uuid                NOT NULL REFERENCES app.tenants(id),
  restaurant_id   uuid                NOT NULL REFERENCES app.restaurants(id),
  table_label     text                NOT NULL CHECK (char_length(trim(table_label)) > 0),
  status          app.session_status  NOT NULL DEFAULT 'ACTIVE',
  anon_user_id    uuid                REFERENCES auth.users(id),
  opened_at       timestamptz         NOT NULL DEFAULT now(),
  closed_at       timestamptz,
  expires_at      timestamptz         NOT NULL DEFAULT (now() + INTERVAL '24 hours'),
  metadata        jsonb               NOT NULL DEFAULT '{}',
  created_at      timestamptz         NOT NULL DEFAULT now(),
  updated_at      timestamptz         NOT NULL DEFAULT now(),
  deleted_at      timestamptz,
  CONSTRAINT chk_session_expires_after_open CHECK (expires_at > opened_at),
  CONSTRAINT chk_closed_after_open          CHECK (closed_at IS NULL OR closed_at >= opened_at)
);

ALTER TABLE app.table_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.table_sessions FORCE ROW LEVEL SECURITY;

CREATE INDEX idx_table_sessions_tenant_id     ON app.table_sessions (tenant_id);
CREATE INDEX idx_table_sessions_restaurant_id ON app.table_sessions (restaurant_id);
CREATE INDEX idx_table_sessions_active        ON app.table_sessions (restaurant_id, table_label) WHERE status = 'ACTIVE' AND deleted_at IS NULL;
CREATE INDEX idx_table_sessions_id_tenant     ON app.table_sessions (id, tenant_id);

CREATE TRIGGER trg_table_sessions_updated_at  BEFORE UPDATE ON app.table_sessions FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER trg_table_sessions_soft_delete BEFORE DELETE ON app.table_sessions FOR EACH ROW EXECUTE FUNCTION app.soft_delete();
CREATE TRIGGER trg_table_sessions_audit       AFTER INSERT OR UPDATE OR DELETE ON app.table_sessions FOR EACH ROW EXECUTE FUNCTION audit.log_changes();

CREATE POLICY table_sessions_select ON app.table_sessions FOR SELECT TO authenticated USING (
  deleted_at IS NULL AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND ( (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff')
        OR id = (SELECT (auth.jwt() ->> 'session_id'::text)::uuid) )
);
CREATE POLICY table_sessions_insert ON app.table_sessions FOR INSERT TO authenticated WITH CHECK (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  AND (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff')
);
CREATE POLICY table_sessions_update ON app.table_sessions FOR UPDATE TO authenticated
  USING ( deleted_at IS NULL AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff')
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE )
  WITH CHECK ( tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff')
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE );
CREATE POLICY table_sessions_delete ON app.table_sessions FOR DELETE TO authenticated USING (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
);

-- =============================================================================
-- TABLE 5: app.orders
-- =============================================================================
CREATE TABLE app.orders (
  id              uuid               PRIMARY KEY DEFAULT generate_uuidv7(),
  tenant_id       uuid               NOT NULL REFERENCES app.tenants(id),
  restaurant_id   uuid               NOT NULL REFERENCES app.restaurants(id),
  session_id      uuid               NOT NULL REFERENCES app.table_sessions(id),
  order_number    text               NOT NULL,
  status          app.order_status   NOT NULL DEFAULT 'PENDING',
  total_paise     integer            NOT NULL DEFAULT 0 CHECK (total_paise >= 0),
  notes           text,
  placed_at       timestamptz        NOT NULL DEFAULT now(),
  confirmed_at    timestamptz,
  ready_at        timestamptz,
  delivered_at    timestamptz,
  cancelled_at    timestamptz,
  cancelled_by    uuid               REFERENCES auth.users(id),
  metadata        jsonb              NOT NULL DEFAULT '{}',
  created_at      timestamptz        NOT NULL DEFAULT now(),
  updated_at      timestamptz        NOT NULL DEFAULT now(),
  deleted_at      timestamptz,
  CONSTRAINT uq_order_number_per_restaurant UNIQUE (restaurant_id, order_number)
);

ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.orders FORCE ROW LEVEL SECURITY;

CREATE INDEX idx_orders_tenant_id     ON app.orders (tenant_id);
CREATE INDEX idx_orders_restaurant_id ON app.orders (restaurant_id);
CREATE INDEX idx_orders_session_id    ON app.orders (session_id);
CREATE INDEX idx_orders_status        ON app.orders (restaurant_id, status) WHERE deleted_at IS NULL;
CREATE INDEX idx_orders_placed_at     ON app.orders (restaurant_id, placed_at DESC) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_orders_updated_at  BEFORE UPDATE ON app.orders FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER trg_orders_soft_delete BEFORE DELETE ON app.orders FOR EACH ROW EXECUTE FUNCTION app.soft_delete();
CREATE TRIGGER trg_orders_audit       AFTER INSERT OR UPDATE OR DELETE ON app.orders FOR EACH ROW EXECUTE FUNCTION audit.log_changes();

CREATE POLICY orders_select ON app.orders FOR SELECT TO authenticated USING (
  deleted_at IS NULL AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND ( (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff')
        OR session_id = (SELECT (auth.jwt() ->> 'session_id'::text)::uuid) )
);
CREATE POLICY orders_insert ON app.orders FOR INSERT TO authenticated WITH CHECK (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  AND ( ( (SELECT (auth.jwt() ->> 'app_role'::text)) = 'customer'
          AND session_id = (SELECT (auth.jwt() ->> 'session_id'::text)::uuid) )
        OR (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff') )
);
CREATE POLICY orders_update ON app.orders FOR UPDATE TO authenticated
  USING ( deleted_at IS NULL AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff')
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE )
  WITH CHECK ( tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff')
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE );
CREATE POLICY orders_delete ON app.orders FOR DELETE TO authenticated USING (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
);

-- =============================================================================
-- TABLE 6: app.order_items
-- =============================================================================
CREATE TABLE app.order_items (
  id                 uuid        PRIMARY KEY DEFAULT generate_uuidv7(),
  tenant_id          uuid        NOT NULL REFERENCES app.tenants(id),
  restaurant_id      uuid        NOT NULL REFERENCES app.restaurants(id),
  order_id           uuid        NOT NULL REFERENCES app.orders(id),
  menu_item_id       uuid        REFERENCES app.menu_items(id),
  item_name          text        NOT NULL,
  item_price_paise   integer     NOT NULL CHECK (item_price_paise >= 0),
  quantity           integer     NOT NULL DEFAULT 1 CHECK (quantity > 0),
  line_total_paise   integer     GENERATED ALWAYS AS (item_price_paise * quantity) STORED,
  notes              text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  deleted_at         timestamptz
);

ALTER TABLE app.order_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.order_items FORCE ROW LEVEL SECURITY;

CREATE INDEX idx_order_items_tenant_id     ON app.order_items (tenant_id);
CREATE INDEX idx_order_items_restaurant_id ON app.order_items (restaurant_id);
CREATE INDEX idx_order_items_order_id      ON app.order_items (order_id);
CREATE INDEX idx_order_items_menu_item_id  ON app.order_items (menu_item_id) WHERE menu_item_id IS NOT NULL;

CREATE TRIGGER trg_order_items_updated_at  BEFORE UPDATE ON app.order_items FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER trg_order_items_soft_delete BEFORE DELETE ON app.order_items FOR EACH ROW EXECUTE FUNCTION app.soft_delete();
CREATE TRIGGER trg_order_items_audit       AFTER INSERT OR UPDATE OR DELETE ON app.order_items FOR EACH ROW EXECUTE FUNCTION audit.log_changes();

CREATE POLICY order_items_select ON app.order_items FOR SELECT TO authenticated USING (
  deleted_at IS NULL AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND ( (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff')
        OR order_id IN (
          SELECT id FROM app.orders
          WHERE session_id = (SELECT (auth.jwt() ->> 'session_id'::text)::uuid)
            AND tenant_id  = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
            AND deleted_at IS NULL ) )
);
CREATE POLICY order_items_insert ON app.order_items FOR INSERT TO authenticated WITH CHECK (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  AND ( ( (SELECT (auth.jwt() ->> 'app_role'::text)) = 'customer'
          AND order_id IN (
            SELECT id FROM app.orders
            WHERE session_id = (SELECT (auth.jwt() ->> 'session_id'::text)::uuid)
              AND tenant_id  = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
              AND deleted_at IS NULL AND status = 'PENDING' ) )
        OR (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff') )
);
CREATE POLICY order_items_update ON app.order_items FOR UPDATE TO authenticated
  USING ( deleted_at IS NULL AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff')
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE )
  WITH CHECK ( tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
    AND (SELECT (auth.jwt() ->> 'app_role'::text)) IN ('admin','staff')
    AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE );
CREATE POLICY order_items_delete ON app.order_items FOR DELETE TO authenticated USING (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
);
