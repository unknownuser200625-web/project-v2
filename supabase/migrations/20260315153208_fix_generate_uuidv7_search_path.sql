-- =============================================================================
-- MIGRATION: fix_generate_uuidv7_search_path
-- DB VERSION: 20260315153208
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-15
-- SEVERITY: CRITICAL — all default primary key INSERTs broken
--
-- ROOT CAUSE:
--   Migration 20260310122633 hardened generate_uuidv7() search_path to
--   'public, pg_catalog, pg_temp'. The function calls gen_random_bytes(10)
--   from pgcrypto which is installed in the 'extensions' schema. With
--   'extensions' absent from search_path, every INSERT that relies on the
--   generate_uuidv7() column default throws:
--     ERROR: function gen_random_bytes(integer) does not exist
--   This breaks all INSERTs on: app.tenants, app.restaurants, app.users,
--   app.staff, app.memberships, and all audit.change_log_* partitions
--   unless an explicit UUID is provided by the caller.
--   Discovered during auth hook simulation (2026-03-15 audit session).
--
-- FIX:
--   Add 'extensions' to search_path and qualify the call as
--   extensions.gen_random_bytes(10) for clarity and forward safety.
--
-- ROLLBACK:
--   CREATE OR REPLACE FUNCTION public.generate_uuidv7()
--   RETURNS uuid LANGUAGE plpgsql PARALLEL SAFE
--   SET search_path = 'public', 'pg_catalog', 'pg_temp'
--   AS $$ ... $$;
--   NOTE: Rollback restores the broken state. Do not apply to production.
-- =============================================================================

CREATE OR REPLACE FUNCTION public.generate_uuidv7()
RETURNS uuid
LANGUAGE plpgsql
PARALLEL SAFE
SET search_path = public, extensions, pg_catalog, pg_temp
AS $$
DECLARE
  v_unix_ms BIGINT;
  v_bytes   BYTEA;
BEGIN
  v_unix_ms := FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT;
  v_bytes   := decode(lpad(to_hex(v_unix_ms), 12, '0'), 'hex')
               || extensions.gen_random_bytes(10);
  v_bytes   := set_byte(v_bytes, 6, (get_byte(v_bytes, 6) & x'0f'::int) | x'70'::int);
  v_bytes   := set_byte(v_bytes, 8, (get_byte(v_bytes, 8) & x'3f'::int) | x'80'::int);
  RETURN encode(v_bytes, 'hex')::uuid;
END;
$$;
