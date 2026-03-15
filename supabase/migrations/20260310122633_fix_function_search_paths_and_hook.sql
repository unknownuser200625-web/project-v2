-- =============================================================================
-- MIGRATION: fix_function_search_paths_and_hook
-- DB VERSION: 20260310122633
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-10
-- PURPOSE:
--   1. Pin SET search_path on all functions (Security Advisor: function_search_path_mutable).
--   2. Canonicalize public.custom_access_token_hook — existed in production,
--      absent from migration files (schema drift). Full rebuild with search_path,
--      staff_id injection, session_id passthrough.
--
-- ROLLBACK:
--   Recreate each function without SET search_path.
--   For hook: restore prior version from production snapshot.
-- =============================================================================

CREATE OR REPLACE FUNCTION public.generate_uuidv7()
RETURNS uuid
LANGUAGE plpgsql
PARALLEL SAFE
SET search_path = public, pg_catalog, pg_temp
AS $$
DECLARE
  v_unix_ms BIGINT;
  v_bytes   BYTEA;
BEGIN
  v_unix_ms := FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT;
  v_bytes := decode(lpad(to_hex(v_unix_ms), 12, '0'), 'hex') || gen_random_bytes(10);
  v_bytes := set_byte(v_bytes, 6, (get_byte(v_bytes, 6) & x'0f'::int) | x'70'::int);
  v_bytes := set_byte(v_bytes, 8, (get_byte(v_bytes, 8) & x'3f'::int) | x'80'::int);
  RETURN encode(v_bytes, 'hex')::uuid;
END;
$$;

DROP FUNCTION IF EXISTS audit.jsonb_diff(jsonb, jsonb);

CREATE OR REPLACE FUNCTION audit.jsonb_diff(p_old jsonb, p_new jsonb)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE PARALLEL SAFE
SET search_path = audit, pg_catalog, pg_temp
AS $$
  SELECT COALESCE(
    jsonb_object_agg(key, value)
    FILTER (WHERE p_new -> key IS DISTINCT FROM p_old -> key),
    '{}'::jsonb
  )
  FROM jsonb_each(COALESCE(p_new, '{}'::jsonb));
$$;

CREATE OR REPLACE FUNCTION app.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = app, pg_catalog, pg_temp
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.soft_delete()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_catalog, pg_temp
AS $$
BEGIN
  EXECUTE format(
    'UPDATE %I.%I SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL',
    TG_TABLE_SCHEMA, TG_TABLE_NAME
  ) USING OLD.id;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION audit.prevent_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = audit, pg_catalog, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION
    'audit.change_log is immutable. DELETE and UPDATE are permanently forbidden. Reference: befoodi PVD V2 Section 6.2.'
    USING ERRCODE = '42501';
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, app, pg_catalog, pg_temp
AS $$
DECLARE
  claims          jsonb;
  v_auth_user_id  uuid;
  v_user_rec      record;
  v_staff_id      uuid;
BEGIN
  claims := event->'claims';
  v_auth_user_id := (claims->>'sub')::uuid;

  claims := jsonb_set(claims, '{tenant_id}',        'null'::jsonb,  true);
  claims := jsonb_set(claims, '{user_id}',           'null'::jsonb,  true);
  claims := jsonb_set(claims, '{app_role}',          'null'::jsonb,  true);
  claims := jsonb_set(claims, '{is_platform_admin}', 'false'::jsonb, true);
  claims := jsonb_set(claims, '{staff_id}',          'null'::jsonb,  true);
  claims := jsonb_set(claims, '{session_id}',        'null'::jsonb,  true);

  SELECT id, tenant_id, app_role
  INTO v_user_rec
  FROM app.users
  WHERE auth_user_id = v_auth_user_id
    AND deleted_at IS NULL
  LIMIT 1;

  IF FOUND THEN
    claims := jsonb_set(claims, '{tenant_id}', to_jsonb(v_user_rec.tenant_id::text), true);
    claims := jsonb_set(claims, '{user_id}',   to_jsonb(v_user_rec.id::text),        true);
    claims := jsonb_set(claims, '{app_role}',  to_jsonb(v_user_rec.app_role::text),  true);
    claims := jsonb_set(claims, '{is_platform_admin}', 'false'::jsonb,               true);

    SELECT s.id INTO v_staff_id
    FROM app.staff s
    WHERE s.tenant_id = v_user_rec.tenant_id
      AND s.deleted_at IS NULL
      AND s.is_active  = TRUE
      AND s.id = v_user_rec.id
    LIMIT 1;

    IF v_staff_id IS NOT NULL THEN
      claims := jsonb_set(claims, '{staff_id}', to_jsonb(v_staff_id::text), true);
    END IF;

  ELSE
    claims := jsonb_set(claims, '{is_platform_admin}', 'true'::jsonb, true);
  END IF;

  IF (event->'user_metadata'->>'session_id') IS NOT NULL THEN
    claims := jsonb_set(
      claims, '{session_id}',
      to_jsonb((event->'user_metadata'->>'session_id')::text),
      true
    );
  END IF;

  event := jsonb_set(event, '{claims}', claims, true);
  RETURN event;
END;
$$;

GRANT EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb)
  TO supabase_auth_admin;

REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb)
  FROM PUBLIC, anon, authenticated;
