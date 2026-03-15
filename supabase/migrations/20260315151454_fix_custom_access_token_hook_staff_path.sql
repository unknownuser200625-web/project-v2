-- =============================================================================
-- MIGRATION: fix_custom_access_token_hook_staff_path
-- DB VERSION: 20260315151454
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-15
-- SEVERITY: HIGH — dead code path + missing SECURITY DEFINER helper
--
-- PROBLEM 1: custom_access_token_hook had a dead staff auth path
--   The function attempted to look up app.staff by auth_user_id, but
--   app.staff has no auth_user_id column. Per PVD V2 §5.2, staff are NOT
--   in auth.users — they authenticate via staff-pin-verify Edge Function
--   which returns a custom-signed JWT. The hook never fires for staff.
--
-- PROBLEM 2: No SECURITY DEFINER helper for PIN verification
--   The staff-pin-verify Edge Function needs to verify PIN against
--   pin_hash using pgcrypto crypt(). This requires a SECURITY DEFINER
--   function to avoid exposing pin_hash to the caller.
--
-- FIX 1: Rebuild custom_access_token_hook (Path 1: platform admin,
--         Path 2: tenant user, Path 3: unrecognised → safe-fail).
--         Platform admin detection uses metadata->>'is_platform_tenant'
--         flag on the app.tenants record.
--
-- FIX 2: Add app.verify_staff_pin(p_tenant_id, p_device_id, p_pin)
--         SECURITY DEFINER — grants to service_role only (Edge Function).
--         Returns safe record (staff_id, tenant_id, staff_name, is_active).
--         Never returns pin_hash.
--
-- ROLLBACK:
--   DROP FUNCTION IF EXISTS app.verify_staff_pin(uuid, text, text);
--   Restore public.custom_access_token_hook from migration 20260310122633.
-- =============================================================================

-- ── 1. Rebuild custom_access_token_hook without dead staff path ──────────────
CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, app, pg_catalog
AS $$
DECLARE
  claims         jsonb;
  auth_uid       uuid;
  membership_rec RECORD;
BEGIN
  claims    := event -> 'claims';
  auth_uid  := (event ->> 'user_id')::uuid;

  -- ── Path 2: Tenant User (admin / manager via app.users) ──────────────────
  SELECT
    u.id          AS app_user_id,
    u.tenant_id,
    u.app_role,
    m.role        AS membership_role
  INTO membership_rec
  FROM app.users u
  LEFT JOIN app.memberships m
    ON m.user_id   = u.id
   AND m.tenant_id = u.tenant_id
   AND m.deleted_at IS NULL
   AND m.revoked_at IS NULL
  WHERE u.auth_user_id = auth_uid
    AND u.deleted_at   IS NULL
  LIMIT 1;

  IF FOUND THEN
    -- Platform admin: app_role = 'admin' AND tenant is the platform operator
    IF membership_rec.app_role = 'admin' AND membership_rec.tenant_id IS NOT NULL THEN
      IF EXISTS (
        SELECT 1 FROM app.tenants t
        WHERE t.id = membership_rec.tenant_id
          AND (t.metadata ->> 'is_platform_tenant')::boolean = true
          AND t.deleted_at IS NULL
      ) THEN
        claims := jsonb_set(claims, '{is_platform_admin}', 'true');
        claims := jsonb_set(claims, '{user_id}',   to_jsonb(membership_rec.app_user_id::text));
        claims := jsonb_set(claims, '{tenant_id}', to_jsonb(membership_rec.tenant_id::text));
        claims := jsonb_set(claims, '{app_role}',  '"admin"');
        RETURN jsonb_set(event, '{claims}', claims);
      END IF;
    END IF;

    -- Normal tenant user
    claims := jsonb_set(claims, '{is_platform_admin}', 'false');
    claims := jsonb_set(claims, '{tenant_id}', to_jsonb(membership_rec.tenant_id::text));
    claims := jsonb_set(claims, '{app_role}',  to_jsonb(membership_rec.app_role::text));
    claims := jsonb_set(claims, '{user_id}',   to_jsonb(membership_rec.app_user_id::text));
    RETURN jsonb_set(event, '{claims}', claims);
  END IF;

  -- ── Path 3: Unrecognised user — safe-fail ────────────────────────────────
  RETURN event;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) FROM anon;
REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) FROM authenticated;
GRANT  EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) TO supabase_auth_admin;


-- ── 2. verify_staff_pin() SECURITY DEFINER helper ────────────────────────────
CREATE OR REPLACE FUNCTION app.verify_staff_pin(
  p_tenant_id  uuid,
  p_device_id  text,
  p_pin        text
)
RETURNS TABLE (
  staff_id   uuid,
  tenant_id  uuid,
  staff_name text,
  is_active  boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, extensions, pg_catalog
AS $$
BEGIN
  IF p_tenant_id IS NULL OR p_device_id IS NULL OR p_device_id = ''
     OR p_pin IS NULL OR p_pin = '' OR length(p_pin) < 4 THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT
    s.id          AS staff_id,
    s.tenant_id,
    s.name        AS staff_name,
    s.is_active
  FROM app.staff s
  WHERE s.tenant_id   = p_tenant_id
    AND s.device_id   = p_device_id
    AND s.is_active   = true
    AND s.deleted_at  IS NULL
    AND extensions.crypt(p_pin, s.pin_hash) = s.pin_hash;
END;
$$;

REVOKE EXECUTE ON FUNCTION app.verify_staff_pin(uuid, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION app.verify_staff_pin(uuid, text, text) FROM anon;
REVOKE EXECUTE ON FUNCTION app.verify_staff_pin(uuid, text, text) FROM authenticated;
GRANT  EXECUTE ON FUNCTION app.verify_staff_pin(uuid, text, text) TO service_role;
