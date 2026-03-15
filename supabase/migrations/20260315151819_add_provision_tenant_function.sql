-- =============================================================================
-- MIGRATION: add_provision_tenant_function
-- DB VERSION: 20260315151819
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-15
--
-- PURPOSE:
--   SECURITY DEFINER function wrapping full tenant provisioning in a single
--   atomic DB transaction. Called exclusively by the tenant-onboard Edge
--   Function via service_role RPC.
--
--   Provisioning steps (all or nothing):
--     1. INSERT app.tenants (status = PENDING)
--     2. INSERT auth.users (bare record — owner sets password via invite link)
--     3. INSERT app.users (app_role = 'admin', linked to auth.users)
--     4. INSERT app.memberships (role = 'owner', granted_by = caller)
--     5. INSERT app.restaurants (initial restaurant for the tenant)
--
--   Returns: (tenant_id, tenant_slug, owner_auth_id, owner_app_user_id,
--              restaurant_id, status)
--
-- SECURITY:
--   - SECURITY DEFINER, search_path locked
--   - GRANT to service_role only — Edge Function access only
--   - Caller auth ID written to membership.granted_by for audit trail
--   - Tenant provisioned with is_platform_tenant = false in metadata
--
-- ROLLBACK:
--   DROP FUNCTION IF EXISTS app.provision_tenant(text, text, text, text, text, text, uuid);
--   Any tenants created by this function must be manually soft-deleted.
-- =============================================================================

CREATE OR REPLACE FUNCTION app.provision_tenant(
  p_name            text,
  p_slug            text,
  p_owner_email     text,
  p_restaurant_name text,
  p_region          text    DEFAULT 'ap-south-1',
  p_plan            text    DEFAULT 'standard',
  p_caller_auth_id  uuid    DEFAULT NULL
)
RETURNS TABLE (
  tenant_id         uuid,
  tenant_slug       text,
  owner_auth_id     uuid,
  owner_app_user_id uuid,
  restaurant_id     uuid,
  status            text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, auth, extensions, pg_catalog
AS $$
DECLARE
  v_tenant_id      uuid;
  v_auth_user_id   uuid;
  v_app_user_id    uuid;
  v_restaurant_id  uuid;
BEGIN
  IF p_name IS NULL OR trim(p_name) = '' THEN
    RAISE EXCEPTION 'name cannot be empty' USING ERRCODE = '22023';
  END IF;
  IF p_slug IS NULL OR p_slug !~ '^[a-z0-9\-]{3,63}$' THEN
    RAISE EXCEPTION 'slug must match ^[a-z0-9-]{3,63}$' USING ERRCODE = '22023';
  END IF;
  IF p_owner_email IS NULL OR p_owner_email !~* '^[^\s@]+@[^\s@]+\.[^\s@]+$' THEN
    RAISE EXCEPTION 'owner_email must be a valid email address' USING ERRCODE = '22023';
  END IF;
  IF p_restaurant_name IS NULL OR trim(p_restaurant_name) = '' THEN
    RAISE EXCEPTION 'restaurant_name cannot be empty' USING ERRCODE = '22023';
  END IF;

  INSERT INTO app.tenants (name, slug, status, owner_email, region, plan, metadata)
  VALUES (
    trim(p_name), p_slug, 'PENDING'::app.tenant_status,
    lower(trim(p_owner_email)), p_region, p_plan,
    jsonb_build_object('is_platform_tenant', false)
  )
  RETURNING id INTO v_tenant_id;

  INSERT INTO auth.users (
    id, instance_id, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
    created_at, updated_at, role, aud
  )
  VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000000',
    lower(trim(p_owner_email)),
    '',  -- No password; owner must use invite link
    NULL,
    jsonb_build_object('provider', 'email', 'providers', ARRAY['email']),
    jsonb_build_object('tenant_id', v_tenant_id::text, 'tenant_name', trim(p_name)),
    now(), now(), 'authenticated', 'authenticated'
  )
  RETURNING id INTO v_auth_user_id;

  INSERT INTO app.users (tenant_id, auth_user_id, email, full_name, app_role)
  VALUES (
    v_tenant_id, v_auth_user_id, lower(trim(p_owner_email)),
    trim(p_name) || ' Owner', 'admin'::app.app_role
  )
  RETURNING id INTO v_app_user_id;

  INSERT INTO app.memberships (tenant_id, user_id, role, granted_by)
  VALUES (v_tenant_id, v_app_user_id, 'owner'::app.membership_role, p_caller_auth_id);

  INSERT INTO app.restaurants (tenant_id, display_name, timezone, currency)
  VALUES (v_tenant_id, trim(p_restaurant_name), 'Asia/Kolkata', 'INR')
  RETURNING id INTO v_restaurant_id;

  RETURN QUERY
  SELECT v_tenant_id, p_slug, v_auth_user_id, v_app_user_id, v_restaurant_id, 'PENDING'::text;
END;
$$;

REVOKE EXECUTE ON FUNCTION app.provision_tenant(text, text, text, text, text, text, uuid)
  FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.provision_tenant(text, text, text, text, text, text, uuid)
  TO service_role;
