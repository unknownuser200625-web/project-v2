-- =============================================================================
-- MIGRATION: add_activation_code_functions
-- DB VERSION: 20260316051312
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-16
--
-- PURPOSE:
--   Two SECURITY DEFINER helper functions for the activation code workflow:
--
--   app.issue_activation_code(p_tenant_id, p_restaurant_id, p_caller_auth_id)
--     Called by: activation-code-issue Edge Function (service_role)
--     - Validates tenant + restaurant existence
--     - Enforces single-active-code-per-restaurant rule
--     - Generates 32-char hex token via pgcrypto gen_random_bytes(16)
--     - Inserts into app.activation_codes (72h TTL default)
--     - Returns: code_id, token, tenant_id, restaurant_id, issued_at, expires_at
--
--   app.redeem_activation_code(p_token, p_auth_user_id)
--     Called by: activation-code-redeem Edge Function (service_role)
--     - Validates token (exists, not expired, not redeemed, not deleted)
--     - Uses FOR UPDATE to prevent race conditions
--     - Verifies calling user belongs to the token's tenant
--     - Atomically marks code as redeemed + activates tenant (PENDING → ACTIVE)
--     - Returns: tenant_id, restaurant_id, tenant_status, redeemed_at
--     - Error codes: invalid_code (P0002), code_already_redeemed (P0001),
--                    code_expired (P0001), forbidden (42501)
--
-- SECURITY:
--   - Both: SECURITY DEFINER, search_path locked
--   - GRANT: service_role only. PUBLIC/anon/authenticated revoked.
--   - Token not logged in errors (timing-safe: invalid_code for all not-found cases)
--
-- ROLLBACK:
--   DROP FUNCTION IF EXISTS app.issue_activation_code(uuid, uuid, uuid);
--   DROP FUNCTION IF EXISTS app.redeem_activation_code(text, uuid);
-- =============================================================================

-- ── 1. issue_activation_code ──────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION app.issue_activation_code(
  p_tenant_id      uuid,
  p_restaurant_id  uuid,
  p_caller_auth_id uuid
)
RETURNS TABLE (
  code_id        uuid,
  token          text,
  tenant_id      uuid,
  restaurant_id  uuid,
  issued_at      timestamptz,
  expires_at     timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, extensions, pg_catalog
AS $$
DECLARE
  v_token       text;
  v_code_id     uuid;
  v_issued_at   timestamptz;
  v_expires_at  timestamptz;
BEGIN
  IF p_tenant_id IS NULL OR p_restaurant_id IS NULL THEN
    RAISE EXCEPTION 'tenant_id and restaurant_id are required' USING ERRCODE = '22023';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM app.tenants
    WHERE id = p_tenant_id AND status != 'CLOSED'::app.tenant_status AND deleted_at IS NULL
  ) THEN
    RAISE EXCEPTION 'Tenant not found or is closed' USING ERRCODE = 'P0002';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM app.restaurants
    WHERE id = p_restaurant_id AND tenant_id = p_tenant_id AND deleted_at IS NULL
  ) THEN
    RAISE EXCEPTION 'Restaurant not found or does not belong to tenant' USING ERRCODE = 'P0002';
  END IF;

  IF EXISTS (
    SELECT 1 FROM app.activation_codes
    WHERE restaurant_id = p_restaurant_id
      AND redeemed_at IS NULL
      AND deleted_at IS NULL
      AND expires_at > now()
  ) THEN
    RAISE EXCEPTION 'An active activation code already exists for this restaurant.'
      USING ERRCODE = '23505';
  END IF;

  v_token := encode(extensions.gen_random_bytes(16), 'hex');

  INSERT INTO app.activation_codes (tenant_id, restaurant_id, token, issued_by)
  VALUES (p_tenant_id, p_restaurant_id, v_token, p_caller_auth_id)
  RETURNING
    app.activation_codes.id,
    app.activation_codes.issued_at,
    app.activation_codes.expires_at
  INTO v_code_id, v_issued_at, v_expires_at;

  RETURN QUERY
  SELECT v_code_id, v_token, p_tenant_id, p_restaurant_id, v_issued_at, v_expires_at;
END;
$$;

REVOKE EXECUTE ON FUNCTION app.issue_activation_code(uuid, uuid, uuid)
  FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.issue_activation_code(uuid, uuid, uuid)
  TO service_role;


-- ── 2. redeem_activation_code ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION app.redeem_activation_code(
  p_token        text,
  p_auth_user_id uuid
)
RETURNS TABLE (
  tenant_id     uuid,
  restaurant_id uuid,
  tenant_status text,
  redeemed_at   timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_catalog
AS $$
DECLARE
  v_code        RECORD;
  v_user        RECORD;
  v_redeemed_at timestamptz;
BEGIN
  IF p_token IS NULL OR p_token = '' THEN
    RAISE EXCEPTION 'token is required' USING ERRCODE = '22023';
  END IF;
  IF p_token !~ '^[0-9a-f]{32}$' THEN
    RAISE EXCEPTION 'invalid token format' USING ERRCODE = '22023';
  END IF;

  SELECT ac.id, ac.tenant_id, ac.restaurant_id, ac.expires_at,
         ac.redeemed_at, ac.deleted_at
  INTO v_code
  FROM app.activation_codes ac
  WHERE ac.token = p_token
  FOR UPDATE;

  IF NOT FOUND OR v_code.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'invalid_code' USING ERRCODE = 'P0002';
  END IF;

  IF v_code.redeemed_at IS NOT NULL THEN
    RAISE EXCEPTION 'code_already_redeemed' USING ERRCODE = 'P0001';
  END IF;

  IF v_code.expires_at <= now() THEN
    RAISE EXCEPTION 'code_expired' USING ERRCODE = 'P0001';
  END IF;

  SELECT u.id, u.tenant_id, u.app_role INTO v_user
  FROM app.users u
  WHERE u.auth_user_id = p_auth_user_id
    AND u.tenant_id    = v_code.tenant_id
    AND u.deleted_at   IS NULL;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'forbidden: caller is not a member of this tenant'
      USING ERRCODE = '42501';
  END IF;

  v_redeemed_at := now();

  UPDATE app.activation_codes
  SET redeemed_at = v_redeemed_at, redeemed_by = p_auth_user_id, updated_at = v_redeemed_at
  WHERE id = v_code.id;

  UPDATE app.tenants
  SET status = 'ACTIVE'::app.tenant_status, updated_at = v_redeemed_at
  WHERE id = v_code.tenant_id AND status = 'PENDING'::app.tenant_status;

  RETURN QUERY
  SELECT v_code.tenant_id, v_code.restaurant_id, 'ACTIVE'::text, v_redeemed_at;
END;
$$;

REVOKE EXECUTE ON FUNCTION app.redeem_activation_code(text, uuid)
  FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.redeem_activation_code(text, uuid)
  TO service_role;
