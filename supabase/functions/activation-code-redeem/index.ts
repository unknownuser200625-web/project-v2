/**
 * activation-code-redeem
 * befoodi V2 — Restaurant Owner: Redeem Activation Code
 *
 * PURPOSE:
 *   Validates an activation code token and activates the restaurant tenant.
 *   Transitions tenant status: PENDING → ACTIVE.
 *   Marks the code as redeemed (single-use enforcement).
 *
 * CALLER:
 *   Authenticated restaurant owner — must be an app.users member of the tenant
 *   that the code was issued for. Requires a valid Supabase JWT (aal1+).
 *
 * REQUEST:
 *   POST /functions/v1/activation-code-redeem
 *   Authorization: Bearer <restaurant_admin_jwt>
 *   Content-Type: application/json
 *   Body: {
 *     "token": "32-char hex activation code"
 *   }
 *
 * RESPONSE (200 — success):
 *   {
 *     "tenant_id":     "uuid",
 *     "restaurant_id": "uuid",
 *     "status":        "ACTIVE",
 *     "redeemed_at":   "ISO timestamp"
 *   }
 *
 * RESPONSE (400 — missing or invalid token format):
 *   { "error": "bad_request", "detail": "..." }
 *
 * RESPONSE (401 — missing / invalid JWT):
 *   { "error": "unauthorized" }
 *
 * RESPONSE (403 — caller not a member of the code's tenant):
 *   { "error": "forbidden" }
 *
 * RESPONSE (410 — code already redeemed or expired):
 *   { "error": "code_already_redeemed" | "code_expired" }
 *
 * RESPONSE (404 — code not found):
 *   { "error": "not_found" }
 *
 * SECURITY:
 *   - JWT verified by Supabase (verify_jwt = true).
 *   - auth_user_id extracted from verified JWT sub claim.
 *   - DB function validates caller membership, expiry, and single-use atomically.
 *   - FOR UPDATE row lock prevents concurrent redemption race conditions.
 *   - Token format validated before DB call (no unnecessary DB round-trip).
 *   - service_role key is server-side only; never returned to caller.
 *
 * DB FUNCTION: app.redeem_activation_code(p_token, p_auth_user_id)
 *   - SECURITY DEFINER — callable by service_role only
 *   - Token lookup with FOR UPDATE row lock (atomic redemption)
 *   - Checks: not deleted, not redeemed, not expired
 *   - Verifies caller is a member of the code's tenant
 *   - Sets redeemed_at + redeemed_by on activation_codes
 *   - Updates tenant status PENDING → ACTIVE
 *
 * ARCHITECTURE REFERENCE: PVD V2 §8.1 — Activation Code Model
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

// ─── Types ────────────────────────────────────────────────────────────────────
interface RedeemResult {
  tenant_id:     string;
  restaurant_id: string;
  status:        string;
  redeemed_at:   string;
}

// ─── JWT claim extraction (payload only — signature verified by Supabase) ─────
function extractClaims(
  authHeader: string | null
): Record<string, unknown> | null {
  if (!authHeader?.startsWith('Bearer ')) return null;
  const parts = authHeader.slice(7).split('.');
  if (parts.length !== 3) return null;
  try {
    const pad = parts[1].length % 4;
    const padded = pad ? parts[1] + '='.repeat(4 - pad) : parts[1];
    return JSON.parse(atob(padded.replace(/-/g, '+').replace(/_/g, '/')));
  } catch {
    return null;
  }
}

// ─── Handler ──────────────────────────────────────────────────────────────────
Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'method_not_allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // ── 1. Extract caller auth_user_id from verified JWT ──────────────────────
  // JWT signature is verified by Supabase before reaching this function.
  // We only need to decode the payload to get sub (auth_user_id).
  const claims = extractClaims(req.headers.get('Authorization'));
  if (!claims || !claims.sub) {
    return new Response(JSON.stringify({ error: 'unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  const callerAuthId = claims.sub as string;

  // ── 2. Parse + validate request body ─────────────────────────────────────
  let rawBody: unknown;
  try {
    rawBody = await req.json();
  } catch {
    return new Response(
      JSON.stringify({ error: 'bad_request', detail: 'Invalid JSON body' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (!rawBody || typeof rawBody !== 'object') {
    return new Response(
      JSON.stringify({ error: 'bad_request', detail: 'Body must be a JSON object' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const body = rawBody as Record<string, unknown>;
  const token = body.token;

  if (!token || typeof token !== 'string') {
    return new Response(
      JSON.stringify({ error: 'bad_request', detail: 'token is required (string)' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // Validate token format before DB call — prevents unnecessary round-trip
  if (!/^[0-9a-f]{32}$/.test(token)) {
    return new Response(
      JSON.stringify({ error: 'bad_request', detail: 'token must be a 32-character hex string' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // ── 3. Environment ────────────────────────────────────────────────────────
  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !serviceRoleKey) {
    console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
    return new Response(
      JSON.stringify({ error: 'internal_error' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const supabase = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false },
  });

  // ── 4. Redeem code via SECURITY DEFINER DB function ───────────────────────
  // app.redeem_activation_code() handles atomically:
  //   - Token lookup with FOR UPDATE row lock
  //   - Expiry check (expires_at > now())
  //   - Already-redeemed check
  //   - Caller tenant membership verification
  //   - Mark redeemed (redeemed_at, redeemed_by)
  //   - Tenant status transition: PENDING → ACTIVE
  const { data, error } = await supabase.rpc('redeem_activation_code', {
    p_token:        token,
    p_auth_user_id: callerAuthId,
  });

  if (error) {
    console.error('redeem_activation_code RPC error:', error);

    // Map DB exception messages to HTTP responses
    const msg = error.message ?? '';

    if (msg.includes('code_already_redeemed')) {
      return new Response(
        JSON.stringify({ error: 'code_already_redeemed', detail: 'This activation code has already been used.' }),
        { status: 410, headers: { 'Content-Type': 'application/json' } }
      );
    }
    if (msg.includes('code_expired')) {
      return new Response(
        JSON.stringify({ error: 'code_expired', detail: 'This activation code has expired. Request a new one from the platform admin.' }),
        { status: 410, headers: { 'Content-Type': 'application/json' } }
      );
    }
    if (msg.includes('invalid_code') || error.code === 'P0002') {
      // Deliberately vague — do not reveal whether code exists
      return new Response(
        JSON.stringify({ error: 'not_found', detail: 'Activation code not found.' }),
        { status: 404, headers: { 'Content-Type': 'application/json' } }
      );
    }
    if (error.code === '42501' || msg.includes('forbidden')) {
      return new Response(
        JSON.stringify({ error: 'forbidden', detail: 'You are not authorised to redeem this code.' }),
        { status: 403, headers: { 'Content-Type': 'application/json' } }
      );
    }

    return new Response(
      JSON.stringify({ error: 'internal_error', detail: error.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (!data || (Array.isArray(data) && data.length === 0)) {
    return new Response(
      JSON.stringify({ error: 'internal_error', detail: 'No data returned from redeem_activation_code' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const result = Array.isArray(data) ? data[0] : data;

  const responseBody: RedeemResult = {
    tenant_id:     result.tenant_id,
    restaurant_id: result.restaurant_id,
    status:        result.tenant_status ?? 'ACTIVE',
    redeemed_at:   result.redeemed_at,
  };

  console.log(`Activation code redeemed: tenant=${responseBody.tenant_id} restaurant=${responseBody.restaurant_id} by=${callerAuthId}`);

  return new Response(JSON.stringify(responseBody), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
});
