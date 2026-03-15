/**
 * activation-code-issue
 * befoodi V2 — Platform Admin: Issue Restaurant Activation Code
 *
 * PURPOSE:
 *   Generates a single-use, 72-hour activation code for a specific restaurant.
 *   The code is cryptographically random (32-char hex) and stored in
 *   app.activation_codes. Once issued, the restaurant owner redeems it
 *   via activation-code-redeem to activate their tenant account.
 *
 * CALLER:
 *   Platform Admin only — JWT must carry is_platform_admin = true.
 *
 * REQUEST:
 *   POST /functions/v1/activation-code-issue
 *   Authorization: Bearer <platform_admin_jwt>
 *   Content-Type: application/json
 *   Body: {
 *     "tenant_id":    "uuid",
 *     "restaurant_id": "uuid"
 *   }
 *
 * RESPONSE (201 — success):
 *   {
 *     "code_id":       "uuid",
 *     "token":         "32-char hex string",
 *     "tenant_id":     "uuid",
 *     "restaurant_id": "uuid",
 *     "issued_at":     "ISO timestamp",
 *     "expires_at":    "ISO timestamp  (+72 hours)"
 *   }
 *
 * RESPONSE (400 — validation failure):
 *   { "error": "bad_request", "detail": "..." }
 *
 * RESPONSE (401 — missing / invalid JWT):
 *   { "error": "unauthorized" }
 *
 * RESPONSE (403 — not platform admin):
 *   { "error": "forbidden" }
 *
 * RESPONSE (409 — active code already exists for restaurant):
 *   { "error": "conflict", "detail": "An active activation code already exists..." }
 *
 * SECURITY:
 *   - JWT verified by Supabase (verify_jwt = true on this function).
 *   - is_platform_admin claim checked before any DB operation.
 *   - Token generated inside SECURITY DEFINER DB function via pgcrypto.
 *   - service_role key used server-side only; never returned to caller.
 *
 * DB FUNCTION: app.issue_activation_code(p_tenant_id, p_restaurant_id, p_caller_auth_id)
 *   - SECURITY DEFINER — callable by service_role only
 *   - Validates tenant + restaurant existence
 *   - Enforces single-active-code-per-restaurant (partial unique index)
 *   - Generates token via pgcrypto gen_random_bytes(16)
 *   - Inserts into app.activation_codes
 *
 * ARCHITECTURE REFERENCE: PVD V2 §8.1 — Activation Code Model
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

// ─── Types ────────────────────────────────────────────────────────────────────
interface IssueRequest {
  tenant_id: string;
  restaurant_id: string;
}

interface IssueResult {
  code_id: string;
  token: string;
  tenant_id: string;
  restaurant_id: string;
  issued_at: string;
  expires_at: string;
}

// ─── Input validation ─────────────────────────────────────────────────────────
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function validateInput(
  body: unknown
): IssueRequest | { error: string; detail: string } {
  if (!body || typeof body !== 'object') {
    return { error: 'bad_request', detail: 'Body must be a JSON object' };
  }
  const b = body as Record<string, unknown>;

  if (!b.tenant_id || typeof b.tenant_id !== 'string') {
    return { error: 'bad_request', detail: 'tenant_id is required (UUID string)' };
  }
  if (!UUID_RE.test(b.tenant_id)) {
    return { error: 'bad_request', detail: 'tenant_id must be a valid UUID' };
  }
  if (!b.restaurant_id || typeof b.restaurant_id !== 'string') {
    return { error: 'bad_request', detail: 'restaurant_id is required (UUID string)' };
  }
  if (!UUID_RE.test(b.restaurant_id)) {
    return { error: 'bad_request', detail: 'restaurant_id must be a valid UUID' };
  }

  return {
    tenant_id: b.tenant_id,
    restaurant_id: b.restaurant_id,
  };
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

  // ── 1. Verify platform admin claim ────────────────────────────────────────
  const claims = extractClaims(req.headers.get('Authorization'));
  if (!claims) {
    return new Response(JSON.stringify({ error: 'unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  if (claims.is_platform_admin !== true) {
    return new Response(JSON.stringify({ error: 'forbidden' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  const callerAuthId = claims.sub as string;

  // ── 2. Parse + validate request ───────────────────────────────────────────
  let rawBody: unknown;
  try {
    rawBody = await req.json();
  } catch {
    return new Response(
      JSON.stringify({ error: 'bad_request', detail: 'Invalid JSON body' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const validated = validateInput(rawBody);
  if ('error' in validated) {
    return new Response(JSON.stringify(validated), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  const { tenant_id, restaurant_id } = validated as IssueRequest;

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

  // ── 4. Issue code via SECURITY DEFINER DB function ────────────────────────
  // app.issue_activation_code() handles:
  //   - Tenant + restaurant existence checks
  //   - Single-active-code-per-restaurant enforcement
  //   - pgcrypto token generation (32-char hex)
  //   - INSERT into app.activation_codes
  const { data, error } = await supabase.rpc('issue_activation_code', {
    p_tenant_id:      tenant_id,
    p_restaurant_id:  restaurant_id,
    p_caller_auth_id: callerAuthId,
  });

  if (error) {
    console.error('issue_activation_code RPC error:', error);

    // 23505 = unique violation (active code already exists)
    if (error.code === '23505' || error.message?.includes('active activation code')) {
      return new Response(
        JSON.stringify({
          error: 'conflict',
          detail: 'An active activation code already exists for this restaurant. Revoke it before issuing a new one.',
        }),
        { status: 409, headers: { 'Content-Type': 'application/json' } }
      );
    }
    // P0002 = tenant or restaurant not found
    if (error.code === 'P0002') {
      return new Response(
        JSON.stringify({ error: 'not_found', detail: error.message }),
        { status: 404, headers: { 'Content-Type': 'application/json' } }
      );
    }

    return new Response(
      JSON.stringify({ error: 'internal_error', detail: error.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (!data || (Array.isArray(data) && data.length === 0)) {
    return new Response(
      JSON.stringify({ error: 'internal_error', detail: 'No data returned from issue_activation_code' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const result = Array.isArray(data) ? data[0] : data;

  const responseBody: IssueResult = {
    code_id:       result.code_id,
    token:         result.token,
    tenant_id:     result.tenant_id,
    restaurant_id: result.restaurant_id,
    issued_at:     result.issued_at,
    expires_at:    result.expires_at,
  };

  console.log(`Activation code issued: code_id=${responseBody.code_id} tenant=${tenant_id} restaurant=${restaurant_id}`);

  return new Response(JSON.stringify(responseBody), {
    status: 201,
    headers: { 'Content-Type': 'application/json' },
  });
});
