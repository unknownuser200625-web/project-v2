/**
 * staff-pin-verify
 * befoodi V2 — Staff PIN + Device Authentication
 *
 * PURPOSE:
 *   Authenticates kitchen staff using PIN + registered device_id.
 *   Staff are NOT in auth.users (PVD V2 §5.2). This function is the sole
 *   authentication path for staff and returns a custom-signed JWT that
 *   PostgREST will accept as a valid bearer token for RLS evaluation.
 *
 * REQUEST:
 *   POST /functions/v1/staff-pin-verify
 *   Content-Type: application/json
 *   Authorization: Bearer <SUPABASE_ANON_KEY>
 *   Body: {
 *     "tenant_id": "uuid",
 *     "device_id": "string",
 *     "pin":       "string (4-8 digits)"
 *   }
 *
 * RESPONSE (200 — success):
 *   {
 *     "token":      "string (JWT)",
 *     "expires_at": "ISO timestamp",
 *     "staff": {
 *       "id":   "uuid",
 *       "name": "string"
 *     }
 *   }
 *
 * RESPONSE (401 — invalid PIN or device):
 *   { "error": "invalid_credentials" }
 *
 * RESPONSE (400 — missing/invalid fields):
 *   { "error": "bad_request", "detail": "..." }
 *
 * RESPONSE (429 — rate limited):
 *   { "error": "too_many_requests" }
 *
 * JWT CLAIMS INJECTED:
 *   sub          — staff UUID (app.staff.id)
 *   role         — "authenticated"  (required by PostgREST)
 *   tenant_id    — tenant isolation key
 *   app_role     — "staff"
 *   staff_id     — app.staff.id
 *   is_platform_admin — false
 *   aal          — "aal1"
 *   iat / exp    — standard JWT timestamps (8h shift window)
 *
 * SECURITY:
 *   - PIN comparison done via SECURITY DEFINER app.verify_staff_pin()
 *     using pgcrypto crypt() — constant-time bcrypt. pin_hash never
 *     leaves the database.
 *   - JWT signed with SUPABASE_JWT_SECRET — same key PostgREST uses.
 *   - device_id must match the registered device (device pinning).
 *   - Rate limiting: implemented via in-memory attempt counter per
 *     (tenant_id, device_id) — max 5 failed attempts per minute.
 *   - service_role key is used server-side only. Never returned to caller.
 *
 * ARCHITECTURE REFERENCE: PVD V2 Section 5.2 — Kitchen Staff Auth
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  create,
  getNumericDate,
} from "https://deno.land/x/djwt@v3.0.2/mod.ts";

// ─── Rate limiting ────────────────────────────────────────────────────────────
// Simple in-memory rate limiter. Resets on Edge Function cold start.
// For production: replace with Supabase KV or Redis.
const failedAttempts = new Map<string, { count: number; window: number }>();
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 60_000; // 1 minute

function checkRateLimit(key: string): boolean {
  const now = Date.now();
  const entry = failedAttempts.get(key);
  if (!entry || now - entry.window > WINDOW_MS) {
    return true; // Allow — window expired or first attempt
  }
  return entry.count < MAX_ATTEMPTS;
}

function recordFailure(key: string): void {
  const now = Date.now();
  const entry = failedAttempts.get(key);
  if (!entry || now - entry.window > WINDOW_MS) {
    failedAttempts.set(key, { count: 1, window: now });
  } else {
    entry.count++;
  }
}

function clearFailures(key: string): void {
  failedAttempts.delete(key);
}

// ─── Input validation ─────────────────────────────────────────────────────────
interface VerifyRequest {
  tenant_id: string;
  device_id: string;
  pin: string;
}

function validateInput(body: unknown): VerifyRequest | { error: string } {
  if (!body || typeof body !== "object") {
    return { error: "Request body must be a JSON object" };
  }
  const b = body as Record<string, unknown>;

  if (!b.tenant_id || typeof b.tenant_id !== "string") {
    return { error: "tenant_id is required (uuid string)" };
  }
  // Basic UUID format check
  const uuidRe =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuidRe.test(b.tenant_id)) {
    return { error: "tenant_id must be a valid UUID" };
  }
  if (!b.device_id || typeof b.device_id !== "string") {
    return { error: "device_id is required (string)" };
  }
  if (b.device_id.length < 8 || b.device_id.length > 256) {
    return { error: "device_id length must be 8–256 characters" };
  }
  if (!b.pin || typeof b.pin !== "string") {
    return { error: "pin is required (numeric string)" };
  }
  if (!/^\d{4,8}$/.test(b.pin)) {
    return { error: "pin must be 4–8 digits" };
  }

  return {
    tenant_id: b.tenant_id,
    device_id: b.device_id,
    pin: b.pin,
  };
}

// ─── JWT signing ──────────────────────────────────────────────────────────────
async function signStaffJwt(
  staffId: string,
  tenantId: string,
  staffName: string,
  jwtSecret: string,
): Promise<{ token: string; expiresAt: string }> {
  const now = getNumericDate(0);
  const exp = getNumericDate(8 * 60 * 60); // 8-hour shift window
  const expiresAt = new Date(exp * 1000).toISOString();

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(jwtSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const token = await create(
    { alg: "HS256", typ: "JWT" },
    {
      // Standard claims
      sub: staffId,
      iat: now,
      exp,
      // PostgREST requires 'role' claim for RLS
      role: "authenticated",
      // befoodi V2 custom claims (consumed by RLS initPlan predicates)
      tenant_id: tenantId,
      app_role: "staff",
      staff_id: staffId,
      is_platform_admin: false,
      aal: "aal1",
      // Informational
      staff_name: staffName,
    },
    key,
  );

  return { token, expiresAt };
}

// ─── Handler ──────────────────────────────────────────────────────────────────
Deno.serve(async (req: Request): Promise<Response> => {
  // Only accept POST
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Parse and validate request body
  let rawBody: unknown;
  try {
    rawBody = await req.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "bad_request", detail: "Invalid JSON body" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  const validated = validateInput(rawBody);
  if ("error" in validated) {
    return new Response(
      JSON.stringify({ error: "bad_request", detail: validated.error }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  const { tenant_id, device_id, pin } = validated;

  // Rate limit check: key = tenant_id:device_id
  const rlKey = `${tenant_id}:${device_id}`;
  if (!checkRateLimit(rlKey)) {
    return new Response(JSON.stringify({ error: "too_many_requests" }), {
      status: 429,
      headers: {
        "Content-Type": "application/json",
        "Retry-After": "60",
      },
    });
  }

  // Environment
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const jwtSecret = Deno.env.get("SUPABASE_JWT_SECRET");

  if (!supabaseUrl || !serviceRoleKey || !jwtSecret) {
    console.error("Missing required environment variables");
    return new Response(
      JSON.stringify({ error: "internal_error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  // Service role client — Edge Function only, never returned to caller
  const supabase = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false },
  });

  // Call SECURITY DEFINER DB function for constant-time PIN verification.
  // pin_hash never leaves the database.
  const { data, error: dbError } = await supabase.rpc("verify_staff_pin", {
    p_tenant_id: tenant_id,
    p_device_id: device_id,
    p_pin: pin,
  });

  if (dbError) {
    console.error("verify_staff_pin RPC error:", dbError);
    recordFailure(rlKey);
    return new Response(
      JSON.stringify({ error: "internal_error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  // Empty result = wrong PIN or device not registered
  if (!data || (Array.isArray(data) && data.length === 0)) {
    recordFailure(rlKey);
    // Deliberate delay to slow brute-force (100ms)
    await new Promise((r) => setTimeout(r, 100));
    return new Response(
      JSON.stringify({ error: "invalid_credentials" }),
      { status: 401, headers: { "Content-Type": "application/json" } },
    );
  }

  // PIN verified — clear failure counter
  clearFailures(rlKey);
  const staff = Array.isArray(data) ? data[0] : data;

  // Sign JWT with staff claims
  let token: string;
  let expiresAt: string;
  try {
    ({ token, expiresAt } = await signStaffJwt(
      staff.staff_id,
      staff.tenant_id,
      staff.staff_name,
      jwtSecret,
    ));
  } catch (err) {
    console.error("JWT signing error:", err);
    return new Response(
      JSON.stringify({ error: "internal_error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  return new Response(
    JSON.stringify({
      token,
      expires_at: expiresAt,
      staff: {
        id: staff.staff_id,
        name: staff.staff_name,
      },
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    },
  );
});
