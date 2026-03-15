/**
 * tenant-onboard
 * befoodi V2 — Platform Admin: New Tenant Provisioning
 *
 * PURPOSE:
 *   Creates a complete tenant record including:
 *     1. app.tenants row (status: PENDING)
 *     2. auth.users entry for the tenant owner
 *     3. app.users row linked to auth.users
 *     4. app.memberships row (role: owner)
 *     5. app.restaurants initial row
 *
 *   All operations are wrapped in a DB transaction via a SECURITY DEFINER
 *   function (app.provision_tenant) to ensure atomicity.
 *
 * CALLER:
 *   Platform Admin only. Caller must present a valid Supabase JWT with
 *   is_platform_admin = true claim.
 *
 * REQUEST:
 *   POST /functions/v1/tenant-onboard
 *   Authorization: Bearer <platform_admin_jwt>
 *   Content-Type: application/json
 *   Body: {
 *     "name":            "string — tenant display name",
 *     "slug":            "string — 3-63 chars [a-z0-9-]",
 *     "owner_email":     "string — tenant owner email",
 *     "restaurant_name": "string — initial restaurant display name",
 *     "region":          "string? — default: ap-south-1",
 *     "plan":            "string? — default: standard",
 *     "send_invite":     "boolean? — send welcome email (default: true)"
 *   }
 *
 * RESPONSE (201 — success):
 *   {
 *     "tenant_id":         "uuid",
 *     "tenant_slug":       "string",
 *     "owner_auth_id":     "uuid (auth.users.id)",
 *     "owner_app_user_id": "uuid (app.users.id)",
 *     "restaurant_id":     "uuid",
 *     "status":            "PENDING",
 *     "invite_sent":       boolean
 *   }
 *
 * RESPONSE (403 — not platform admin):
 *   { "error": "forbidden" }
 *
 * RESPONSE (409 — slug already taken):
 *   { "error": "conflict", "detail": "slug already exists" }
 *
 * RESPONSE (400 — validation failure):
 *   { "error": "bad_request", "detail": "..." }
 *
 * SECURITY:
 *   - Caller JWT verified for is_platform_admin = true before any DB operation.
 *   - All DB writes use service_role via app.provision_tenant() SECURITY DEFINER.
 *   - service_role key is never returned to the caller.
 *   - Tenant owner receives a password reset link, not a temporary password.
 *     Temporary passwords are banned per PVD V2 §13.2.
 *
 * ARCHITECTURE REFERENCE: PVD V2 Section 7 — Admin Isolation Rules
 *                          PVD V2 Section 8 — Anti-Spam & Session Protection
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// ─── Types ────────────────────────────────────────────────────────────────────
interface OnboardRequest {
  name: string;
  slug: string;
  owner_email: string;
  restaurant_name: string;
  region?: string;
  plan?: string;
  send_invite?: boolean;
}

interface ProvisionResult {
  tenant_id: string;
  tenant_slug: string;
  owner_auth_id: string;
  owner_app_user_id: string;
  restaurant_id: string;
  status: string;
}

// ─── Input validation ─────────────────────────────────────────────────────────
const SLUG_RE = /^[a-z0-9-]{3,63}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateInput(
  body: unknown,
): OnboardRequest | { error: string; detail: string } {
  if (!body || typeof body !== "object") {
    return { error: "bad_request", detail: "Body must be a JSON object" };
  }
  const b = body as Record<string, unknown>;

  if (!b.name || typeof b.name !== "string" || b.name.trim().length === 0) {
    return { error: "bad_request", detail: "name is required (non-empty string)" };
  }
  if (b.name.trim().length > 200) {
    return { error: "bad_request", detail: "name must be ≤ 200 characters" };
  }
  if (!b.slug || typeof b.slug !== "string") {
    return { error: "bad_request", detail: "slug is required" };
  }
  if (!SLUG_RE.test(b.slug)) {
    return {
      error: "bad_request",
      detail: "slug must be 3–63 lowercase alphanumeric characters or hyphens",
    };
  }
  if (!b.owner_email || typeof b.owner_email !== "string") {
    return { error: "bad_request", detail: "owner_email is required" };
  }
  if (!EMAIL_RE.test(b.owner_email)) {
    return { error: "bad_request", detail: "owner_email must be a valid email address" };
  }
  if (
    !b.restaurant_name ||
    typeof b.restaurant_name !== "string" ||
    b.restaurant_name.trim().length === 0
  ) {
    return {
      error: "bad_request",
      detail: "restaurant_name is required (non-empty string)",
    };
  }

  return {
    name: b.name.trim(),
    slug: b.slug,
    owner_email: b.owner_email.toLowerCase().trim(),
    restaurant_name: b.restaurant_name.trim(),
    region: typeof b.region === "string" ? b.region : "ap-south-1",
    plan: typeof b.plan === "string" ? b.plan : "standard",
    send_invite: b.send_invite !== false, // default true
  };
}

// ─── JWT claim extraction ─────────────────────────────────────────────────────
// Decode the JWT payload without signature verification.
// Signature is verified by Supabase Auth — we only need the claims.
function extractClaims(
  authHeader: string | null,
): Record<string, unknown> | null {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = parts[1]
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(parts[1].length + ((4 - (parts[1].length % 4)) % 4), "=");
    return JSON.parse(atob(payload));
  } catch {
    return null;
  }
}

// ─── Provision tenant (transactional DB operation) ────────────────────────────
// Calls app.provision_tenant() SECURITY DEFINER DB function which wraps
// all INSERTs in a single transaction. See migration:
// 20260315_add_provision_tenant_function.sql
async function provisionTenant(
  supabase: ReturnType<typeof createClient>,
  input: OnboardRequest,
  callerAuthId: string,
): Promise<
  | { data: ProvisionResult; error: null }
  | { data: null; error: { code: string; message: string } }
> {
  const { data, error } = await supabase.rpc("provision_tenant", {
    p_name: input.name,
    p_slug: input.slug,
    p_owner_email: input.owner_email,
    p_restaurant_name: input.restaurant_name,
    p_region: input.region ?? "ap-south-1",
    p_plan: input.plan ?? "standard",
    p_caller_auth_id: callerAuthId,
  });

  if (error) {
    // Unique constraint on slug → 409
    if (error.code === "23505" || error.message?.includes("slug")) {
      return {
        data: null,
        error: { code: "conflict", message: "slug already exists" },
      };
    }
    return {
      data: null,
      error: { code: "internal_error", message: error.message },
    };
  }

  return { data: data as ProvisionResult, error: null };
}

// ─── Handler ──────────────────────────────────────────────────────────────────
Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  // ── 1. Verify platform admin claim ────────────────────────────────────────
  const claims = extractClaims(req.headers.get("Authorization"));
  if (!claims) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  if (claims.is_platform_admin !== true) {
    return new Response(JSON.stringify({ error: "forbidden" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }
  const callerAuthId = claims.sub as string;

  // ── 2. Parse + validate request body ──────────────────────────────────────
  let rawBody: unknown;
  try {
    rawBody = await req.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "bad_request", detail: "Invalid JSON" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  const validated = validateInput(rawBody);
  if ("error" in validated && "detail" in validated) {
    return new Response(JSON.stringify(validated), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
  const input = validated as OnboardRequest;

  // ── 3. Environment ─────────────────────────────────────────────────────────
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
    return new Response(
      JSON.stringify({ error: "internal_error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  const supabase = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false },
  });

  // ── 4. Provision tenant (transactional) ───────────────────────────────────
  const { data: provisionData, error: provisionError } = await provisionTenant(
    supabase,
    input,
    callerAuthId,
  );

  if (provisionError) {
    const status = provisionError.code === "conflict" ? 409 : 500;
    return new Response(
      JSON.stringify({
        error: provisionError.code,
        detail: provisionError.message,
      }),
      { status, headers: { "Content-Type": "application/json" } },
    );
  }

  // ── 5. Send invite email (optional) ──────────────────────────────────────
  let inviteSent = false;
  if (input.send_invite) {
    const { error: inviteError } = await supabase.auth.admin.inviteUserByEmail(
      input.owner_email,
      {
        redirectTo: `${Deno.env.get("APP_URL") ?? "https://app.befoodi.com"}/onboarding`,
        data: {
          tenant_id: provisionData!.tenant_id,
          tenant_name: input.name,
          role: "admin",
        },
      },
    );
    if (inviteError) {
      // Non-fatal: tenant was created. Log but don't fail the request.
      console.error("Invite email error:", inviteError);
    } else {
      inviteSent = true;
    }
  }

  // ── 6. Respond ────────────────────────────────────────────────────────────
  return new Response(
    JSON.stringify({
      tenant_id: provisionData!.tenant_id,
      tenant_slug: provisionData!.tenant_slug,
      owner_auth_id: provisionData!.owner_auth_id,
      owner_app_user_id: provisionData!.owner_app_user_id,
      restaurant_id: provisionData!.restaurant_id,
      status: provisionData!.status,
      invite_sent: inviteSent,
    }),
    {
      status: 201,
      headers: { "Content-Type": "application/json" },
    },
  );
});
