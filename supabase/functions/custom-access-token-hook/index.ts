/**
 * custom-access-token-hook
 * befoodi V2 — Auth JWT Claim Injection
 *
 * PURPOSE:
 *   Injects tenant-scoped claims into every Supabase JWT so that all RLS
 *   policies can use cached initPlan predicates without hitting the DB
 *   on every row evaluation.
 *
 * REQUIRED CLAIMS INJECTED:
 *   tenant_id        (uuid)    — Primary tenant isolation key
 *   app_role         (string)  — 'admin' | 'staff' | 'customer'
 *   user_id          (uuid)    — app.users.id (NOT auth.users.id)
 *   is_platform_admin (bool)   — true only for SaaS platform admins
 *   staff_id         (uuid)    — app.staff.id (staff auth only)
 *   session_id       (string)  — anonymous customer session (QR auth only)
 *   aal              (string)  — 'aal1' | 'aal2' — injected by Supabase Auth
 *
 * REGISTRATION:
 *   Supabase Dashboard → Authentication → Hooks
 *   Hook type: Custom Access Token
 *   Function: supabase/functions/custom-access-token-hook
 *
 * SECURITY:
 *   - SECURITY DEFINER DB function (public.custom_access_token_hook) handles
 *     the actual DB lookup. This Edge Function is the registered hook entry point.
 *   - service_role key MUST NOT be used client-side.
 *   - Hook is granted to supabase_auth_admin only (see migration 20260310122633).
 *
 * ARCHITECTURE REFERENCE: PVD V2 Section 5 — Auth & JWT Strategy
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

interface HookEvent {
  user_id: string;
  claims: Record<string, unknown>;
  authentication_method: string;
  user_metadata?: Record<string, unknown>;
}

Deno.serve(async (req: Request) => {
  // Validate Supabase auth admin secret
  const authHeader = req.headers.get("Authorization");
  const hookSecret = Deno.env.get("HOOK_SECRET");

  if (!authHeader || !hookSecret) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (authHeader !== `Bearer ${hookSecret}`) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  let event: HookEvent;
  try {
    event = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Use service_role client — this is an Edge Function, not frontend.
  // service_role key is permitted here per PVD V2 Section 7.3.
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false } }
  );

  // Delegate claim injection to the SECURITY DEFINER DB function.
  // The DB function performs the app.users lookup and constructs all claims.
  const { data, error } = await supabase.rpc("custom_access_token_hook", {
    event: event,
  });

  if (error) {
    console.error("custom_access_token_hook DB error:", error);
    // Return event unmodified on error — do not block auth flow.
    // RLS will return zero rows, which is safe-fail behaviour.
    return new Response(JSON.stringify(event), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
});
