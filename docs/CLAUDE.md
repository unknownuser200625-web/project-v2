# CLAUDE.md — befoodi V2 Session Anchor

> **Constitutional Rule:** Read this file at the start of every AI session.
> Do NOT redesign architecture. Do NOT bypass tenant isolation.
> All deviations from this document are errors.

---

## PROJECT OVERVIEW

| Field        | Value                                        |
|--------------|----------------------------------------------|
| Project      | befoodi V2                                   |
| Type         | Multi-tenant Restaurant SaaS                 |
| Tagline      | QR ordering made simple                      |
| Authority    | PVD V2 Constitutional Blueprint (Feb 2026)   |
| Staging DB   | spkjdfynuoktuicrwpkl (ap-south-1, PG 17.6)  |
| Prod DB      | grbocctbkyvftcyoxtei (INACTIVE — not yet activated) |
| Repo         | C:\dev\project-v2                            |

**Stack:**
- **Database:** Supabase (PostgreSQL 17.6) — primary security and business logic layer
- **Auth:** Supabase Auth + custom JWT hook (`public.custom_access_token_hook`)
- **API:** PostgREST (automatic, RLS-enforced) + Supabase Edge Functions (Deno)
- **Frontend:** Next.js 14 (App Router) — UI only, never trusted for security decisions
- **Realtime:** Supabase Realtime — Kitchen Display System (KDS) updates
- **Security boundary:** Row Level Security is the ONLY security layer

---

## FOUR CONSTITUTIONAL PRINCIPLES

```
1. Security is a Database Property
   RLS is the absolute and only security boundary.
   Application-layer security is supplementary, never primary.

2. Production is the Source of Truth
   The live database state is the definitive reference.
   Repository migration files are secondary artifacts.

3. Verification Beats Generation
   No agent may claim completion without deterministic proof.
   Trust is the bottleneck — test before claiming done.

4. Performance is a Constraint
   <50ms RLS overhead. <2s menu load time.
   100+ tenants without architectural redesign.
```

---

## DATABASE ARCHITECTURE

### Tenant Hierarchy

```
app.tenants                    ← Top-level SaaS isolation unit
  └── app.restaurants          ← Operational restaurant per tenant
        └── app.restaurant_tables   ← Physical tables / QR stations
              └── app.table_sessions     ← Anonymous customer sessions (QR scan)
                    └── app.orders             ← Customer orders
                          └── app.order_items        ← Line items (price snapshot)

app.tenants
  └── app.menu_categories      ← Menu category hierarchy
        └── app.menu_items     ← Menu items with pricing (stored in paise)

app.tenants
  └── app.users                ← Tenant admin/staff users (linked to auth.users)
  └── app.staff                ← Kitchen staff (PIN + device auth, NOT in auth.users)
  └── app.memberships          ← Role assignments per tenant
  └── app.activation_codes     ← Single-use 72h onboarding codes

audit.change_log               ← Append-only audit log (partitioned by month)
  └── change_log_2026_02 ... change_log_2027_03   ← 14 monthly partitions
```

### All App Schema Tables (12)

| Table               | Phase | Key Columns                                      |
|---------------------|-------|--------------------------------------------------|
| `tenants`           | 2     | id, name, slug, status, owner_email, metadata    |
| `restaurants`       | 2     | id, tenant_id, display_name, timezone, currency  |
| `users`             | 2     | id, tenant_id, auth_user_id, email, app_role     |
| `staff`             | 2     | id, tenant_id, name, pin_hash, device_id         |
| `memberships`       | 2     | id, tenant_id, user_id, role                     |
| `activation_codes`  | 5     | id, tenant_id, token (32-char hex), expires_at   |
| `menu_categories`   | 5     | id, tenant_id, restaurant_id, parent_id, name    |
| `menu_items`        | 5     | id, tenant_id, restaurant_id, price_paise, availability |
| `restaurant_tables` | 5     | id, tenant_id, restaurant_id, label, qr_code_token |
| `table_sessions`    | 5     | id, tenant_id, restaurant_id, table_id, status  |
| `orders`            | 5     | id, tenant_id, restaurant_id, session_id, status |
| `order_items`       | 5     | id, tenant_id, order_id, item_price_paise (snapshot) |

### Enums

| Enum                  | Values                                                    |
|-----------------------|-----------------------------------------------------------|
| `app.tenant_status`   | PENDING, ACTIVE, SUSPENDED, CLOSED                        |
| `app.app_role`        | admin, staff, customer                                    |
| `app.membership_role` | owner, manager, staff                                     |
| `app.order_status`    | PENDING, CONFIRMED, PREPARING, READY, DELIVERED, CANCELLED|
| `app.session_status`  | ACTIVE, CLOSED, EXPIRED                                   |
| `app.item_availability` | AVAILABLE, SOLD_OUT, HIDDEN                             |

### Foreign Key Chain

```
menu_items.category_id       → menu_categories.id
menu_items.restaurant_id     → restaurants.id
restaurant_tables.restaurant_id → restaurants.id
table_sessions.table_id      → restaurant_tables.id
table_sessions.restaurant_id → restaurants.id
orders.session_id            → table_sessions.id
orders.restaurant_id         → restaurants.id
order_items.order_id         → orders.id
order_items.menu_item_id     → menu_items.id (nullable — item may be deleted)
All 12 tables.tenant_id      → tenants.id
```

---

## SECURITY MODEL

### RLS Pattern (mandatory on all app tables)

```sql
-- SELECT (with soft-delete + platform admin exclusion)
USING (
  deleted_at IS NULL
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
  AND tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
)

-- INSERT (WITH CHECK required)
WITH CHECK (
  tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)
  AND (SELECT (auth.jwt() ->> 'app_role'::text)) = 'admin'
  AND (SELECT ((auth.jwt() ->> 'is_platform_admin'::text))::boolean) IS NOT TRUE
)
```

**Critical rules:**
- Always use `(SELECT auth.jwt() ->> 'claim')` — the `(SELECT ...)` wrapper is mandatory for initPlan caching
- Never use `USING (true)` — permanently banned
- Never use `auth.role()` for RBAC — use JWT claims only
- `FORCE ROW LEVEL SECURITY` required on all app tables
- Every RLS predicate column must be indexed

### JWT Claims (injected by `public.custom_access_token_hook`)

| Claim               | Type    | Description                                  |
|---------------------|---------|----------------------------------------------|
| `tenant_id`         | UUID    | Primary tenant isolation key                 |
| `user_id`           | UUID    | app.users.id (NOT auth.users.id)             |
| `app_role`          | string  | admin \| staff \| customer                   |
| `is_platform_admin` | boolean | true only for SaaS platform admins           |
| `aal`               | string  | aal1 \| aal2 (from Supabase Auth natively)   |
| `staff_id`          | UUID    | app.staff.id (staff auth path only)          |
| `session_id`        | UUID    | table_sessions.id (customer QR path only)    |

### Auth Hook Status

```
DB function:    public.custom_access_token_hook  ✅ EXISTS, SECURITY DEFINER
Edge Function:  custom-access-token-hook         ✅ DEPLOYED (ACTIVE)
Dashboard reg:  Authentication → Hooks           🔴 NOT REGISTERED — BLOCKS ALL AUTH
```

**⚠️ CRITICAL ACTION REQUIRED:**
Register the hook at:
`Supabase Dashboard → Authentication → Hooks → Customize Access Token (JWT) Claims`
Select: `public.custom_access_token_hook`

---

## AUTHENTICATION PATHS

| Role             | Method                      | Path                         | Status        |
|------------------|-----------------------------|------------------------------|---------------|
| Restaurant Admin | Email + Password            | Supabase Auth + JWT hook     | PARTIAL       |
| Kitchen Staff    | PIN + device_id             | staff-pin-verify Edge Fn     | DEPLOYED      |
| Customer         | Anonymous QR scan           | customer-session-create (TBD)| MISSING       |
| Platform Admin   | Email + Password + MFA      | Supabase Auth + JWT hook     | PARTIAL       |

**Staff auth:** Staff are NOT in `auth.users`. They authenticate via `POST /functions/v1/staff-pin-verify`
with `{ tenant_id, device_id, pin }`. Returns a custom-signed 8h JWT.

**Customer auth:** Anonymous Supabase Auth session scoped to one `table_sessions` row.
`session_id` claim in JWT controls order placement access.

---

## AUDIT SYSTEM

- **All 12 app tables** have `AFTER INSERT OR UPDATE OR DELETE` trigger → `audit.log_changes()`
- **audit.change_log** is partitioned by month (RANGE on `executed_at`)
- **14 active partitions:** `change_log_2026_02` through `change_log_2027_03`
- **All partitions:** RLS=true, FORCE RLS=true, `audit_select` policy (requires `aal2` MFA)
- **Immutability:** `BEFORE DELETE` trigger → `audit.prevent_mutation()` blocks all deletes
- **Storage:** JSONB diff only — stores changed fields only (up to 80% storage reduction)
- **Retention:** 7-10 years (PVD V2 §6.2)

---

## EDGE FUNCTIONS

| Function                | Deploy Status | verify_jwt | Purpose                                  |
|-------------------------|--------------|------------|------------------------------------------|
| custom-access-token-hook| ACTIVE       | false      | JWT claim injection (Supabase Auth hook) |
| staff-pin-verify        | ACTIVE       | false      | Staff PIN + device authentication        |
| tenant-onboard          | ACTIVE       | true       | Platform admin provisions full tenant    |
| activation-code-issue   | MISSING      | —          | Issue 72h onboarding codes               |
| activation-code-redeem  | MISSING      | —          | Validate and consume codes               |

---

## DATABASE FUNCTIONS

| Function                       | Schema | Security | Called By        |
|--------------------------------|--------|----------|------------------|
| `custom_access_token_hook`     | public | DEFINER  | supabase_auth_admin |
| `generate_uuidv7`              | public | INVOKER  | Column defaults  |
| `provision_tenant`             | app    | DEFINER  | tenant-onboard Edge Fn |
| `verify_staff_pin`             | app    | DEFINER  | staff-pin-verify Edge Fn |
| `cascade_tenant_soft_delete`   | app    | DEFINER  | Trigger          |
| `grant_membership`             | app    | DEFINER  | Trigger          |
| `set_tenant_id`                | app    | DEFINER  | Trigger          |
| `set_updated_at`               | app    | INVOKER  | Trigger          |
| `soft_delete`                  | app    | DEFINER  | Trigger          |
| `validate_restaurant_tenant_active` | app | DEFINER | Trigger        |
| `validate_user_tenant_active`  | app    | DEFINER  | Trigger          |
| `log_changes`                  | audit  | DEFINER  | Trigger          |
| `prevent_mutation`             | audit  | DEFINER  | Trigger          |
| `jsonb_diff`                   | audit  | INVOKER  | Trigger          |

---

## MIGRATION STATE

**17 migrations applied to staging** (`spkjdfynuoktuicrwpkl`) as of March 15, 2026.

| Version        | Name                                                     | Phase |
|----------------|----------------------------------------------------------|-------|
| 20260220151421 | baseline_v1                                              | 2     |
| 20260310122331 | audit_partition_rls_remediation                          | 3     |
| 20260310122348 | fix_memberships_policy_drift                             | 3     |
| 20260310122633 | fix_function_search_paths_and_hook                       | 3     |
| 20260310122642 | add_pgjwt_extension                                      | 3     |
| 20260311120655 | fix_multiple_permissive_policies_and_jwt_consolidation   | 3     |
| 20260311121131 | fix_audit_partition_dual_policies_and_remaining_initplan | 3     |
| 20260311121609 | fix_tenants_bootstrap_insert_predicate                   | 3     |
| 20260311121627 | restore_audit_aal2_mfa_requirement                       | 3     |
| 20260315070404 | fix_users_select_jwt_first_pattern                       | 3     |
| 20260315150714 | repo_stub_20260311000500_noop                            | hygiene |
| 20260315150721 | repo_stub_20260311001000_noop                            | hygiene |
| 20260315151454 | fix_custom_access_token_hook_staff_path                  | 4     |
| 20260315151819 | add_provision_tenant_function                            | 4     |
| 20260315153208 | fix_generate_uuidv7_search_path                          | 4     |
| 20260315154516 | phase5_business_logic_tables                             | 5     |
| 20260315165443 | add_restaurant_tables_and_session_fk                     | 5     |

**Migration discipline:**
- Versioning: apply via MCP → query `schema_migrations` for assigned version → name repo file with that exact version
- Files in `supabase/migrations/` — never modified after creation
- Stale prefix files (20260310001-004, 20260311000500, 20260311001000) are `SELECT 1` no-ops — do not delete

---

## DEVELOPMENT RULES (Non-Negotiable)

```
1. NEVER bypass tenant isolation — tenant_id must be in every app table
2. ALL tables must have RLS ENABLED + FORCE ROW LEVEL SECURITY
3. ALL RLS policies must use (SELECT auth.jwt() ->> 'claim') initPlan pattern
4. ALL schema changes must be versioned migrations — no dashboard edits
5. NEVER modify old migrations — only create new ones
6. ALL new tables need 4 policies (SELECT/INSERT/UPDATE/DELETE)
7. ALL INSERT/UPDATE policies require WITH CHECK clause
8. NEVER use USING (true) — permanently banned
9. NEVER use auth.role() for RBAC — use JWT claims only
10. service_role key is BANNED from frontend — Edge Functions only
11. Prices stored in paise (integer) — never float
12. Soft delete via deleted_at timestamp — never hard DELETE app data
13. Rollback script required in every migration
```

---

## CURRENTLY BANNED PATTERNS

```sql
-- BANNED: USING (true)
CREATE POLICY bad ON app.orders FOR SELECT USING (true);

-- BANNED: auth.role()
CREATE POLICY bad ON app.orders FOR SELECT USING (auth.role() = 'authenticated');

-- BANNED: bare auth.jwt() call (not wrapped in SELECT)
tenant_id = auth.jwt() ->> 'tenant_id'  -- WRONG: re-evaluates per row

-- CORRECT: initPlan cached pattern
tenant_id = (SELECT (auth.jwt() ->> 'tenant_id'::text)::uuid)  -- CORRECT
```

---

## CURRENT PROJECT STATUS

| Phase | Name                    | Status                          |
|-------|-------------------------|---------------------------------|
| 1     | Foundation              | PARTIAL — CI/CD done; CLAUDE.md, ADRs, pre-commit hooks missing |
| 2     | Core Schema             | ✅ COMPLETE                     |
| 3     | RLS Security            | ✅ COMPLETE                     |
| 4     | Auth & Authorization    | 🟡 PARTIAL — hook unregistered  |
| 5     | Business Logic          | 🟡 PARTIAL — schema done, workflows missing |
| 6     | Performance & Monitoring| 🔴 NOT STARTED                  |
| 7     | AI Orchestration        | 🔴 NOT STARTED                  |
| 8     | Testing & Validation    | 🔴 NOT STARTED                  |
| 9     | Production Prep         | 🔴 NOT STARTED                  |
| 10    | Launch & Monitor        | 🔴 NOT STARTED                  |

---

## IMMEDIATE BLOCKERS (Phase 3 entry gates)

| Priority | Blocker                              | Action                                        |
|----------|--------------------------------------|-----------------------------------------------|
| 🔴 CRIT  | Auth hook not registered             | Dashboard → Auth → Hooks → select hook fn     |
| 🔴 HIGH  | activation-code-issue missing        | Build + deploy Edge Function                  |
| 🔴 HIGH  | activation-code-redeem missing       | Build + deploy Edge Function                  |
| 🔴 HIGH  | Customer QR session flow missing     | Build customer-session-create Edge Function   |
| 🔴 HIGH  | Zero product UI implemented          | Build Next.js admin + customer interfaces     |
| 🟡 WARN  | Leaked password protection disabled  | Dashboard → Auth → Password Settings          |

---

## REPOSITORY STRUCTURE

```
C:\dev\project-v2\
├── supabase/
│   ├── migrations/          ← 23 files (17 canonical + 6 stubs)
│   ├── functions/
│   │   ├── custom-access-token-hook/index.ts   ✅ deployed
│   │   ├── staff-pin-verify/index.ts           ✅ deployed
│   │   └── tenant-onboard/index.ts             ✅ deployed
│   ├── backups/baseline_schema.sql
│   └── MIGRATION_POLICY.md
├── src/
│   ├── app/                 ← Next.js scaffold only — no product UI
│   ├── components/          ← EMPTY
│   ├── lib/supabase/client.ts
│   └── types/               ← EMPTY — no TypeScript types yet
├── docs/
│   ├── CLAUDE.md            ← THIS FILE
│   ├── decisions/           ← EMPTY — 0 ADRs written
│   └── snapshots/           ← EMPTY
├── .github/workflows/migrations.yml
└── New folder/              ← Architecture PDFs
```

---

## ENVIRONMENT CONFIGURATION

```bash
# .env.local (never commit — in .gitignore)
NEXT_PUBLIC_SUPABASE_URL=https://spkjdfynuoktuicrwpkl.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=<anon_key>
SUPABASE_SERVICE_ROLE_KEY=<service_role_key>  # Edge Functions only
SUPABASE_JWT_SECRET=<jwt_secret>              # staff-pin-verify signing
APP_URL=https://app.befoodi.com               # invite redirect
```

---

## AI AGENT OPERATING RULES

1. **Read this file before every session.** Do not proceed without grounding context.
2. **Inspect before implementing.** Use MCP `execute_sql` to verify live DB state.
3. **Apply via MCP, then get version.** Query `schema_migrations` for assigned version → write repo file.
4. **Never claim completion without verification.** Run advisory checks after every DDL change.
5. **Additive only.** Never rewrite prior migrations. Never restructure existing schema.
6. **Security Advisor after every migration.** `get_advisors(type='security')` must return zero HIGH/CRITICAL.
7. **Context limit:** Reset session if approaching 85% context usage. Re-inject only this file.

---

*Document Status: ACTIVE*
*Last Updated: March 15, 2026*
*Source of Truth: PVD V2 Constitutional Blueprint (February 2026)*
*Conformance is mandatory. Deviations are errors.*
