-- =============================================================================
-- MIGRATION: add_pgjwt_extension
-- DB VERSION: 20260310122642
-- AUTHOR: Technical Implementer AI — befoodi V2
-- DATE: 2026-03-10
-- PURPOSE:
--   Install pgjwt extension for JWT verification within database functions.
--   Required for Phase 4 Auth & Authorization.
-- ROLLBACK: DROP EXTENSION IF EXISTS pgjwt;
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgjwt WITH SCHEMA extensions;
