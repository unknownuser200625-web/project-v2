-- Explicit public schema ownership enforcement
ALTER SCHEMA public OWNER TO postgres;

-- Future app schema
CREATE SCHEMA IF NOT EXISTS app;
