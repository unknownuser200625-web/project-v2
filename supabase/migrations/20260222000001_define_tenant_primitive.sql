CREATE TABLE IF NOT EXISTS app.tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz DEFAULT now()
);

ALTER TABLE app.tenants ENABLE ROW LEVEL SECURITY;
