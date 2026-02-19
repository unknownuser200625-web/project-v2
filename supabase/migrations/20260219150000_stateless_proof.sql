-- Stateless verification migration
CREATE TABLE IF NOT EXISTS public.stateless_pipeline_verification (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    verified_at timestamptz DEFAULT now()
);
