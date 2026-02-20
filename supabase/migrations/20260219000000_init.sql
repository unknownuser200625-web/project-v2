CREATE TABLE IF NOT EXISTS public.pipeline_verification_test (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz DEFAULT now()
);
