-- Final verification migration
CREATE TABLE IF NOT EXISTS public.pipeline_automation_proof (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    automated boolean DEFAULT true
);
