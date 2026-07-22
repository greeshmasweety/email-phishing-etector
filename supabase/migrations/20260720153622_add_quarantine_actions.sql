/*
# Add quarantine actions table and AI analysis table

## Changes

### New Tables
1. `quarantine_actions` — tracks quarantine/release/delete actions on emails
   - `id` (uuid PK)
   - `email_id` (uuid FK to emails)
   - `action` (text: quarantined | released | deleted | false_positive)
   - `reason` (text)
   - `performed_by` (text, default 'system')
   - `created_at` (timestamptz default now())

2. `ai_analyses` — stores AI Security Analyst analysis results
   - `id` (uuid PK)
   - `email_id` (uuid FK to emails)
   - `analysis` (jsonb — full AI analysis output)
   - `summary` (text)
   - `risk_assessment` (text)
   - `recommendations` (jsonb array)
   - `created_at` (timestamptz default now())

### Security
- RLS enabled on both tables
- `TO anon, authenticated` CRUD (single-tenant, no auth)
*/

CREATE TABLE IF NOT EXISTS quarantine_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id uuid REFERENCES emails(id) ON DELETE CASCADE,
  action text NOT NULL,
  reason text,
  performed_by text DEFAULT 'system',
  created_at timestamptz DEFAULT now()
);

ALTER TABLE quarantine_actions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "qa_select" ON quarantine_actions;
CREATE POLICY "qa_select" ON quarantine_actions FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "qa_insert" ON quarantine_actions;
CREATE POLICY "qa_insert" ON quarantine_actions FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "qa_update" ON quarantine_actions;
CREATE POLICY "qa_update" ON quarantine_actions FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "qa_delete" ON quarantine_actions;
CREATE POLICY "qa_delete" ON quarantine_actions FOR DELETE
  TO anon, authenticated USING (true);

CREATE TABLE IF NOT EXISTS ai_analyses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id uuid REFERENCES emails(id) ON DELETE CASCADE,
  analysis jsonb,
  summary text,
  risk_assessment text,
  recommendations jsonb DEFAULT '[]'::jsonb,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE ai_analyses ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "ai_select" ON ai_analyses;
CREATE POLICY "ai_select" ON ai_analyses FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "ai_insert" ON ai_analyses;
CREATE POLICY "ai_insert" ON ai_analyses FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "ai_update" ON ai_analyses;
CREATE POLICY "ai_update" ON ai_analyses FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "ai_delete" ON ai_analyses;
CREATE POLICY "ai_delete" ON ai_analyses FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_quarantine_actions_email_id ON quarantine_actions(email_id);
CREATE INDEX IF NOT EXISTS idx_ai_analyses_email_id ON ai_analyses(email_id);
