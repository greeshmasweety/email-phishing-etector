/*
# Phishing Email Detector — Core Schema

1. Overview
   Single-tenant security dashboard. No sign-in screen, so all tables are
   read/write by the anon + authenticated roles (data is intentionally shared
   within the deployment). Stores real analyzed emails, extracted URLs,
   per-engine detection results, alerts, quarantine actions, audit logs,
   allow/block lists, trusted brands, and system settings.

2. New Tables
   - emails              : one row per analyzed email, with full extraction + verdict
   - email_urls          : every URL extracted from an email, with static + VT analysis
   - detections          : per-engine results (rules, url, header, virustotal, ml, risk)
   - alerts              : admin alerts for high-risk emails
   - quarantine_actions  : quarantine / restore actions applied to emails
   - audit_logs          : append-only audit trail of every significant action
   - system_settings     : key/value runtime configuration (dry-run, thresholds, etc.)
   - allowlist_entries   : trusted senders/domains that reduce score
   - blocklist_entries   : known-bad senders/domains that increase score
   - trusted_brands      : brand names + legitimate domains used for impersonation checks

3. Security
   RLS enabled on every table. Policies allow anon + authenticated full CRUD
   because this is a single-tenant shared dashboard (no per-user isolation).

4. Notes
   - emails.gmail_message_id is UNIQUE to prevent duplicate analysis.
   - JSONB columns store structured evidence / reasons / breakdowns.
   - created_at / updated_at timestamps on all mutable tables.
*/

CREATE TABLE IF NOT EXISTS emails (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  gmail_message_id text UNIQUE NOT NULL,
  thread_id text,
  message_id_header text,
  sender_name text,
  sender_email text,
  sender_domain text,
  recipient text,
  cc text,
  subject text,
  received_at timestamptz,
  reply_to text,
  return_path text,
  auth_results text,
  spf_result text,
  dkim_result text,
  dmarc_result text,
  plain_body text,
  html_body_sanitized text,
  visible_link_texts text[],
  risk_score integer NOT NULL DEFAULT 0,
  classification text NOT NULL DEFAULT 'safe',
  confidence real NOT NULL DEFAULT 0.0,
  status text NOT NULL DEFAULT 'inbox',
  false_positive boolean NOT NULL DEFAULT false,
  scan_timestamp timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_emails_classification ON emails(classification);
CREATE INDEX IF NOT EXISTS idx_emails_scan_timestamp ON emails(scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_emails_sender_domain ON emails(sender_domain);

CREATE TABLE IF NOT EXISTS email_urls (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id uuid NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
  url text NOT NULL,
  domain text,
  scheme text,
  is_http boolean NOT NULL DEFAULT false,
  is_ip boolean NOT NULL DEFAULT false,
  is_shortened boolean NOT NULL DEFAULT false,
  is_punycode boolean NOT NULL DEFAULT false,
  suspicious_keywords text[],
  visible_text text,
  link_text_mismatch boolean NOT NULL DEFAULT false,
  sender_domain_mismatch boolean NOT NULL DEFAULT false,
  vt_malicious integer NOT NULL DEFAULT 0,
  vt_suspicious integer NOT NULL DEFAULT 0,
  vt_harmless integer NOT NULL DEFAULT 0,
  vt_undetected integer NOT NULL DEFAULT 0,
  vt_last_scan timestamptz,
  vt_status text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email_urls_email_id ON email_urls(email_id);
CREATE INDEX IF NOT EXISTS idx_email_urls_domain ON email_urls(domain);

CREATE TABLE IF NOT EXISTS detections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id uuid NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
  engine_name text NOT NULL,
  score integer NOT NULL DEFAULT 0,
  verdict text,
  confidence real NOT NULL DEFAULT 0.0,
  reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  error text,
  scan_timestamp timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_detections_email_id ON detections(email_id);
CREATE INDEX IF NOT EXISTS idx_detections_engine ON detections(engine_name);

CREATE TABLE IF NOT EXISTS alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id uuid NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
  severity text NOT NULL DEFAULT 'high',
  message text,
  acknowledged boolean NOT NULL DEFAULT false,
  acknowledged_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);

CREATE TABLE IF NOT EXISTS quarantine_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id uuid NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
  action text NOT NULL,
  applied boolean NOT NULL DEFAULT false,
  restored boolean NOT NULL DEFAULT false,
  dry_run boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_quarantine_email_id ON quarantine_actions(email_id);

CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action text NOT NULL,
  entity_type text,
  entity_id uuid,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS system_settings (
  id integer PRIMARY KEY DEFAULT 1,
  dry_run boolean NOT NULL DEFAULT true,
  auto_quarantine boolean NOT NULL DEFAULT false,
  monitoring_enabled boolean NOT NULL DEFAULT false,
  monitoring_interval_sec integer NOT NULL DEFAULT 60,
  risk_threshold_suspicious integer NOT NULL DEFAULT 40,
  risk_threshold_phishing integer NOT NULL DEFAULT 70,
  virustotal_enabled boolean NOT NULL DEFAULT false,
  virustotal_api_key_present boolean NOT NULL DEFAULT false,
  gmail_connected boolean NOT NULL DEFAULT false,
  gmail_last_scan timestamptz,
  gmail_last_scan_count integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS allowlist_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entry_type text NOT NULL,
  value text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_allowlist_unique ON allowlist_entries(entry_type, value);

CREATE TABLE IF NOT EXISTS blocklist_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entry_type text NOT NULL,
  value text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_blocklist_unique ON blocklist_entries(entry_type, value);

CREATE TABLE IF NOT EXISTS trusted_brands (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  legitimate_domains text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Seed default settings row
INSERT INTO system_settings (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

-- Seed a handful of trusted brands for impersonation detection
INSERT INTO trusted_brands (name, legitimate_domains)
VALUES
  ('microsoft', ARRAY['microsoft.com','outlook.com','live.com','office.com','microsoftonline.com']),
  ('google', ARRAY['google.com','gmail.com']),
  ('paypal', ARRAY['paypal.com']),
  ('amazon', ARRAY['amazon.com']),
  ('apple', ARRAY['apple.com','icloud.com']),
  ('facebook', ARRAY['facebook.com']),
  ('netflix', ARRAY['netflix.com']),
  ('linkedin', ARRAY['linkedin.com']),
  ('bank of america', ARRAY['bankofamerica.com']),
  ('chase', ARRAY['chase.com'])
ON CONFLICT (name) DO NOTHING;

-- Enable RLS on all tables
ALTER TABLE emails ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_urls ENABLE ROW LEVEL SECURITY;
ALTER TABLE detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE quarantine_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE allowlist_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE blocklist_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE trusted_brands ENABLE ROW LEVEL SECURITY;

-- Helper to apply full CRUD policies for a shared single-tenant table
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['emails','email_urls','detections','alerts','quarantine_actions','audit_logs','system_settings','allowlist_entries','blocklist_entries','trusted_brands'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I;', t || '_select', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR SELECT TO anon, authenticated USING (true);', t || '_select', t);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I;', t || '_insert', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR INSERT TO anon, authenticated WITH CHECK (true);', t || '_insert', t);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I;', t || '_update', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);', t || '_update', t);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I;', t || '_delete', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR DELETE TO anon, authenticated USING (true);', t || '_delete', t);
  END LOOP;
END $$;
