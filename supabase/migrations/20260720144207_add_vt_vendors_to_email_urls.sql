ALTER TABLE email_urls ADD COLUMN IF NOT EXISTS vt_vendors jsonb;
ALTER TABLE email_urls ADD COLUMN IF NOT EXISTS vt_reputation integer;
