import { supabase } from './supabase';

export interface EmailRow {
  id: string;
  gmail_message_id: string;
  sender_name: string | null;
  sender_email: string | null;
  sender_domain: string | null;
  subject: string | null;
  received_at: string | null;
  risk_score: number;
  classification: 'safe' | 'suspicious' | 'phishing';
  status: string;
  false_positive: boolean;
  scan_timestamp: string;
  email_urls: { id: string; url: string; is_http: boolean; vt_malicious: number }[];
}

export async function fetchRecentEmails(limit = 50): Promise<EmailRow[]> {
  const { data, error } = await supabase
    .from('emails')
    .select('*, email_urls(id, url, is_http, vt_malicious)')
    .order('scan_timestamp', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return (data ?? []) as EmailRow[];
}

export async function fetchEmailById(id: string) {
  const { data, error } = await supabase
    .from('emails')
    .select('*, email_urls(*), detections(*)')
    .eq('id', id)
    .maybeSingle();
  if (error) throw error;
  return data;
}

export async function fetchSummary() {
  const { count: total } = await supabase.from('emails').select('*', { count: 'exact', head: true });
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const { count: todayCount } = await supabase
    .from('emails')
    .select('*', { count: 'exact', head: true })
    .gte('scan_timestamp', today.toISOString());

  const { count: safe } = await supabase
    .from('emails')
    .select('*', { count: 'exact', head: true })
    .eq('classification', 'safe');
  const { count: suspicious } = await supabase
    .from('emails')
    .select('*', { count: 'exact', head: true })
    .eq('classification', 'suspicious');
  const { count: phishing } = await supabase
    .from('emails')
    .select('*', { count: 'exact', head: true })
    .eq('classification', 'phishing');
  const { count: quarantined } = await supabase
    .from('emails')
    .select('*', { count: 'exact', head: true })
    .eq('status', 'quarantined');
  const { count: criticalAlerts } = await supabase
    .from('alerts')
    .select('*', { count: 'exact', head: true })
    .eq('acknowledged', false);
  const { count: falsePositives } = await supabase
    .from('emails')
    .select('*', { count: 'exact', head: true })
    .eq('false_positive', true);
  const { count: urlThreats } = await supabase
    .from('email_urls')
    .select('*', { count: 'exact', head: true })
    .gt('vt_malicious', 0);

  return {
    total: total ?? 0,
    todayCount: todayCount ?? 0,
    safe: safe ?? 0,
    suspicious: suspicious ?? 0,
    phishing: phishing ?? 0,
    quarantined: quarantined ?? 0,
    criticalAlerts: criticalAlerts ?? 0,
    falsePositives: falsePositives ?? 0,
    urlThreats: urlThreats ?? 0,
  };
}

export async function fetchTrends(days = 7) {
  const since = new Date();
  since.setDate(since.getDate() - days);
  since.setHours(0, 0, 0, 0);
  const { data, error } = await supabase
    .from('emails')
    .select('classification, scan_timestamp')
    .gte('scan_timestamp', since.toISOString());
  if (error) throw error;

  const buckets: Record<string, { safe: number; suspicious: number; phishing: number }> = {};
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    d.setHours(0, 0, 0, 0);
    buckets[d.toISOString().slice(0, 10)] = { safe: 0, suspicious: 0, phishing: 0 };
  }
  for (const row of data ?? []) {
    const day = (row.scan_timestamp as string).slice(0, 10);
    if (buckets[day]) buckets[day][row.classification as 'safe' | 'suspicious' | 'phishing']++;
  }
  return Object.entries(buckets).map(([date, v]) => ({ date, ...v }));
}

export async function fetchTopDomains(limit = 8) {
  const { data, error } = await supabase.from('emails').select('sender_domain, classification');
  if (error) throw error;
  const counts: Record<string, { domain: string; phishing: number; suspicious: number; safe: number }> = {};
  for (const r of data ?? []) {
    const d = (r.sender_domain as string) ?? 'unknown';
    counts[d] = counts[d] || { domain: d, phishing: 0, suspicious: 0, safe: 0 };
    counts[d][r.classification as 'safe' | 'suspicious' | 'phishing']++;
  }
  return Object.values(counts)
    .map((v) => ({ ...v, total: v.phishing + v.suspicious + v.safe }))
    .sort((a, b) => b.total - a.total)
    .slice(0, limit);
}

export async function fetchTopIndicators(limit = 10) {
  const { data, error } = await supabase.from('detections').select('reasons');
  if (error) throw error;
  const counts: Record<string, number> = {};
  for (const r of data ?? []) {
    for (const reason of (r.reasons as string[]) ?? []) {
      counts[reason] = (counts[reason] ?? 0) + 1;
    }
  }
  return Object.entries(counts)
    .map(([reason, count]) => ({ reason, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export async function fetchAlerts() {
  const { data, error } = await supabase
    .from('alerts')
    .select('*, emails(subject, sender_email, risk_score)')
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) throw error;
  return data ?? [];
}

export async function acknowledgeAlert(id: string) {
  await supabase.from('alerts').update({ acknowledged: true, acknowledged_at: new Date().toISOString() }).eq('id', id);
}

export async function updateEmailStatus(
  id: string,
  update: { status?: string; classification?: string; false_positive?: boolean },
) {
  await supabase.from('emails').update({ ...update, updated_at: new Date().toISOString() }).eq('id', id);
  await supabase.from('audit_logs').insert({
    action: 'status_update',
    entity_type: 'email',
    entity_id: id,
    details: update,
  });
}

export async function quarantineEmail(id: string, dryRun: boolean) {
  await supabase.from('emails').update({ status: dryRun ? 'inbox' : 'quarantined', updated_at: new Date().toISOString() }).eq('id', id);
  await supabase.from('quarantine_actions').insert({
    email_id: id,
    action: 'quarantine',
    applied: !dryRun,
    dry_run: dryRun,
  });
  await supabase.from('audit_logs').insert({
    action: 'manual_quarantine',
    entity_type: 'email',
    entity_id: id,
    details: { dry_run: dryRun },
  });
}

export async function restoreEmail(id: string) {
  await supabase.from('emails').update({ status: 'inbox', updated_at: new Date().toISOString() }).eq('id', id);
  await supabase.from('quarantine_actions').insert({
    email_id: id,
    action: 'restore',
    applied: true,
    restored: true,
    dry_run: false,
  });
  await supabase.from('audit_logs').insert({
    action: 'restore',
    entity_type: 'email',
    entity_id: id,
    details: {},
  });
}

export async function fetchQuarantined() {
  const { data, error } = await supabase
    .from('emails')
    .select('*, email_urls(id, url, is_http, vt_malicious)')
    .eq('status', 'quarantined')
    .order('scan_timestamp', { ascending: false });
  if (error) throw error;
  return data ?? [];
}

export async function fetchAuditLogs(limit = 100) {
  const { data, error } = await supabase
    .from('audit_logs')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return data ?? [];
}

export async function fetchSettings() {
  const { data } = await supabase.from('system_settings').select('*').eq('id', 1).maybeSingle();
  return data;
}

export async function updateSettings(update: Record<string, unknown>) {
  await supabase.from('system_settings').update({ ...update, updated_at: new Date().toISOString() }).eq('id', 1);
  await supabase.from('audit_logs').insert({ action: 'settings_update', entity_type: 'settings', details: update });
}

export async function fetchListEntries(table: 'allowlist_entries' | 'blocklist_entries') {
  const { data, error } = await supabase.from(table).select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data ?? [];
}

export async function addListEntry(table: 'allowlist_entries' | 'blocklist_entries', entryType: string, value: string) {
  await supabase.from(table).insert({ entry_type: entryType, value });
}

export async function removeListEntry(table: 'allowlist_entries' | 'blocklist_entries', id: string) {
  await supabase.from(table).delete().eq('id', id);
}

export async function fetchTrustedBrands() {
  const { data } = await supabase.from('trusted_brands').select('*').order('name');
  return data ?? [];
}

export async function updateGmailScanStatus(connected: boolean, count: number) {
  await supabase
    .from('system_settings')
    .update({
      gmail_connected: connected,
      gmail_last_scan: new Date().toISOString(),
      gmail_last_scan_count: count,
      updated_at: new Date().toISOString(),
    })
    .eq('id', 1);
}
