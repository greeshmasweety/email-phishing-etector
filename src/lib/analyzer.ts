import { supabase } from './supabase';
import { parseEmail, type ParsedEmail } from './emailParser';
import { extractUrls, analyzeUrl } from './urlAnalyzer';
import {
  contentRuleEngine,
  headerAnalysisEngine,
  urlAnalysisEngine,
  mlHeuristicEngine,
} from './engines';
import { calculateRisk } from './riskEngine';
import { lookupUrlVt, applyVtToUrl, clearVtCache } from './virustotal';
import type { AnalysisResult, EngineResult, UrlAnalysis } from './types';

export async function getSettings() {
  const { data } = await supabase.from('system_settings').select('*').eq('id', 1).maybeSingle();
  return (
    data ?? {
      dry_run: true,
      auto_quarantine: false,
      monitoring_enabled: false,
      monitoring_interval_sec: 60,
      risk_threshold_suspicious: 40,
      risk_threshold_phishing: 70,
      virustotal_enabled: false,
      gmail_connected: false,
      gmail_last_scan: null,
      gmail_last_scan_count: 0,
    }
  );
}

function generateMessageId(raw: string, parsed: ParsedEmail): string {
  if (parsed.messageId) return parsed.messageId;
  let hash = 0;
  for (let i = 0; i < raw.length; i++) hash = ((hash << 5) - hash + raw.charCodeAt(i)) | 0;
  return `local-${Math.abs(hash).toString(16)}`;
}

export async function analyzeRawEmail(raw: string): Promise<AnalysisResult> {
  const parsed = parseEmail(raw);
  const settings = await getSettings();
  const gmailMessageId = generateMessageId(raw, parsed);

  // Duplicate prevention
  const { data: existing } = await supabase
    .from('emails')
    .select('id, gmail_message_id')
    .eq('gmail_message_id', gmailMessageId)
    .maybeSingle();
  if (existing) {
    const { data: full } = await supabase
      .from('emails')
      .select('*, email_urls(*)')
      .eq('id', existing.id)
      .maybeSingle();
    if (full) return reconstructFromDb(full);
  }

  const extracted = extractUrls(parsed.plainBody, parsed.htmlBody);
  let urls: UrlAnalysis[] = extracted.map((u) =>
    analyzeUrl(u.url, u.visibleText, parsed.fromDomain),
  );

  const vtEnabled = !!settings.virustotal_enabled;
  let vtEngine: EngineResult;

  if (vtEnabled) {
    clearVtCache();
    const vtResults = await Promise.all(urls.map((u) => lookupUrlVt(u.url)));
    urls = urls.map((u, i) => applyVtToUrl(u, vtResults[i]));

    const totalMalicious = vtResults.reduce((s, r) => s + r.malicious, 0);
    const totalSuspicious = vtResults.reduce((s, r) => s + r.suspicious, 0);
    const scanned = vtResults.filter((r) => r.status === 'completed').length;
    const errored = vtResults.filter((r) => r.status !== 'completed').length;
    const vtScore = Math.min(100, vtResults.reduce((s, r) => s + r.vt_score, 0));

    const reasons: string[] = [];
    if (totalMalicious > 0) reasons.push(`${totalMalicious} VirusTotal malicious report(s) across URLs`);
    if (totalSuspicious > 0) reasons.push(`${totalSuspicious} VirusTotal suspicious report(s)`);
    if (errored > 0 && scanned === 0) reasons.push('VirusTotal lookup failed for all URLs');

    vtEngine = {
      engineName: 'virustotal',
      score: vtScore,
      verdict: totalMalicious > 0 ? 'malicious' : totalSuspicious > 0 ? 'suspicious' : 'clean',
      confidence: scanned > 0 ? Math.min(1, (totalMalicious + totalSuspicious) / 10 + 0.3) : 0,
      reasons,
      evidence: { scanned, errored, totalMalicious, totalSuspicious },
      error: scanned === 0 ? 'all_lookups_failed' : null,
    };
  } else {
    vtEngine = {
      engineName: 'virustotal',
      score: 0,
      verdict: 'disabled',
      confidence: 0,
      reasons: ['VirusTotal disabled in settings'],
      evidence: { status: 'disabled' },
      error: 'disabled',
    };
  }

  const content = contentRuleEngine(parsed);
  const header = headerAnalysisEngine(parsed);
  const urlEngine = urlAnalysisEngine(urls, parsed.fromDomain);
  const ml = mlHeuristicEngine(parsed, urls, content.score, header.score, urlEngine.score);

  const engines: EngineResult[] = [content, header, urlEngine, ml, vtEngine];

  const risk = calculateRisk(engines, urls, {
    suspicious: settings.risk_threshold_suspicious,
    phishing: settings.risk_threshold_phishing,
  });

  const result: AnalysisResult = {
    email: {
      gmail_message_id: gmailMessageId,
      thread_id: null,
      message_id_header: parsed.messageId,
      sender_name: parsed.fromName,
      sender_email: parsed.fromEmail,
      sender_domain: parsed.fromDomain,
      recipient: parsed.recipient,
      cc: parsed.cc,
      subject: parsed.subject,
      received_at: parsed.receivedAt,
      reply_to: parsed.replyTo,
      return_path: parsed.returnPath,
      auth_results: parsed.authResults,
      spf_result: parsed.spf,
      dkim_result: parsed.dkim,
      dmarc_result: parsed.dmarc,
      plain_body: parsed.plainBody,
      html_body_sanitized: parsed.htmlBody,
      visible_link_texts: parsed.visibleLinkTexts.length ? parsed.visibleLinkTexts : null,
    },
    urls,
    engines,
    riskScore: risk.riskScore,
    classification: risk.classification,
    confidence: risk.confidence,
    reasons: risk.reasons,
    scoreBreakdown: risk.scoreBreakdown,
  };

  await persistAnalysis(result, settings);
  return result;
}

async function persistAnalysis(result: AnalysisResult, settings: Record<string, unknown>) {
  const e = result.email;
  const insertRow = {
    gmail_message_id: e.gmail_message_id,
    message_id_header: e.message_id_header,
    sender_name: e.sender_name,
    sender_email: e.sender_email,
    sender_domain: e.sender_domain,
    recipient: e.recipient,
    cc: e.cc,
    subject: e.subject,
    received_at: e.received_at,
    reply_to: e.reply_to,
    return_path: e.return_path,
    auth_results: e.auth_results,
    spf_result: e.spf_result,
    dkim_result: e.dkim_result,
    dmarc_result: e.dmarc_result,
    plain_body: (e.plain_body ?? '').slice(0, 20000),
    html_body_sanitized: (e.html_body_sanitized ?? '').slice(0, 50000),
    visible_link_texts: e.visible_link_texts,
    risk_score: result.riskScore,
    classification: result.classification,
    confidence: result.confidence,
    status: 'inbox',
    false_positive: false,
  };

  const { data: inserted, error } = await supabase
    .from('emails')
    .insert(insertRow)
    .select('id')
    .maybeSingle();
  if (error || !inserted) return;
  const emailId = inserted.id;

  if (result.urls.length) {
    await supabase.from('email_urls').insert(
      result.urls.map((u) => ({
        email_id: emailId,
        url: u.url,
        domain: u.domain,
        scheme: u.scheme,
        is_http: u.isHttp,
        is_ip: u.isIp,
        is_shortened: u.isShortened,
        is_punycode: u.isPunycode,
        suspicious_keywords: u.suspiciousKeywords,
        visible_text: u.visibleText,
        link_text_mismatch: u.linkTextMismatch,
        sender_domain_mismatch: u.senderDomainMismatch,
        vt_malicious: u.vtMalicious,
        vt_suspicious: u.vtSuspicious,
        vt_harmless: u.vtHarmless,
        vt_undetected: u.vtUndetected,
        vt_status: u.vtStatus,
      })),
    );
  }

  await supabase.from('detections').insert(
    result.engines.map((eng) => ({
      email_id: emailId,
      engine_name: eng.engineName,
      score: eng.score,
      verdict: eng.verdict,
      confidence: eng.confidence,
      reasons: eng.reasons,
      evidence: eng.evidence,
      error: eng.error,
    })),
  );

  if (result.classification === 'phishing') {
    await supabase.from('alerts').insert({
      email_id: emailId,
      severity: 'critical',
      message: `Phishing detected: "${e.subject ?? '(no subject)'}" from ${e.sender_email ?? 'unknown'} — risk ${result.riskScore}/100`,
    });

    const dryRun = !!settings.dry_run;
    const autoQ = !!settings.auto_quarantine;
    await supabase.from('quarantine_actions').insert({
      email_id: emailId,
      action: 'quarantine',
      applied: autoQ && !dryRun,
      restored: false,
      dry_run: dryRun,
    });
    if (autoQ && !dryRun) {
      await supabase.from('emails').update({ status: 'quarantined' }).eq('id', emailId);
    }

    await supabase.from('audit_logs').insert({
      action: 'phishing_detected',
      entity_type: 'email',
      entity_id: emailId,
      details: {
        risk_score: result.riskScore,
        classification: result.classification,
        dry_run: dryRun,
        auto_quarantine: autoQ,
        reasons: result.reasons.slice(0, 10),
      },
    });
  }
}

function reconstructFromDb(row: Record<string, unknown>): AnalysisResult {
  const engines = (row.detections as Record<string, unknown>[]) ?? [];
  const urls = (row.email_urls as Record<string, unknown>[]) ?? [];
  return {
    email: {
      gmail_message_id: row.gmail_message_id as string,
      thread_id: (row.thread_id as string) ?? null,
      message_id_header: (row.message_id_header as string) ?? null,
      sender_name: (row.sender_name as string) ?? null,
      sender_email: (row.sender_email as string) ?? null,
      sender_domain: (row.sender_domain as string) ?? null,
      recipient: (row.recipient as string) ?? null,
      cc: (row.cc as string) ?? null,
      subject: (row.subject as string) ?? null,
      received_at: (row.received_at as string) ?? null,
      reply_to: (row.reply_to as string) ?? null,
      return_path: (row.return_path as string) ?? null,
      auth_results: (row.auth_results as string) ?? null,
      spf_result: (row.spf_result as string) ?? null,
      dkim_result: (row.dkim_result as string) ?? null,
      dmarc_result: (row.dmarc_result as string) ?? null,
      plain_body: (row.plain_body as string) ?? null,
      html_body_sanitized: (row.html_body_sanitized as string) ?? null,
      visible_link_texts: (row.visible_link_texts as string[]) ?? null,
    },
    urls: urls.map((u) => ({
      url: u.url as string,
      domain: u.domain as string,
      scheme: u.scheme as string,
      isHttp: !!u.is_http,
      isIp: !!u.is_ip,
      isShortened: !!u.is_shortened,
      isPunycode: !!u.is_punycode,
      suspiciousKeywords: (u.suspicious_keywords as string[]) ?? [],
      visibleText: (u.visible_text as string) ?? null,
      linkTextMismatch: !!u.link_text_mismatch,
      senderDomainMismatch: !!u.sender_domain_mismatch,
      vtMalicious: (u.vt_malicious as number) ?? 0,
      vtSuspicious: (u.vt_suspicious as number) ?? 0,
      vtHarmless: (u.vt_harmless as number) ?? 0,
      vtUndetected: (u.vt_undetected as number) ?? 0,
      vtLastScan: (u.vt_last_scan as string) ?? null,
      vtStatus: (u.vt_status as string) ?? null,
    })),
    engines: engines.map((eng) => ({
      engineName: eng.engine_name as string,
      score: (eng.score as number) ?? 0,
      verdict: (eng.verdict as string) ?? '',
      confidence: (eng.confidence as number) ?? 0,
      reasons: (eng.reasons as string[]) ?? [],
      evidence: (eng.evidence as Record<string, unknown>) ?? {},
      error: (eng.error as string) ?? null,
    })),
    riskScore: (row.risk_score as number) ?? 0,
    classification: (row.classification as AnalysisResult['classification']) ?? 'safe',
    confidence: (row.confidence as number) ?? 0,
    reasons: engines.flatMap((eng) => (eng.reasons as string[]) ?? []),
    scoreBreakdown: [],
  };
}
