import { useState } from 'react';
import { parseQuickInput } from '../lib/emailParser';
import { scanEmail, ScanResult } from '../lib/detectionEngine';
import { EMAIL_TEMPLATES } from '../lib/templates';
import { supabase } from '../lib/supabase';
import { useAlerts } from '../context/AlertContext';
import { RiskBadge, ScoreGauge, SeverityDot } from '../components/RiskBadge';
import VirusTotalTable from '../components/VirusTotalTable';

export default function ScanEmail() {
  const [raw, setRaw] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [savedId, setSavedId] = useState<string | null>(null);
  const [parsedInfo, setParsedInfo] = useState<{ sender: string; subject: string } | null>(null);
  const [error, setError] = useState('');
  const { showAlert } = useAlerts();

  async function handleScan() {
    if (!raw.trim()) return;
    setScanning(true);
    setError('');
    setResult(null);
    setSavedId(null);
    try {
      const parsed = parseQuickInput(raw);
      setParsedInfo({ sender: parsed.sender_email, subject: parsed.subject });
      const res = await scanEmail({
        sender_email: parsed.sender_email,
        sender_name: parsed.sender_name,
        subject: parsed.subject,
        plain_body: parsed.plain_body,
        html_body: parsed.html_body,
        spf: parsed.spf,
        dkim: parsed.dkim,
        dmarc: parsed.dmarc,
        reply_to: parsed.reply_to,
        return_path: parsed.return_path,
      });
      setResult(res);

      const now = new Date().toISOString();
      const { data, error: insErr } = await supabase.from('emails').insert({
        gmail_message_id: `manual-${Date.now()}`,
        sender_email: parsed.sender_email,
        sender_name: parsed.sender_name || null,
        sender_domain: parsed.sender_email.split('@')[1] || null,
        subject: parsed.subject,
        plain_body: parsed.plain_body,
        html_body_sanitized: parsed.html_body || null,
        reply_to: parsed.reply_to || null,
        return_path: parsed.return_path || null,
        spf_result: parsed.spf || null,
        dkim_result: parsed.dkim || null,
        dmarc_result: parsed.dmarc || null,
        visible_link_texts: res.urls.map((u) => u.display_text),
        risk_score: res.risk_score,
        classification: res.risk_level,
        confidence: Math.min(1, res.risk_score / 100),
        status: res.risk_level === 'malicious' ? 'quarantined' : 'reviewed',
        false_positive: false,
        scan_timestamp: now,
        received_at: now,
      }).select('id').single();

      if (insErr) throw insErr;
      const emailId = data?.id;
      setSavedId(emailId);

      if (emailId) {
        for (const f of res.findings.filter((f) => f.score > 0)) {
          await supabase.from('detections').insert({
            email_id: emailId,
            engine_name: f.engine,
            score: f.score,
            verdict: f.severity,
            confidence: 0.8,
            reasons: [{ description: f.description, severity: f.severity }],
            evidence: { engine: f.engine, score: f.score },
            scan_timestamp: now,
          });
        }

        for (const u of res.urls) {
          const vt = res.vt_results.find((v) => v.url === u.url);
          await supabase.from('email_urls').insert({
            email_id: emailId,
            url: u.url,
            domain: u.domain,
            scheme: u.url.startsWith('https') ? 'https' : 'http',
            is_http: u.uses_http,
            is_ip: u.is_ip,
            is_shortened: u.is_shortened,
            is_punycode: u.has_punycode,
            visible_text: u.display_text,
            link_text_mismatch: u.mismatch,
            sender_domain_mismatch: false,
            vt_malicious: vt?.malicious_count || 0,
            vt_suspicious: 0,
            vt_harmless: vt ? vt.total_engines - vt.malicious_count : 0,
            vt_undetected: 0,
            vt_vendors: vt?.vendors || null,
            vt_reputation: vt?.reputation ?? null,
            vt_last_scan: vt && vt.total_engines > 0 ? now : null,
            vt_status: vt?.error ? 'error' : (vt && vt.total_engines > 0 ? 'completed' : 'pending'),
          });
        }

        if (res.risk_level !== 'safe') {
          await supabase.from('quarantine_actions').insert({
            email_id: emailId,
            action: 'quarantined',
            reason: `Auto-quarantined: risk score ${res.risk_score}, classification ${res.risk_level}`,
            performed_by: 'system',
          });

          const isMalicious = res.risk_level === 'malicious';
          showAlert({
            type: isMalicious ? 'malicious' : 'phishing',
            title: isMalicious ? 'Malicious Email Detected!' : 'Phishing Email Detected!',
            message: `Risk score: ${res.risk_score}/100 — "${parsed.subject}"`,
            email_id: emailId,
            sender: parsed.sender_email,
            subject: parsed.subject,
            risk_score: res.risk_score,
          });
        } else {
          showAlert({
            type: 'success',
            title: 'Email Scan Complete',
            message: `"${parsed.subject}" is safe. Risk score: ${res.risk_score}/100`,
            email_id: emailId,
            sender: parsed.sender_email,
            subject: parsed.subject,
            risk_score: res.risk_score,
          });
        }
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  }

  function loadTemplate(id: string) {
    const t = EMAIL_TEMPLATES.find((t) => t.id === id);
    if (t) setRaw(t.raw);
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Scan Email</h1>
        <p className="text-gray-500 mt-1">Paste any email to scan — phishing emails are detected and you get an instant alert</p>
      </div>

      <div className="card p-5 mb-6">
        <h3 className="font-semibold text-gray-900 mb-3">Test Templates</h3>
        <div className="flex flex-wrap gap-2">
          {EMAIL_TEMPLATES.map((t) => (
            <button key={t.id} onClick={() => loadTemplate(t.id)}
              className="px-3 py-1.5 rounded-lg text-sm bg-gray-100 hover:bg-blue-50 hover:text-blue-700 text-gray-700 transition-colors"
              title={t.description}>
              {t.name}
            </button>
          ))}
        </div>
      </div>

      <div className="card p-5 mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-2">Raw Email or Email Content</label>
        <textarea value={raw} onChange={(e) => setRaw(e.target.value)} rows={12}
          className="input font-mono text-sm"
          placeholder="Paste any raw email (with headers) or email body text here..." />
        <div className="flex gap-3 mt-3">
          <button onClick={handleScan} disabled={scanning || !raw.trim()} className="btn btn-primary disabled:opacity-50">
            {scanning ? 'Scanning...' : 'Scan Email'}
          </button>
          <button onClick={() => { setRaw(''); setResult(null); setParsedInfo(null); setSavedId(null); }} className="btn btn-ghost">Clear</button>
        </div>
        {error && <div className="mt-3 text-sm text-red-600">{error}</div>}
      </div>

      {result && (
        <div className="space-y-6">
          {result.risk_level !== 'safe' && (
            <div className={`card p-4 border-l-4 ${result.risk_level === 'malicious' ? 'border-l-red-700 bg-red-50' : 'border-l-red-500 bg-red-50'}`}>
              <div className="flex items-center gap-3">
                <svg className="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <div>
                  <h3 className="font-bold text-red-900">
                    {result.risk_level === 'malicious' ? 'MALICIOUS EMAIL DETECTED!' : 'PHISHING EMAIL DETECTED!'}
                  </h3>
                  <p className="text-sm text-red-700 mt-0.5">
                    This email has been flagged as {result.risk_level === 'malicious' ? 'malicious' : 'phishing'} and auto-quarantined.
                    An alert has been sent. Do not click any links or reply to this email.
                  </p>
                </div>
              </div>
            </div>
          )}

          <div className="card p-6">
            <div className="flex items-center gap-8">
              <ScoreGauge score={result.risk_score} level={result.risk_level} />
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Scan Results</h3>
                {parsedInfo && (
                  <div className="space-y-1 text-sm text-gray-600">
                    <div><span className="font-medium">From:</span> {parsedInfo.sender}</div>
                    <div><span className="font-medium">Subject:</span> {parsedInfo.subject}</div>
                    <div><span className="font-medium">URLs found:</span> {result.urls.length}</div>
                    <div><span className="font-medium">Findings:</span> {result.findings.length}</div>
                  </div>
                )}
                <div className="mt-3 flex items-center gap-3">
                  <RiskBadge level={result.risk_level} score={result.risk_score} />
                  {savedId && <a href={`/emails/${savedId}`} className="text-sm text-blue-600 hover:underline">View saved email &rarr;</a>}
                </div>
              </div>
            </div>
          </div>

          <div className="card p-6">
            <h3 className="font-semibold text-gray-900 mb-4">Detection Findings ({result.findings.length})</h3>
            {result.findings.length === 0 ? (
              <p className="text-gray-400 text-sm">No threats detected.</p>
            ) : (
              <div className="space-y-2">
                {result.findings.map((f, i) => (
                  <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-gray-50">
                    <SeverityDot severity={f.severity} />
                    <div className="flex-1">
                      <div className="text-sm font-medium text-gray-900">{f.engine}</div>
                      <div className="text-sm text-gray-600">{f.description}</div>
                    </div>
                    {f.score > 0 && <span className="text-sm font-semibold text-gray-700">+{f.score}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>

          {result.vt_results.map((vt, i) => (
            <div key={i}>
              <div className="mb-2 text-sm text-gray-600">
                <span className="font-medium">URL:</span>{' '}
                <a href={vt.url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline break-all">{vt.url}</a>
              </div>
              <VirusTotalTable vendors={vt.vendors} maliciousCount={vt.malicious_count} totalEngines={vt.total_engines} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
