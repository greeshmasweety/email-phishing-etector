import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { RiskBadge, ScoreGauge, SeverityDot } from '../components/RiskBadge';
import VirusTotalTable from '../components/VirusTotalTable';
import { VendorResult } from '../lib/virustotal';
import { analyzeWithAI, AIAnalysis } from '../lib/aiAnalyst';

interface EmailDetail {
  id: string;
  sender_email: string;
  sender_name: string | null;
  subject: string;
  plain_body: string | null;
  html_body_sanitized: string | null;
  risk_score: number;
  classification: string;
  received_at: string | null;
  spf_result: string | null;
  dkim_result: string | null;
  dmarc_result: string | null;
  reply_to: string | null;
  return_path: string | null;
  visible_link_texts: string[] | null;
  status: string;
}

interface DetectionRow {
  id: string;
  engine_name: string;
  score: number;
  verdict: string;
  reasons: { description: string; severity: string }[];
}

interface UrlRow {
  id: string;
  url: string;
  domain: string | null;
  is_ip: boolean;
  is_http: boolean;
  is_shortened: boolean;
  is_punycode: boolean;
  link_text_mismatch: boolean;
  vt_malicious: number;
  vt_harmless: number;
  vt_reputation: number | null;
  vt_vendors: VendorResult[] | null;
  visible_text: string | null;
}

export default function EmailDetail() {
  const { id } = useParams();
  const [email, setEmail] = useState<EmailDetail | null>(null);
  const [detections, setDetections] = useState<DetectionRow[]>([]);
  const [urls, setUrls] = useState<UrlRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState('');

  useEffect(() => {
    if (!id) return;
    Promise.all([
      supabase.from('emails').select('*').eq('id', id).single(),
      supabase.from('detections').select('*').eq('email_id', id).order('score', { ascending: false }),
      supabase.from('email_urls').select('*').eq('email_id', id),
    ]).then(([emailRes, detRes, urlRes]) => {
      setEmail(emailRes.data);
      setDetections(detRes.data || []);
      setUrls(urlRes.data || []);
      setLoading(false);
    });
  }, [id]);

  async function runAIAnalysis() {
    if (!email) return;
    setAiLoading(true);
    setAiError('');
    try {
      const result = await analyzeWithAI({
        email_id: email.id,
        sender_email: email.sender_email,
        sender_name: email.sender_name || undefined,
        subject: email.subject,
        plain_body: email.plain_body || '',
        risk_score: email.risk_score,
        risk_level: email.classification,
        findings: detections.flatMap((d) => (d.reasons || []).map((r) => ({ engine: d.engine_name, severity: r.severity, description: r.description, score: d.score }))),
        urls: urls.map((u) => ({ url: u.url, domain: u.domain || '', is_ip: u.is_ip, mismatch: u.link_text_mismatch })),
        vt_results: urls.map((u) => ({ malicious_count: u.vt_malicious, total_engines: u.vt_malicious + u.vt_harmless, vendors: u.vt_vendors || [] })),
      });
      setAiAnalysis(result);
    } catch (e) {
      setAiError(String(e));
    } finally {
      setAiLoading(false);
    }
  }

  async function handleQuarantine(action: 'quarantined' | 'released' | 'deleted' | 'false_positive') {
    if (!email) return;
    await supabase.from('emails').update({ status: action === 'false_positive' ? 'reviewed' : action }).eq('id', email.id);
    await supabase.from('quarantine_actions').insert({ email_id: email.id, action, reason: `Manual ${action}`, performed_by: 'user' });
    setEmail({ ...email, status: action === 'false_positive' ? 'reviewed' : action });
  }

  if (loading) return <div className="text-center text-gray-400 py-20">Loading...</div>;
  if (!email) return <div className="text-center text-gray-400 py-20">Email not found</div>;

  const findings = detections.flatMap((d) =>
    (d.reasons || []).map((r) => ({ engine: d.engine_name, severity: r.severity, description: r.description, score: d.score }))
  );

  return (
    <div>
      <div className="mb-6">
        <Link to="/emails" className="text-sm text-blue-600 hover:underline mb-2 inline-block">&larr; Back to Emails</Link>
        <h1 className="text-2xl font-bold text-gray-900">{email.subject}</h1>
        <p className="text-gray-500 mt-1">From {email.sender_name ? `${email.sender_name} <${email.sender_email}>` : email.sender_email}</p>
      </div>

      <div className="card p-6 mb-6">
        <div className="flex items-center gap-8">
          <ScoreGauge score={email.risk_score} level={email.classification as any} />
          <div className="flex-1 space-y-2">
            <div className="flex gap-3 items-center">
              <RiskBadge level={email.classification as any} score={email.risk_score} />
              <span className="badge bg-gray-100 text-gray-700">Status: {email.status}</span>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <Info label="Received" value={email.received_at ? new Date(email.received_at).toLocaleString() : '—'} />
              <Info label="SPF" value={email.spf_result || '—'} />
              <Info label="DKIM" value={email.dkim_result || '—'} />
              <Info label="DMARC" value={email.dmarc_result || '—'} />
              <Info label="Reply-To" value={email.reply_to || '—'} />
              <Info label="Return-Path" value={email.return_path || '—'} />
            </div>
            <div className="flex gap-2 mt-3">
              {email.status !== 'quarantined' && <button onClick={() => handleQuarantine('quarantined')} className="btn btn-danger text-sm">Quarantine</button>}
              {email.status === 'quarantined' && <button onClick={() => handleQuarantine('released')} className="btn btn-success text-sm">Release</button>}
              <button onClick={() => handleQuarantine('false_positive')} className="btn btn-ghost text-sm">Mark False Positive</button>
              <button onClick={runAIAnalysis} disabled={aiLoading} className="btn btn-primary text-sm disabled:opacity-50">
                {aiLoading ? 'Analyzing...' : 'Run AI Analysis'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {aiError && <div className="card p-4 mb-6 bg-red-50 text-red-700 text-sm">{aiError}</div>}

      {aiAnalysis && (
        <div className="card p-6 mb-6 border-l-4 border-l-blue-500">
          <div className="flex items-center gap-2 mb-4">
            <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            <h3 className="font-semibold text-gray-900">AI Security Analyst Report</h3>
          </div>
          <div className="space-y-4">
            <div>
              <div className="text-sm font-medium text-gray-700">Summary</div>
              <p className="text-sm text-gray-600 mt-1">{aiAnalysis.summary}</p>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div><div className="text-sm font-medium text-gray-700">Threat Type</div><p className="text-sm text-gray-600 mt-1">{aiAnalysis.threat_type}</p></div>
              <div><div className="text-sm font-medium text-gray-700">Attack Vector</div><p className="text-sm text-gray-600 mt-1">{aiAnalysis.attack_vector}</p></div>
              <div><div className="text-sm font-medium text-gray-700">Targeted Brand</div><p className="text-sm text-gray-600 mt-1">{aiAnalysis.targeted_brand || 'Unknown'}</p></div>
              <div><div className="text-sm font-medium text-gray-700">Confidence</div><p className="text-sm text-gray-600 mt-1">{(aiAnalysis.confidence * 100).toFixed(0)}%</p></div>
            </div>
            <div>
              <div className="text-sm font-medium text-gray-700">Risk Assessment</div>
              <p className="text-sm text-gray-600 mt-1">{aiAnalysis.risk_assessment}</p>
            </div>
            <div>
              <div className="text-sm font-medium text-gray-700">User Action Required</div>
              <p className="text-sm text-gray-600 mt-1">{aiAnalysis.user_action_required}</p>
            </div>
            <div>
              <div className="text-sm font-medium text-gray-700 mb-2">Recommendations</div>
              <ul className="space-y-1">
                {aiAnalysis.recommendations.map((r, i) => (
                  <li key={i} className="text-sm text-gray-600 flex items-start gap-2">
                    <span className="text-blue-600 mt-0.5">→</span> {r}
                  </li>
                ))}
              </ul>
            </div>
            {aiAnalysis.indicators.length > 0 && (
              <div>
                <div className="text-sm font-medium text-gray-700 mb-2">Key Indicators</div>
                <div className="space-y-1">
                  {aiAnalysis.indicators.map((ind, i) => (
                    <div key={i} className="text-sm text-gray-600 flex items-start gap-2">
                      <span className={`badge ${ind.weight === 'high' ? 'bg-red-100 text-red-800' : ind.weight === 'medium' ? 'bg-yellow-100 text-yellow-800' : 'bg-gray-100 text-gray-700'}`}>{ind.weight}</span>
                      <span><span className="font-medium">{ind.indicator}</span>: {ind.detail}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="card p-6 mb-6">
        <h3 className="font-semibold text-gray-900 mb-4">Detection Findings ({findings.length})</h3>
        {findings.length === 0 ? (
          <p className="text-gray-400 text-sm">No threats detected.</p>
        ) : (
          <div className="space-y-2">
            {findings.map((f, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-gray-50">
                <SeverityDot severity={f.severity} />
                <div className="flex-1">
                  <div className="text-sm font-medium text-gray-900">{f.engine}</div>
                  <div className="text-sm text-gray-600">{f.description}</div>
                </div>
                <span className="text-sm font-semibold text-gray-700">+{f.score}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {urls.length > 0 && (
        <div className="space-y-6 mb-6">
          {urls.map((u) => (
            <div key={u.id}>
              <div className="mb-2 text-sm text-gray-600">
                <span className="font-medium">URL:</span>{' '}
                <a href={u.url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline break-all">{u.url}</a>
              </div>
              <VirusTotalTable vendors={u.vt_vendors || []} maliciousCount={u.vt_malicious} totalEngines={u.vt_malicious + u.vt_harmless} />
            </div>
          ))}
        </div>
      )}

      <div className="card p-6">
        <h3 className="font-semibold text-gray-900 mb-4">Email Body</h3>
        <pre className="text-sm text-gray-700 whitespace-pre-wrap font-mono bg-gray-50 p-4 rounded-lg max-h-96 overflow-y-auto">
          {email.plain_body || 'No body content'}
        </pre>
        {email.visible_link_texts && email.visible_link_texts.length > 0 && (
          <div className="mt-4">
            <h4 className="text-sm font-medium text-gray-700 mb-2">Visible Links</h4>
            <ul className="space-y-1">
              {email.visible_link_texts.map((link, i) => (
                <li key={i} className="text-sm text-blue-600 break-all">{link}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-gray-400 uppercase">{label}</div>
      <div className="text-sm text-gray-700">{value}</div>
    </div>
  );
}
