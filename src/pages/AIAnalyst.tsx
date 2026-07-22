import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { RiskBadge } from '../components/RiskBadge';
import { analyzeWithAI, AIAnalysis } from '../lib/aiAnalyst';

interface EmailRow {
  id: string;
  sender_email: string;
  sender_name: string | null;
  subject: string;
  risk_score: number;
  classification: string;
  received_at: string | null;
  plain_body: string | null;
}

interface DetectionRow {
  engine_name: string;
  score: number;
  verdict: string;
  reasons: { description: string; severity: string }[];
}

interface UrlRow {
  url: string;
  domain: string | null;
  is_ip: boolean;
  link_text_mismatch: boolean;
  vt_malicious: number;
  vt_harmless: number;
  vt_vendors: { engine_name: string; category: string; result: string; is_malicious: boolean }[] | null;
}

export default function AIAnalyst() {
  const [emails, setEmails] = useState<EmailRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState('');
  const [savedAnalyses, setSavedAnalyses] = useState<Record<string, AIAnalysis>>({});

  useEffect(() => {
    supabase
      .from('emails')
      .select('id, sender_email, sender_name, subject, risk_score, classification, received_at, plain_body')
      .order('received_at', { ascending: false })
      .limit(50)
      .then(({ data }) => {
        setEmails(data || []);
        setLoading(false);
      });

    supabase
      .from('ai_analyses')
      .select('email_id, analysis')
      .then(({ data }) => {
        const map: Record<string, AIAnalysis> = {};
        (data || []).forEach((r: any) => { map[r.email_id] = r.analysis; });
        setSavedAnalyses(map);
      });
  }, []);

  async function runAnalysis(emailId: string) {
    setSelectedId(emailId);
    setAnalysis(null);
    setError('');
    setAnalyzing(true);
    try {
      const email = emails.find((e) => e.id === emailId);
      if (!email) throw new Error('Email not found');

      const [detRes, urlRes] = await Promise.all([
        supabase.from('detections').select('*').eq('email_id', emailId).order('score', { ascending: false }),
        supabase.from('email_urls').select('*').eq('email_id', emailId),
      ]);

      const detections: DetectionRow[] = detRes.data || [];
      const urls: UrlRow[] = urlRes.data || [];

      const result = await analyzeWithAI({
        email_id: emailId,
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

      setAnalysis(result);
      setSavedAnalyses({ ...savedAnalyses, [emailId]: result });

      await supabase.from('ai_analyses').upsert({
        email_id: emailId,
        analysis: result,
        summary: result.summary,
        risk_assessment: result.risk_assessment,
        recommendations: result.recommendations,
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setAnalyzing(false);
    }
  }

  const threatEmails = emails.filter((e) => e.classification !== 'safe');

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">AI Security Analyst</h1>
        <p className="text-gray-500 mt-1">AI-powered deep analysis of email threats with recommendations</p>
      </div>

      <div className="card p-6 mb-6 border-l-4 border-l-blue-500">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-lg bg-blue-50 flex items-center justify-center flex-shrink-0">
            <svg className="w-7 h-7 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
          </div>
          <div>
            <h3 className="font-semibold text-gray-900">How it works</h3>
            <p className="text-sm text-gray-600 mt-1">
              The AI Security Analyst examines email content, headers, URLs, and VirusTotal results to produce a
              comprehensive threat assessment. It identifies attack vectors, targeted brands, and provides actionable
              recommendations. Select an email below to run a full AI analysis.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-1">
          <div className="card p-4">
            <h3 className="font-semibold text-gray-900 mb-3">Threat Emails ({threatEmails.length})</h3>
            {loading ? (
              <div className="text-center text-gray-400 py-8">Loading...</div>
            ) : threatEmails.length === 0 ? (
              <div className="text-center text-gray-400 py-8">No threats found</div>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {threatEmails.map((e) => (
                  <button key={e.id} onClick={() => runAnalysis(e.id)}
                    className={`w-full text-left p-3 rounded-lg border transition-colors ${
                      selectedId === e.id ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:bg-gray-50'
                    }`}>
                    <div className="flex items-center justify-between mb-1">
                      <RiskBadge level={e.classification as any} score={e.risk_score} />
                      {savedAnalyses[e.id] && <span className="badge bg-blue-100 text-blue-800">Analyzed</span>}
                    </div>
                    <div className="text-sm font-medium text-gray-900 truncate">{e.subject}</div>
                    <div className="text-xs text-gray-500 truncate">{e.sender_email}</div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="col-span-2">
          {error && <div className="card p-4 mb-4 bg-red-50 text-red-700 text-sm">{error}</div>}

          {analyzing && (
            <div className="card p-12 text-center">
              <div className="inline-block w-8 h-8 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin mb-4"></div>
              <p className="text-gray-600">AI Analyst is examining the email...</p>
            </div>
          )}

          {analysis && !analyzing && (
            <div className="card p-6 border-l-4 border-l-blue-500">
              <div className="flex items-center gap-2 mb-4">
                <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
                <h3 className="font-semibold text-gray-900">AI Analysis Report</h3>
              </div>

              <div className="space-y-5">
                <div>
                  <div className="text-sm font-medium text-gray-700 mb-1">Executive Summary</div>
                  <p className="text-sm text-gray-600">{analysis.summary}</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <Field label="Threat Type" value={analysis.threat_type} />
                  <Field label="Attack Vector" value={analysis.attack_vector} />
                  <Field label="Targeted Brand" value={analysis.targeted_brand || 'Unknown'} />
                  <Field label="Confidence" value={`${(analysis.confidence * 100).toFixed(0)}%`} />
                </div>

                <div>
                  <div className="text-sm font-medium text-gray-700 mb-1">Risk Assessment</div>
                  <p className="text-sm text-gray-600">{analysis.risk_assessment}</p>
                </div>

                <div>
                  <div className="text-sm font-medium text-gray-700 mb-1">User Action Required</div>
                  <div className="p-3 rounded-lg bg-red-50 border border-red-200">
                    <p className="text-sm text-red-800">{analysis.user_action_required}</p>
                  </div>
                </div>

                <div>
                  <div className="text-sm font-medium text-gray-700 mb-2">Recommendations</div>
                  <ul className="space-y-2">
                    {analysis.recommendations.map((r, i) => (
                      <li key={i} className="text-sm text-gray-600 flex items-start gap-2 p-2 rounded-lg bg-gray-50">
                        <span className="text-blue-600 font-bold mt-0.5">{i + 1}.</span> {r}
                      </li>
                    ))}
                  </ul>
                </div>

                {analysis.indicators.length > 0 && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Key Threat Indicators</div>
                    <div className="space-y-2">
                      {analysis.indicators.map((ind, i) => (
                        <div key={i} className="flex items-start gap-3 p-2 rounded-lg bg-gray-50">
                          <span className={`badge flex-shrink-0 ${
                            ind.weight === 'high' ? 'bg-red-100 text-red-800' :
                            ind.weight === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-gray-100 text-gray-700'
                          }`}>{ind.weight}</span>
                          <div className="text-sm">
                            <span className="font-medium text-gray-900">{ind.indicator}</span>
                            <span className="text-gray-600"> — {ind.detail}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selectedId && (
                  <Link to={`/emails/${selectedId}`} className="text-sm text-blue-600 hover:underline block">
                    View full email details &rarr;
                  </Link>
                )}
              </div>
            </div>
          )}

          {!analysis && !analyzing && !error && (
            <div className="card p-12 text-center">
              <svg className="w-16 h-16 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
              <p className="text-gray-500">Select an email from the list to run AI analysis</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-3 rounded-lg bg-gray-50">
      <div className="text-xs text-gray-400 uppercase mb-1">{label}</div>
      <div className="text-sm text-gray-700">{value}</div>
    </div>
  );
}
