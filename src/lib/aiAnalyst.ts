import { SUPABASE_URL } from './supabase';

export interface AIAnalysis {
  email_id: string;
  summary: string;
  risk_assessment: string;
  threat_type: string;
  confidence: number;
  recommendations: string[];
  indicators: { indicator: string; weight: string; detail: string }[];
  attack_vector: string;
  targeted_brand: string | null;
  user_action_required: string;
}

export async function analyzeWithAI(emailData: {
  email_id?: string;
  sender_email: string;
  sender_name?: string;
  subject: string;
  plain_body: string;
  risk_score: number;
  risk_level: string;
  findings: { engine: string; severity: string; description: string; score: number }[];
  urls: { url: string; domain: string; is_ip: boolean; mismatch: boolean }[];
  vt_results: { malicious_count: number; total_engines: number; vendors: { engine_name: string; category: string; result: string; is_malicious: boolean }[] }[];
}): Promise<AIAnalysis> {
  const fnUrl = `${SUPABASE_URL}/functions/v1/ai-security-analyst`;
  const resp = await fetch(fnUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(emailData),
  });

  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`AI analysis failed: HTTP ${resp.status}: ${txt}`);
  }

  const data = await resp.json();
  if (data.error) throw new Error(data.error);
  return data as AIAnalysis;
}
