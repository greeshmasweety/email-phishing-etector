export type Classification = 'safe' | 'suspicious' | 'phishing';

export interface UrlAnalysis {
  url: string;
  domain: string;
  scheme: string;
  isHttp: boolean;
  isIp: boolean;
  isShortened: boolean;
  isPunycode: boolean;
  suspiciousKeywords: string[];
  visibleText: string | null;
  linkTextMismatch: boolean;
  senderDomainMismatch: boolean;
  vtMalicious: number;
  vtSuspicious: number;
  vtHarmless: number;
  vtUndetected: number;
  vtLastScan: string | null;
  vtStatus: string | null;
}

export interface EngineResult {
  engineName: string;
  score: number;
  verdict: string;
  confidence: number;
  reasons: string[];
  evidence: Record<string, unknown>;
  error: string | null;
}

export interface AnalysisResult {
  email: {
    gmail_message_id: string;
    thread_id: string | null;
    message_id_header: string | null;
    sender_name: string | null;
    sender_email: string | null;
    sender_domain: string | null;
    recipient: string | null;
    cc: string | null;
    subject: string | null;
    received_at: string | null;
    reply_to: string | null;
    return_path: string | null;
    auth_results: string | null;
    spf_result: string | null;
    dkim_result: string | null;
    dmarc_result: string | null;
    plain_body: string | null;
    html_body_sanitized: string | null;
    visible_link_texts: string[] | null;
  };
  urls: UrlAnalysis[];
  engines: EngineResult[];
  riskScore: number;
  classification: Classification;
  confidence: number;
  reasons: string[];
  scoreBreakdown: { label: string; points: number; weight: number }[];
}
