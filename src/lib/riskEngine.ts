import type { Classification, EngineResult, UrlAnalysis } from './types';

export interface RiskResult {
  riskScore: number;
  classification: Classification;
  confidence: number;
  reasons: string[];
  scoreBreakdown: { label: string; points: number; weight: number }[];
}

// Additive evidence model. Each engine contributes its weighted score
// (scaled so the max combined engine contribution reaches ~55), and direct
// URL/header/content indicators add on top. Evidence accumulates — multiple
// corroborating engines push the score higher, not lower.
const ENGINE_WEIGHTS: Record<string, number> = {
  virustotal: 0.30,
  url_analysis: 0.25,
  header_analysis: 0.25,
  ml_classifier: 0.25,
  content_rules: 0.25,
};

// Max possible engine contribution if all 5 engines scored 100:
// 100*(0.30+0.25+0.25+0.25+0.25) = 130. We scale this to 55.
const ENGINE_SCALE = 55 / 130;

export function calculateRisk(
  engines: EngineResult[],
  urls: UrlAnalysis[],
  thresholds: { suspicious: number; phishing: number },
): RiskResult {
  const byName = (name: string) => engines.find((e) => e.engineName === name);
  const vt = byName('virustotal');
  const url = byName('url_analysis');
  const header = byName('header_analysis');
  const ml = byName('ml_classifier');
  const content = byName('content_rules');

  const vtContrib = vt && vt.error !== 'disabled' && vt.error !== 'not_configured'
    ? (vt.score ?? 0) * ENGINE_WEIGHTS.virustotal
    : 0;
  const urlContrib = (url?.score ?? 0) * ENGINE_WEIGHTS.url_analysis;
  const headerContrib = (header?.score ?? 0) * ENGINE_WEIGHTS.header_analysis;
  const mlContrib = (ml?.score ?? 0) * ENGINE_WEIGHTS.ml_classifier;
  const contentContrib = (content?.score ?? 0) * ENGINE_WEIGHTS.content_rules;

  const engineTotal = vtContrib + urlContrib + headerContrib + mlContrib + contentContrib;
  const engineScaled = Math.min(engineTotal * ENGINE_SCALE, 55);

  // Direct additive penalties for concrete URL indicators
  let additive = 0;
  for (const u of urls) {
    if (u.isHttp) additive += 10;
    if (u.isHttp && u.suspiciousKeywords.length > 0) additive += 10;
    if (u.isIp) additive += 15;
    if (u.isShortened) additive += 8;
    if (u.isPunycode) additive += 12;
    if (u.linkTextMismatch) additive += 15;
    if (u.senderDomainMismatch) additive += 10;
    if (u.vtMalicious > 0) additive += Math.min(30, u.vtMalicious * 3);
  }

  // Header-based additive penalties
  if (header?.reasons.some((r) => r.includes('From/Reply-To'))) additive += 10;
  if (header?.reasons.some((r) => r.includes('Display name impersonates'))) additive += 12;
  if (header?.reasons.some((r) => r.includes('typosquatting'))) additive += 12;
  if (header?.reasons.some((r) => r.includes('SPF fail'))) additive += 8;
  if (header?.reasons.some((r) => r.includes('DKIM fail'))) additive += 8;
  if (header?.reasons.some((r) => r.includes('DMARC fail'))) additive += 10;

  // Content-based additive penalties for high-confidence phishing phrases
  if (content?.reasons.some((r) => r.includes('Account suspension'))) additive += 10;
  if (content?.reasons.some((r) => r.includes('Login form'))) additive += 15;
  if (content?.reasons.some((r) => r.includes('Credential harvesting'))) additive += 10;
  if (content?.reasons.some((r) => r.includes('Direct credential'))) additive += 10;
  if (content?.reasons.some((r) => r.includes('Gift-card'))) additive += 15;
  if (content?.reasons.some((r) => r.includes('Wire transfer'))) additive += 10;

  // Corroboration bonus: if 2+ engines flag suspicious/phishing, boost
  const flaggingEngines = [vt, url, header, ml, content].filter(
    (e) => e && e.error !== 'disabled' && e.error !== 'not_configured' && (e!.score >= 20),
  ).length;
  if (flaggingEngines >= 2) additive += 12;
  if (flaggingEngines >= 3) additive += 10;
  if (flaggingEngines >= 4) additive += 8;

  const additiveScaled = Math.min(additive, 100) * 0.5;
  const riskScore = Math.min(Math.round(engineScaled + additiveScaled), 100);

  let classification: Classification = 'safe';
  if (riskScore >= thresholds.phishing) classification = 'phishing';
  else if (riskScore >= thresholds.suspicious) classification = 'suspicious';

  const reasons = engines.flatMap((e) => e.reasons);
  const uniqueReasons = Array.from(new Set(reasons));

  const confidences = [vt, url, header, ml, content]
    .filter((e) => e && e.error !== 'disabled' && e.error !== 'not_configured')
    .map((e) => e!.confidence);
  const confidence = confidences.length > 0
    ? Math.min(1, confidences.reduce((s, c) => s + c, 0) / confidences.length + 0.2)
    : 0.5;

  const scoreBreakdown = [
    { label: 'VirusTotal reputation', points: Math.round(vtContrib * ENGINE_SCALE), weight: ENGINE_WEIGHTS.virustotal },
    { label: 'URL analysis', points: Math.round(urlContrib * ENGINE_SCALE), weight: ENGINE_WEIGHTS.url_analysis },
    { label: 'Header & sender', points: Math.round(headerContrib * ENGINE_SCALE), weight: ENGINE_WEIGHTS.header_analysis },
    { label: 'ML classifier', points: Math.round(mlContrib * ENGINE_SCALE), weight: ENGINE_WEIGHTS.ml_classifier },
    { label: 'Content rules', points: Math.round(contentContrib * ENGINE_SCALE), weight: ENGINE_WEIGHTS.content_rules },
    { label: 'Direct indicators (additive)', points: Math.round(additiveScaled), weight: 0.45 },
  ];

  return { riskScore, classification, confidence, reasons: uniqueReasons, scoreBreakdown };
}
