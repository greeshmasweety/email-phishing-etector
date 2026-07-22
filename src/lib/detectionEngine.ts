import { ExtractedUrl, extractUrls, analyzeUrl, isTyposquat } from './urlAnalyzer';
import { VTResponse, lookupUrl } from './virustotal';

export type RiskLevel = 'safe' | 'suspicious' | 'malicious';

export interface DetectionFinding {
  engine: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  description: string;
  score: number;
}

export interface ScanResult {
  risk_score: number;
  risk_level: RiskLevel;
  findings: DetectionFinding[];
  urls: ExtractedUrl[];
  vt_results: VTResponse[];
  domain: string;
}

const PHISHING_PATTERNS: { pattern: RegExp; name: string; severity: DetectionFinding['severity']; score: number }[] = [
  { pattern: /urgent|immediately|asap|right away|act now|expires? (today|soon|in \d)/i, name: 'Urgency / time pressure language', severity: 'high', score: 20 },
  { pattern: /verify your (account|email|identity|password)|confirm your (account|email|identity)/i, name: 'Account verification request', severity: 'high', score: 22 },
  { pattern: /suspended|deactivated|terminated|disabled|locked|restricted/i, name: 'Account suspension threat', severity: 'high', score: 22 },
  { pattern: /password (has )?expired|password will expire/i, name: 'Password expiry claim', severity: 'high', score: 20 },
  { pattern: /unusual (activity|sign.?in|login)|unauthorized (access|activity|attempt)/i, name: 'Unusual activity alert', severity: 'high', score: 20 },
  { pattern: /click (here|below|the link) (to|and)|follow this link/i, name: 'Generic "click here" prompt', severity: 'medium', score: 15 },
  { pattern: /update your (payment|billing|card|information|details)/i, name: 'Payment info update request', severity: 'high', score: 22 },
  { pattern: /you(?:'ve| have) (won|been selected|qualified for)/i, name: 'Prize / lottery claim', severity: 'high', score: 25 },
  { pattern: /wire transfer|western union|moneygram|gift card|bitcoin|crypto(?:currency)? payment/i, name: 'Wire/crypto payment request', severity: 'high', score: 22 },
  { pattern: /invoice|purchase|order|receipt|statement (attached|due|overdue)/i, name: 'Fake invoice / billing document', severity: 'medium', score: 16 },
  { pattern: /dear (customer|user|valued|sir|madam|account holder)/i, name: 'Generic greeting (no name)', severity: 'medium', score: 12 },
  { pattern: /IRS|tax (refund|return|payment)|social security|SSN/i, name: 'Tax/SSN reference', severity: 'high', score: 20 },
  { pattern: /bank of (america|america|the west)|chase|wells fargo|citibank|paypal|apple id|microsoft (account|365)|google (account|workspace)/i, name: 'Brand impersonation reference', severity: 'medium', score: 15 },
  { pattern: /security (alert|warning|notice|update)|important (security|notice|update|message)/i, name: 'Security alert framing', severity: 'medium', score: 15 },
  { pattern: /login|sign in|account (login|sign in)|portal/i, name: 'Login page reference', severity: 'medium', score: 10 },
  { pattern: /reset your password|password reset|change your password/i, name: 'Password reset request', severity: 'high', score: 18 },
  { pattern: /package (delivery|pending|waiting)|shipment|tracking number|UPS|FedEx|DHL|USPS/i, name: 'Package delivery scam', severity: 'medium', score: 16 },
  { pattern: /meeting (invite|request|attachment)|shared document|view document|open document/i, name: 'Document sharing lure', severity: 'medium', score: 15 },
  { pattern: /hr|payroll|benefits|direct deposit|salary update/i, name: 'HR/payroll lure', severity: 'medium', score: 15 },
  { pattern: /limited time|offer expires|today only|final (notice|reminder|warning)/i, name: 'Limited-time pressure', severity: 'high', score: 18 },
  { pattern: /do not reply|noreply|no-reply/i, name: 'No-reply sender', severity: 'low', score: 8 },
  { pattern: /kindly|please kindly|we kindly/i, name: '"Kindly" phrasing', severity: 'medium', score: 10 },
  { pattern: /discrepancy|reconciliation|payment (is )?pending|outstanding balance/i, name: 'Business payment discrepancy', severity: 'medium', score: 15 },
  { pattern: /download (the )?(attachment|file|report|document)/i, name: 'Attachment download prompt', severity: 'medium', score: 12 },
];

export async function scanEmail(params: {
  sender_email: string;
  sender_name?: string;
  subject: string;
  plain_body: string;
  html_body?: string;
  spf?: string;
  dkim?: string;
  dmarc?: string;
  reply_to?: string;
  return_path?: string;
}): Promise<ScanResult> {
  const findings: DetectionFinding[] = [];
  let score = 0;

  const spf = params.spf?.toLowerCase() || '';
  const dkim = params.dkim?.toLowerCase() || '';
  const dmarc = params.dmarc?.toLowerCase() || '';

  if (spf === 'fail' || spf === 'softfail') {
    findings.push({ engine: 'Header Analysis', severity: 'critical', description: `SPF ${spf.toUpperCase()} — sender IP not authorized`, score: 30 });
    score += 30;
  } else if (spf === 'none' || !spf) {
    findings.push({ engine: 'Header Analysis', severity: 'medium', description: 'SPF not configured (none)', score: 12 });
    score += 12;
  }

  if (dkim === 'fail' || dkim === 'none' || !dkim) {
    findings.push({ engine: 'Header Analysis', severity: 'medium', description: 'DKIM missing or failed', score: 14 });
    score += 14;
  }

  if (dmarc === 'fail' || dmarc === 'none' || !dmarc) {
    findings.push({ engine: 'Header Analysis', severity: 'medium', description: 'DMARC not enforced', score: 12 });
    score += 12;
  }

  if (params.reply_to && params.reply_to !== params.sender_email) {
    findings.push({ engine: 'Header Analysis', severity: 'critical', description: `Reply-To (${params.reply_to}) differs from sender`, score: 25 });
    score += 25;
  }
  if (params.return_path && params.return_path !== params.sender_email) {
    findings.push({ engine: 'Header Analysis', severity: 'medium', description: `Return-Path differs from sender`, score: 12 });
    score += 12;
  }

  const senderDomain = params.sender_email.split('@')[1] || '';
  const typo = isTyposquat(senderDomain);
  if (typo) {
    findings.push({ engine: 'Domain Analysis', severity: 'critical', description: `Sender domain "${senderDomain}" mimics "${typo}"`, score: 35 });
    score += 35;
  }

  const fullText = `${params.subject} ${params.plain_body}`;
  for (const p of PHISHING_PATTERNS) {
    if (p.pattern.test(fullText)) {
      findings.push({ engine: 'Content Analysis', severity: p.severity, description: p.name, score: p.score });
      score += p.score;
    }
  }

  const urls = extractUrls(params.html_body || '', params.plain_body || '');
  for (const u of urls) {
    if (u.is_ip) { findings.push({ engine: 'URL Analysis', severity: 'critical', description: `Link uses raw IP: ${u.domain}`, score: 28 }); score += 28; }
    if (u.uses_http) { findings.push({ engine: 'URL Analysis', severity: 'medium', description: `Insecure HTTP link: ${u.domain}`, score: 12 }); score += 12; }
    if (u.mismatch) { findings.push({ engine: 'URL Analysis', severity: 'critical', description: `Link text "${u.display_text}" hides different URL`, score: 30 }); score += 30; }
    if (u.is_shortened) { findings.push({ engine: 'URL Analysis', severity: 'medium', description: `Shortened URL: ${u.domain}`, score: 14 }); score += 14; }
    if (u.has_punycode) { findings.push({ engine: 'URL Analysis', severity: 'high', description: `Punycode/IDN domain: ${u.domain}`, score: 20 }); score += 20; }
    if (u.has_suspicious_tld) { findings.push({ engine: 'URL Analysis', severity: 'medium', description: `Suspicious TLD in ${u.domain}`, score: 12 }); score += 12; }
    if (u.has_at_sign) { findings.push({ engine: 'URL Analysis', severity: 'high', description: `URL contains @ symbol: ${u.url}`, score: 18 }); score += 18; }
    if (u.has_subdomain_excess) { findings.push({ engine: 'URL Analysis', severity: 'medium', description: `Excessive subdomains in ${u.domain}`, score: 10 }); score += 10; }
    if (u.port) { findings.push({ engine: 'URL Analysis', severity: 'medium', description: `Non-standard port :${u.port}`, score: 10 }); score += 10; }
  }

  const vtResults: VTResponse[] = [];
  const uniqueUrls = [...new Set(urls.map((u) => u.url))].slice(0, 5);
  if (uniqueUrls.length > 0) {
    const vtPromises = uniqueUrls.map((u) => lookupUrl(u).catch((e) => ({
      url: u, malicious_count: 0, total_engines: 0, vendors: [], reputation: null, error: String(e),
    } as VTResponse)));
    const settled = await Promise.all(vtPromises);
    vtResults.push(...settled);

    for (const vt of vtResults) {
      if (vt.malicious_count > 0) {
        const vtScore = Math.min(70, vt.malicious_count * 10);
        findings.push({
          engine: 'VirusTotal',
          severity: vt.malicious_count >= 3 ? 'critical' : 'high',
          description: `${vt.malicious_count}/${vt.total_engines} security vendors flagged this URL as malicious`,
          score: vtScore,
        });
        score += vtScore;
        const maliciousVendors = vt.vendors.filter((v) => v.is_malicious).slice(0, 5);
        for (const v of maliciousVendors) {
          findings.push({ engine: `VirusTotal — ${v.engine_name}`, severity: 'high', description: `${v.engine_name}: ${v.result || v.category}`, score: 0 });
        }
      } else if (vt.total_engines > 0) {
        findings.push({ engine: 'VirusTotal', severity: 'info', description: `0/${vt.total_engines} vendors flagged — URL appears clean on VirusTotal`, score: 0 });
      }
      if (vt.reputation !== null && vt.reputation < 0) {
        const repScore = Math.min(20, Math.abs(vt.reputation));
        findings.push({ engine: 'VirusTotal', severity: 'medium', description: `Negative reputation score: ${vt.reputation}`, score: repScore });
        score += repScore;
      }
    }
  }

  const highSeverityCount = findings.filter((f) => f.severity === 'high' || f.severity === 'critical').length;
  if (highSeverityCount >= 3) {
    findings.push({ engine: 'ML Heuristic', severity: 'critical', description: `${highSeverityCount} high-severity indicators — strong phishing pattern`, score: 20 });
    score += 20;
  } else if (highSeverityCount >= 1) {
    findings.push({ engine: 'ML Heuristic', severity: 'medium', description: `${highSeverityCount} high-severity indicator(s) detected`, score: 12 });
    score += 12;
  }

  score = Math.min(100, score);

  let risk_level: RiskLevel = 'safe';
  if (score >= 40) risk_level = 'malicious';
  else if (score >= 15) risk_level = 'suspicious';

  const hasHighSeverity = findings.some((f) => f.severity === 'high' || f.severity === 'critical');
  if (hasHighSeverity && risk_level === 'safe') risk_level = 'suspicious';

  return { risk_score: score, risk_level, findings, urls, vt_results: vtResults, domain: senderDomain };
}

export async function scanSingleUrl(url: string): Promise<ScanResult> {
  const u = analyzeUrl(url, url);
  const findings: DetectionFinding[] = [];
  let score = 0;

  if (u.is_ip) { findings.push({ engine: 'URL Analysis', severity: 'critical', description: `Raw IP address: ${u.domain}`, score: 28 }); score += 28; }
  if (u.uses_http) { findings.push({ engine: 'URL Analysis', severity: 'medium', description: 'Insecure HTTP', score: 12 }); score += 12; }
  if (u.is_shortened) { findings.push({ engine: 'URL Analysis', severity: 'medium', description: `Shortened URL: ${u.domain}`, score: 14 }); score += 14; }
  if (u.has_punycode) { findings.push({ engine: 'URL Analysis', severity: 'high', description: `Punycode domain: ${u.domain}`, score: 20 }); score += 20; }
  if (u.has_suspicious_tld) { findings.push({ engine: 'URL Analysis', severity: 'medium', description: `Suspicious TLD`, score: 12 }); score += 12; }
  if (u.has_subdomain_excess) { findings.push({ engine: 'URL Analysis', severity: 'medium', description: 'Excessive subdomains', score: 10 }); score += 10; }

  const typo = isTyposquat(u.domain);
  if (typo) { findings.push({ engine: 'Domain Analysis', severity: 'critical', description: `Domain mimics "${typo}"`, score: 35 }); score += 35; }

  const vt = await lookupUrl(url).catch((e) => ({
    url, malicious_count: 0, total_engines: 0, vendors: [], reputation: null, error: String(e),
  } as VTResponse));

  const vtResults = [vt];
  if (vt.malicious_count > 0) {
    const vtScore = Math.min(70, vt.malicious_count * 10);
    findings.push({ engine: 'VirusTotal', severity: vt.malicious_count >= 3 ? 'critical' : 'high', description: `${vt.malicious_count}/${vt.total_engines} security vendors flagged this URL`, score: vtScore });
    score += vtScore;
    const maliciousVendors = vt.vendors.filter((v) => v.is_malicious).slice(0, 5);
    for (const v of maliciousVendors) {
      findings.push({ engine: `VirusTotal — ${v.engine_name}`, severity: 'high', description: `${v.engine_name}: ${v.result || v.category}`, score: 0 });
    }
  } else if (vt.total_engines > 0) {
    findings.push({ engine: 'VirusTotal', severity: 'info', description: `0/${vt.total_engines} vendors flagged — clean on VirusTotal`, score: 0 });
  }
  if (vt.reputation !== null && vt.reputation < 0) {
    const repScore = Math.min(20, Math.abs(vt.reputation));
    findings.push({ engine: 'VirusTotal', severity: 'medium', description: `Negative reputation: ${vt.reputation}`, score: repScore });
    score += repScore;
  }

  score = Math.min(100, score);
  let risk_level: RiskLevel = 'safe';
  if (score >= 40) risk_level = 'malicious';
  else if (score >= 15) risk_level = 'suspicious';

  const hasHighSeverity = findings.some((f) => f.severity === 'high' || f.severity === 'critical');
  if (hasHighSeverity && risk_level === 'safe') risk_level = 'suspicious';

  return { risk_score: score, risk_level, findings, urls: [u], vt_results: vtResults, domain: u.domain };
}
