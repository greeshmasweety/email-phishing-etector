import type { ParsedEmail } from './emailParser';
import type { UrlAnalysis, EngineResult } from './types';

const TRUSTED_BRANDS: { name: string; domains: string[] }[] = [
  { name: 'microsoft', domains: ['microsoft.com', 'outlook.com', 'live.com', 'office.com', 'microsoftonline.com'] },
  { name: 'google', domains: ['google.com', 'gmail.com'] },
  { name: 'paypal', domains: ['paypal.com'] },
  { name: 'amazon', domains: ['amazon.com'] },
  { name: 'apple', domains: ['apple.com', 'icloud.com'] },
  { name: 'facebook', domains: ['facebook.com'] },
  { name: 'netflix', domains: ['netflix.com'] },
  { name: 'linkedin', domains: ['linkedin.com'] },
  { name: 'bank of america', domains: ['bankofamerica.com'] },
  { name: 'chase', domains: ['chase.com'] },
];

const PHRASES = [
  { regex: /account.{0,12}(suspend|suspended|locked|restricted|disabled)/i, reason: 'Account suspension threat', points: 14 },
  { regex: /verify your account/i, reason: 'Account verification request', points: 12 },
  { regex: /password.{0,12}(expire|expired|reset|update|change)/i, reason: 'Password expiry/reset pressure', points: 12 },
  { regex: /unusual.{0,8}(login|activity|sign-?in|access)/i, reason: 'Unusual login alert', points: 10 },
  { regex: /click (here|below|immediately|now|the link|this link)/i, reason: 'Urgent click directive', points: 8 },
  { regex: /confirm your identity/i, reason: 'Identity confirmation request', points: 10 },
  { regex: /payment (failed|declined|pending|on hold)/i, reason: 'Payment failure pressure', points: 10 },
  { regex: /refund (available|pending|processing|approved)/i, reason: 'Refund bait', points: 8 },
  { regex: /update (your )?(banking|bank|payment|card) (details|info|information)/i, reason: 'Banking detail update request', points: 12 },
  { regex: /gift.?card/i, reason: 'Gift-card fraud pattern', points: 22 },
  { regex: /(bitcoin|crypto|wallet|usdt) (payment|transfer|deposit|send)/i, reason: 'Cryptocurrency payment request', points: 10 },
  { regex: /(one.?time|otp|verification) (code|password|pin)/i, reason: 'OTP/verification code request', points: 8 },
  { regex: /(legal action|lawsuit|court proceeding|warrant|arrest)/i, reason: 'Legal threat', points: 10 },
  { regex: /account (closure|termination|deactivation|delete)/i, reason: 'Account closure warning', points: 10 },
  { regex: /invoice attached|see attached invoice|invoice #/i, reason: 'Invoice attachment lure', points: 8 },
  { regex: /(security alert|suspicious activity|unusual activity).{0,20}(account|login|sign)/i, reason: 'Fake security alert', points: 10 },
  { regex: /(immediately|urgent|within \d+ hours|24 hours|today only|before it.s too late|final (notice|warning|reminder)|asap|right away)/i, reason: 'False urgency', points: 10 },
  { regex: /(enter|provide|submit) your (password|credentials|login|account)/i, reason: 'Credential harvesting request', points: 14 },
  { regex: /(re-?activate|reactivate|unlock|restore).{0,12}account/i, reason: 'Account reactivation lure', points: 10 },
  { regex: /(dear (customer|user|valued|sir|madam|account holder))/i, reason: 'Generic impersonal greeting', points: 6 },
  { regex: /(ssn|social security|date of birth|full name|address).{0,20}(required|needed|verify|confirm)/i, reason: 'Personal information request', points: 12 },
  { regex: /(your (account|mailbox|inbox|storage|quota).{0,15}(full|exceeded|almost full|reaching))/i, reason: 'Storage/quota scam', points: 10 },
  { regex: /(wire|transfer|ach|payment).{0,15}(pending|requested|required|urgent)/i, reason: 'Wire transfer fraud', points: 12 },
  { regex: /(we (detected|noticed|observed).{0,20}(unusual|suspicious|unauthorized))/i, reason: 'Fake detection notice', points: 10 },
];

function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function isTyposquat(candidate: string, legitimate: string): boolean {
  if (candidate === legitimate) return false;
  if (Math.abs(candidate.length - legitimate.length) > 3) return false;
  const dist = editDistance(candidate, legitimate);
  return dist > 0 && dist <= 2;
}

export function contentRuleEngine(parsed: ParsedEmail): EngineResult {
  const reasons: string[] = [];
  let score = 0;
  const text = `${parsed.subject || ''}\n${parsed.plainBody || ''}\n${parsed.htmlBody || ''}`;

  for (const { regex, reason, points } of PHRASES) {
    if (regex.test(text)) {
      reasons.push(reason);
      score += points;
    }
  }

  // Excessive capital letters
  const caps = (text.match(/[A-Z]/g) || []).length;
  const letters = (text.match(/[A-Za-z]/g) || []).length;
  if (letters > 40 && caps / letters > 0.4) {
    reasons.push('Excessive capital letters');
    score += 8;
  }

  const exclam = (text.match(/!/g) || []).length;
  if (exclam >= 3) {
    reasons.push('Excessive exclamation marks');
    score += 6;
  }

  if (parsed.htmlBody && /<form/i.test(parsed.htmlBody) && /password|login|account|verify|email/i.test(parsed.htmlBody)) {
    reasons.push('Login form embedded in HTML');
    score += 16;
  }

  // Credential/password request anywhere in body
  if (/(enter|provide|submit|send|reply with|give us) (your )?(password|credentials|login details|account details|credit card|card number|cvv|pin)/i.test(text)) {
    reasons.push('Direct credential/financial request');
    score += 14;
  }

  // Multiple phishing phrases compound — bonus for 3+ matches
  if (reasons.length >= 3) {
    reasons.push('Multiple phishing indicators (corroborating)');
    score += 10;
  }
  if (reasons.length >= 5) {
    score += 8;
  }

  score = Math.min(score, 100);
  return {
    engineName: 'content_rules',
    score,
    verdict: score >= 50 ? 'phishing' : score >= 25 ? 'suspicious' : 'clean',
    confidence: Math.min(score / 100, 1),
    reasons,
    evidence: { phraseMatches: reasons.length, capsRatio: letters > 0 ? caps / letters : 0, exclamationCount: exclam },
    error: null,
  };
}

export function headerAnalysisEngine(parsed: ParsedEmail): EngineResult {
  const reasons: string[] = [];
  let score = 0;

  if (parsed.spf === 'fail' || parsed.spf === 'softfail') {
    reasons.push(`SPF ${parsed.spf}`);
    score += 8;
  } else if (parsed.spf === 'neutral' || parsed.spf === 'none') {
    if (parsed.spf === 'none') {
      reasons.push('SPF missing');
      score += 4;
    }
  }

  if (parsed.dkim === 'fail' || parsed.dkim === 'none') {
    reasons.push(parsed.dkim === 'fail' ? 'DKIM fail' : 'DKIM missing');
    score += parsed.dkim === 'fail' ? 8 : 4;
  }

  if (parsed.dmarc === 'fail' || parsed.dmarc === 'none') {
    reasons.push(parsed.dmarc === 'fail' ? 'DMARC fail' : 'DMARC missing');
    score += parsed.dmarc === 'fail' ? 10 : 4;
  }

  if (parsed.fromDomain && parsed.replyTo) {
    const replyDomain = parsed.replyTo.split('@')[1]?.toLowerCase();
    if (replyDomain && replyDomain !== parsed.fromDomain) {
      reasons.push(`From/Reply-To domain mismatch (${parsed.fromDomain} vs ${replyDomain})`);
      score += 10;
    }
  }

  if (parsed.fromDomain && parsed.returnPath) {
    const returnDomain = parsed.returnPath.split('@')[1]?.toLowerCase();
    if (returnDomain && returnDomain !== parsed.fromDomain) {
      reasons.push(`From/Return-Path domain mismatch`);
      score += 6;
    }
  }

  // Display-name spoofing: brand name in From display name but domain not the brand's
  if (parsed.fromName && parsed.fromDomain) {
    const nameLower = parsed.fromName.toLowerCase();
    for (const brand of TRUSTED_BRANDS) {
      if (nameLower.includes(brand.name)) {
        if (!brand.domains.includes(parsed.fromDomain)) {
          reasons.push(`Display name impersonates "${brand.name}" but domain is ${parsed.fromDomain}`);
          score += 12;
        }
      }
    }
  }

  // Typosquatting of sender domain against trusted brands
  if (parsed.fromDomain) {
    for (const brand of TRUSTED_BRANDS) {
      for (const legit of brand.domains) {
        const candidate = parsed.fromDomain.split('.')[0];
        const legitPart = legit.split('.')[0];
        if (isTyposquat(candidate, legitPart)) {
          reasons.push(`Sender domain "${parsed.fromDomain}" resembles "${legit}" (typosquatting)`);
          score += 12;
          break;
        }
      }
    }
  }

  if (parsed.fromDomain && /xn--/i.test(parsed.fromDomain)) {
    reasons.push('Punycode sender domain');
    score += 8;
  }

  score = Math.min(score, 100);
  return {
    engineName: 'header_analysis',
    score,
    verdict: score >= 50 ? 'phishing' : score >= 25 ? 'suspicious' : 'clean',
    confidence: Math.min(score / 100, 1),
    reasons,
    evidence: {
      spf: parsed.spf, dkim: parsed.dkim, dmarc: parsed.dmarc,
      fromDomain: parsed.fromDomain, replyTo: parsed.replyTo, returnPath: parsed.returnPath,
    },
    error: null,
  };
}

export function urlAnalysisEngine(urls: UrlAnalysis[], senderDomain: string | null): EngineResult {
  const reasons: string[] = [];
  let score = 0;

  for (const u of urls) {
    if (u.isHttp) {
      reasons.push(`HTTP URL (no encryption): ${u.url}`);
      score += 10;
      if (u.suspiciousKeywords.length > 0) {
        reasons.push(`HTTP URL with sensitive keywords (${u.suspiciousKeywords.join(', ')})`);
        score += 10;
      }
    }
    if (u.isIp) {
      reasons.push(`IP-address URL: ${u.url}`);
      score += 15;
    }
    if (u.isShortened) {
      reasons.push(`Shortened URL: ${u.url}`);
      score += 8;
    }
    if (u.isPunycode) {
      reasons.push(`Punycode URL: ${u.url}`);
      score += 12;
    }
    if (u.linkTextMismatch) {
      reasons.push(`Link text "${u.visibleText}" does not match destination`);
      score += 15;
    }
    if (u.senderDomainMismatch) {
      reasons.push(`URL domain ${u.domain} mismatches sender domain ${senderDomain}`);
      score += 10;
    }
    if (u.vtMalicious > 0) {
      const add = Math.min(30, u.vtMalicious * 3);
      reasons.push(`VirusTotal: ${u.vtMalicious} malicious reports`);
      score += add;
    }
  }

  score = Math.min(score, 100);
  return {
    engineName: 'url_analysis',
    score,
    verdict: score >= 50 ? 'phishing' : score >= 25 ? 'suspicious' : 'clean',
    confidence: Math.min(score / 100, 1),
    reasons,
    evidence: { urlCount: urls.length, httpCount: urls.filter((u) => u.isHttp).length },
    error: null,
  };
}

export function mlHeuristicEngine(
  parsed: ParsedEmail,
  urls: UrlAnalysis[],
  contentScore: number,
  headerScore: number,
  urlScore: number,
): EngineResult {
  // Lightweight heuristic standing in for the TF-IDF + Logistic Regression model.
  // Combines lexical phishing signals + structural features into a pseudo-probability.
  const text = `${parsed.subject || ''} ${parsed.plainBody || ''}`.toLowerCase();
  const phishingVocab = ['account', 'verify', 'suspend', 'suspended', 'password', 'login', 'secure', 'update', 'confirm', 'bank', 'urgent', 'click', 'immediately', 'credential', 'identity', 'locked', 'restricted', 'deactivate', 'closure', 'warning', 'alert', 'unusual', 'suspicious', 'reset', 'reactivate', 'unlock'];
  const hits = phishingVocab.reduce((acc, w) => acc + (text.includes(w) ? 1 : 0), 0);
  const lexicalProb = Math.min(hits / 10, 1);

  const httpCount = urls.filter((u) => u.isHttp).length;
  const mismatchCount = urls.filter((u) => u.linkTextMismatch || u.senderDomainMismatch).length;
  const structuralProb = Math.min((httpCount * 0.3 + mismatchCount * 0.4 + (urls.some((u) => u.isIp) ? 0.3 : 0)), 1);

  const authFail = parsed.spf === 'fail' || parsed.dkim === 'fail' || parsed.dmarc === 'fail';
  const authProb = authFail ? 0.5 : 0;

  const prob = Math.min(0.35 * lexicalProb + 0.30 * structuralProb + 0.20 * authProb + 0.15 * (contentScore / 100) + 0.10 * (headerScore / 100) + (urls.some((u) => u.isHttp) ? 0.05 : 0), 1);
  const score = Math.round(prob * 100);

  const reasons: string[] = [];
  if (lexicalProb > 0.4) reasons.push('Phishing vocabulary density high');
  if (structuralProb > 0.3) reasons.push('Suspicious URL structure features');
  if (authFail) reasons.push('Authentication failure correlates with phishing');
  if (hits >= 5) reasons.push(`${hits} phishing keywords detected`);

  return {
    engineName: 'ml_classifier',
    score,
    verdict: score >= 50 ? 'phishing' : score >= 30 ? 'suspicious' : 'clean',
    confidence: prob,
    reasons,
    evidence: { lexicalProb, structuralProb, authProb, model: 'heuristic_v1' },
    error: null,
  };
}
