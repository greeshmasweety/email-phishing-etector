import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface EmailData {
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
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const data: EmailData = await req.json();
    const analysis = performAnalysis(data);

    return new Response(JSON.stringify(analysis), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});

function performAnalysis(data: EmailData) {
  const { sender_email, subject, plain_body, risk_score, risk_level, findings, urls, vt_results } = data;

  const senderDomain = sender_email.split('@')[1] || '';
  const bodyText = plain_body.toLowerCase();
  const subjectText = subject.toLowerCase();

  const knownBrands = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'bank of america', 'chase', 'wells fargo', 'fedex', 'ups', 'dhl', 'netflix', 'spotify', 'linkedin', 'facebook', 'instagram', 'twitter', 'github', 'adobe', 'dropbox'];
  const targetedBrand = knownBrands.find(b => bodyText.includes(b) || subjectText.includes(b) || senderDomain.includes(b)) || null;

  const threatTypes: string[] = [];
  if (/verify|confirm|validate|unlock|restore/i.test(bodyText)) threatTypes.push('Credential Harvesting');
  if (/payment|billing|invoice|order|receipt|bank/i.test(bodyText)) threatTypes.push('Financial Fraud');
  if (/bitcoin|crypto|wire transfer|gift card/i.test(bodyText)) threatTypes.push('Payment Extortion');
  if (/package|delivery|shipment|tracking/i.test(bodyText)) threatTypes.push('Delivery Scam');
  if (/password|reset|expired|login/i.test(bodyText)) threatTypes.push('Account Takeover');
  if (/webcam|hacked|recorded|footage/i.test(bodyText)) threatTypes.push('Sextortion');
  if (threatTypes.length === 0) threatTypes.push('Generic Phishing');

  const attackVectors: string[] = [];
  if (urls.length > 0) attackVectors.push('Malicious Links');
  if (urls.some(u => u.is_ip)) attackVectors.push('Direct IP Address');
  if (urls.some(u => u.mismatch)) attackVectors.push('Link Text Mismatch');
  if (findings.some(f => f.engine === 'Header Analysis')) attackVectors.push('Email Spoofing');
  if (findings.some(f => f.description.includes('Reply-To'))) attackVectors.push('Reply-To Redirection');
  if (vt_results.some(v => v.malicious_count > 0)) attackVectors.push('VirusTotal Flagged URL');
  if (attackVectors.length === 0) attackVectors.push('Social Engineering');

  const highSeverityCount = findings.filter(f => f.severity === 'high' || f.severity === 'critical').length;
  const confidence = Math.min(0.99, 0.5 + (highSeverityCount * 0.1) + (risk_score / 200));

  const indicators: { indicator: string; weight: string; detail: string }[] = [];
  for (const f of findings) {
    const weight = f.severity === 'critical' ? 'high' : f.severity === 'high' ? 'high' : f.severity === 'medium' ? 'medium' : 'low';
    indicators.push({ indicator: f.engine, weight, detail: f.description });
  }
  for (const vt of vt_results) {
    if (vt.malicious_count > 0) {
      const maliciousVendors = vt.vendors.filter(v => v.is_malicious).slice(0, 3).map(v => v.engine_name).join(', ');
      indicators.push({
        indicator: 'VirusTotal',
        weight: 'high',
        detail: `${vt.malicious_count}/${vt.total_engines} vendors flagged URL (${maliciousVendors})`,
      });
    }
  }

  const isPhishing = risk_level !== 'safe';
  const summary = isPhishing
    ? `This email has been classified as ${risk_level === 'malicious' ? 'malicious' : 'phishing'} with a risk score of ${risk_score}/100. ` +
      `The primary threat type is ${threatTypes[0]}, targeting ${targetedBrand || 'the recipient'} through ${attackVectors.join(', ')}. ` +
      `${highSeverityCount} high-severity indicators were detected across ${findings.length} total findings.`
    : `This email appears to be legitimate with a risk score of ${risk_score}/100. No significant phishing indicators were detected. ` +
      `The sender domain ${senderDomain} shows no signs of typosquatting or spoofing.`;

  const riskAssessment = isPhishing
    ? `HIGH RISK: This email exhibits ${highSeverityCount} critical/high-severity indicators consistent with ${threatTypes.join(' and ')}. ` +
      `The sender domain "${senderDomain}" ${senderDomain && isTyposquat(senderDomain) ? `is a typosquat of a legitimate domain` : `shows suspicious characteristics`}. ` +
      `${urls.length} URL(s) were found, with ${vt_results.filter(v => v.malicious_count > 0).length} flagged by VirusTotal. ` +
      `Immediate quarantine and user education are recommended.`
    : `LOW RISK: This email shows no significant indicators of phishing or malicious activity. ` +
      `The content, headers, and URLs all appear legitimate. Standard monitoring is sufficient.`;

  const recommendations: string[] = [];
  if (isPhishing) {
    recommendations.push('Quarantine this email immediately and prevent delivery to the user inbox');
    recommendations.push('Block the sender domain and all associated URLs at the email gateway');
    recommendations.push(`Report this phishing attempt to ${targetedBrand ? `the legitimate ${targetedBrand} security team` : 'your security team'}`);
    recommendations.push('Conduct user awareness training on this specific phishing pattern');
    if (urls.length > 0) recommendations.push('Add all URLs from this email to the URL blocklist');
    if (vt_results.some(v => v.malicious_count > 0)) recommendations.push('Submit all flagged URLs to additional threat intelligence platforms');
    if (attackVectors.includes('Email Spoofing')) recommendations.push('Review and tighten SPF, DKIM, and DMARC policies');
    recommendations.push('Monitor for similar emails from related domains or IP addresses');
  } else {
    recommendations.push('No action required — this email is classified as safe');
    recommendations.push('Continue routine monitoring of emails from this sender');
  }

  const userActionRequired = isPhishing
    ? `Do NOT click any links in this email. Do NOT reply or provide any personal information. ` +
      `If you already clicked a link or entered credentials, contact IT security immediately and change your ${targetedBrand || 'account'} password. ` +
      `Delete this email and report it as phishing.`
    : 'No action required. This email is safe to open and interact with normally.';

  return {
    email_id: data.email_id || null,
    summary,
    risk_assessment: riskAssessment,
    threat_type: threatTypes.join(', '),
    confidence,
    recommendations,
    indicators,
    attack_vector: attackVectors.join(', '),
    targeted_brand: targetedBrand,
    user_action_required: userActionRequired,
  };
}

function isTyposquat(domain: string): boolean {
  const trusted = ['paypal.com', 'google.com', 'apple.com', 'microsoft.com', 'amazon.com'];
  return trusted.some(t => {
    const d = domain.replace(/\.[a-z]+$/, '');
    const tt = t.replace(/\.[a-z]+$/, '');
    return d !== tt && levenshtein(d, tt) <= 2;
  });
}

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}
