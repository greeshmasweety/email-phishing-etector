export interface ExtractedUrl {
  url: string;
  display_text: string;
  href: string;
  mismatch: boolean;
  domain: string;
  is_ip: boolean;
  uses_http: boolean;
  is_shortened: boolean;
  has_punycode: boolean;
  has_suspicious_tld: boolean;
  has_at_sign: boolean;
  has_subdomain_excess: boolean;
  port: string | null;
}

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc',
  'rb.gy', 's.id', 'lnkd.in', 'shorte.st',
]);

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'country',
  'work', 'gdn', 'bid', 'loan', 'win', 'date', 'racing', 'stream',
  'review', 'trade', 'webcam', 'science', 'party', 'download', 'kim',
  'men', 'pw', 'cc', 'biz', 'info', 'su', 'ru', 'cn',
]);

const TRUSTED_DOMAINS = new Set([
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com',
  'linkedin.com', 'facebook.com', 'twitter.com', 'instagram.com',
  'paypal.com', 'ebay.com', 'netflix.com', 'spotify.com', 'adobe.com',
  'cloudflare.com', 'stripe.com', 'wikipedia.org', 'mozilla.org',
  'yahoo.com', 'office.com', 'live.com', 'outlook.com', 'gmail.com',
]);

export function extractUrls(html: string, plain: string): ExtractedUrl[] {
  const results: ExtractedUrl[] = [];
  const seen = new Set<string>();

  const hrefRegex = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = hrefRegex.exec(html || '')) !== null) {
    const href = m[1];
    const text = m[2].replace(/<[^>]*>/g, '').trim();
    if (!seen.has(href)) {
      seen.add(href);
      results.push(analyzeUrl(href, text));
    }
  }

  const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  const rawText = (plain || '') + ' ' + (html || '').replace(/<[^>]*>/g, ' ');
  while ((m = urlRegex.exec(rawText)) !== null) {
    const u = m[0].replace(/[.,;:!?]$/, '');
    if (!seen.has(u)) {
      seen.add(u);
      results.push(analyzeUrl(u, u));
    }
  }

  return results;
}

export function analyzeUrl(href: string, displayText: string): ExtractedUrl {
  let domain = '';
  let is_ip = false;
  let uses_http = false;
  let has_punycode = false;
  let port: string | null = null;

  try {
    const u = new URL(href);
    domain = u.hostname.toLowerCase();
    is_ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain) || domain.includes(':');
    uses_http = u.protocol === 'http:';
    has_punycode = domain.includes('xn--');
    port = u.port || null;
  } catch {
    domain = href.split('/')[0] || href;
  }

  const parts = domain.split('.');
  const tld = parts.length > 1 ? parts[parts.length - 1] : '';
  const rootDomain = parts.length > 1 ? parts.slice(-2).join('.') : domain;

  return {
    url: href,
    display_text: displayText,
    href,
    mismatch: displayText !== href && /^https?:\/\//i.test(displayText) && !displayText.includes(domain),
    domain,
    is_ip,
    uses_http,
    is_shortened: SHORTENERS.has(rootDomain),
    has_punycode,
    has_suspicious_tld: SUSPICIOUS_TLDS.has(tld),
    has_at_sign: href.includes('@') && !href.startsWith('mailto:'),
    has_subdomain_excess: parts.length > 4,
    port,
  };
}

export function isTyposquat(domain: string): string | null {
  const parts = domain.split('.');
  if (parts.length < 2) return null;
  const root = parts.slice(-2).join('.');
  for (const trusted of TRUSTED_DOMAINS) {
    if (domain === trusted) return null;
    if (levenshtein(root, trusted.split('.').slice(-2).join('.')) === 1 && root !== trusted) {
      return trusted;
    }
  }
  return null;
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
