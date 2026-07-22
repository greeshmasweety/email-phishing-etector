export interface ParsedEmail {
  sender_email: string;
  sender_name?: string;
  recipient?: string;
  subject: string;
  plain_body: string;
  html_body?: string;
  reply_to?: string;
  return_path?: string;
  message_id?: string;
  received_at?: string;
  spf?: string;
  dkim?: string;
  dmarc?: string;
}

export function parseEmail(raw: string): ParsedEmail {
  const result: ParsedEmail = { sender_email: '', subject: '', plain_body: '' };
  const headerEnd = raw.indexOf('\n\n');
  const headerBlock = headerEnd >= 0 ? raw.slice(0, headerEnd) : raw;
  const body = headerEnd >= 0 ? raw.slice(headerEnd + 2) : '';

  const lines = headerBlock.split('\n');
  const headers: Record<string, string> = {};
  let currentKey = '';
  for (const line of lines) {
    if (/^\s/.test(line) && currentKey) {
      headers[currentKey] += ' ' + line.trim();
    } else {
      const idx = line.indexOf(':');
      if (idx > 0) {
        currentKey = line.slice(0, idx).trim().toLowerCase();
        headers[currentKey] = line.slice(idx + 1).trim();
      }
    }
  }

  const fromMatch = headers['from']?.match(/<([^>]+)>/) || [null, headers['from']];
  result.sender_email = fromMatch[1] || headers['from'] || '';
  result.sender_name = headers['from']?.replace(/<[^>]+>/, '').trim().replace(/"/g, '') || undefined;
  result.recipient = headers['to'] || undefined;
  result.subject = headers['subject'] || '(no subject)';
  result.reply_to = headers['reply-to'] || undefined;
  result.return_path = headers['return-path'] || undefined;
  result.message_id = headers['message-id'] || undefined;
  result.received_at = headers['date'] || undefined;

  const authResults = headers['authentication-results'] || '';
  if (authResults) {
    const spfMatch = authResults.match(/spf=(\w+)/i);
    const dkimMatch = authResults.match(/dkim=(\w+)/i);
    const dmarcMatch = authResults.match(/dmarc=(\w+)/i);
    result.spf = spfMatch?.[1]?.toLowerCase();
    result.dkim = dkimMatch?.[1]?.toLowerCase();
    result.dmarc = dmarcMatch?.[1]?.toLowerCase();
  }

  if (body.includes('Content-Type: text/html')) {
    const htmlStart = body.indexOf('Content-Type: text/html');
    const htmlSection = body.slice(htmlStart);
    const afterBoundary = htmlSection.split('\n\n').slice(1).join('\n\n');
    result.html_body = afterBoundary.split(/\r?\n--/)[0];
    result.plain_body = afterBoundary.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  } else if (body.includes('<html') || body.includes('<div') || body.includes('<a ')) {
    result.html_body = body;
    result.plain_body = body.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  } else {
    result.plain_body = body.trim();
  }

  return result;
}

export function parseQuickInput(input: string): ParsedEmail {
  if (/^from:/im.test(input) || /^subject:/im.test(input) || /^received:/im.test(input)) {
    return parseEmail(input);
  }
  return {
    sender_email: 'unknown@example.com',
    subject: 'Quick scan',
    plain_body: input,
  };
}
