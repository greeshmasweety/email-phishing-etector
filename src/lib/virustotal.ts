import { SUPABASE_URL } from './supabase';

export interface VendorResult {
  engine_name: string;
  category: string;
  result: string;
  is_malicious: boolean;
}

export interface VTResponse {
  url: string;
  malicious_count: number;
  total_engines: number;
  vendors: VendorResult[];
  reputation: number | null;
  error?: string;
}

export async function lookupUrl(url: string): Promise<VTResponse> {
  const fnUrl = `${SUPABASE_URL}/functions/v1/virustotal-lookup`;
  const resp = await fetch(fnUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!resp.ok) {
    const txt = await resp.text();
    return { url, malicious_count: 0, total_engines: 0, vendors: [], reputation: null, error: `HTTP ${resp.status}: ${txt}` };
  }
  const data = await resp.json();
  return data as VTResponse;
}
