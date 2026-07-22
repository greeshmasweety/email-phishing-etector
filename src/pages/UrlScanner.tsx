import { useState } from 'react';
import { scanSingleUrl, ScanResult } from '../lib/detectionEngine';
import { PHISHING_URL_SAMPLES } from '../lib/templates';
import { RiskBadge, ScoreGauge, SeverityDot } from '../components/RiskBadge';
import VirusTotalTable from '../components/VirusTotalTable';

export default function UrlScanner() {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');

  async function handleScan() {
    if (!url.trim()) return;
    setScanning(true);
    setError('');
    setResult(null);
    try {
      const res = await scanSingleUrl(url.trim());
      setResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">URL Scanner</h1>
        <p className="text-gray-500 mt-1">Analyze a URL for phishing and malware with VirusTotal</p>
      </div>

      <div className="card p-5 mb-6">
        <h3 className="font-semibold text-gray-900 mb-3">Sample URLs</h3>
        <div className="flex flex-wrap gap-2">
          {PHISHING_URL_SAMPLES.map((u) => (
            <button key={u} onClick={() => setUrl(u)}
              className="px-3 py-1.5 rounded-lg text-sm bg-gray-100 hover:bg-blue-50 hover:text-blue-700 text-gray-700 transition-colors font-mono">
              {u}
            </button>
          ))}
        </div>
      </div>

      <div className="card p-5 mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-2">URL to scan</label>
        <input type="text" value={url} onChange={(e) => setUrl(e.target.value)}
          className="input font-mono text-sm" placeholder="https://example.com"
          onKeyDown={(e) => e.key === 'Enter' && handleScan()} />
        <div className="flex gap-3 mt-3">
          <button onClick={handleScan} disabled={scanning || !url.trim()} className="btn btn-primary disabled:opacity-50">
            {scanning ? 'Scanning...' : 'Scan URL'}
          </button>
          <button onClick={() => { setUrl(''); setResult(null); }} className="btn btn-ghost">Clear</button>
        </div>
        {error && <div className="mt-3 text-sm text-red-600">{error}</div>}
      </div>

      {result && (
        <div className="space-y-6">
          <div className="card p-6">
            <div className="flex items-center gap-8">
              <ScoreGauge score={result.risk_score} level={result.risk_level} />
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-gray-900 mb-2">URL Analysis</h3>
                <div className="text-sm text-gray-600 break-all mb-3">{result.urls[0]?.url}</div>
                <RiskBadge level={result.risk_level} score={result.risk_score} />
              </div>
            </div>
          </div>

          <div className="card p-6">
            <h3 className="font-semibold text-gray-900 mb-4">Findings ({result.findings.length})</h3>
            <div className="space-y-2">
              {result.findings.map((f, i) => (
                <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-gray-50">
                  <SeverityDot severity={f.severity} />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-gray-900">{f.engine}</div>
                    <div className="text-sm text-gray-600">{f.description}</div>
                  </div>
                  {f.score > 0 && <span className="text-sm font-semibold text-gray-700">+{f.score}</span>}
                </div>
              ))}
            </div>
          </div>

          {result.vt_results.map((vt, i) => (
            <VirusTotalTable key={i} vendors={vt.vendors} maliciousCount={vt.malicious_count} totalEngines={vt.total_engines} />
          ))}
        </div>
      )}
    </div>
  );
}
