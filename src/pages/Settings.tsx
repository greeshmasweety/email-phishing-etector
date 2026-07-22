import { useState } from 'react';

export default function Settings() {
  const [thresholds] = useState({ suspicious: 15, malicious: 40 });

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-500 mt-1">Detection thresholds and integrations</p>
      </div>

      <div className="card p-6 mb-6">
        <h3 className="font-semibold text-gray-900 mb-4">Risk Thresholds</h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between p-3 rounded-lg bg-red-50 border border-red-200">
            <div>
              <div className="font-medium text-gray-900">Phishing threshold</div>
              <div className="text-sm text-gray-600">Score {'>='} {thresholds.suspicious} = flagged as phishing</div>
            </div>
            <span className="badge bg-red-100 text-red-800">Aggressive</span>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg bg-gray-50">
            <div>
              <div className="font-medium text-gray-900">Malicious threshold</div>
              <div className="text-sm text-gray-600">Score {'>='} {thresholds.malicious} = classified as malicious</div>
            </div>
          </div>
        </div>
        <p className="text-sm text-gray-500 mt-4">
          Any suspicious indicator (urgency language, spoofed headers, mismatched links, VirusTotal flags) will classify the email as phishing and trigger an alert.
        </p>
      </div>

      <div className="card p-6">
        <h3 className="font-semibold text-gray-900 mb-4">Integrations</h3>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-4 rounded-lg bg-green-50 border border-green-200">
            <div>
              <div className="font-medium text-gray-900">VirusTotal</div>
              <div className="text-sm text-gray-600">API key configured and edge function deployed</div>
            </div>
            <span className="badge bg-green-100 text-green-800">Connected</span>
          </div>
          <div className="flex items-center justify-between p-4 rounded-lg bg-green-50 border border-green-200">
            <div>
              <div className="font-medium text-gray-900">AI Security Analyst</div>
              <div className="text-sm text-gray-600">Heuristic-based threat analysis engine deployed</div>
            </div>
            <span className="badge bg-green-100 text-green-800">Active</span>
          </div>
          <div className="flex items-center justify-between p-4 rounded-lg bg-green-50 border border-green-200">
            <div>
              <div className="font-medium text-gray-900">Real-time Alerts</div>
              <div className="text-sm text-gray-600">Toast notifications + bell icon for phishing detections</div>
            </div>
            <span className="badge bg-green-100 text-green-800">Active</span>
          </div>
        </div>
      </div>
    </div>
  );
}
