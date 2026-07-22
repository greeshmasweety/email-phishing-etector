import { RiskLevel } from '../lib/detectionEngine';

export function RiskBadge({ level, score }: { level: RiskLevel; score?: number }) {
  const config = {
    safe: { bg: 'bg-green-100', text: 'text-green-800', label: 'Safe' },
    suspicious: { bg: 'bg-red-100', text: 'text-red-800', label: 'Phishing' },
    malicious: { bg: 'bg-red-900', text: 'text-red-100', label: 'Malicious' },
  };
  const c = config[level];
  return (
    <span className={`badge ${c.bg} ${c.text}`}>
      {c.label}{score !== undefined ? ` (${score})` : ''}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    info: 'bg-gray-400',
    low: 'bg-blue-400',
    medium: 'bg-yellow-500',
    high: 'bg-orange-500',
    critical: 'bg-red-600',
  };
  return <span className={`inline-block w-2.5 h-2.5 rounded-full ${colors[severity] || 'bg-gray-400'}`} />;
}

export function ScoreGauge({ score, level }: { score: number; level: RiskLevel }) {
  const color = level === 'malicious' ? 'text-red-700' : level === 'suspicious' ? 'text-red-600' : 'text-green-600';
  const stroke = level === 'malicious' ? '#991b1b' : level === 'suspicious' ? '#dc2626' : '#16a34a';
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (score / 100) * circumference;
  return (
    <div className="relative w-32 h-32">
      <svg className="w-32 h-32 -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="45" fill="none" stroke="#e5e7eb" strokeWidth="8" />
        <circle cx="50" cy="50" r="45" fill="none" stroke={stroke} strokeWidth="8"
          strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
          className="transition-all duration-500" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-3xl font-bold ${color}`}>{score}</span>
        <span className="text-xs text-gray-500 uppercase tracking-wide">
          {level === 'suspicious' ? 'Phishing' : level}
        </span>
      </div>
    </div>
  );
}
