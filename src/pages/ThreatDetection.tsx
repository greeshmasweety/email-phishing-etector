import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { RiskBadge, SeverityDot } from '../components/RiskBadge';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';

interface DetectionRow {
  id: string;
  email_id: string;
  engine_name: string;
  score: number;
  verdict: string;
  reasons: { description: string; severity: string }[];
  scan_timestamp: string;
}

interface EmailRow {
  id: string;
  sender_email: string;
  subject: string;
  risk_score: number;
  classification: string;
  received_at: string | null;
}

export default function ThreatDetection() {
  const [detections, setDetections] = useState<DetectionRow[]>([]);
  const [emails, setEmails] = useState<EmailRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      supabase.from('detections').select('*').order('score', { ascending: false }).limit(200),
      supabase.from('emails').select('id, sender_email, subject, risk_score, classification, received_at').order('received_at', { ascending: false }).limit(100),
    ]).then(([detRes, emailRes]) => {
      setDetections(detRes.data || []);
      setEmails(emailRes.data || []);
      setLoading(false);
    });
  }, []);

  const engineCounts: Record<string, number> = {};
  detections.forEach((d) => { engineCounts[d.engine_name] = (engineCounts[d.engine_name] || 0) + 1; });
  const engineData = Object.entries(engineCounts).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, 10);

  const severityCounts: Record<string, number> = {};
  detections.forEach((d) => { const sev = d.verdict || 'info'; severityCounts[sev] = (severityCounts[sev] || 0) + 1; });
  const severityData = [
    { name: 'Critical', value: severityCounts['critical'] || 0, color: '#dc2626' },
    { name: 'High', value: severityCounts['high'] || 0, color: '#f97316' },
    { name: 'Medium', value: severityCounts['medium'] || 0, color: '#eab308' },
    { name: 'Low', value: severityCounts['low'] || 0, color: '#3b82f6' },
    { name: 'Info', value: severityCounts['info'] || 0, color: '#9ca3af' },
  ].filter((d) => d.value > 0);

  const topThreats = emails.filter((e) => e.classification !== 'safe').slice(0, 10);

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Threat Detection</h1>
        <p className="text-gray-500 mt-1">Detection engine results and threat intelligence</p>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Detections" value={detections.length} color="blue" />
        <StatCard label="Critical" value={severityCounts['critical'] || 0} color="red" />
        <StatCard label="High" value={severityCounts['high'] || 0} color="orange" />
        <StatCard label="Engines Active" value={Object.keys(engineCounts).length} color="green" />
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        <div className="card p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Detections by Engine</h3>
          {engineData.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-gray-400">No data</div>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={engineData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" allowDecimals={false} />
                <YAxis type="category" dataKey="name" width={120} />
                <Tooltip />
                <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Severity Distribution</h3>
          {severityData.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-gray-400">No data</div>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100} label>
                  {severityData.map((d) => <Cell key={d.name} fill={d.color} />)}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="card p-6 mb-6">
        <h3 className="font-semibold text-gray-900 mb-4">Top Threats</h3>
        {loading ? (
          <div className="text-center text-gray-400 py-8">Loading...</div>
        ) : topThreats.length === 0 ? (
          <div className="text-center text-gray-400 py-8">No threats detected</div>
        ) : (
          <div className="space-y-2">
            {topThreats.map((e) => (
              <Link key={e.id} to={`/emails/${e.id}`} className="block p-3 rounded-lg hover:bg-gray-50 border border-gray-100">
                <div className="flex items-center justify-between">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-gray-900 truncate">{e.subject}</div>
                    <div className="text-xs text-gray-500 truncate">{e.sender_email}</div>
                  </div>
                  <RiskBadge level={e.classification as any} score={e.risk_score} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>

      <div className="card p-6">
        <h3 className="font-semibold text-gray-900 mb-4">Recent Detection Findings</h3>
        {detections.length === 0 ? (
          <div className="text-center text-gray-400 py-8">No detections recorded</div>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {detections.slice(0, 50).map((d) => {
              const email = emails.find((e) => e.id === d.email_id);
              return (
                <div key={d.id} className="flex items-start gap-3 p-3 rounded-lg bg-gray-50">
                  <SeverityDot severity={d.verdict} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-gray-900">{d.engine_name}</div>
                    <div className="text-sm text-gray-600 truncate">
                      {(d.reasons || []).map((r) => r.description).join(', ') || '—'}
                    </div>
                    {email && <Link to={`/emails/${d.email_id}`} className="text-xs text-blue-600 hover:underline">{email.subject}</Link>}
                  </div>
                  <span className="text-sm font-semibold text-gray-700">+{d.score}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  const colors: Record<string, string> = {
    blue: 'bg-blue-50 text-blue-700 border-blue-200',
    red: 'bg-red-50 text-red-700 border-red-200',
    orange: 'bg-orange-50 text-orange-700 border-orange-200',
    green: 'bg-green-50 text-green-700 border-green-200',
  };
  return (
    <div className={`card p-5 border-l-4 ${colors[color]}`}>
      <div className="text-3xl font-bold">{value}</div>
      <div className="text-sm text-gray-600 mt-1">{label}</div>
    </div>
  );
}
