import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { RiskBadge } from '../components/RiskBadge';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';

interface EmailRow {
  id: string;
  sender_email: string;
  sender_name: string | null;
  subject: string;
  risk_score: number;
  classification: string;
  received_at: string | null;
  status: string;
}

export default function Dashboard() {
  const [emails, setEmails] = useState<EmailRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    supabase
      .from('emails')
      .select('id, sender_email, sender_name, subject, risk_score, classification, received_at, status')
      .order('received_at', { ascending: false })
      .limit(100)
      .then(({ data }) => {
        setEmails(data || []);
        setLoading(false);
      });
  }, []);

  const safe = emails.filter((e) => e.classification === 'safe').length;
  const phishing = emails.filter((e) => e.classification !== 'safe').length;
  const quarantined = emails.filter((e) => e.status === 'quarantined').length;

  const pieData = [
    { name: 'Safe', value: safe, color: '#16a34a' },
    { name: 'Phishing', value: phishing, color: '#dc2626' },
  ].filter((d) => d.value > 0);

  const recentThreats = emails.filter((e) => e.classification !== 'safe').slice(0, 5);

  const scoreBuckets = [
    { range: '0-15', count: emails.filter((e) => e.risk_score < 15).length },
    { range: '15-40', count: emails.filter((e) => e.risk_score >= 15 && e.risk_score < 40).length },
    { range: '40-70', count: emails.filter((e) => e.risk_score >= 40 && e.risk_score < 70).length },
    { range: '70-100', count: emails.filter((e) => e.risk_score >= 70).length },
  ];

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-500 mt-1">Email threat overview and recent detections</p>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-8">
        <StatCard label="Total Emails" value={emails.length} color="blue" />
        <StatCard label="Safe" value={safe} color="green" />
        <StatCard label="Phishing Detected" value={phishing} color="red" />
        <StatCard label="Quarantined" value={quarantined} color="orange" />
      </div>

      <div className="grid grid-cols-2 gap-6 mb-8">
        <div className="card p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Threat Distribution</h3>
          {loading ? (
            <div className="h-64 flex items-center justify-center text-gray-400">Loading...</div>
          ) : emails.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-gray-400">No emails scanned yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                  {pieData.map((d) => <Cell key={d.name} fill={d.color} />)}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Risk Score Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={scoreBuckets}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="range" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card p-6 mb-8">
        <h3 className="font-semibold text-gray-900 mb-4">Recent Threats</h3>
        {recentThreats.length === 0 ? (
          <div className="text-gray-400 text-sm py-8 text-center">No threats detected</div>
        ) : (
          <div className="space-y-3">
            {recentThreats.map((e) => (
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
        <h3 className="font-semibold text-gray-900 mb-4">Quick Actions</h3>
        <div className="flex gap-3 flex-wrap">
          <Link to="/scan" className="btn btn-primary">Scan an Email</Link>
          <Link to="/url-scan" className="btn btn-ghost">Scan a URL</Link>
          <Link to="/threats" className="btn btn-ghost">Threat Detection</Link>
          <Link to="/quarantine" className="btn btn-ghost">Quarantine</Link>
          <Link to="/ai-analyst" className="btn btn-ghost">AI Analyst</Link>
          <Link to="/reports" className="btn btn-ghost">Reports</Link>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  const colors: Record<string, string> = {
    blue: 'bg-blue-50 text-blue-700 border-blue-200',
    green: 'bg-green-50 text-green-700 border-green-200',
    red: 'bg-red-50 text-red-700 border-red-200',
    orange: 'bg-orange-50 text-orange-700 border-orange-200',
  };
  return (
    <div className={`card p-5 border-l-4 ${colors[color]}`}>
      <div className="text-3xl font-bold">{value}</div>
      <div className="text-sm text-gray-600 mt-1">{label}</div>
    </div>
  );
}
