import { useEffect, useState } from 'react';
import { supabase } from '../lib/supabase';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Legend, PieChart, Pie, Cell } from 'recharts';

interface EmailRow {
  id: string;
  sender_email: string;
  sender_domain: string | null;
  subject: string;
  risk_score: number;
  classification: string;
  received_at: string | null;
  status: string;
}

interface UrlRow {
  url: string;
  domain: string | null;
  vt_malicious: number;
  vt_harmless: number;
}

export default function Reports() {
  const [emails, setEmails] = useState<EmailRow[]>([]);
  const [urls, setUrls] = useState<UrlRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      supabase.from('emails').select('id, sender_email, sender_domain, subject, risk_score, classification, received_at, status').order('received_at', { ascending: false }).limit(500),
      supabase.from('email_urls').select('url, domain, vt_malicious, vt_harmless').limit(500),
    ]).then(([emailRes, urlRes]) => {
      setEmails(emailRes.data || []);
      setUrls(urlRes.data || []);
      setLoading(false);
    });
  }, []);

  const total = emails.length;
  const safe = emails.filter((e) => e.classification === 'safe').length;
  const phishing = emails.filter((e) => e.classification === 'suspicious').length;
  const malicious = emails.filter((e) => e.classification === 'malicious').length;
  const quarantined = emails.filter((e) => e.status === 'quarantined').length;
  const released = emails.filter((e) => e.status === 'released').length;
  const falsePositives = emails.filter((e) => e.status === 'reviewed').length;
  const detectionRate = total > 0 ? ((phishing + malicious) / total * 100).toFixed(1) : '0';
  const avgScore = total > 0 ? (emails.reduce((s, e) => s + e.risk_score, 0) / total).toFixed(1) : '0';

  const domainCounts: Record<string, number> = {};
  emails.forEach((e) => {
    const d = e.sender_domain || e.sender_email.split('@')[1] || 'unknown';
    domainCounts[d] = (domainCounts[d] || 0) + 1;
  });
  const topDomains = Object.entries(domainCounts).map(([domain, count]) => ({ domain, count })).sort((a, b) => b.count - a.count).slice(0, 10);

  const trendData: { date: string; count: number; threats: number }[] = [];
  const dateMap: Record<string, { count: number; threats: number }> = {};
  emails.forEach((e) => {
    if (!e.received_at) return;
    const date = new Date(e.received_at).toLocaleDateString();
    if (!dateMap[date]) dateMap[date] = { count: 0, threats: 0 };
    dateMap[date].count++;
    if (e.classification !== 'safe') dateMap[date].threats++;
  });
  Object.entries(dateMap).forEach(([date, v]) => trendData.push({ date, ...v }));
  trendData.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

  const urlThreatData = [
    { name: 'Malicious URLs', value: urls.filter((u) => u.vt_malicious > 0).length, color: '#dc2626' },
    { name: 'Clean URLs', value: urls.filter((u) => u.vt_malicious === 0).length, color: '#16a34a' },
  ].filter((d) => d.value > 0);

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Reports & Analytics</h1>
        <p className="text-gray-500 mt-1">Comprehensive threat intelligence and trend analysis</p>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Scanned" value={total} color="blue" />
        <StatCard label="Detection Rate" value={`${detectionRate}%`} color="red" />
        <StatCard label="Avg Risk Score" value={avgScore} color="orange" />
        <StatCard label="Quarantined" value={quarantined} color="gray" />
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        <div className="card p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Email Volume & Threats Over Time</h3>
          {trendData.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-gray-400">No data</div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="count" stroke="#3b82f6" name="Total Emails" strokeWidth={2} />
                <Line type="monotone" dataKey="threats" stroke="#dc2626" name="Threats" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Top Sender Domains</h3>
          {topDomains.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-gray-400">No data</div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={topDomains} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" allowDecimals={false} />
                <YAxis type="category" dataKey="domain" width={150} />
                <Tooltip />
                <Bar dataKey="count" fill="#f97316" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6 mb-6">
        <div className="card p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Classification Breakdown</h3>
          <div className="space-y-3">
            <BreakdownRow label="Safe" value={safe} total={total} color="bg-green-500" />
            <BreakdownRow label="Phishing" value={phishing} total={total} color="bg-red-500" />
            <BreakdownRow label="Malicious" value={malicious} total={total} color="bg-red-800" />
          </div>
        </div>

        <div className="card p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Action Summary</h3>
          <div className="space-y-3">
            <BreakdownRow label="Quarantined" value={quarantined} total={total} color="bg-red-500" />
            <BreakdownRow label="Released" value={released} total={total} color="bg-green-500" />
            <BreakdownRow label="Reviewed" value={falsePositives} total={total} color="bg-blue-500" />
          </div>
        </div>

        <div className="card p-6">
          <h3 className="font-semibold text-gray-900 mb-4">URL Threat Analysis</h3>
          {urlThreatData.length === 0 ? (
            <div className="h-48 flex items-center justify-center text-gray-400">No URL data</div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={urlThreatData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60} label>
                    {urlThreatData.map((d) => <Cell key={d.name} fill={d.color} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
              <div className="text-center text-sm text-gray-600 mt-2">
                {urls.filter((u) => u.vt_malicious > 0).length} malicious URLs detected
              </div>
            </>
          )}
        </div>
      </div>

      <div className="card p-6">
        <h3 className="font-semibold text-gray-900 mb-4">Summary Report</h3>
        {loading ? (
          <div className="text-center text-gray-400 py-8">Loading...</div>
        ) : (
          <div className="space-y-3 text-sm text-gray-700">
            <p><span className="font-medium">Total emails scanned:</span> {total}</p>
            <p><span className="font-medium">Safe emails:</span> {safe} ({total > 0 ? (safe / total * 100).toFixed(1) : 0}%)</p>
            <p><span className="font-medium">Phishing detected:</span> {phishing + malicious} ({detectionRate}%)</p>
            <p><span className="font-medium">Average risk score:</span> {avgScore} / 100</p>
            <p><span className="font-medium">URLs analyzed:</span> {urls.length}</p>
            <p><span className="font-medium">Malicious URLs (VirusTotal):</span> {urls.filter((u) => u.vt_malicious > 0).length}</p>
            <p><span className="font-medium">Emails quarantined:</span> {quarantined}</p>
            <p><span className="font-medium">Emails released:</span> {released}</p>
            <p><span className="font-medium">Top threat domain:</span> {topDomains[0]?.domain || 'N/A'}</p>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  const colors: Record<string, string> = {
    blue: 'bg-blue-50 text-blue-700 border-blue-200',
    red: 'bg-red-50 text-red-700 border-red-200',
    orange: 'bg-orange-50 text-orange-700 border-orange-200',
    gray: 'bg-gray-50 text-gray-700 border-gray-200',
  };
  return (
    <div className={`card p-5 border-l-4 ${colors[color]}`}>
      <div className="text-3xl font-bold">{value}</div>
      <div className="text-sm text-gray-600 mt-1">{label}</div>
    </div>
  );
}

function BreakdownRow({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const pct = total > 0 ? (value / total * 100).toFixed(1) : '0';
  return (
    <div>
      <div className="flex justify-between text-sm mb-1">
        <span className="text-gray-700">{label}</span>
        <span className="text-gray-500">{value} ({pct}%)</span>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-2">
        <div className={`${color} h-2 rounded-full transition-all`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
