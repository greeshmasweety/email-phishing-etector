import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { RiskBadge } from '../components/RiskBadge';

interface EmailRow {
  id: string;
  sender_email: string;
  sender_name: string | null;
  subject: string;
  risk_score: number;
  classification: string;
  received_at: string | null;
}

export default function Emails() {
  const [emails, setEmails] = useState<EmailRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'safe' | 'suspicious' | 'malicious'>('all');

  useEffect(() => {
    supabase
      .from('emails')
      .select('id, sender_email, sender_name, subject, risk_score, classification, received_at')
      .order('received_at', { ascending: false })
      .then(({ data }) => {
        setEmails(data || []);
        setLoading(false);
      });
  }, []);

  const filtered = filter === 'all' ? emails : emails.filter((e) => e.classification === filter);

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Scanned Emails</h1>
        <p className="text-gray-500 mt-1">All emails analyzed by PhishGuard</p>
      </div>

      <div className="flex gap-2 mb-4">
        {(['all', 'safe', 'suspicious', 'malicious'] as const).map((f) => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              filter === f ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}>
            {f === 'suspicious' ? 'Phishing' : f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      <div className="card overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-gray-400">Loading...</div>
        ) : filtered.length === 0 ? (
          <div className="p-8 text-center text-gray-400">No emails found</div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">Subject</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">Sender</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filtered.map((e) => (
                <tr key={e.id} className="hover:bg-gray-50">
                  <td className="px-5 py-3">
                    <Link to={`/emails/${e.id}`} className="text-sm font-medium text-gray-900 hover:text-blue-600">{e.subject}</Link>
                  </td>
                  <td className="px-5 py-3 text-sm text-gray-600">{e.sender_email}</td>
                  <td className="px-5 py-3"><RiskBadge level={e.classification as any} score={e.risk_score} /></td>
                  <td className="px-5 py-3 text-sm text-gray-500">{e.received_at ? new Date(e.received_at).toLocaleDateString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
