import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { RiskBadge } from '../components/RiskBadge';

interface QuarantineEmail {
  id: string;
  sender_email: string;
  sender_name: string | null;
  subject: string;
  risk_score: number;
  classification: string;
  received_at: string | null;
  status: string;
}

interface QuarantineAction {
  id: string;
  email_id: string;
  action: string;
  reason: string | null;
  performed_by: string;
  created_at: string;
}

export default function Quarantine() {
  const [emails, setEmails] = useState<QuarantineEmail[]>([]);
  const [actions, setActions] = useState<QuarantineAction[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'quarantined' | 'released' | 'deleted' | 'all'>('quarantined');

  async function loadData() {
    const [emailRes, actionRes] = await Promise.all([
      supabase.from('emails')
        .select('id, sender_email, sender_name, subject, risk_score, classification, received_at, status')
        .order('received_at', { ascending: false }),
      supabase.from('quarantine_actions')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50),
    ]);
    setEmails(emailRes.data || []);
    setActions(actionRes.data || []);
    setLoading(false);
  }

  useEffect(() => { loadData(); }, []);

  const filtered = filter === 'all' ? emails : emails.filter((e) => e.status === filter);

  async function handleAction(emailId: string, action: 'released' | 'deleted' | 'false_positive') {
    const newStatus = action === 'false_positive' ? 'reviewed' : action;
    await supabase.from('emails').update({ status: newStatus }).eq('id', emailId);
    await supabase.from('quarantine_actions').insert({
      email_id: emailId, action, reason: `Manual ${action}`, performed_by: 'user',
    });
    if (action === 'false_positive') {
      await supabase.from('emails').update({ false_positive: true }).eq('id', emailId);
    }
    loadData();
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Quarantine</h1>
        <p className="text-gray-500 mt-1">Isolated phishing and malicious emails</p>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        <StatCard label="Quarantined" value={emails.filter((e) => e.status === 'quarantined').length} color="red" />
        <StatCard label="Released" value={emails.filter((e) => e.status === 'released').length} color="green" />
        <StatCard label="Deleted" value={emails.filter((e) => e.status === 'deleted').length} color="gray" />
      </div>

      <div className="flex gap-2 mb-4">
        {(['quarantined', 'released', 'deleted', 'all'] as const).map((f) => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              filter === f ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}>
            {f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="text-center text-gray-400 py-20">Loading...</div>
      ) : filtered.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-gray-500">No emails in this category.</p>
        </div>
      ) : (
        <div className="space-y-3 mb-8">
          {filtered.map((e) => (
            <div key={e.id} className="card p-4">
              <div className="flex items-center justify-between">
                <div className="min-w-0 flex-1">
                  <Link to={`/emails/${e.id}`} className="font-medium text-gray-900 hover:text-blue-600 truncate block">
                    {e.subject}
                  </Link>
                  <div className="text-sm text-gray-500 truncate">{e.sender_email}</div>
                </div>
                <div className="flex items-center gap-3 ml-4">
                  <RiskBadge level={e.classification as any} score={e.risk_score} />
                  <span className={`badge ${e.status === 'quarantined' ? 'bg-red-100 text-red-800' : e.status === 'released' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-700'}`}>
                    {e.status}
                  </span>
                </div>
              </div>
              {e.status === 'quarantined' && (
                <div className="flex gap-2 mt-3">
                  <button onClick={() => handleAction(e.id, 'released')} className="btn btn-success text-sm">Release</button>
                  <button onClick={() => handleAction(e.id, 'deleted')} className="btn btn-danger text-sm">Delete</button>
                  <button onClick={() => handleAction(e.id, 'false_positive')} className="btn btn-ghost text-sm">Mark False Positive</button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="card p-6">
        <h3 className="font-semibold text-gray-900 mb-4">Quarantine Action Log</h3>
        {actions.length === 0 ? (
          <p className="text-gray-400 text-sm">No actions recorded.</p>
        ) : (
          <div className="space-y-2">
            {actions.map((a) => {
              const email = emails.find((e) => e.id === a.email_id);
              return (
                <div key={a.id} className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 text-sm">
                  <span className={`badge ${
                    a.action === 'quarantined' ? 'bg-red-100 text-red-800' :
                    a.action === 'released' ? 'bg-green-100 text-green-800' :
                    a.action === 'deleted' ? 'bg-gray-200 text-gray-700' :
                    'bg-blue-100 text-blue-800'
                  }`}>{a.action}</span>
                  <span className="text-gray-700 flex-1 truncate">{email ? email.subject : a.email_id}</span>
                  <span className="text-gray-400 text-xs">{a.performed_by}</span>
                  <span className="text-gray-400 text-xs">{new Date(a.created_at).toLocaleString()}</span>
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
    red: 'bg-red-50 text-red-700 border-red-200',
    green: 'bg-green-50 text-green-700 border-green-200',
    gray: 'bg-gray-50 text-gray-700 border-gray-200',
  };
  return (
    <div className={`card p-5 border-l-4 ${colors[color]}`}>
      <div className="text-3xl font-bold">{value}</div>
      <div className="text-sm text-gray-600 mt-1">{label}</div>
    </div>
  );
}
