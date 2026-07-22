import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { RiskBadge } from '../components/RiskBadge';
import { useAlerts } from '../context/AlertContext';

interface EmailRow {
  id: string;
  sender_email: string;
  subject: string;
  risk_score: number;
  classification: string;
  received_at: string | null;
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<EmailRow[]>([]);
  const [loading, setLoading] = useState(true);
  const { alerts: notifications, clearAlerts } = useAlerts();

  useEffect(() => {
    supabase
      .from('emails')
      .select('id, sender_email, subject, risk_score, classification, received_at')
      .in('classification', ['suspicious', 'malicious'])
      .order('risk_score', { ascending: false })
      .then(({ data }) => {
        setAlerts(data || []);
        setLoading(false);
      });
  }, []);

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Alerts</h1>
        <p className="text-gray-500 mt-1">Phishing and malicious emails that need attention</p>
      </div>

      {notifications.length > 0 && (
        <div className="card p-4 mb-6 bg-blue-50 border-l-4 border-l-blue-500">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
              </svg>
              <span className="text-sm font-medium text-blue-900">{notifications.length} active notification(s)</span>
            </div>
            <button onClick={clearAlerts} className="text-xs text-blue-600 hover:underline">Dismiss all</button>
          </div>
        </div>
      )}

      {loading ? (
        <div className="text-center text-gray-400 py-20">Loading...</div>
      ) : alerts.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="text-green-600 text-4xl mb-2">&#10003;</div>
          <p className="text-gray-600">No alerts. All scanned emails are safe.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {alerts.map((e) => (
            <Link key={e.id} to={`/emails/${e.id}`} className="card p-4 hover:shadow-md transition-shadow block">
              <div className="flex items-center justify-between">
                <div className="min-w-0 flex-1">
                  <div className="font-medium text-gray-900 truncate">{e.subject}</div>
                  <div className="text-sm text-gray-500 truncate">{e.sender_email}</div>
                </div>
                <div className="flex items-center gap-3 ml-4">
                  <span className="text-sm text-gray-400">{e.received_at ? new Date(e.received_at).toLocaleDateString() : ''}</span>
                  <RiskBadge level={e.classification as any} score={e.risk_score} />
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
