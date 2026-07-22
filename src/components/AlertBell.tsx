import { useState, useRef, useEffect } from 'react';
import { useAlerts } from '../context/AlertContext';
import { Link } from 'react-router-dom';

export default function AlertBell() {
  const { alerts, unreadCount, markAllRead, dismissAlert, clearAlerts } = useAlerts();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => { setOpen(!open); if (!open) markAllRead(); }}
        className="relative p-2 rounded-lg hover:bg-slate-800 transition-colors"
        title="Alerts"
      >
        <svg className="w-6 h-6 text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 w-5 h-5 rounded-full bg-red-500 text-white text-xs font-bold flex items-center justify-center animate-pulse-ring">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-96 bg-white rounded-xl shadow-xl border border-gray-200 z-50 overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
            <h3 className="font-semibold text-gray-900">Notifications</h3>
            <div className="flex items-center gap-2">
              <button onClick={clearAlerts} className="text-xs text-gray-500 hover:text-gray-700">Clear all</button>
              <Link to="/alerts" onClick={() => setOpen(false)} className="text-xs text-blue-600 hover:underline">View all</Link>
            </div>
          </div>

          <div className="max-h-96 overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="p-8 text-center text-gray-400 text-sm">No alerts</div>
            ) : (
              alerts.map((alert) => (
                <div key={alert.id} className={`p-3 border-b border-gray-100 hover:bg-gray-50 ${!alert.read ? 'bg-blue-50/50' : ''}`}>
                  <div className="flex items-start gap-3">
                    <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
                      alert.type === 'malicious' ? 'bg-red-100' : alert.type === 'phishing' ? 'bg-red-50' : 'bg-blue-100'
                    }`}>
                      <svg className={`w-5 h-5 ${
                        alert.type === 'malicious' ? 'text-red-700' : alert.type === 'phishing' ? 'text-red-600' : 'text-blue-600'
                      }`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium text-gray-900">{alert.title}</span>
                        <button onClick={() => dismissAlert(alert.id)} className="text-gray-300 hover:text-gray-500">
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        </button>
                      </div>
                      <p className="text-xs text-gray-600 mt-0.5">{alert.message}</p>
                      {alert.sender && <p className="text-xs text-gray-400 mt-0.5">From: {alert.sender}</p>}
                      <div className="flex items-center gap-2 mt-1">
                        {alert.email_id && (
                          <Link to={`/emails/${alert.email_id}`} onClick={() => setOpen(false)}
                            className="text-xs text-blue-600 hover:underline">View email</Link>
                        )}
                        <span className="text-xs text-gray-400">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
