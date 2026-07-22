import { useEffect, useState } from 'react';
import { fetchAuditLogs } from '../lib/api';
import { ScrollText, RefreshCw } from 'lucide-react';

export default function AuditLogs() {
  const [logs, setLogs] = useState<Awaited<ReturnType<typeof fetchAuditLogs>>>([]);
  const [loading, setLoading] = useState(true);

  async function load() {
    try {
      setLogs(await fetchAuditLogs(100));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { load(); }, []);

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Audit Logs</h1>
          <p className="text-sm text-slate-500">Append-only record of every significant system action</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-3 py-2 text-sm rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200">
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>

      {loading ? (
        <p className="text-sm text-slate-500">Loading...</p>
      ) : logs.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-10 text-center">
          <ScrollText className="h-8 w-8 text-slate-600 mx-auto mb-2" />
          <p className="text-sm text-slate-500">No audit entries yet.</p>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden">
          <div className="divide-y divide-slate-800/50 max-h-[70vh] overflow-auto">
            {logs.map((l) => (
              <div key={l.id} className="p-3 flex items-start gap-3 hover:bg-slate-800/20">
                <span className="text-xs text-slate-500 font-mono whitespace-nowrap mt-0.5">
                  {new Date(l.created_at).toLocaleString()}
                </span>
                <div className="flex-1 min-w-0">
                  <span className="text-sm text-cyan-300 font-medium">{l.action}</span>
                  {l.entity_type && <span className="text-xs text-slate-500 ml-2">{l.entity_type}</span>}
                  {Object.keys(l.details as object).length > 0 && (
                    <pre className="text-[11px] text-slate-500 mt-1 font-mono whitespace-pre-wrap">
                      {JSON.stringify(l.details)}
                    </pre>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
