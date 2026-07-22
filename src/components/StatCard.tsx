interface Props {
  label: string;
  value: string | number;
  icon?: React.ReactNode;
  tone?: 'neutral' | 'good' | 'warn' | 'bad' | 'info';
  sub?: string;
}

const tones: Record<string, string> = {
  neutral: 'border-slate-800 bg-slate-900/40',
  good: 'border-emerald-500/20 bg-emerald-500/5',
  warn: 'border-amber-500/20 bg-amber-500/5',
  bad: 'border-rose-500/20 bg-rose-500/5',
  info: 'border-cyan-500/20 bg-cyan-500/5',
};

export default function StatCard({ label, value, icon, tone = 'neutral', sub }: Props) {
  return (
    <div className={`rounded-xl border p-4 ${tones[tone]}`}>
      <div className="flex items-start justify-between">
        <p className="text-xs text-slate-400 uppercase tracking-wide">{label}</p>
        {icon && <span className="text-slate-500">{icon}</span>}
      </div>
      <p className="mt-2 text-2xl font-semibold text-slate-100">{value}</p>
      {sub && <p className="mt-1 text-[11px] text-slate-500">{sub}</p>}
    </div>
  );
}
