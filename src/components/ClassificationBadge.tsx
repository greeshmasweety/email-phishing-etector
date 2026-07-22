import type { Classification } from '../lib/types';

const styles: Record<Classification, { bg: string; text: string; ring: string; label: string }> = {
  safe: { bg: 'bg-emerald-500/10', text: 'text-emerald-300', ring: 'ring-emerald-500/30', label: 'Safe' },
  suspicious: { bg: 'bg-amber-500/10', text: 'text-amber-300', ring: 'ring-amber-500/30', label: 'Suspicious' },
  phishing: { bg: 'bg-rose-500/10', text: 'text-rose-300', ring: 'ring-rose-500/30', label: 'Phishing' },
};

export default function ClassificationBadge({ classification }: { classification: Classification }) {
  const s = styles[classification];
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ring-1 ${s.bg} ${s.text} ${s.ring}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.text.replace('text', 'bg')}`} />
      {s.label}
    </span>
  );
}
