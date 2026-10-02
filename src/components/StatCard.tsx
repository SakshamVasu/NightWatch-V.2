import type { ReactNode } from 'react';

export function StatCard({
  label,
  value,
  tone = 'slate',
  icon,
}: {
  label: string;
  value: ReactNode;
  tone?: 'slate' | 'accent' | 'critical' | 'potential' | 'info' | 'emerald';
  icon?: ReactNode;
}) {
  const tones: Record<string, string> = {
    slate: 'text-white',
    accent: 'text-accent',
    critical: 'text-sev-critical',
    potential: 'text-sev-medium',
    info: 'text-conf-info',
    emerald: 'text-emerald-400',
  };
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          {label}
        </p>
        {icon && <span className="text-slate-500">{icon}</span>}
      </div>
      <p className={`mt-2 text-3xl font-bold tabular-nums ${tones[tone]}`}>{value}</p>
    </div>
  );
}

/** A simple horizontal bar for the attack-surface summary. */
export function Meter({
  label,
  value,
  max,
  color,
}: {
  label: string;
  value: number;
  max: number;
  color: string;
}) {
  const pct = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="text-slate-300">{label}</span>
        <span className="tabular-nums text-slate-400">{value}</span>
      </div>
      <div className="h-2.5 w-full overflow-hidden rounded-full bg-base-800">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}
