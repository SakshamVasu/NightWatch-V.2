import type { ReactNode } from 'react';
import type { Confidence, Severity } from '../parser';

const sevClasses: Record<Severity, string> = {
  CRITICAL: 'bg-sev-critical/15 text-sev-critical border border-sev-critical/40',
  HIGH: 'bg-sev-high/15 text-sev-high border border-sev-high/40',
  MEDIUM: 'bg-sev-medium/15 text-sev-medium border border-sev-medium/40',
  LOW: 'bg-sev-low/15 text-sev-low border border-sev-low/40',
  INFO: 'bg-sev-info/15 text-slate-300 border border-slate-500/40',
  UNRATED: 'bg-sev-unrated/20 text-slate-400 border border-slate-500/30',
};

const confClasses: Record<Confidence, string> = {
  CONFIRMED: 'bg-conf-confirmed/15 text-conf-confirmed border border-conf-confirmed/40',
  POTENTIAL: 'bg-conf-potential/15 text-conf-potential border border-conf-potential/40',
  INFORMATIONAL: 'bg-conf-info/15 text-conf-info border border-conf-info/40',
  UNKNOWN: 'bg-conf-unknown/15 text-slate-400 border border-slate-500/30',
};

export function SeverityBadge({ value }: { value: Severity }) {
  return <span className={`badge ${sevClasses[value]}`}>{value}</span>;
}

export function ConfidenceBadge({ value }: { value: Confidence }) {
  const label =
    value === 'INFORMATIONAL' ? 'INFO' : value.charAt(0) + value.slice(1).toLowerCase();
  return <span className={`badge ${confClasses[value]}`}>{label}</span>;
}

export function StateBadge({ state }: { state: string }) {
  const s = state.toLowerCase();
  const cls = s.startsWith('open')
    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/40'
    : s.includes('filtered')
      ? 'bg-amber-500/15 text-amber-400 border border-amber-500/40'
      : 'bg-slate-600/20 text-slate-400 border border-slate-500/30';
  return <span className={`badge ${cls}`}>{state}</span>;
}

export function Pill({ children, tone = 'slate' }: { children: ReactNode; tone?: 'slate' | 'accent' | 'red' | 'amber' }) {
  const tones = {
    slate: 'bg-base-800 text-slate-300 border border-edge',
    accent: 'bg-accent/15 text-accent border border-accent/40',
    red: 'bg-sev-critical/15 text-sev-critical border border-sev-critical/40',
    amber: 'bg-sev-medium/15 text-sev-medium border border-sev-medium/40',
  };
  return <span className={`badge normal-case ${tones[tone]}`}>{children}</span>;
}
