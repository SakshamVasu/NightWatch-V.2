import { useState, type ReactNode } from 'react';
import { Check, Copy, Inbox } from 'lucide-react';

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="btn !px-2 !py-1 text-xs"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* clipboard blocked — ignore */
        }
      }}
      title="Copy to clipboard"
    >
      {done ? <Check size={13} /> : <Copy size={13} />}
      {done ? 'Copied' : label}
    </button>
  );
}

export function EmptyState({
  title,
  hint,
  icon,
}: {
  title: string;
  hint?: string;
  icon?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-edge bg-base-900/40 py-16 text-center">
      <div className="mb-3 text-slate-600">{icon ?? <Inbox size={34} />}</div>
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {hint && <p className="mt-1 max-w-md text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

export function SectionTitle({ children, sub }: { children: ReactNode; sub?: string }) {
  return (
    <div className="mb-3">
      <h2 className="text-lg font-semibold text-white">{children}</h2>
      {sub && <p className="text-xs text-slate-400">{sub}</p>}
    </div>
  );
}
