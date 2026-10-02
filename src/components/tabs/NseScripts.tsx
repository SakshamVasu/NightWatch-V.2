import { useDeferredValue, useMemo, useState } from 'react';
import { Search, Terminal } from 'lucide-react';
import type { ParsedScan } from '../../parser';
import { CopyButton, EmptyState } from '../ui';
import { ExploitToggle } from '../ExploitBlock';

export default function NseScripts({ scan }: { scan: ParsedScan }) {
  const [q, setQ] = useState('');
  const deferredQ = useDeferredValue(q);
  const [visibleCount, setVisibleCount] = useState(100);
  const scripts = useMemo(() => {
    if (!deferredQ.trim()) return scan.nseScripts;
    const t = deferredQ.toLowerCase();
    return scan.nseScripts.filter((s) =>
      `${s.id} ${s.host} ${s.port ?? ''} ${s.state ?? ''} ${s.output}`.toLowerCase().includes(t)
    );
  }, [scan.nseScripts, deferredQ]);

  if (!scan.nseScripts.length)
    return <EmptyState title="No NSE scripts found" icon={<Terminal size={34} />} />;

  const stateColor = (state?: string) => {
    if (!state) return 'bg-base-700 text-slate-400';
    if (/NOT VULNERABLE/i.test(state)) return 'bg-emerald-500/15 text-emerald-400';
    if (/LIKELY/i.test(state)) return 'bg-sev-medium/15 text-sev-medium';
    if (/VULNERABLE/i.test(state)) return 'bg-sev-critical/15 text-sev-critical';
    return 'bg-base-700 text-slate-400';
  };

  return (
    <div>
      <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative">
          <Search size={15} className="absolute left-2.5 top-2.5 text-slate-500" />
          <input
            className="input !w-72 !pl-8 max-w-[70vw]"
            aria-label="Search NSE scripts and output"
            placeholder="Search scripts & output…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <span className="text-xs text-slate-500">
          {scripts.length} of {scan.nseScripts.length} scripts
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {scripts.slice(0, visibleCount).map((s, i) => (
          <div key={`${s.id}-${s.host}-${s.port}-${i}`} className="card overflow-hidden">
            <div className="flex items-center justify-between border-b border-edge bg-base-900/50 px-3 py-2">
              <span className="font-mono text-sm font-medium text-accent">{s.id}</span>
              {s.state && <span className={`badge ${stateColor(s.state)}`}>{s.state}</span>}
            </div>
            <div className="px-3 py-2">
              <div className="mb-1.5 flex items-center justify-between text-[11px] text-slate-500">
                <span>
                  {s.host}
                  {s.port ? `:${s.port}/${s.protocol}` : ` · ${s.scope}`}
                  {s.cves.length ? ` · ${s.cves.length} CVE${s.cves.length > 1 ? 's' : ''}` : ''}
                </span>
                <CopyButton text={s.output} />
              </div>
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded bg-base-950 p-2 font-mono text-[11px] leading-relaxed text-slate-300">
                {s.output || '(no output)'}
              </pre>
              <ExploitToggle scriptId={s.id} title={s.id} cves={s.cves} />
            </div>
          </div>
        ))}
      </div>
      {scripts.length > visibleCount && (
        <button className="btn mt-3 w-full justify-center" onClick={() => setVisibleCount((n) => n + 100)}>
          Show next {Math.min(100, scripts.length - visibleCount)} ({scripts.length - visibleCount} remaining)
        </button>
      )}
    </div>
  );
}
