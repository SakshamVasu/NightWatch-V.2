import { useDeferredValue, useMemo, useState } from 'react';
import { Download, Search } from 'lucide-react';
import type { ParsedScan } from '../../parser';
import { CopyButton } from '../ui';

export default function RawOutput({ scan, fileName }: { scan: ParsedScan; fileName: string }) {
  const [q, setQ] = useState('');
  const deferredQ = useDeferredValue(q);
  const [visibleCount, setVisibleCount] = useState(500);
  const lines = useMemo(() => scan.rawOutput.split('\n'), [scan.rawOutput]);

  const matches = useMemo(() => {
    if (!deferredQ.trim()) return null;
    const t = deferredQ.toLowerCase();
    const found: number[] = [];
    lines.forEach((l, i) => l.toLowerCase().includes(t) && found.push(i));
    return found;
  }, [lines, deferredQ]);
  const shownRows = useMemo(() => {
    const indices = matches ? matches.slice(0, visibleCount) : Array.from({ length: Math.min(visibleCount, lines.length) }, (_, i) => i);
    return indices.map((i) => [i, lines[i]] as const);
  }, [lines, matches, visibleCount]);

  const download = () => {
    const blob = new Blob([scan.rawOutput], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName || 'nmap_scan.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-edge bg-base-900/50 px-3 py-2">
        <div className="relative">
          <Search size={15} className="absolute left-2.5 top-2.5 text-slate-500" />
          <input
            className="input !w-64 !pl-8 !py-1.5"
            placeholder="Search raw output…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-2">
          {matches && (
            <span className="text-xs text-slate-500">{matches.length} matching line(s)</span>
          )}
          <CopyButton text={scan.rawOutput} label="Copy all" />
          <button className="btn !px-2 !py-1 text-xs" onClick={download}>
            <Download size={13} /> Download
          </button>
        </div>
      </div>
      <div className="max-h-[calc(100vh-220px)] overflow-auto">
        <table className="w-full border-collapse font-mono text-[11px] leading-relaxed">
          <tbody>
            {shownRows.map(([i, l]) => {
              const hit = !!matches;
              return (
                <tr key={i} className={hit ? 'bg-accent/10' : ''}>
                  <td className="select-none border-r border-edge/60 px-2 text-right align-top text-slate-600">
                    {i + 1}
                  </td>
                  <td className="whitespace-pre-wrap break-all px-3 text-slate-300">{l || ' '}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {(matches ? matches.length : lines.length) > visibleCount && (
          <button className="btn m-3 w-[calc(100%-1.5rem)] justify-center" onClick={() => setVisibleCount((n) => n + 500)}>
            Show next 500 ({(matches ? matches.length : lines.length) - visibleCount} remaining)
          </button>
        )}
      </div>
    </div>
  );
}
