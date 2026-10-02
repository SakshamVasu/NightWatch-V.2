import { useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { Search, X } from 'lucide-react';
import type { ParsedScan } from '../parser';

interface Hit {
  tab: string;
  type: string;
  title: string;
  detail: string;
}

/** Global search across ports, services, vulns, CVEs, NSE output and findings. */
export function GlobalSearch({
  scan,
  onClose,
  onNavigate,
}: {
  scan: ParsedScan;
  onClose: () => void;
  onNavigate: (tab: string) => void;
}) {
  const [q, setQ] = useState('');
  const deferredQ = useDeferredValue(q);
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    inputRef.current?.focus();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'Tab') {
        const elements = dialogRef.current?.querySelectorAll<HTMLElement>(
          'button:not(:disabled), input:not(:disabled), [tabindex]:not([tabindex="-1"])'
        );
        if (!elements?.length) return;
        const first = elements[0];
        const last = elements[elements.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      previousFocus?.focus();
    };
  }, [onClose]);

  const hits = useMemo<Hit[]>(() => {
    const t = deferredQ.trim().toLowerCase();
    if (!t) return [];
    const out: Hit[] = [];

    for (const p of scan.ports) {
      if (out.length >= 60) break;
      if (`${p.port} ${p.service} ${p.product} ${p.version} ${p.protocol}`.toLowerCase().includes(t))
        out.push({
          tab: 'ports',
          type: 'Port',
          title: `${p.port}/${p.protocol} ${p.service || ''}`,
          detail: [p.product, p.version].filter(Boolean).join(' ') || p.state,
        });
    }
    for (const v of scan.vulnerabilities) {
      if (out.length >= 60) break;
      const cveHit = v.cves.some((c) => c.id.toLowerCase().includes(t));
      if (v.title.toLowerCase().includes(t) || cveHit || (v.service || '').toLowerCase().includes(t))
        out.push({
          tab: 'vulns',
          type: v.confidence === 'CONFIRMED' ? 'Confirmed' : 'Potential',
          title: v.title,
          detail: `${v.host}${v.port ? `:${v.port}` : ''}${cveHit ? ` · ${v.cves.filter((c) => c.id.toLowerCase().includes(t)).map((c) => c.id).slice(0, 3).join(', ')}` : ''}`,
        });
    }
    for (const s of scan.nseScripts) {
      if (out.length >= 60) break;
      if (`${s.id} ${s.output}`.toLowerCase().includes(t))
        out.push({
          tab: 'nse',
          type: 'NSE',
          title: s.id,
          detail: `${s.host}${s.port ? `:${s.port}` : ''}${s.state ? ` · ${s.state}` : ''}`,
        });
    }
    for (const f of scan.findings) {
      if (out.length >= 60) break;
      if (`${f.title} ${f.detail} ${f.category}`.toLowerCase().includes(t))
        out.push({
          tab: 'findings',
          type: f.category,
          title: f.title,
          detail: f.detail,
        });
    }
    for (const w of scan.webFindings) {
      if (out.length >= 60) break;
      const all = [...w.directories, ...w.technologies, w.server].join(' ').toLowerCase();
      if (all.includes(t))
        out.push({
          tab: 'web',
          type: 'Web',
          title: `${w.port} · ${w.server || 'HTTP'}`,
          detail: w.directories.filter((d) => d.toLowerCase().includes(t)).join(', ') || 'match',
        });
    }
    return out.slice(0, 60);
  }, [deferredQ, scan]);

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-12 sm:pt-24" onClick={onClose}>
      <div
        role="dialog"
        ref={dialogRef}
        aria-modal="true"
        aria-labelledby="global-search-title"
        className="w-full max-w-2xl overflow-hidden rounded-xl border border-edge bg-base-850 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="global-search-title" className="sr-only">Search scan data</h2>
        <div className="flex items-center gap-2 border-b border-edge px-4 py-3">
          <Search size={18} className="text-slate-500" />
          <input
            ref={inputRef}
            aria-label="Search scan data"
            className="flex-1 bg-transparent text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none"
            placeholder="Search everything — try “vsftpd”, “3306”, or a CVE id…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <button onClick={onClose} className="rounded p-1 text-slate-500 hover:text-white">
            <X size={16} aria-hidden="true" /><span className="sr-only">Close search</span>
          </button>
        </div>
        <div className="max-h-[60vh] overflow-auto">
          {q.trim() && hits.length === 0 && (
            <p className="px-4 py-8 text-center text-sm text-slate-500">No matches for “{q}”.</p>
          )}
          {hits.map((h, i) => (
            <button
              key={i}
              onClick={() => onNavigate(h.tab)}
              className="flex w-full items-center gap-3 border-b border-edge/40 px-4 py-2.5 text-left transition hover:bg-base-800"
            >
              <span className="badge shrink-0 bg-base-800 text-slate-400">{h.type}</span>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm text-slate-100">{h.title}</p>
                <p className="truncate text-xs text-slate-500">{h.detail}</p>
              </div>
            </button>
          ))}
          {!q.trim() && (
            <p className="px-4 py-8 text-center text-xs text-slate-600">
              Search ports, services, vulnerabilities, CVEs, NSE output, web paths and findings.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
