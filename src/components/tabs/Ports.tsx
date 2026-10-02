import { useDeferredValue, useMemo, useState } from 'react';
import { ChevronDown, ChevronUp, Search, X } from 'lucide-react';
import type { NseScript, ParsedScan, Port } from '../../parser';
import { StateBadge } from '../Badges';
import { CopyButton, EmptyState } from '../ui';
import { ExploitToggle } from '../ExploitBlock';

type SortKey = 'port' | 'state' | 'service' | 'product';
type Filter = 'all' | 'open' | 'closed' | 'filtered';

export default function Ports({ scan }: { scan: ParsedScan }) {
  const [q, setQ] = useState('');
  const deferredQ = useDeferredValue(q);
  const [filter, setFilter] = useState<Filter>('open');
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'port', dir: 1 });
  const [selected, setSelected] = useState<Port | null>(null);
  const [visibleCount, setVisibleCount] = useState(100);

  const rows = useMemo(() => {
    let r = scan.ports.slice();
    if (filter !== 'all') r = r.filter((p) => p.state.includes(filter));
    if (deferredQ.trim()) {
      const t = deferredQ.toLowerCase();
      r = r.filter((p) =>
        [p.port, p.service, p.product, p.version, p.extra, p.protocol, p.host]
          .filter(Boolean)
          .join(' ')
          .toLowerCase()
          .includes(t)
      );
    }
    r.sort((a, b) => {
      const k = sort.key;
      const av = k === 'port' ? a.port : (a[k] || '').toString().toLowerCase();
      const bv = k === 'port' ? b.port : (b[k] || '').toString().toLowerCase();
      if (av < bv) return -1 * sort.dir;
      if (av > bv) return 1 * sort.dir;
      return 0;
    });
    return r;
  }, [scan.ports, deferredQ, filter, sort]);

  const toggleSort = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, dir: (s.dir * -1) as 1 | -1 } : { key, dir: 1 }));

  const counts = useMemo(() => ({
    all: scan.ports.length,
    open: scan.ports.filter((p) => p.state.includes('open')).length,
    closed: scan.ports.filter((p) => p.state === 'closed').length,
    filtered: scan.ports.filter((p) => p.state.includes('filtered')).length,
  }), [scan.ports]);

  if (!scan.ports.length)
    return <EmptyState title="No ports parsed" hint="The scan did not contain a port table." />;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className={selected ? 'lg:col-span-2' : 'lg:col-span-3'}>
        <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative">
            <Search size={15} className="absolute left-2.5 top-2.5 text-slate-500" />
            <input
              className="input !w-64 !pl-8 max-w-[70vw]"
              aria-label="Search ports and services"
              placeholder="Search ports, services…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <div className="flex flex-wrap gap-1">
            {(['all', 'open', 'closed', 'filtered'] as Filter[]).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                aria-pressed={filter === f}
                className={`rounded-md px-2.5 py-1.5 text-xs font-medium capitalize transition ${
                  filter === f
                    ? 'bg-accent text-base-950'
                    : 'bg-base-800 text-slate-300 hover:text-white'
                }`}
              >
                {f} ({counts[f]})
              </button>
            ))}
          </div>
        </div>

        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px]">
              <thead className="border-b border-edge bg-base-900/60">
                <tr>
                  <SortableTh label="Port" col="port" sort={sort} onClick={toggleSort} />
                  <SortableTh label="State" col="state" sort={sort} onClick={toggleSort} />
                  <SortableTh label="Service" col="service" sort={sort} onClick={toggleSort} />
                  <SortableTh label="Product" col="product" sort={sort} onClick={toggleSort} />
                  <th className="th">Version</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge/60">
                {rows.slice(0, visibleCount).map((p) => (
                  <tr
                    key={`${p.host}-${p.port}-${p.protocol}`}
                    onClick={() => setSelected(p)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setSelected(p);
                      }
                    }}
                    tabIndex={0}
                    aria-label={`Open details for ${p.port}/${p.protocol} on ${p.host}`}
                    aria-selected={selected?.port === p.port && selected?.host === p.host}
                    className={`cursor-pointer transition hover:bg-base-800/60 ${
                      selected?.port === p.port && selected?.host === p.host ? 'bg-base-800' : ''
                    }`}
                  >
                    <td className="td font-mono font-medium text-white">
                      {p.port}
                      <span className="text-slate-500">/{p.protocol}</span>
                    </td>
                    <td className="td">
                      <StateBadge state={p.state} />
                    </td>
                    <td className="td text-accent">{p.service || '—'}</td>
                    <td className="td">{p.product || '—'}</td>
                    <td className="td text-slate-400">{p.version || '—'}</td>
                  </tr>
                ))}
                {!rows.length && (
                  <tr>
                    <td colSpan={5} className="td py-8 text-center text-slate-500">
                      No ports match.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
        {rows.length > visibleCount && (
          <button className="btn mt-2 w-full justify-center" onClick={() => setVisibleCount((n) => n + 100)}>
            Show next {Math.min(100, rows.length - visibleCount)} ({rows.length - visibleCount} remaining)
          </button>
        )}
      </div>

      {selected && (
        <PortDetail
          port={selected}
          scripts={scan.nseScripts.filter(
            (s) => s.host === selected.host && s.port === selected.port
          )}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

function SortableTh({
  label,
  col,
  sort,
  onClick,
}: {
  label: string;
  col: SortKey;
  sort: { key: SortKey; dir: 1 | -1 };
  onClick: (k: SortKey) => void;
}) {
  return (
    <th className="th">
      <button type="button" className="inline-flex items-center gap-1 hover:text-slate-200" onClick={() => onClick(col)} aria-label={`Sort by ${label}${sort.key === col ? (sort.dir === 1 ? ', ascending' : ', descending') : ''}`}>
        {label}
        {sort.key === col &&
          (sort.dir === 1 ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
      </button>
    </th>
  );
}

function PortDetail({
  port,
  scripts,
  onClose,
}: {
  port: Port;
  scripts: NseScript[];
  onClose: () => void;
}) {
  return (
    <div className="card h-fit p-4 lg:sticky lg:top-4">
      <div className="mb-3 flex items-start justify-between">
        <div>
          <h3 className="font-mono text-lg font-semibold text-white">
            {port.port}/{port.protocol}
          </h3>
          <p className="text-xs text-slate-400">on {port.host}</p>
        </div>
        <button className="rounded p-1 text-slate-500 hover:bg-base-700 hover:text-white" onClick={onClose} aria-label="Close port details">
          <X size={16} />
        </button>
      </div>
      <dl className="space-y-2 text-sm">
        <Row k="State" v={port.state} />
        <Row k="Service" v={port.service} />
        <Row k="Product" v={port.product} />
        <Row k="Version" v={port.version} />
        <Row k="Extra info" v={port.extra} />
      </dl>

      {scripts.length > 0 && (
        <div className="mt-4">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            NSE scripts ({scripts.length})
          </p>
          <div className="space-y-2">
            {scripts.map((s) => (
              <details key={s.id} className="rounded-lg border border-edge bg-base-900">
                <summary className="flex cursor-pointer items-center justify-between px-3 py-2 text-xs font-medium text-slate-200">
                  <span className="font-mono text-accent">{s.id}</span>
                  {s.state && (
                    <span
                      className={`badge ${
                        /NOT/i.test(s.state)
                          ? 'bg-emerald-500/15 text-emerald-400'
                          : 'bg-sev-critical/15 text-sev-critical'
                      }`}
                    >
                      {s.state}
                    </span>
                  )}
                </summary>
                <div className="border-t border-edge p-2">
                  <div className="mb-1 flex justify-end">
                    <CopyButton text={s.output} />
                  </div>
                  <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded bg-base-950 p-2 font-mono text-[11px] leading-relaxed text-slate-300">
                    {s.output || '(no output)'}
                  </pre>
                </div>
              </details>
            ))}
          </div>
        </div>
      )}

      {port.state.startsWith('open') && (
        <ExploitToggle
          scriptId={scripts[0]?.id || port.service || ''}
          title={port.product || port.service || `port ${port.port}`}
          cves={scripts.flatMap((s) => s.cves)}
          service={port.service}
          product={[port.product, port.version].filter(Boolean).join(' ') || undefined}
        />
      )}
    </div>
  );
}

function Row({ k, v }: { k: string; v?: string }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-slate-500">{k}</dt>
      <dd className="text-right text-slate-200">{v || '—'}</dd>
    </div>
  );
}
