import { useState } from 'react';
import { X } from 'lucide-react';
import type { Host, ParsedScan } from '../../parser';
import { EmptyState } from '../ui';

export default function Hosts({ scan }: { scan: ParsedScan }) {
  const [sel, setSel] = useState<Host | null>(null);
  const hosts = scan.hosts.filter((h) => !h.ip.startsWith('('));
  if (!hosts.length) return <EmptyState title="No hosts parsed" />;

  const portsFor = (ip: string) => scan.ports.filter((p) => p.host === ip && p.state.includes('open'));

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className={sel ? 'lg:col-span-2' : 'lg:col-span-3'}>
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px]">
              <thead className="border-b border-edge bg-base-900/60">
                <tr>
                  <th className="th">Host</th>
                  <th className="th">Status</th>
                  <th className="th">Latency</th>
                  <th className="th">Hostname</th>
                  <th className="th">OS</th>
                  <th className="th">MAC / Vendor</th>
                  <th className="th">Open</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge/60">
                {hosts.map((h) => (
                  <tr
                    key={h.ip}
                    onClick={() => setSel(h)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setSel(h);
                      }
                    }}
                    tabIndex={0}
                    aria-label={`Open details for host ${h.ip}`}
                    aria-selected={sel?.ip === h.ip}
                    className="cursor-pointer transition hover:bg-base-800/60"
                  >
                    <td className="td font-mono font-medium text-white">{h.ip}</td>
                    <td className="td">
                      <span
                        className={`badge ${
                          h.status === 'up'
                            ? 'bg-emerald-500/15 text-emerald-400'
                            : 'bg-slate-600/20 text-slate-400'
                        }`}
                      >
                        {h.status || 'unknown'}
                      </span>
                    </td>
                    <td className="td text-slate-400">{h.latency || '—'}</td>
                    <td className="td">{h.hostnames.join(', ') || '—'}</td>
                    <td className="td text-slate-300">{h.os || '—'}</td>
                    <td className="td text-slate-400">
                      {h.mac ? `${h.mac}${h.vendor ? ` (${h.vendor})` : ''}` : '—'}
                    </td>
                    <td className="td font-mono text-accent">{portsFor(h.ip).length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {sel && (
        <div className="card h-fit p-4 lg:sticky lg:top-4">
          <div className="mb-3 flex items-start justify-between">
            <h3 className="font-mono text-lg font-semibold text-white">{sel.ip}</h3>
            <button
              className="rounded p-1 text-slate-500 hover:bg-base-700 hover:text-white"
              onClick={() => setSel(null)}
            >
              <X size={16} />
            </button>
          </div>
          <dl className="space-y-2 text-sm">
            <Row k="Status" v={sel.status} />
            <Row k="Latency" v={sel.latency} />
            <Row k="Hostnames" v={sel.hostnames.join(', ')} />
            <Row k="OS" v={sel.os} />
            <Row k="OS family" v={sel.osFamily} />
            <Row k="MAC" v={sel.mac} />
            <Row k="Vendor" v={sel.vendor} />
            <Row k="Uptime" v={sel.uptime} />
            <Row k="Distance" v={sel.distance} />
          </dl>
          <div className="mt-4">
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Open ports ({portsFor(sel.ip).length})
            </p>
            <div className="flex flex-wrap gap-1.5">
              {portsFor(sel.ip).map((p) => (
                <span
                  key={p.port}
                  className="badge normal-case bg-base-800 text-slate-300"
                  title={`${p.service || ''} ${p.product || ''} ${p.version || ''}`}
                >
                  {p.port} {p.service}
                </span>
              ))}
            </div>
          </div>
        </div>
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
