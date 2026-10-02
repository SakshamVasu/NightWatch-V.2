import type { OsNetwork, ParsedScan } from '../../parser';
import { EmptyState } from '../ui';
import { Cpu, Route } from 'lucide-react';

export default function OsNetworkTab({ scan }: { scan: ParsedScan }) {
  if (!scan.osNetwork.length) return <EmptyState title="No OS/network data" icon={<Cpu size={34} />} />;
  return (
    <div className="space-y-4">
      {scan.osNetwork.map((o) => (
        <HostOs key={o.host} o={o} />
      ))}
    </div>
  );
}

function HostOs({ o }: { o: OsNetwork }) {
  return (
    <div className="card p-5">
      <h3 className="mb-4 font-mono text-lg font-semibold text-white">{o.host}</h3>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div>
          <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            <Cpu size={13} /> OS &amp; Detection
          </p>
          <dl className="space-y-2 text-sm">
            <Row k="OS details" v={o.os} />
            <Row k="OS family" v={o.osFamily} />
            <Row k="Accuracy" v={o.accuracy ? `${o.accuracy}%` : undefined} />
            <Row k="MAC" v={o.mac} />
            <Row k="Vendor" v={o.vendor} />
            <Row k="Latency" v={o.latency} />
            <Row k="Uptime" v={o.uptime} />
            <Row k="Distance" v={o.distance} />
            <Row k="TCP sequence" v={o.tcpSequence} />
            <Row k="IP ID sequence" v={o.ipIdSequence} />
          </dl>
          {o.osCpe.length > 0 && (
            <div className="mt-3">
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                OS CPE
              </p>
              <div className="flex flex-wrap gap-1.5">
                {o.osCpe.map((c) => (
                  <span key={c} className="badge normal-case bg-base-800 font-mono text-[10px] text-slate-400">
                    {c}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div>
          <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            <Route size={13} /> Traceroute
          </p>
          {o.traceroute.length ? (
            <div className="overflow-hidden rounded-lg border border-edge">
              <table className="w-full">
                <thead className="bg-base-900/60">
                  <tr>
                    <th className="th">Hop</th>
                    <th className="th">RTT</th>
                    <th className="th">Address</th>
                    <th className="th">Hostname</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge/60">
                  {o.traceroute.map((h) => (
                    <tr key={h.hop}>
                      <td className="td font-mono">{h.hop}</td>
                      <td className="td text-slate-400">{h.rtt || '—'}</td>
                      <td className="td font-mono text-slate-200">{h.address || '—'}</td>
                      <td className="td text-slate-400">{h.hostname || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-slate-500">No traceroute in this scan.</p>
          )}
        </div>
      </div>
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
