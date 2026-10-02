import type { ParsedScan } from '../../parser';
import { EmptyState } from '../ui';
import { Boxes } from 'lucide-react';
import { ExploitToggle } from '../ExploitBlock';

export default function Services({ scan }: { scan: ParsedScan }) {
  if (!scan.services.length)
    return <EmptyState title="No services detected" icon={<Boxes size={34} />} />;

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
      {scan.services.map((g) => (
        <div key={g.name} className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="font-semibold text-white">{g.name}</h3>
            <span className="badge bg-accent/15 text-accent">
              {g.ports.length} port{g.ports.length > 1 ? 's' : ''}
            </span>
          </div>
          <div className="space-y-2">
            {g.ports.map((p) => (
              <div key={`${p.port}-${p.protocol}`} className="rounded-lg border border-edge bg-base-900 p-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm font-medium text-slate-100">
                    {p.port}/{p.protocol}
                  </span>
                  {p.scripts.length > 0 && (
                    <span className="badge bg-base-700 text-slate-400">
                      {p.scripts.length} NSE
                    </span>
                  )}
                </div>
                {(p.product || p.version) && (
                  <p className="mt-1 text-xs text-slate-400">
                    {[p.product, p.version].filter(Boolean).join(' ')}
                  </p>
                )}
                {p.extra && <p className="mt-0.5 text-[11px] text-slate-500">{p.extra}</p>}
                {p.scripts.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {p.scripts.slice(0, 6).map((sid) => (
                      <span key={sid} className="badge normal-case bg-base-800 text-[10px] text-slate-500">
                        {sid}
                      </span>
                    ))}
                    {p.scripts.length > 6 && (
                      <span className="text-[10px] text-slate-600">+{p.scripts.length - 6}</span>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
          <ExploitToggle
            scriptId={g.ports[0]?.scripts[0] || g.name}
            title={g.ports[0]?.product || g.name}
            service={g.name}
            product={[g.ports[0]?.product, g.ports[0]?.version].filter(Boolean).join(' ') || undefined}
          />
        </div>
      ))}
    </div>
  );
}
