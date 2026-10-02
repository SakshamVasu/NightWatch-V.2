import type { ParsedScan, WebFinding } from '../../parser';
import { EmptyState } from '../ui';
import { Globe, FolderTree, Lock, ShieldQuestion } from 'lucide-react';
import { ExploitToggle } from '../ExploitBlock';

export default function Web({ scan }: { scan: ParsedScan }) {
  if (!scan.webFindings.length)
    return <EmptyState title="No web services found" icon={<Globe size={34} />} />;

  return (
    <div className="space-y-4">
      {scan.webFindings.map((w) => (
        <WebCard key={`${w.port}`} w={w} host={scan.hosts[0]?.ip || ''} />
      ))}
    </div>
  );
}

function WebCard({ w, host }: { w: WebFinding; host: string }) {
  const scheme = w.port === 443 || w.port === 8443 ? 'https' : 'http';
  const base = `${scheme}://${host}${[80, 443].includes(w.port) ? '' : `:${w.port}`}`;
  return (
    <div className="card p-5">
      <div className="mb-4 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/10 text-accent">
          <Globe size={20} />
        </div>
        <div>
          <h3 className="font-semibold text-white">
            {w.port}/{w.protocol} · {w.server || 'HTTP service'}
          </h3>
          <p className="text-xs text-slate-400">{base}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
        {w.directories.length > 0 && (
          <Block icon={<FolderTree size={13} />} title={`Discovered directories (${w.directories.length})`}>
            <div className="flex flex-wrap gap-1.5">
              {w.directories.map((d) => (
                <a
                  key={d}
                  href={`${base}${d}`}
                  target="_blank"
                  rel="noreferrer"
                  className="badge normal-case bg-base-800 font-mono text-slate-300 hover:border-accent hover:text-accent"
                >
                  {d}
                </a>
              ))}
            </div>
          </Block>
        )}

        {w.technologies.length > 0 && (
          <Block title="Technologies">
            <div className="flex flex-wrap gap-1.5">
              {w.technologies.map((t) => (
                <span key={t} className="badge normal-case bg-base-800 text-slate-300">
                  {t}
                </span>
              ))}
            </div>
          </Block>
        )}

        {w.methods.length > 0 && (
          <Block title="HTTP methods">
            <div className="flex flex-wrap gap-1.5">
              {w.methods.map((m) => (
                <span
                  key={m}
                  className={`badge ${
                    /TRACE|PUT|DELETE/i.test(m)
                      ? 'bg-sev-medium/15 text-sev-medium'
                      : 'bg-base-800 text-slate-300'
                  }`}
                >
                  {m}
                </span>
              ))}
            </div>
          </Block>
        )}

        {Object.keys(w.headers).length > 0 && (
          <Block title="Server headers">
            <dl className="space-y-0.5 text-xs">
              {Object.entries(w.headers).map(([k, v]) => (
                <div key={k} className="flex gap-2">
                  <dt className="shrink-0 font-mono text-slate-500">{k}:</dt>
                  <dd className="truncate font-mono text-slate-300" title={v}>
                    {v}
                  </dd>
                </div>
              ))}
            </dl>
          </Block>
        )}

        {w.auth.length > 0 && (
          <Block icon={<Lock size={13} />} title="Authentication points">
            <ul className="space-y-1 text-xs text-slate-300">
              {w.auth.map((a, i) => (
                <li key={i} className="font-mono">{a}</li>
              ))}
            </ul>
          </Block>
        )}

        {w.tls.length > 0 && (
          <Block icon={<Lock size={13} />} title="SSL/TLS findings">
            <ul className="space-y-1 text-xs text-sev-medium">
              {w.tls.map((t, i) => (
                <li key={i}>{t}</li>
              ))}
            </ul>
          </Block>
        )}

        {w.securityNotes.length > 0 && (
          <Block icon={<ShieldQuestion size={13} />} title="Notes">
            <ul className="space-y-1 text-xs text-slate-400">
              {w.securityNotes.map((n, i) => (
                <li key={i}>{n}</li>
              ))}
            </ul>
          </Block>
        )}

        {w.scripts.length > 0 && (
          <Block title={`Web NSE scripts (${w.scripts.length})`}>
            <div className="flex flex-wrap gap-1">
              {w.scripts.map((s) => (
                <span key={s} className="badge normal-case bg-base-800 text-[10px] text-slate-500">
                  {s}
                </span>
              ))}
            </div>
          </Block>
        )}
      </div>
      <ExploitToggle
        scriptId={w.scripts[0] || 'http'}
        title={w.server || 'web server'}
        service="http"
        product={w.server}
      />
    </div>
  );
}

function Block({
  title,
  icon,
  children,
}: {
  title: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div>
      <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
        {icon}
        {title}
      </p>
      {children}
    </div>
  );
}
