import { useMemo, useState } from 'react';
import type { Confidence, Finding, ParsedScan } from '../../parser';
import { ConfidenceBadge } from '../Badges';
import { EmptyState } from '../ui';
import { ListChecks } from 'lucide-react';

const GROUPS: { key: Confidence; label: string; color: string }[] = [
  { key: 'CONFIRMED', label: 'Confirmed', color: 'text-conf-confirmed' },
  { key: 'POTENTIAL', label: 'Potential', color: 'text-conf-potential' },
  { key: 'INFORMATIONAL', label: 'Informational', color: 'text-conf-info' },
];

export default function Findings({ scan }: { scan: ParsedScan }) {
  const [cat, setCat] = useState<string>('all');
  const [visibleCount, setVisibleCount] = useState(100);

  const categories = useMemo(
    () => ['all', ...Array.from(new Set(scan.findings.map((f) => f.category))).sort()],
    [scan.findings]
  );

  const filtered = useMemo(
    () => (cat === 'all' ? scan.findings : scan.findings.filter((f) => f.category === cat)),
    [scan.findings, cat]
  );
  const visible = useMemo(() => filtered.slice(0, visibleCount), [filtered, visibleCount]);
  const sourceOutputs = useMemo(
    () => new Map<string, string>(scan.nseScripts.map((s) => [`${s.host}:${s.port ?? ''}:NSE: ${s.id}`, s.output] as const)),
    [scan.nseScripts]
  );
  const portSourceLines = useMemo(() => indexPortSourceLines(scan), [scan.rawOutput]);

  if (!scan.findings.length)
    return <EmptyState title="No findings" icon={<ListChecks size={34} />} />;

  return (
    <div>
      <div className="mb-4 flex flex-wrap gap-1">
        {categories.map((c) => (
          <button
            key={c}
            onClick={() => setCat(c)}
            aria-pressed={cat === c}
            className={`rounded-md px-2.5 py-1.5 text-xs font-medium capitalize transition ${
              cat === c ? 'bg-accent text-base-950' : 'bg-base-800 text-slate-300 hover:text-white'
            }`}
          >
            {c}
          </button>
        ))}
      </div>

      <div className="space-y-6">
        {GROUPS.map((g) => {
          const items = visible.filter((f) => f.confidence === g.key);
          if (!items.length) return null;
          return (
            <div key={g.key}>
              <h3 className={`mb-2 flex items-center gap-2 text-sm font-semibold ${g.color}`}>
                {g.label}
                <span className="badge bg-base-800 text-slate-400">{filtered.filter((f) => f.confidence === g.key).length}</span>
              </h3>
              <div className="card divide-y divide-edge/60">
                {items.map((f) => (
                  <FindingRow
                    key={f.id}
                    f={f}
                    sourceOutput={sourceOutputs.get(`${f.host}:${f.port ?? ''}:${f.source}`)}
                    rawSourceLine={f.port ? portSourceLines.get(`${f.host}:${f.port}:${f.protocol || ''}`) : undefined}
                  />
                ))}
              </div>
            </div>
          );
        })}
        {filtered.length > visibleCount && (
          <button className="btn w-full justify-center" onClick={() => setVisibleCount((n) => n + 100)}>
            Show next {Math.min(100, filtered.length - visibleCount)} ({filtered.length - visibleCount} remaining)
          </button>
        )}
      </div>
    </div>
  );
}

function FindingRow({ f, sourceOutput, rawSourceLine }: { f: Finding; sourceOutput?: string; rawSourceLine?: string }) {
  return (
    <div className="flex items-start gap-3 px-4 py-2.5">
      <span className="mt-0.5 badge shrink-0 bg-base-800 text-slate-400">{f.category}</span>
      <div className="min-w-0 flex-1">
        <p className="text-sm text-slate-100">{f.title}</p>
        {f.detail && <p className="truncate text-xs text-slate-500">{f.detail}</p>}
        {(sourceOutput || rawSourceLine) && (
          <details className="mt-1">
            <summary className="cursor-pointer text-xs text-accent">View source: {f.source}</summary>
            <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded bg-base-950 p-2 font-mono text-[11px] text-slate-300">{sourceOutput || rawSourceLine}</pre>
          </details>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <span className="hidden text-[11px] text-slate-500 sm:inline">
          {f.host}
          {f.port ? `:${f.port}` : ''}
        </span>
        <ConfidenceBadge value={f.confidence} />
      </div>
    </div>
  );
}

/** Index original port lines once so findings can show the exact captured row. */
function indexPortSourceLines(scan: ParsedScan): Map<string, string> {
  const found = new Map<string, string>();
  let currentHost = '';
  const put = (host: string, port: string | number, protocol: string, line: string) => {
    const key = `${host}:${port}:${protocol}`;
    if (host && !found.has(key)) found.set(key, line.trim());
  };
  for (const line of scan.rawOutput.split(/\r?\n/)) {
    if (/^\s*<host\b/i.test(line)) currentHost = '';
    const normalHost = line.match(/^Nmap scan report for\s+(.+)$/i);
    if (normalHost) {
      const target = normalHost[1].trim();
      currentHost = target.match(/\(([^)]+)\)$/)?.[1] || target;
    }
    const gnmapHost = line.match(/^Host:\s+(\S+)/);
    if (gnmapHost) currentHost = gnmapHost[1];
    const addressTag = line.match(/<address\b[^>]*>/i)?.[0];
    if (addressTag) {
      const address = addressTag.match(/\baddr="([^"]+)"/i)?.[1];
      const type = addressTag.match(/\baddrtype="([^"]+)"/i)?.[1];
      if (address && type?.toLowerCase() === 'ipv4') currentHost = address;
      else if (address && type?.toLowerCase() === 'ipv6' && !currentHost) currentHost = address;
    }

    const normalPort = line.match(/^\s*(\d+)\/(tcp|udp|sctp)\s+/i);
    if (normalPort) put(currentHost, normalPort[1], normalPort[2].toLowerCase(), line);

    const gnmapPorts = line.match(/\bPorts:\s*([^\t]+)/i)?.[1];
    if (gnmapPorts) {
      for (const entry of gnmapPorts.split(/,\s*/)) {
        const m = entry.match(/^(\d+)\/[^/]+\/(tcp|udp|sctp)\//i);
        if (m) put(currentHost, m[1], m[2].toLowerCase(), line);
      }
    }

    const xmlPort = line.match(/<port\b[^>]*\bportid="(\d+)"/i);
    const xmlProtocol = line.match(/<port\b[^>]*\bprotocol="([^"]+)"/i);
    if (xmlPort) put(currentHost, xmlPort[1], xmlProtocol?.[1] || '', line);
  }
  return found;
}
