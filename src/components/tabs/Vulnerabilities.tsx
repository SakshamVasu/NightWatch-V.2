import { useMemo, useState } from 'react';
import { ChevronRight, ExternalLink, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { Confidence, ParsedScan, Vulnerability } from '../../parser';
import { ConfidenceBadge, SeverityBadge } from '../Badges';
import { EmptyState } from '../ui';
import { ExploitBlock } from '../ExploitBlock';

export default function Vulnerabilities({ scan }: { scan: ParsedScan }) {
  const [conf, setConf] = useState<Confidence | 'ALL'>('ALL');
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [visibleCount, setVisibleCount] = useState(100);

  const rows = useMemo(
    () => (conf === 'ALL' ? scan.vulnerabilities : scan.vulnerabilities.filter((v) => v.confidence === conf)),
    [scan.vulnerabilities, conf]
  );

  const counts = useMemo(() => ({
    ALL: scan.vulnerabilities.length,
    CONFIRMED: scan.vulnerabilities.filter((v) => v.confidence === 'CONFIRMED').length,
    POTENTIAL: scan.vulnerabilities.filter((v) => v.confidence === 'POTENTIAL').length,
  }), [scan.vulnerabilities]);
  const sourceOutputs = useMemo(
    () => new Map<string, string>(scan.nseScripts.map((s) => [`${s.host}:${s.port ?? ''}:NSE: ${s.id}`, s.output] as const)),
    [scan.nseScripts]
  );

  if (!scan.vulnerabilities.length)
    return (
      <EmptyState
        title="No vulnerabilities parsed"
        hint="No NSE vulnerability states or version-associated CVEs were found in this scan."
        icon={<ShieldCheck size={34} />}
      />
    );

  const toggle = (id: string) =>
    setOpen((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });

  return (
    <div>
      <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-300/90">
        <strong>Confidence matters.</strong> “Confirmed” means an NSE script reported a VULNERABLE
        state. “Potential” means a CVE is associated with a detected software version — a lead to
        verify, not proof of exploitability.
      </div>

      <div className="mb-3 flex flex-wrap gap-1">
        {(['ALL', 'CONFIRMED', 'POTENTIAL'] as const).map((c) => (
          <button
            key={c}
            onClick={() => setConf(c)}
            aria-pressed={conf === c}
            className={`rounded-md px-2.5 py-1.5 text-xs font-medium capitalize transition ${
              conf === c ? 'bg-accent text-base-950' : 'bg-base-800 text-slate-300 hover:text-white'
            }`}
          >
            {c.toLowerCase()} ({counts[c] ?? rows.length})
          </button>
        ))}
      </div>

      <div className="space-y-3">
        {rows.slice(0, visibleCount).map((v) => (
          <VulnCard
            key={v.id}
            v={v}
            sourceOutput={sourceOutputs.get(`${v.host}:${v.port ?? ''}:${v.source}`)}
            open={open.has(v.id)}
            onToggle={() => toggle(v.id)}
          />
        ))}
        {rows.length > visibleCount && (
          <button className="btn w-full justify-center" onClick={() => setVisibleCount((n) => n + 100)}>
            Show next {Math.min(100, rows.length - visibleCount)} ({rows.length - visibleCount} remaining)
          </button>
        )}
      </div>
    </div>
  );
}

function VulnCard({ v, sourceOutput, open, onToggle }: { v: Vulnerability; sourceOutput?: string; open: boolean; onToggle: () => void }) {
  const confirmed = v.confidence === 'CONFIRMED';
  return (
    <div
      className={`card overflow-hidden border-l-4 ${
        confirmed ? 'border-l-sev-critical' : 'border-l-sev-medium'
      }`}
    >
      <button onClick={onToggle} className="flex w-full items-center gap-3 p-4 text-left">
        <ChevronRight
          size={16}
          className={`shrink-0 text-slate-500 transition ${open ? 'rotate-90' : ''}`}
        />
        <ShieldAlert size={18} className={confirmed ? 'text-sev-critical' : 'text-sev-medium'} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-white">{v.title}</span>
            <ConfidenceBadge value={v.confidence} />
            <SeverityBadge value={v.severity} />
            {v.severitySource === 'heuristic' && (
              <span className="badge bg-base-700 text-slate-400" title="Derived from CVSS score, not stated by Nmap">
                heuristic
              </span>
            )}
          </div>
          <p className="mt-0.5 truncate text-xs text-slate-400">
            {v.host}
            {v.port ? `:${v.port}/${v.protocol}` : ''} · {v.source}
            {v.cves.length ? ` · ${v.cves.length} CVE${v.cves.length > 1 ? 's' : ''}` : ''}
          </p>
        </div>
      </button>

      {open && (
        <div className="border-t border-edge px-4 py-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div>
              <Label>Evidence (from scan)</Label>
              <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded bg-base-950 p-2.5 font-mono text-[11px] leading-relaxed text-slate-300">
                {v.evidence}
              </pre>
              {sourceOutput && (
                <details className="mt-2">
                  <summary className="cursor-pointer text-xs text-accent">View complete NSE source output</summary>
                  <pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded bg-base-950 p-2.5 font-mono text-[11px] leading-relaxed text-slate-300">{sourceOutput}</pre>
                </details>
              )}
              {v.disclosureDate && (
                <p className="mt-2 text-xs text-slate-500">Disclosed: {v.disclosureDate}</p>
              )}
            </div>
            <div>
              <Label>Analysis</Label>
              <p className="mt-1 text-sm leading-relaxed text-slate-300">{v.explanation}</p>
            </div>
          </div>

          {v.cves.length > 0 && (
            <div className="mt-4">
              <Label>Associated CVEs {v.confidence === 'POTENTIAL' && '(version-associated)'}</Label>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {v.cves.slice(0, 40).map((c) => (
                  <a
                    key={c.id}
                    href={c.url || `https://nvd.nist.gov/vuln/detail/${c.id}`}
                    target="_blank"
                    rel="noreferrer"
                    className={`badge normal-case transition hover:border-accent ${
                      c.exploit
                        ? 'bg-sev-critical/10 text-sev-critical border border-sev-critical/40'
                        : 'bg-base-800 text-slate-300 border border-edge'
                    }`}
                    title={c.exploit ? 'Public exploit referenced' : undefined}
                  >
                    {c.id}
                    {c.score !== undefined && <span className="opacity-70">·{c.score}</span>}
                    {c.exploit && <ExternalLink size={9} />}
                  </a>
                ))}
                {v.cves.length > 40 && (
                  <span className="text-xs text-slate-500">+{v.cves.length - 40} more</span>
                )}
              </div>
            </div>
          )}

          {v.exploitation && <ExploitBlock ex={v.exploitation} />}
        </div>
      )}
    </div>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{children}</p>
  );
}
