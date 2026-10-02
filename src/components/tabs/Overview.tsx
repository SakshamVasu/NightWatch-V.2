import {
  Server,
  Network,
  Boxes,
  ShieldAlert,
  ShieldQuestion,
  Info,
  Clock,
  Terminal,
  Cpu,
  Bug,
} from 'lucide-react';
import type { ParsedScan } from '../../parser';
import { StatCard, Meter } from '../StatCard';
import { SectionTitle } from '../ui';

/** Inline SVG donut — no external chart library needed. */
function DonutChart({ data, size = 176 }: { data: { name: string; value: number; color: string }[]; size?: number }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total) return null;
  const R = 70, r = 45, cx = size / 2, cy = size / 2;
  let a = -Math.PI / 2;
  const seg = data.map((d) => {
    const frac = d.value / total;
    const a2 = a + frac * Math.PI * 2;
    const x1 = cx + R * Math.cos(a), y1 = cy + R * Math.sin(a);
    const x2 = cx + R * Math.cos(a2), y2 = cy + R * Math.sin(a2);
    const xi1 = cx + r * Math.cos(a2), yi1 = cy + r * Math.sin(a2);
    const xi2 = cx + r * Math.cos(a), yi2 = cy + r * Math.sin(a);
    const large = frac > 0.5 ? 1 : 0;
    const mid = (a + a2) / 2;
    a = a2;
    const path = `M ${x1} ${y1} A ${R} ${R} 0 ${large} 1 ${x2} ${y2} L ${xi1} ${yi1} A ${r} ${r} 0 ${large} 0 ${xi2} ${yi2} Z`;
    return { path, color: d.color, name: d.name, value: d.value, pct: Math.round(frac * 100), lx: cx + ((R + r) / 2) * Math.cos(mid), ly: cy + ((R + r) / 2) * Math.sin(mid) };
  });
  return (
    <svg viewBox={`0 0 ${size} ${size}`} width="100%" height={size}>
      {seg.map((s, i) => (
        <path key={i} d={s.path} fill={s.color}>
          <title>{s.name}: {s.value} ({s.pct}%)</title>
        </path>
      ))}
      {seg.filter((s) => s.pct >= 8).map((s, i) => (
        <text key={i} x={s.lx} y={s.ly} fill="#0b111c" fontSize="11" fontWeight="700" textAnchor="middle" dominantBaseline="middle">
          {s.pct}%
        </text>
      ))}
    </svg>
  );
}

/** Inline SVG horizontal bar chart. */
function HBarChart({ data, height = 224 }: { data: { name: string; cves: number }[]; height?: number }) {
  if (!data.length) return null;
  const max = Math.max(...data.map((d) => d.cves), 1);
  const rowH = Math.min(28, (height - 10) / data.length);
  const labelW = 76, pad = 8;
  return (
    <svg viewBox={`0 0 400 ${height}`} width="100%" height={height} preserveAspectRatio="none" style={{ overflow: 'visible' }}>
      {data.map((d, i) => {
        const y = i * rowH + 2;
        const w = Math.max(2, (d.cves / max) * (400 - labelW - pad - 30));
        return (
          <g key={i}>
            <text x={labelW - 6} y={y + rowH / 2} fill="#94a3b8" fontSize="11" textAnchor="end" dominantBaseline="middle">{d.name}</text>
            <rect x={labelW} y={y + 2} width={w} height={rowH - 6} fill="#e5e7eb" rx="2">
              <title>{d.name}: {d.cves} CVEs</title>
            </rect>
            <text x={labelW + w + 5} y={y + rowH / 2} fill="#cbd5e1" fontSize="10" dominantBaseline="middle">{d.cves}</text>
          </g>
        );
      })}
    </svg>
  );
}

export default function Overview({ scan }: { scan: ParsedScan }) {
  const s = scan.stats;
  const meta = scan.scan;
  const host = scan.hosts[0];

  const confData = [
    { name: 'Confirmed', value: s.confirmed, color: '#f43f5e' },
    { name: 'Potential', value: s.potential, color: '#facc15' },
    { name: 'Informational', value: s.informational, color: '#e5e7eb' },
  ].filter((d) => d.value > 0);

  const cveByService = scan.vulnerabilities
    .filter((v) => v.confidence === 'POTENTIAL')
    .map((v) => ({
      name: `${v.service || v.port || '?'}${v.port ? `:${v.port}` : ''}`,
      cves: v.cves.length,
    }))
    .sort((a, b) => b.cves - a.cves)
    .slice(0, 8);

  const maxSurface = Math.max(s.openPorts, s.confirmed, s.potential, s.informational, 1);

  return (
    <div className="space-y-6">
      {/* summary cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard label="Hosts Up" value={s.hostsUp} icon={<Server size={16} />} tone="emerald" />
        <StatCard label="Open Ports" value={s.openPorts} icon={<Network size={16} />} tone="accent" />
        <StatCard label="Services" value={s.services} icon={<Boxes size={16} />} />
        <StatCard label="Confirmed" value={s.confirmed} icon={<ShieldAlert size={16} />} tone="critical" />
        <StatCard label="Potential" value={s.potential} icon={<ShieldQuestion size={16} />} tone="potential" />
        <StatCard label="Informational" value={s.informational} icon={<Info size={16} />} tone="info" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* scan metadata */}
        <div className="card p-5 lg:col-span-2">
          <SectionTitle sub="Parsed directly from the uploaded scan">Scan Overview</SectionTitle>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
            <Field icon={<Server size={14} />} k="Target" v={host?.ip} />
            <Field icon={<Terminal size={14} />} k="Nmap version" v={meta.nmapVersion} />
            <Field icon={<Clock size={14} />} k="Started" v={meta.startTime} />
            <Field icon={<Clock size={14} />} k="Duration" v={meta.duration} />
            <Field icon={<Cpu size={14} />} k="OS detection" v={host?.os} />
            <Field icon={<Network size={14} />} k="Hostname" v={host?.hostnames.join(', ') || '—'} />
            <Field k="Open ports" v={String(s.openPorts)} />
            <Field k="Closed ports" v={s.closedPorts ? s.closedPorts.toLocaleString() : '—'} />
            <Field k="Filtered ports" v={s.filteredPorts ? String(s.filteredPorts) : '—'} />
            <Field k="Hosts scanned" v={String(s.hostsTotal)} />
          </dl>
          {meta.command && (
            <div className="mt-4 overflow-x-auto rounded-lg border border-edge bg-base-950 p-3">
              <code className="whitespace-pre text-xs text-slate-300">{meta.command}</code>
            </div>
          )}
        </div>

        {/* confidence donut */}
        <div className="card p-5">
          <SectionTitle sub="How much the scan actually proves">Findings by confidence</SectionTitle>
          {confData.length ? (
            <>
              <div className="h-44">
                <DonutChart data={confData} />
              </div>
              <div className="mt-2 space-y-1">
                {confData.map((d) => (
                  <div key={d.name} className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-2 text-slate-300">
                      <span className="h-2.5 w-2.5 rounded-sm" style={{ background: d.color }} />
                      {d.name}
                    </span>
                    <span className="tabular-nums text-slate-400">{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="py-8 text-center text-sm text-slate-500">No findings.</p>
          )}
        </div>
      </div>

      {/* attack surface meters + CVE bar */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="card p-5">
          <SectionTitle>Attack surface</SectionTitle>
          <div className="space-y-4">
            <Meter label="Open ports" value={s.openPorts} max={maxSurface} color="#e5e7eb" />
            <Meter label="Confirmed findings" value={s.confirmed} max={maxSurface} color="#f43f5e" />
            <Meter label="Potential findings" value={s.potential} max={maxSurface} color="#facc15" />
            <Meter label="Informational" value={s.informational} max={maxSurface} color="#64748b" />
          </div>
        </div>

        <div className="card p-5">
          <SectionTitle sub="Version-associated CVE counts per service">
            CVE exposure by service
          </SectionTitle>
          {cveByService.length ? (
            <div className="h-56">
              <HBarChart data={cveByService} />
            </div>
          ) : (
            <div className="flex h-56 items-center justify-center text-sm text-slate-500">
              <Bug size={16} className="mr-2" /> No version-associated CVEs found.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Field({ k, v, icon }: { k: string; v?: string; icon?: React.ReactNode }) {
  return (
    <div>
      <dt className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
        {icon}
        {k}
      </dt>
      <dd className="mt-0.5 text-sm text-slate-200">{v || '—'}</dd>
    </div>
  );
}
