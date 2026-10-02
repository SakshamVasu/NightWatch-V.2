/**
 * Client-facing security report generator.
 *
 * Produces a self-contained, print-styled HTML document from a ParsedScan and
 * opens it in a new window with the browser's print dialog, so the user can
 * "Save as PDF". Everything is derived from the parsed scan — no invented data.
 * Report content is defensive (findings + remediation), suitable to hand to an
 * employer/client; offensive tool/video links stay in the app UI, not here.
 */
import type { ParsedScan, Vulnerability } from './types';

export interface ReportMeta {
  assessmentName?: string;
  reportId?: string;
  clientName?: string;
  preparedBy?: string;
  includeAppendix?: boolean;
  includeConfirmed?: boolean;
  includePotential?: boolean;
}

const esc = (s: unknown) =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

/** Format a Date in Indian Standard Time, e.g. "27 Sep 2026, 03:45 PM IST". */
function istString(d: Date): string {
  try {
    const s = d.toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
    });
    return `${s} IST`;
  } catch {
    return d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  }
}

/** Best-effort: render a scan's date string in IST; fall back to the raw text. */
function scanDateIst(raw?: string): string {
  if (!raw) return '—';
  // Try to normalize common nmap forms so Date can parse them.
  let s = raw.trim();
  // "2026-09-26 23:14 +0530" -> "2026-09-26T23:14:00+05:30"
  const m1 = s.match(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})(?::(\d{2}))?\s*([+-]\d{2})(\d{2})$/);
  if (m1) s = `${m1[1]}T${m1[2]}:${m1[3] || '00'}${m1[4]}:${m1[5]}`;
  const d = new Date(s);
  if (!Number.isNaN(d.getTime())) return istString(d);
  return raw; // unparseable — show as captured
}

const sevColor: Record<string, string> = {
  CRITICAL: '#b91c1c',
  HIGH: '#c2410c',
  MEDIUM: '#a16207',
  LOW: '#444444',
  INFO: '#555555',
  UNRATED: '#777777',
};
const prioColor: Record<string, string> = {
  Immediate: '#b91c1c',
  High: '#c2410c',
  Medium: '#a16207',
  Low: '#444444',
};

/** Build the full HTML string for the report. */
export function buildReportHtml(scan: ParsedScan, meta: ReportMeta = {}): string {
  const host = scan.hosts[0];
  const s = scan.stats;
  const now = new Date();
  const confirmed = scan.vulnerabilities.filter((v) => v.confidence === 'CONFIRMED');
  const potential = scan.vulnerabilities.filter((v) => v.confidence === 'POTENTIAL');
  const includedVulns = [
    ...(meta.includeConfirmed === false ? [] : confirmed),
    ...(meta.includePotential === false ? [] : potential),
  ];

  const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNRATED'];
  const sevCounts = sevOrder
    .map((sev) => ({ sev, n: includedVulns.filter((v) => v.severity === sev).length }))
    .filter((x) => x.n > 0);

  const vulnSection = (title: string, list: Vulnerability[], note: string) =>
    list.length
      ? `
    <h2>${esc(title)} <span class="count">(${list.length})</span></h2>
    <p class="note">${esc(note)}</p>
    ${list.map(vulnBlock).join('')}
  `
      : '';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Security Report — ${esc(host?.ip || 'scan')}</title>
<style>
  @page { margin: 20mm 18mm; }
  * { box-sizing: border-box; }
  body { font-family: 'Times New Roman', Times, serif; color: #111111; line-height: 1.55;
         font-size: 12.5px; margin: 0; }
  h1 { font-size: 27px; margin: 0 0 6px; color: #000; letter-spacing: 0.01em; }
  h2 { font-size: 17px; margin: 26px 0 10px; padding-bottom: 5px; border-bottom: 1.5px solid #000;
       color: #000; page-break-after: avoid; }
  h3 { font-size: 14px; margin: 0 0 4px; color: #000; }
  h4 { font-size: 11.5px; margin: 10px 0 2px; text-transform: uppercase; letter-spacing: .05em;
       color: #333; font-weight: bold; }
  p { margin: 0 0 8px; }
  .note { color: #555; font-style: italic; font-size: 11.5px; }
  .count { color: #666; font-weight: normal; font-size: 14px; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 11.5px; }
  th, td { border: 1px solid #999; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #efefef; font-size: 10.5px; text-transform: uppercase; letter-spacing: .04em; }
  .cover { border-top: 4px solid #000; border-bottom: 1px solid #000; padding: 14px 0 16px; margin-bottom: 10px; }
  .eyebrow { text-transform: uppercase; letter-spacing: .28em; font-size: 10px; color: #555; margin: 0 0 6px; }
  .sub { color: #333; font-size: 13.5px; margin-top: 4px; }
  .kv { display: grid; grid-template-columns: 180px 1fr; gap: 3px 14px; font-size: 12.5px; margin-top: 14px; }
  .kv dt { color: #555; }
  .kv dd { margin: 0; }
  .badge { display: inline-block; padding: 1px 7px; border-radius: 2px; color: #fff;
           font-size: 10px; font-weight: bold; }
  .finding { border: 1px solid #999; border-left: 4px solid #555; border-radius: 2px;
             padding: 12px 14px; margin: 12px 0; page-break-inside: avoid; }
  .finding.confirmed { border-left-color: #b91c1c; }
  .finding.potential { border-left-color: #a16207; }
  .meta-row { font-size: 10.5px; color: #555; margin: 2px 0 8px; }
  ul { margin: 4px 0 8px; padding-left: 20px; }
  li { margin: 2px 0; }
  pre { background: #f5f5f5; border: 1px solid #ddd; border-radius: 2px; padding: 6px 8px;
        font-family: 'Courier New', monospace; font-size: 10.5px; white-space: pre-wrap;
        word-break: break-word; margin: 4px 0; }
  .summary-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 12px 0; }
  .scard { border: 1px solid #999; border-radius: 2px; padding: 10px; text-align: center; }
  .scard .n { font-size: 24px; font-weight: bold; color: #000; }
  .scard .l { font-size: 9px; text-transform: uppercase; letter-spacing: .06em; color: #555; }
  .footer { margin-top: 30px; padding-top: 8px; border-top: 1px solid #999; font-size: 10px; color: #777; }
  .disclaimer { border: 1px solid #999; border-left: 4px solid #000; padding: 9px 12px;
                font-size: 11px; color: #222; margin: 14px 0; background: #fafafa; }
  @media print { .noprint { display: none; } }
</style></head>
<body>

<div class="noprint" style="background:#111;color:#fff;padding:10px 14px;font-family:'Times New Roman',serif;font-size:13px;display:flex;justify-content:space-between;align-items:center;">
  <span>Report ready — use your browser's Print dialog and choose “Save as PDF”.</span>
  <button onclick="window.print()" style="background:#fff;border:none;color:#000;font-weight:bold;padding:6px 14px;border-radius:3px;cursor:pointer;font-family:inherit;">Print / Save as PDF</button>
</div>

<div style="padding: 0 4px;">
  <div class="cover">
    <p class="eyebrow">Night Watch · Confidential Security Assessment</p>
    <h1>Network Security Assessment Report</h1>
    <p class="sub">Prepared for <strong>${esc(meta.clientName || '—')}</strong>${
      meta.preparedBy ? ` &nbsp;·&nbsp; Prepared by <strong>${esc(meta.preparedBy)}</strong>` : ''
    }</p>
    <dl class="kv">
      <dt>Target host</dt><dd>${esc(host?.ip || '—')}${host?.hostnames?.length ? ` (${esc(host.hostnames.join(', '))})` : ''}</dd>
      ${meta.assessmentName ? `<dt>Assessment</dt><dd>${esc(meta.assessmentName)}</dd>` : ''}
      ${meta.reportId ? `<dt>Report reference</dt><dd>${esc(meta.reportId)}</dd>` : ''}
      <dt>Operating system</dt><dd>${esc(host?.os || 'Not determined')}</dd>
      <dt>Scan date</dt><dd>${esc(scanDateIst(scan.scan.startTime))}</dd>
      <dt>Scanner</dt><dd>Nmap ${esc(scan.scan.nmapVersion || '')}</dd>
      <dt>Report generated</dt><dd>${esc(istString(now))}</dd>
    </dl>
  </div>

  <div class="disclaimer">
    <strong>Confidential.</strong> This report documents the results of an authorized security scan.
    “Confirmed” findings were positively identified by scanner checks; “potential” findings are
    associated with detected software versions and require validation before they are treated as
    exploitable. This assessment reflects the point in time of the scan only.
  </div>

  ${meta.includeConfirmed === false || meta.includePotential === false ? '<p class="note">Executive summary metrics describe the full scan. Detailed finding sections and remediation reflect the finding sections selected for this report.</p>' : ''}

  <h2>1. Executive Summary</h2>
  <p>${esc(execSummary(scan))}</p>
  <div class="summary-cards">
    <div class="scard"><div class="n">${s.hostsUp}</div><div class="l">Hosts Up</div></div>
    <div class="scard"><div class="n">${s.openPorts}</div><div class="l">Open Ports</div></div>
    <div class="scard"><div class="n" style="color:#b91c1c">${s.confirmed}</div><div class="l">Confirmed</div></div>
    <div class="scard"><div class="n" style="color:#a16207">${s.potential}</div><div class="l">Potential</div></div>
  </div>

  <h2>2. Risk Overview</h2>
  ${
    sevCounts.length
      ? `<p>Findings are distributed across the following severity levels:</p>
        <table><thead><tr><th style="width:140px">Severity</th><th>Count</th></tr></thead><tbody>${sevCounts
          .map(
            (x) =>
              `<tr><td><span class="badge" style="background:${sevColor[x.sev]}">${x.sev}</span></td><td>${x.n}</td></tr>`
          )
          .join('')}</tbody></table>`
      : '<p class="note">No severity-rated findings.</p>'
  }

  <h2>3. Prioritized Remediation</h2>
  <p class="note">The highest-impact actions first. Full detail follows in the selected finding sections.</p>
  ${remediationTable(includedVulns)}

  ${meta.includeConfirmed === false ? '' : vulnSection(
    '4. Confirmed Findings',
    confirmed,
    'These were positively identified by scanner checks and should be treated as real.'
  )}
  ${meta.includePotential === false ? '' : vulnSection(
    `${meta.includeConfirmed === false ? '4' : '5'}. Potential Findings (version-associated)`,
    potential,
    'These CVEs are associated with detected software versions. Confirm the exact build and patch level before treating them as exploitable.'
  )}

  ${
    meta.includeAppendix !== false
      ? `<h2>Appendix A — Open Ports &amp; Services</h2>${portTable(scan)}`
      : ''
  }

  <div class="footer">
    Generated by Night Watch on ${esc(istString(now))} · Findings derived solely from the provided
    Nmap scan output for ${esc(host?.ip || 'the target')}. This document is confidential.
  </div>
</div>

<script>window.addEventListener('load', function(){ setTimeout(function(){ try{ window.print(); }catch(e){} }, 400); });<\/script>
</body></html>`;
}

function execSummary(scan: ParsedScan): string {
  const s = scan.stats;
  const host = scan.hosts[0];
  const parts: string[] = [];
  parts.push(
    `An authorized network scan of ${host?.ip || 'the target'} identified ${s.openPorts} open ${
      s.openPorts === 1 ? 'port' : 'ports'
    } exposing ${s.services} ${s.services === 1 ? 'service' : 'services'}.`
  );
  if (s.confirmed > 0) {
    parts.push(
      `The assessment positively confirmed ${s.confirmed} ${
        s.confirmed === 1 ? 'vulnerability' : 'vulnerabilities'
      }, including issues that could allow an attacker to take control of the host. These require immediate attention.`
    );
  } else {
    parts.push('No vulnerabilities were positively confirmed by scanner checks.');
  }
  if (s.potential > 0) {
    parts.push(
      `A further ${s.potential} ${
        s.potential === 1 ? 'service was' : 'services were'
      } found running software versions associated with known CVEs; these should be validated and patched.`
    );
  }
  parts.push(
    'Prioritized remediation guidance is provided below. Addressing the confirmed and immediate-priority items first will most reduce risk.'
  );
  return parts.join(' ');
}

function remediationTable(vulns: Vulnerability[]): string {
  const order = { Immediate: 0, High: 1, Medium: 2, Low: 3 } as Record<string, number>;
  const rows = vulns
    .filter((v) => v.remediation)
    .slice()
    .sort((a, b) => (order[a.remediation!.priority] ?? 9) - (order[b.remediation!.priority] ?? 9));
  if (!rows.length) return '<p class="note">No remediation items.</p>';
  return `<table><thead><tr><th style="width:90px">Priority</th><th>Finding</th><th style="width:80px">Port</th><th style="width:90px">Confidence</th></tr></thead><tbody>${rows
    .map(
      (v) =>
        `<tr><td><span class="badge" style="background:${prioColor[v.remediation!.priority]}">${
          v.remediation!.priority
        }</span></td><td>${esc(v.title)}</td><td>${v.port ? `${v.port}/${esc(v.protocol || '')}` : '—'}</td><td>${
          v.confidence === 'CONFIRMED' ? 'Confirmed' : 'Potential'
        }</td></tr>`
    )
    .join('')}</tbody></table>`;
}

function vulnBlock(v: Vulnerability): string {
  const cls = v.confidence === 'CONFIRMED' ? 'confirmed' : 'potential';
  const cves = v.cves.slice(0, 25);
  return `
  <div class="finding ${cls}">
    <h3>${esc(v.title)}
      <span class="badge" style="background:${sevColor[v.severity]}">${v.severity}</span>
      ${
        v.remediation
          ? `<span class="badge" style="background:${prioColor[v.remediation.priority]}">${v.remediation.priority}</span>`
          : ''
      }
    </h3>
    <div class="meta-row">${esc(v.host)}${v.port ? `:${v.port}/${esc(v.protocol || '')}` : ''}${
      v.service ? ` · ${esc(v.service)}` : ''
    } · Source: ${esc(v.source)}${v.disclosureDate ? ` · Disclosed ${esc(v.disclosureDate)}` : ''}</div>

    <h4>What was found</h4>
    <p>${esc(v.explanation)}</p>

    ${
      v.remediation
        ? `<h4>Business impact</h4><p>${esc(v.remediation.impact)}</p>
    <h4>Recommended remediation</h4><ul>${v.remediation.fixes.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>`
        : ''
    }

    <h4>Evidence from scan</h4>
    <pre>${esc(v.evidence)}</pre>

    ${
      cves.length
        ? `<h4>Associated CVEs${v.confidence === 'POTENTIAL' ? ' (version-associated)' : ''}</h4>
      <p style="font-family:'Courier New',monospace;font-size:10px;">${cves
        .map((c) => esc(c.id) + (c.exploit ? ' *' : ''))
        .join(', ')}${v.cves.length > 25 ? ` … +${v.cves.length - 25} more` : ''}${
            v.cves.some((c) => c.exploit) ? '<br><span class="note">* public exploit reference exists</span>' : ''
          }</p>`
        : ''
    }
  </div>`;
}

function portTable(scan: ParsedScan): string {
  const open = scan.ports.filter((p) => p.state.startsWith('open'));
  if (!open.length) return '<p class="note">No open ports.</p>';
  return `<table><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>${open
    .map(
      (p) =>
        `<tr><td>${p.port}/${esc(p.protocol)}</td><td>${esc(p.service || '—')}</td><td>${esc(
          p.product || '—'
        )}</td><td>${esc(p.version || '—')}</td></tr>`
    )
    .join('')}</tbody></table>`;
}

/** Open the report in a new window (triggers its own print dialog). */
export function openReport(scan: ParsedScan, meta: ReportMeta = {}): boolean {
  const html = buildReportHtml(scan, meta);
  const w = window.open('', '_blank');
  if (!w) return false; // popup blocked
  w.document.open();
  w.document.write(html);
  w.document.close();
  return true;
}
