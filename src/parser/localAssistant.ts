/**
 * Local Scan Assistant — answers questions about a parsed scan with NO AI/API.
 *
 * Pure intent-matching over the ParsedScan model. Everything stays in the
 * browser. Returns a plain-text (light markdown) answer string.
 *
 * This is the default chatbot mode; the optional BYO-key AI mode lives in
 * aiChat.ts and uses buildScanContext() from here for grounding.
 */
import type { ParsedScan, Vulnerability } from './types';

export interface ChatMsg {
  role: 'user' | 'assistant';
  content: string;
}

const CONFIRMED = 'CONFIRMED';
const POTENTIAL = 'POTENTIAL';

/** Answer a user question locally from the parsed scan. */
export function answerLocally(scan: ParsedScan, question: string): string {
  const q = question.toLowerCase().trim();
  if (!q) return 'Ask me anything about your scan — try “what are my critical vulnerabilities?”';

  // greetings / help
  if (/^(hi|hello|hey|help|what can you do)\b/.test(q)) return helpText(scan);

  // ---- direct port lookup: "is port 3306 open", "port 22", "3306" ----
  const portMatch = q.match(/\b(?:port\s*)?(\d{1,5})\b/);
  if (portMatch && (/port|open|closed|\bis\b/.test(q) || /^\d+$/.test(q))) {
    return portAnswer(scan, parseInt(portMatch[1], 10));
  }

  // ---- named service/product search takes priority over generic summary ----
  //  ("tell me about mysql" should describe mysql, not print the whole summary)
  const namedEarly = findByKeyword(scan, q);
  if (namedEarly && /\b(about|tell|info|detail|explain|what is|whats|describe)\b/.test(q)) {
    return namedEarly;
  }

  // ---- summary / overview ----
  if (/\b(summary|overview|overall|what did (you|the scan) find|results?)\b/.test(q)) {
    return summaryAnswer(scan);
  }

  // ---- most critical / worst / priority ----
  if (/\b(most )?(critical|worst|dangerous|severe|serious|biggest|top|priority|urgent|first)\b/.test(q)) {
    return criticalAnswer(scan);
  }

  // ---- confirmed vs potential ----
  if (/\bconfirmed\b/.test(q)) return listVulns(scan, CONFIRMED, 'confirmed');
  if (/\bpotential\b/.test(q)) return listVulns(scan, POTENTIAL, 'potential');

  // ---- remediation / fix / prevent ----
  if (/\b(fix|remediat|prevent|patch|mitigat|how (do|to)|secure|harden|solve|remove)\b/.test(q)) {
    return remediationAnswer(scan, q);
  }

  // ---- exploitation / tools ----
  if (/\b(exploit|attack|tool|metasploit|hack|penetrat|how.*(exploit|attack))\b/.test(q)) {
    return exploitationAnswer(scan, q);
  }

  // ---- CVE lookup ----
  const cveMatch = question.match(/CVE-\d{4}-\d{3,7}/i);
  if (cveMatch) return cveAnswer(scan, cveMatch[0].toUpperCase());

  // ---- web / directories ----
  if (/\b(web|http|website|directon|directories|url|apache|nginx|php)\b/.test(q)) {
    return webAnswer(scan);
  }

  // ---- hosts / OS ----
  if (/\b(host|os|operating system|mac|vendor|target|machine)\b/.test(q)) {
    return hostAnswer(scan);
  }

  // ---- services / ports listing ----
  if (/\b(service|port|open port|what.?s running|running)\b/.test(q)) {
    return portsAnswer(scan);
  }

  // ---- named service/product search: "vsftpd", "mysql", "ssh" ----
  const named = findByKeyword(scan, q);
  if (named) return named;

  // fallback
  return (
    `I couldn't map that to your scan data. I answer from what the scan found — try:\n` +
    `• “what are my critical vulnerabilities?”\n` +
    `• “is port 3306 open?”\n` +
    `• “how do I fix the SSL issues?”\n` +
    `• “tell me about vsftpd”\n` +
    `• “show confirmed findings”\n\n` +
    `For open-ended questions, switch to AI mode (top of this panel) and add your own API key.`
  );
}

// ---------------------------------------------------------------------------
function helpText(scan: ParsedScan): string {
  const s = scan.stats;
  return (
    `Hi! I'm your local scan assistant — I answer from your parsed scan, nothing leaves this browser.\n\n` +
    `Your scan of **${scan.hosts[0]?.ip || 'the target'}**: ${s.openPorts} open ports, ` +
    `**${s.confirmed} confirmed** and **${s.potential} potential** vulnerabilities.\n\n` +
    `Try asking: “most critical issue?”, “is port 445 open?”, “how do I fix vsftpd?”, ` +
    `“show potential findings”, or a CVE id. For anything open-ended, switch to AI mode above.`
  );
}

function summaryAnswer(scan: ParsedScan): string {
  const s = scan.stats;
  const h = scan.hosts[0];
  const topSev = scan.vulnerabilities.filter((v) => v.confidence === CONFIRMED).slice(0, 3);
  let out = `**Scan summary — ${h?.ip || 'target'}**\n`;
  out += `• OS: ${h?.os || 'not determined'}\n`;
  out += `• ${s.openPorts} open ports, ${s.services} services\n`;
  out += `• **${s.confirmed} confirmed**, ${s.potential} potential, ${s.informational} informational findings\n`;
  out += `• ${s.cves} associated CVEs total\n`;
  if (topSev.length) {
    out += `\nTop confirmed issues:\n` + topSev.map((v) => `• ${v.title} (${v.port ? `port ${v.port}` : 'host'})`).join('\n');
  }
  return out;
}

function criticalAnswer(scan: ParsedScan): string {
  const confirmed = scan.vulnerabilities.filter((v) => v.confidence === CONFIRMED);
  if (!confirmed.length) {
    const pot = scan.vulnerabilities.filter((v) => v.confidence === POTENTIAL);
    if (!pot.length) return 'No confirmed or potential vulnerabilities were found in this scan.';
    return (
      `No **confirmed** vulnerabilities, but ${pot.length} potential (version-associated) ones exist. ` +
      `The highest-exposure service is ${pot[0].title} (${pot[0].cves.length} CVEs). These need validation before they're treated as exploitable.`
    );
  }
  const rank = { Immediate: 0, High: 1, Medium: 2, Low: 3 } as Record<string, number>;
  const sorted = confirmed
    .slice()
    .sort((a, b) => (rank[a.remediation?.priority || 'Low'] ?? 9) - (rank[b.remediation?.priority || 'Low'] ?? 9));
  let out = `**${confirmed.length} confirmed ${confirmed.length === 1 ? 'vulnerability' : 'vulnerabilities'}** — most urgent first:\n\n`;
  sorted.slice(0, 6).forEach((v, i) => {
    out += `${i + 1}. **${v.title}** — ${v.port ? `port ${v.port}/${v.protocol}` : 'host'}`;
    out += ` [${v.severity}${v.remediation ? `, ${v.remediation.priority}` : ''}]\n`;
    if (v.remediation) out += `   → ${v.remediation.fixes[0]}\n`;
  });
  out += `\nAsk “how do I fix <name>” for full remediation, or open the Vulnerabilities tab.`;
  return out;
}

function listVulns(scan: ParsedScan, conf: string, label: string): string {
  const list = scan.vulnerabilities.filter((v) => v.confidence === conf);
  if (!list.length) return `No ${label} vulnerabilities were found.`;
  let out = `**${list.length} ${label} ${list.length === 1 ? 'finding' : 'findings'}:**\n\n`;
  list.slice(0, 15).forEach((v) => {
    out += `• **${v.title}** — ${v.port ? `port ${v.port}` : 'host'}`;
    if (v.cves.length) out += ` · ${v.cves.length} CVE${v.cves.length > 1 ? 's' : ''}`;
    out += `\n`;
  });
  if (list.length > 15) out += `…and ${list.length - 15} more (see the Vulnerabilities tab).`;
  return out;
}

function remediationAnswer(scan: ParsedScan, q: string): string {
  // Try to target a specific finding named in the question.
  const target = scan.vulnerabilities.find((v) => {
    const words = [v.title, v.service, v.source].join(' ').toLowerCase();
    return v.cves.some((c) => q.includes(c.id.toLowerCase())) || nameHit(q, words);
  });
  if (target && target.remediation) {
    let out = `**How to fix: ${target.title}**\n\n`;
    out += `_Impact:_ ${target.remediation.impact}\n\n`;
    out += `_Priority:_ ${target.remediation.priority}\n\n`;
    out += `_Steps:_\n` + target.remediation.fixes.map((f) => `• ${f}`).join('\n');
    return out;
  }
  // General: list the top remediation items.
  const withRem = scan.vulnerabilities.filter((v) => v.remediation);
  if (!withRem.length) return 'No remediation items — the scan found nothing to fix.';
  const rank = { Immediate: 0, High: 1, Medium: 2, Low: 3 } as Record<string, number>;
  const sorted = withRem.slice().sort((a, b) => (rank[a.remediation!.priority] ?? 9) - (rank[b.remediation!.priority] ?? 9));
  let out = `**Top remediation priorities:**\n\n`;
  sorted.slice(0, 6).forEach((v) => {
    out += `• **${v.title}** [${v.remediation!.priority}] — ${v.remediation!.fixes[0]}\n`;
  });
  out += `\nAsk “how do I fix <name>” for the full steps on any one. A full report is available via **Export Report**.`;
  return out;
}

function exploitationAnswer(scan: ParsedScan, q: string): string {
  const target = scan.vulnerabilities.find((v) => {
    const words = [v.title, v.service, v.source].join(' ').toLowerCase();
    return nameHit(q, words);
  });
  const pick = target || scan.vulnerabilities.find((v) => v.confidence === CONFIRMED);
  if (!pick || !pick.exploitation) {
    return 'I don’t have exploitation notes for that. Open a finding in the Vulnerabilities tab to see its tools and learning links.';
  }
  const e = pick.exploitation;
  let out = `**${pick.title} — how it's exploited**\n\n${e.summary}\n\n`;
  out += `_Tools:_\n` + e.tools.map((t) => `• ${t}`).join('\n');
  out += `\n\n_Learn more:_ ` + e.learning.map((l) => l.label).join(' · ');
  out += `\n\n(Full clickable links are in the Vulnerabilities tab. Educational only — authorized testing.)`;
  return out;
}

function cveAnswer(scan: ParsedScan, cve: string): string {
  const hits = scan.vulnerabilities.filter((v) => v.cves.some((c) => c.id === cve));
  if (!hits.length) return `${cve} wasn't referenced anywhere in this scan.`;
  let out = `**${cve}** appears in ${hits.length} finding${hits.length > 1 ? 's' : ''}:\n\n`;
  hits.forEach((v) => {
    const c = v.cves.find((x) => x.id === cve)!;
    out += `• **${v.title}** — ${v.port ? `port ${v.port}` : 'host'} [${v.confidence}]`;
    if (c.exploit) out += ` ⚠ public exploit referenced`;
    if (c.score !== undefined) out += ` · CVSS ${c.score}`;
    out += `\n`;
  });
  return out;
}

function webAnswer(scan: ParsedScan): string {
  if (!scan.webFindings.length) return 'No web services were found in this scan.';
  let out = `**Web services (${scan.webFindings.length}):**\n\n`;
  scan.webFindings.forEach((w) => {
    out += `• **Port ${w.port}** — ${w.server || 'HTTP'}\n`;
    if (w.directories.length) out += `   Directories: ${w.directories.slice(0, 8).join(', ')}\n`;
    if (w.technologies.length) out += `   Tech: ${w.technologies.join(', ')}\n`;
  });
  return out;
}

function hostAnswer(scan: ParsedScan): string {
  const hosts = scan.hosts.filter((h) => !h.ip.startsWith('('));
  if (!hosts.length) return 'No host information was parsed.';
  return hosts
    .map((h) => {
      let o = `**${h.ip}** (${h.status || 'unknown'})\n`;
      o += `• OS: ${h.os || 'not determined'}\n`;
      if (h.mac) o += `• MAC: ${h.mac}${h.vendor ? ` (${h.vendor})` : ''}\n`;
      if (h.latency) o += `• Latency: ${h.latency}\n`;
      o += `• ${scan.ports.filter((p) => p.host === h.ip && p.state.includes('open')).length} open ports`;
      return o;
    })
    .join('\n\n');
}

function portsAnswer(scan: ParsedScan): string {
  const open = scan.ports.filter((p) => p.state.startsWith('open'));
  if (!open.length) return 'No open ports were found.';
  let out = `**${open.length} open ports:**\n\n`;
  open.slice(0, 30).forEach((p) => {
    out += `• **${p.port}/${p.protocol}** ${p.service || ''}${p.product ? ` — ${p.product} ${p.version || ''}` : ''}\n`;
  });
  if (open.length > 30) out += `…and ${open.length - 30} more.`;
  return out;
}

function portAnswer(scan: ParsedScan, port: number): string {
  const matches = scan.ports.filter((p) => p.port === port);
  if (!matches.length) {
    return `Port ${port} was not reported as open in this scan (it may be closed or filtered and not individually listed).`;
  }
  return matches
    .map((p) => {
      let o = `**Port ${p.port}/${p.protocol}** is **${p.state}** on ${p.host}.\n`;
      if (p.service) o += `• Service: ${p.service}\n`;
      if (p.product) o += `• Product: ${p.product} ${p.version || ''}\n`;
      if (p.extra) o += `• Info: ${p.extra}\n`;
      const vulns = scan.vulnerabilities.filter((v) => v.port === p.port);
      if (vulns.length) {
        o += `\n⚠ ${vulns.length} finding${vulns.length > 1 ? 's' : ''} on this port: ${vulns.map((v) => v.title).join(', ')}`;
      }
      return o;
    })
    .join('\n\n');
}

function findByKeyword(scan: ParsedScan, q: string): string | null {
  // Look for a service/product name mentioned in the question.
  for (const p of scan.ports) {
    const names = [p.service, p.product].filter(Boolean).map((x) => x!.toLowerCase());
    for (const n of names) {
      const token = n.split(/[\s/]/)[0];
      if (token.length >= 3 && q.includes(token)) {
        const vulns = scan.vulnerabilities.filter((v) => v.port === p.port);
        let o = `**${p.product || p.service}** on port ${p.port}/${p.protocol} (${p.version || 'version n/a'}).\n`;
        if (vulns.length) {
          o += `\n${vulns.length} related finding${vulns.length > 1 ? 's' : ''}:\n`;
          o += vulns.map((v) => `• ${v.title} [${v.confidence}]`).join('\n');
        } else {
          o += `\nNo vulnerabilities were flagged specifically on this service.`;
        }
        return o;
      }
    }
  }
  return null;
}

function nameHit(q: string, words: string): boolean {
  const toks = words.split(/[^a-z0-9]+/i).filter((t) => t.length >= 4);
  return toks.some((t) => q.includes(t.toLowerCase()));
}

// ---------------------------------------------------------------------------
/**
 * Compact, factual context string about the scan for grounding an external LLM.
 * Kept concise to limit tokens; the raw scan is never sent unless the user asks.
 */
export function buildScanContext(scan: ParsedScan): string {
  const s = scan.stats;
  const h = scan.hosts[0];
  const lines: string[] = [];
  lines.push(`SCAN CONTEXT (from a local Nmap parse; use only this, do not invent):`);
  lines.push(`Target: ${h?.ip || '?'}  OS: ${h?.os || '?'}  Nmap ${scan.scan.nmapVersion || ''}`);
  lines.push(`Open ports: ${s.openPorts}  Services: ${s.services}  Confirmed: ${s.confirmed}  Potential: ${s.potential}`);
  lines.push('');
  lines.push('OPEN PORTS:');
  scan.ports
    .filter((p) => p.state.startsWith('open'))
    .forEach((p) => lines.push(`- ${p.port}/${p.protocol} ${p.service || ''} ${p.product || ''} ${p.version || ''}`.trim()));
  lines.push('');
  lines.push('CONFIRMED VULNERABILITIES:');
  scan.vulnerabilities.filter((v) => v.confidence === CONFIRMED).forEach((v) => lines.push(vulnLine(v)));
  lines.push('');
  lines.push('POTENTIAL (version-associated) VULNERABILITIES:');
  scan.vulnerabilities.filter((v) => v.confidence === POTENTIAL).forEach((v) => lines.push(vulnLine(v)));
  return lines.join('\n');
}

function vulnLine(v: Vulnerability): string {
  const cves = v.cves.slice(0, 6).map((c) => c.id).join(',');
  return `- ${v.title} @ ${v.port ? `${v.port}/${v.protocol}` : 'host'} [${v.severity}] ${cves}${
    v.remediation ? ` | fix: ${v.remediation.fixes[0]}` : ''
  }`;
}
