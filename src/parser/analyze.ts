/**
 * Analysis layer.
 *
 * Takes the raw core parse and derives the classified, UI-ready collections:
 * NSE scripts, vulnerabilities (with strict confidence/severity rules),
 * service groups, web findings, OS/network, and categorized findings.
 *
 * Guiding rule: never upgrade a finding beyond what the scan proves.
 *   - "State: VULNERABLE" / "VULNERABLE (Exploitable)"  -> CONFIRMED
 *   - Vulners version->CVE association                  -> POTENTIAL
 *   - open port / banner / anon-ftp / TRACE / dir       -> INFORMATIONAL
 */
import type {
  Cve,
  Finding,
  Host,
  NseScript,
  OsNetwork,
  ParsedScan,
  Port,
  ServiceGroup,
  Severity,
  TracerouteHop,
  Vulnerability,
  WebFinding,
} from './types';
import { parseCore } from './core';
import { buildExploitation } from './exploitation';
import { buildRemediation } from './remediation';
import {
  extractCves,
  isWebService,
  parseVulnersRows,
  scoreToSeverity,
  serviceLabel,
} from './util';

let vidCounter = 0;
const nextId = (prefix: string) => `${prefix}-${++vidCounter}`;

/** Shape produced by any format parser, fed into the shared analysis layer. */
export interface CoreLike {
  scan: ParsedScan['scan'];
  hosts: ParsedScan['hosts'];
  ports: ParsedScan['ports'];
  rawScripts: { id: string; body: string; scope: 'prescript' | 'port' | 'host' | 'postscript'; host: string; port?: number; protocol?: string }[];
  unparsed: ParsedScan['unparsed'];
  osBlocks: Record<string, string[]>;
  traceroute: Record<string, string[]>;
}

/** Run the shared analysis (NSE, vulns, services, web, findings, stats) on any parsed core. */
export function analyzeCore(core: CoreLike, raw: string): ParsedScan {
  vidCounter = 0;
  const nseScripts = buildNseScripts(core.rawScripts);
  const vulnerabilities = buildVulnerabilities(nseScripts, core.ports);
  const services = buildServices(core.ports, nseScripts);
  const webFindings = buildWebFindings(core.ports, nseScripts);
  const osNetwork = buildOsNetwork(core.hosts, core.osBlocks, core.traceroute);
  const findings = buildFindings(core.ports, nseScripts, vulnerabilities);
  const stats = computeStats(core.hosts, core.ports, services, findings, vulnerabilities);
  return {
    scan: core.scan,
    hosts: core.hosts,
    ports: core.ports,
    services,
    vulnerabilities,
    nseScripts,
    webFindings,
    osNetwork,
    findings,
    unparsed: core.unparsed,
    rawOutput: raw,
    stats,
  };
}

export function analyze(raw: string): ParsedScan {
  vidCounter = 0;
  const core = parseCore(raw);

  const nseScripts = buildNseScripts(core.rawScripts);
  const vulnerabilities = buildVulnerabilities(nseScripts, core.ports);
  const services = buildServices(core.ports, nseScripts);
  const webFindings = buildWebFindings(core.ports, nseScripts);
  const osNetwork = buildOsNetwork(core.hosts, core.osBlocks, core.traceroute);
  const findings = buildFindings(core.ports, nseScripts, vulnerabilities);

  const stats = computeStats(core.hosts, core.ports, services, findings, vulnerabilities);

  return {
    scan: core.scan,
    hosts: core.hosts,
    ports: core.ports,
    services,
    vulnerabilities,
    nseScripts,
    webFindings,
    osNetwork,
    findings,
    unparsed: core.unparsed,
    rawOutput: raw,
    stats,
  };
}

// ---------------------------------------------------------------------------
// NSE scripts
// ---------------------------------------------------------------------------
function buildNseScripts(
  raw: ReturnType<typeof parseCore>['rawScripts']
): NseScript[] {
  return raw.map((r) => {
    const state = detectState(r.body);
    const cves = collectCves(r.body);
    return {
      id: r.id,
      host: r.host,
      port: r.port,
      protocol: r.protocol,
      scope: r.scope,
      state,
      output: r.body,
      cves,
    };
  });
}

function detectState(body: string): string | undefined {
  // Only treat explicit result lines as states. Explanatory prose can mention
  // “vulnerable” without the script having reported a positive result.
  const lines = body.split('\n').map((line) => line.trim());
  const state = lines.find((line) => /^State:\s*/i.test(line));
  if (state) {
    const value = state.replace(/^State:\s*/i, '').trim();
    if (/^NOT VULNERABLE\b/i.test(value)) return 'NOT VULNERABLE';
    if (/^LIKELY VULNERABLE\b/i.test(value)) return 'LIKELY VULNERABLE';
    if (/^VULNERABLE\s*\(Exploitable\)/i.test(value)) return 'VULNERABLE (Exploitable)';
    if (/^VULNERABLE\b/i.test(value)) return 'VULNERABLE';
    return value || undefined;
  }
  const banner = lines.find((line) => /^VULNERABLE\s*(?:\(Exploitable\))?\s*:?\s*$/i.test(line));
  if (banner) return /Exploitable/i.test(banner) ? 'VULNERABLE (Exploitable)' : 'VULNERABLE';
  return undefined;
}

/** Merge structured vulners rows with any loose CVE ids in the body. */
function collectCves(body: string): Cve[] {
  const rows = parseVulnersRows(body);
  const byId = new Map<string, Cve>();
  for (const r of rows) byId.set(r.id, r);
  for (const c of extractCves(body)) {
    if (!byId.has(c)) byId.set(c, { id: c });
  }
  return Array.from(byId.values());
}

// ---------------------------------------------------------------------------
// Vulnerabilities (confidence-aware)
// ---------------------------------------------------------------------------
const VULN_STATES = /VULNERABLE/i;
const CONFIRMED_STATES = /(?:^|\n)\s*(?:State:\s*VULNERABLE\b|VULNERABLE\s*\(Exploitable\))/i;

function buildVulnerabilities(
  scripts: NseScript[],
  ports: Port[]
): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const portMap = new Map(ports.map((p) => [`${p.host}:${p.port}`, p]));

  for (const s of scripts) {
    const svc = s.port ? portMap.get(`${s.host}:${s.port}`) : undefined;
    const isVulnersLike = s.id === 'vulners';

    // 1) Explicit NSE vulnerability state -> CONFIRMED / potential
    if (s.state && VULN_STATES.test(s.state) && !/NOT VULNERABLE/i.test(s.state)) {
      const confirmed =
        CONFIRMED_STATES.test(s.output) || /\(Exploitable\)/i.test(s.state);
      const likely = /LIKELY VULNERABLE/i.test(s.state);
      const disclosure = s.output.match(/Disclosure date:\s*(.+)/i)?.[1]?.trim();
      const title = titleFromScript(s);
      vulns.push({
        id: nextId('vuln'),
        title,
        host: s.host,
        port: s.port,
        protocol: s.protocol,
        service: svc?.service,
        severity: severityFromScript(s),
        severitySource: 'nse',
        confidence: confirmed ? 'CONFIRMED' : likely ? 'POTENTIAL' : 'CONFIRMED',
        cves: s.cves,
        evidence: firstLines(s.output, 6),
        source: `NSE: ${s.id}`,
        explanation: explainConfirmed(s, svc, confirmed, likely),
        disclosureDate: disclosure,
      });
      continue;
    }

    // 2) Vulners version-association -> POTENTIAL (one card per script/service)
    if (isVulnersLike && s.cves.length) {
      const cpe = s.output.match(/^\s*(cpe:\/[^\s:]+:[^\s]+)/im)?.[1];
      const forWhat = cpe
        ? ` for ${cpe}`
        : svc?.product
          ? ` for ${svc.product} ${svc.version || ''}`.trimEnd()
          : '';
      const topExploit = s.cves.filter((c) => c.exploit).length;
      vulns.push({
        id: nextId('vuln'),
        title: `Version-associated CVEs${forWhat}`,
        host: s.host,
        port: s.port,
        protocol: s.protocol,
        service: svc?.service,
        severity: heuristicSeverity(s.cves),
        severitySource: s.cves.some((c) => c.score !== undefined) ? 'heuristic' : 'none',
        confidence: 'POTENTIAL',
        cves: s.cves,
        evidence: `Vulners listed ${s.cves.length} CVE(s)${topExploit ? `, ${topExploit} tagged *EXPLOIT*` : ''} associated with the detected version.`,
        source: `NSE: ${s.id}`,
        explanation: explainPotential(s, svc, topExploit),
      });
      continue;
    }

    // 3) Other scripts that carry CVEs but no explicit state (rare) -> POTENTIAL
    if (!isVulnersLike && s.cves.length && !s.state) {
      vulns.push({
        id: nextId('vuln'),
        title: titleFromScript(s),
        host: s.host,
        port: s.port,
        protocol: s.protocol,
        service: svc?.service,
        severity: heuristicSeverity(s.cves),
        severitySource: s.cves.some((c) => c.score !== undefined) ? 'heuristic' : 'none',
        confidence: 'POTENTIAL',
        cves: s.cves,
        evidence: firstLines(s.output, 5),
        source: `NSE: ${s.id}`,
        explanation:
          `The ${s.id} script referenced CVE(s) for the service on ${s.host}` +
          `${s.port ? `:${s.port}` : ''}. Treat as a lead to verify, not a proven exploit.`,
      });
    }
  }

  // Sort: CONFIRMED first, then by severity rank, then potential.
  const sevRank: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
    UNRATED: 5,
  };
  const confRank = { CONFIRMED: 0, POTENTIAL: 1, INFORMATIONAL: 2, UNKNOWN: 3 };

  // Dedupe: the same check can appear twice (e.g. ssl-poodle re-run on a port
  // whose scripts were also captured host-scoped). Keep one per
  // source+host+port+title.
  const seen = new Set<string>();
  const deduped = vulns.filter((v) => {
    const key = `${v.source}|${v.host}|${v.port ?? ''}|${v.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Attach non-weaponized exploitation guidance (named tools + learning links).
  const portByKey = new Map(ports.map((p) => [`${p.host}:${p.port}`, p]));
  for (const v of deduped) {
    const p = v.port ? portByKey.get(`${v.host}:${v.port}`) : undefined;
    const product = p ? [p.product, p.version].filter(Boolean).join(' ') || undefined : undefined;
    v.exploitation = buildExploitation(v.source, v.title, v.cves, v.service, product);
    v.remediation = buildRemediation(
      v.source,
      v.title,
      v.cves,
      v.confidence,
      v.severity,
      v.service,
      product
    );
  }

  deduped.sort(
    (a, b) =>
      confRank[a.confidence] - confRank[b.confidence] ||
      sevRank[a.severity] - sevRank[b.severity]
  );
  return deduped;
}

function titleFromScript(s: NseScript): string {
  const firstLine = s.output.split('\n').find((l) => l.trim() && !/^VULNERABLE/i.test(l.trim()));
  const pretty = SCRIPT_TITLES[s.id];
  if (pretty) return pretty;
  if (firstLine && firstLine.length < 90 && !/^IDs:/i.test(firstLine.trim()))
    return firstLine.trim();
  return s.id;
}

const SCRIPT_TITLES: Record<string, string> = {
  'ftp-vsftpd-backdoor': 'vsftpd 2.3.4 Backdoor',
  'rmi-vuln-classloader': 'Java RMI Registry Default Config RCE',
  'distcc-cve2004-2687': 'distcc Daemon Command Execution',
  'irc-unrealircd-backdoor': 'UnrealIRCd Backdoor',
  'ssl-poodle': 'SSL POODLE (CVE-2014-3566)',
  'ssl-ccs-injection': 'OpenSSL CCS Injection (CVE-2014-0224)',
  'ssl-dh-params': 'Weak Diffie-Hellman Parameters',
  'http-slowloris-check': 'Slowloris DoS (CVE-2007-6750)',
  'smb-vuln-ms08-067': 'SMB MS08-067',
  'smb-vuln-ms17-010': 'SMB MS17-010 (EternalBlue)',
};

function severityFromScript(s: NseScript): Severity {
  // Use an NSE-provided risk/CVSS if present, else heuristic from CVEs.
  const risk = s.output.match(/Risk factor:\s*(\w+)/i)?.[1];
  const cvss = s.output.match(/CVSSv?2?:\s*([\d.]+)/i)?.[1];
  if (cvss) return scoreToSeverity(parseFloat(cvss));
  if (risk) {
    const r = risk.toUpperCase();
    if (r === 'HIGH') return 'HIGH';
    if (r === 'MEDIUM') return 'MEDIUM';
    if (r === 'LOW') return 'LOW';
  }
  if (s.cves.length) return heuristicSeverity(s.cves);
  return 'UNRATED';
}

function heuristicSeverity(cves: Cve[]): Severity {
  const scored = cves.filter((c) => c.score !== undefined);
  if (!scored.length) return 'UNRATED';
  const max = Math.max(...scored.map((c) => c.score as number));
  return scoreToSeverity(max);
}

function explainConfirmed(
  s: NseScript,
  svc: Port | undefined,
  confirmed: boolean,
  likely: boolean
): string {
  const where = `${s.host}${s.port ? `:${s.port}/${s.protocol}` : ''}`;
  const svcTxt = svc ? `${svc.service || 'service'}${svc.product ? ` (${svc.product} ${svc.version || ''})`.trim() : ''}` : 'the service';
  const proof = confirmed
    ? 'The NSE script reported an exploitable/VULNERABLE state, which the scan treats as confirmed.'
    : likely
      ? 'The NSE script reported a LIKELY VULNERABLE state — strong indication, not fully proven.'
      : 'The NSE script reported a VULNERABLE state.';
  const idmatch = s.output.match(/Exploit results:[\s\S]*?(uid=\S+[^\n]*)/i);
  const evidenceNote = idmatch
    ? ` The script even returned command output (${idmatch[1].trim()}), demonstrating code execution.`
    : '';
  const next = `Next steps: manually validate against ${where} in your authorized lab, confirm the affected version of ${svcTxt}, and check remediation/patch status.`;
  const cveTxt = s.cves.length ? ` Associated: ${s.cves.map((c) => c.id).slice(0, 4).join(', ')}.` : '';
  return `${proof}${evidenceNote} Detected on ${where} (${svcTxt}).${cveTxt} ${next}`;
}

function explainPotential(s: NseScript, svc: Port | undefined, exploitCount: number): string {
  const where = `${s.host}${s.port ? `:${s.port}/${s.protocol}` : ''}`;
  const svcTxt = svc ? `${svc.product || svc.service || 'the service'} ${svc.version || ''}`.trim() : 'the detected software';
  return (
    `Vulners matched the detected version of ${svcTxt} on ${where} against its CVE database. ` +
    `These are version-associated CVEs — the scan proved a version match, not that any of them is exploitable here` +
    `${exploitCount ? `, though ${exploitCount} carry a public *EXPLOIT* reference` : ''}. ` +
    `Next steps: verify the exact build/patch level, discount CVEs fixed by distro backports, and prioritise the highest-scored, exploit-tagged CVEs for manual testing.`
  );
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------
function buildServices(ports: Port[], scripts: NseScript[]): ServiceGroup[] {
  const groups = new Map<string, ServiceGroup>();
  const open = ports.filter((p) => p.state.startsWith('open'));
  for (const p of open) {
    const label = serviceLabel(p.service, p.product);
    if (!groups.has(label)) groups.set(label, { name: label, ports: [] });
    const scriptIds = scripts
      .filter((s) => s.host === p.host && s.port === p.port)
      .map((s) => s.id);
    groups.get(label)!.ports.push({
      port: p.port,
      protocol: p.protocol,
      product: p.product,
      version: p.version,
      extra: p.extra,
      scripts: scriptIds,
    });
  }
  return Array.from(groups.values()).sort((a, b) => a.name.localeCompare(b.name));
}

// ---------------------------------------------------------------------------
// Web findings
// ---------------------------------------------------------------------------
function buildWebFindings(ports: Port[], scripts: NseScript[]): WebFinding[] {
  const out: WebFinding[] = [];
  for (const p of ports) {
    if (!p.state.startsWith('open')) continue;
    if (!isWebService(p.service, p.product, p.port)) continue;
    const portScripts = scripts.filter((s) => s.host === p.host && s.port === p.port);
    const wf: WebFinding = {
      port: p.port,
      protocol: p.protocol,
      server: [p.product, p.version].filter(Boolean).join(' ') || p.service,
      technologies: [],
      headers: {},
      directories: [],
      urls: [],
      methods: [],
      auth: [],
      securityNotes: [],
      tls: [],
      scripts: portScripts.map((s) => s.id),
    };
    if (p.extra && /php|dav|powered/i.test(p.extra)) wf.technologies.push(p.extra);

    for (const s of portScripts) {
      const body = s.output;
      if (s.id === 'http-server-header') wf.server = body.trim() || wf.server;
      if (s.id === 'http-headers') {
        for (const line of body.split('\n')) {
          const hm = line.match(/^\s*([A-Za-z-]+):\s*(.+)$/);
          if (hm && hm[1].toLowerCase() !== 'request type') wf.headers[hm[1]] = hm[2].trim();
        }
      }
      if (/php-version|x-powered-by/i.test(s.id) || /PHP\//i.test(body)) {
        const php = body.match(/PHP\/[\d.]+\w*/i);
        if (php) wf.technologies.push(php[0]);
      }
      if (s.id === 'http-methods') {
        const mm = body.match(/Supported Methods:\s*(.+)/i);
        if (mm) wf.methods = mm[1].trim().split(/\s+/);
      }
      if (s.id === 'http-enum' || s.id === 'http-sitemap-generator') {
        for (const line of body.split('\n')) {
          const dm = line.match(/(\/[A-Za-z0-9_./-]+\/)\s*:/);
          if (dm) wf.directories.push(dm[1]);
          const dm2 = line.match(/Dir:\s*(\S+)/);
          if (dm2) wf.directories.push(dm2[1]);
        }
      }
      if (/^http-title/i.test(s.id)) {
        // keep as note
        wf.securityNotes.push(`Title: ${body.trim()}`);
      }
      if (/trace/i.test(s.id) || /TRACE is enabled/i.test(body)) {
        if (/TRACE is enabled/i.test(body)) wf.securityNotes.push('HTTP TRACE method is enabled.');
      }
      if (/xss|csrf|dombased|security-headers/i.test(s.id)) {
        const firstMeaningful = body.split('\n').map((l) => l.trim()).find((l) => l && !/^ERROR/i.test(l));
        if (firstMeaningful) wf.securityNotes.push(`${s.id}: ${firstMeaningful}`);
      }
      if (s.id === 'http-auth-finder' || s.id === 'http-auth' || /manager\/html/i.test(body)) {
        for (const line of body.split('\n')) {
          const um = line.match(/(https?:\/\/\S+)\s+(FORM|HTTP:.*|Basic)/i);
          if (um) wf.auth.push(`${um[1]} (${um[2].trim()})`);
        }
      }
      if (/^ssl|^tls|poodle|ccs-injection|dh-params|enum-ciphers/i.test(s.id)) {
        const summary = summarizeTls(s.id, body);
        if (summary) wf.tls.push(summary);
      }
      // collect any absolute URLs mentioned
      for (const um of body.matchAll(/https?:\/\/[^\s"'|)]+/gi)) {
        if (/192\.168|127\.0|10\.|localhost|[a-z]:\/\/\S+\//i.test(um[0]) && um[0].includes(String(p.port === 80 ? p.host : p.host))) {
          // keep host-local URLs only, cap later
          wf.urls.push(um[0]);
        }
      }
    }
    // dedupe
    wf.directories = uniq(wf.directories);
    wf.technologies = uniq(wf.technologies);
    wf.methods = uniq(wf.methods);
    wf.auth = uniq(wf.auth);
    wf.securityNotes = uniq(wf.securityNotes);
    wf.tls = uniq(wf.tls);
    wf.urls = uniq(wf.urls).slice(0, 40);
    out.push(wf);
  }
  return out;
}

function summarizeTls(id: string, body: string): string | undefined {
  if (/State:\s*VULNERABLE/i.test(body)) {
    const name = body.match(/^\s*([A-Z][\w /()-]+)\n/m)?.[1] || id;
    return `${id}: VULNERABLE — ${name.trim()}`;
  }
  if (id.includes('enum-ciphers')) {
    const weak = (body.match(/- F\b/g) || []).length;
    if (weak) return `${id}: ${weak} cipher(s) graded F (weak/broken)`;
  }
  if (/SSLv2 supported/i.test(body)) return `${id}: SSLv2 supported (obsolete)`;
  return undefined;
}

// ---------------------------------------------------------------------------
// OS & network
// ---------------------------------------------------------------------------
function buildOsNetwork(
  hosts: Host[],
  osBlocks: Record<string, string[]>,
  traceroute: Record<string, string[]>
): OsNetwork[] {
  return hosts.map((h) => {
    const block = osBlocks[h.ip] || [];
    const get = (re: RegExp) => block.map((l) => l.match(re)?.[1]).find(Boolean);
    return {
      host: h.ip,
      os: h.os || get(/^OS details:\s*(.+)$/i),
      osDetails: get(/^OS details:\s*(.+)$/i),
      osFamily: h.osFamily || get(/^Running:\s*(.+)$/i),
      osCpe: h.osCpe && h.osCpe.length ? h.osCpe : (get(/^OS CPE:\s*(.+)$/i)?.split(/\s+/) || []),
      accuracy: get(/accuracy[:=]\s*(\d+)/i),
      mac: h.mac,
      vendor: h.vendor,
      latency: h.latency,
      uptime: h.uptime || get(/^Uptime guess:\s*(.+)$/i),
      distance: h.distance || get(/^Network Distance:\s*(.+)$/i),
      tcpSequence: get(/^TCP Sequence Prediction:\s*(.+)$/i),
      ipIdSequence: get(/^IP ID Sequence Generation:\s*(.+)$/i),
      traceroute: parseTraceroute(traceroute[h.ip] || []),
    };
  });
}

function parseTraceroute(lines: string[]): TracerouteHop[] {
  const hops: TracerouteHop[] = [];
  for (const l of lines) {
    if (/^HOP\s+RTT/i.test(l)) continue;
    // "1   0.94 ms 192.168.1.8"  or  "2  1.20 ms 10.0.0.1 (gw.local)"
    const m = l.match(/^(\d+)\s+([\d.]+\s*ms|\.\.\.|\*)\s*(\S+)?\s*(?:\(([^)]+)\))?/);
    if (!m) continue;
    hops.push({
      hop: parseInt(m[1], 10),
      rtt: m[2],
      address: m[3],
      hostname: m[4],
    });
  }
  return hops;
}

// ---------------------------------------------------------------------------
// Findings (categorized, consolidated)
// ---------------------------------------------------------------------------
function buildFindings(
  ports: Port[],
  scripts: NseScript[],
  vulns: Vulnerability[]
): Finding[] {
  const findings: Finding[] = [];

  // Confirmed vulns feed the Confirmed group.
  for (const v of vulns) {
    if (v.confidence === 'CONFIRMED') {
      findings.push({
        id: nextId('find'),
        category: 'Vulnerability',
        title: v.title,
        detail: v.evidence.split('\n')[0] || v.title,
        host: v.host,
        port: v.port,
        protocol: v.protocol,
        confidence: 'CONFIRMED',
        source: v.source,
      });
    }
  }

  // Potential (version-associated) summary per vuln card.
  for (const v of vulns) {
    if (v.confidence === 'POTENTIAL') {
      findings.push({
        id: nextId('find'),
        category: 'Version CVE',
        title: v.title,
        detail: `${v.cves.length} associated CVE(s)${v.cves.some((c) => c.exploit) ? ' (some with public exploits)' : ''}`,
        host: v.host,
        port: v.port,
        protocol: v.protocol,
        confidence: 'POTENTIAL',
        source: v.source,
      });
    }
  }

  // Informational: open ports, banners, and notable NSE observations.
  for (const p of ports.filter((x) => x.state.startsWith('open'))) {
    findings.push({
      id: nextId('find'),
      category: 'Open Port',
      title: `${p.port}/${p.protocol} open — ${p.service || 'unknown'}`,
      detail: [p.product, p.version, p.extra].filter(Boolean).join(' ') || 'Service detected',
      host: p.host,
      port: p.port,
      protocol: p.protocol,
      confidence: 'INFORMATIONAL',
      source: 'port scan',
    });
  }

  // NSE-derived informational observations.
  for (const s of scripts) {
    const body = s.output;
    const cat = categorize(s.id);
    if (s.id === 'ftp-anon' || /Anonymous FTP login allowed/i.test(body)) {
      findings.push(info('FTP', 'Anonymous FTP login allowed', s, 'Server permits anonymous FTP access.'));
    }
    if (s.id === 'mysql-empty-password' || /account has empty password/i.test(body)) {
      const who = body.match(/(\w+) account has empty password/i)?.[1] || 'An';
      findings.push(info('Database', `${who} account has empty password`, s, body.trim()));
    }
    if (s.id === 'smb-enum-shares' && /Anonymous access:\s*READ\/WRITE/i.test(body)) {
      findings.push(info('SMB', 'SMB share with anonymous READ/WRITE access', s, 'One or more shares allow anonymous read/write.'));
    }
    if (s.id === 'nfs-showmount' || s.id === 'nfs-ls') {
      findings.push(info('NFS', 'NFS export enumerated', s, firstLines(body, 3)));
    }
    if (s.id === 'http-methods' && /TRACE|PUT|DELETE/i.test(body)) {
      const risky = (body.match(/\b(TRACE|PUT|DELETE)\b/gi) || []).join(', ');
      findings.push(info('HTTP', `Risky HTTP methods enabled: ${risky}`, s, body.trim()));
    }
    if (s.id === 'http-trace' && /TRACE is enabled/i.test(body)) {
      findings.push(info('HTTP', 'HTTP TRACE enabled', s, body.trim()));
    }
    if (s.id === 'dns-recursion' && /Recursion appears to be enabled/i.test(body)) {
      findings.push(info('DNS', 'Open DNS recursion', s, body.trim()));
    }
    if (s.id === 'mysql-users' || s.id === 'smb-enum-users') {
      findings.push(info(cat, `${s.id.includes('mysql') ? 'MySQL' : 'SMB'} users enumerated`, s, firstLines(body, 4)));
    }
    if (/backdoor|shell/i.test(s.id) === false && s.state && /NOT VULNERABLE/i.test(s.state)) {
      // record explicit not-vulnerable checks as informational reassurance
      findings.push(info(cat, `${s.id}: NOT VULNERABLE`, s, 'Checked and reported not vulnerable.'));
    }
    if (s.id === 'ssl-cert') {
      const cn = body.match(/commonName=([^/\n]+)/i)?.[1];
      findings.push(info('TLS', `SSL certificate present${cn ? ` (CN=${cn.trim()})` : ''}`, s, firstLines(body, 3)));
    }
  }

  return findings;
}

function categorize(id: string): string {
  if (id.startsWith('ftp')) return 'FTP';
  if (id.startsWith('ssh')) return 'SSH';
  if (id.startsWith('smb') || id.startsWith('nbstat')) return 'SMB';
  if (id.startsWith('http')) return 'HTTP';
  if (id.startsWith('dns')) return 'DNS';
  if (id.startsWith('ssl') || id.startsWith('tls')) return 'TLS';
  if (id.startsWith('nfs') || id.startsWith('rpc')) return 'RPC/NFS';
  if (id.startsWith('mysql') || id.startsWith('pgsql') || id.includes('postgres')) return 'Database';
  if (id.startsWith('smtp')) return 'SMTP';
  if (id.startsWith('irc')) return 'IRC';
  if (id.startsWith('rmi') || id.includes('java')) return 'Java';
  return 'Info';
}

function info(category: string, title: string, s: NseScript, detail: string): Finding {
  return {
    id: nextId('find'),
    category,
    title,
    detail,
    host: s.host,
    port: s.port,
    protocol: s.protocol,
    confidence: 'INFORMATIONAL',
    source: `NSE: ${s.id}`,
  };
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------
function computeStats(
  hosts: Host[],
  ports: Port[],
  services: ServiceGroup[],
  findings: Finding[],
  vulns: Vulnerability[]
) {
  const open = ports.filter((p) => p.state.startsWith('open'));
  const closed = hosts.reduce((acc, h) => {
    const ns = (h as unknown as { notShown?: string }).notShown || '';
    const m = ns.match(/(\d+)\s+closed/);
    return acc + (m ? parseInt(m[1], 10) : 0);
  }, ports.filter((p) => p.state === 'closed').length);
  const filtered = ports.filter((p) => p.state.includes('filtered')).length;

  const cveSet = new Set<string>();
  vulns.forEach((v) => v.cves.forEach((c) => cveSet.add(c.id)));

  return {
    hostsTotal: hosts.filter((h) => !h.ip.startsWith('(')).length,
    hostsUp: hosts.filter((h) => h.status === 'up').length,
    openPorts: open.length,
    closedPorts: closed,
    filteredPorts: filtered,
    services: services.reduce((n, g) => n + g.ports.length, 0),
    confirmed: vulns.filter((v) => v.confidence === 'CONFIRMED').length,
    potential: vulns.filter((v) => v.confidence === 'POTENTIAL').length,
    informational: findings.filter((f) => f.confidence === 'INFORMATIONAL').length,
    unknown: findings.filter((f) => f.confidence === 'UNKNOWN').length,
    cves: cveSet.size,
  };
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------
function firstLines(text: string, n: number): string {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(0, n)
    .join('\n');
}
function uniq<T>(a: T[]): T[] {
  return Array.from(new Set(a));
}

export { analyze as parseNmap };
