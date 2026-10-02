/**
 * Preprocessing + shared helpers.
 *
 * Nmap's terminal output arrives wrapped in ANSI codes, shell prompts, `sudo`
 * noise and progress lines when captured with `tee`. Everything here turns
 * that mess into clean lines the section parsers can rely on.
 */
import type { Cve } from './types';

// eslint-disable-next-line no-control-regex
const ANSI_RE = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
// Other C0 control chars except tab/newline (e.g. \r, bell).
// eslint-disable-next-line no-control-regex
const CTRL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g;

/** Remove ANSI escape sequences and stray carriage returns. */
export function stripAnsi(text: string): string {
  return text.replace(ANSI_RE, '').replace(/\r/g, '');
}

/**
 * Lines that are terminal decoration, progress spam or shell noise rather than
 * Nmap output. Dropping them keeps the section parsers simple.
 */
export function isNoiseLine(line: string): boolean {
  const t = line.trim();
  if (t === '') return false; // keep blanks — they delimit script blocks
  // Kali-style prompt boxes: ┌──(root㉿kali)-[~]  └─# ...
  if (/^[┌└├│]/.test(t)) return true;
  if (/^\(?[a-z0-9_.-]+㉿[a-z0-9_.-]+\)?/i.test(t)) return true;
  // A leading shell prompt char followed by a command (the tee'd command line).
  if (/^[#$]\s/.test(t)) return true;
  if (/^\s*[#$]\s*sudo\s+nmap/i.test(t)) return true;
  // Live progress + timing lines.
  if (/^Stats:\s/.test(t)) return true;
  if (/^(NSE Timing|Service scan Timing|ARP Ping Scan Timing|SYN Stealth Scan Timing|Connect Scan Timing|UDP Scan Timing):/i.test(t))
    return true;
  if (/^NSE: Active NSE Script Threads:/i.test(t)) return true;
  if (/percent (done|completed)/i.test(t) && /ETC:/i.test(t)) return true;
  return false;
}

/**
 * Split into logical lines, strip control chars + noise, and join Nmap's
 * continuation lines. Nmap wraps long script output with a leading "| " or
 * "|_" pipe; a plain wrapped line (no pipe) that clearly belongs to the
 * previous script line is re-joined.
 */
export function normalizeLines(raw: string): string[] {
  const cleaned = stripAnsi(raw).replace(CTRL_RE, '');
  const out: string[] = [];
  for (const line of cleaned.split('\n')) {
    if (isNoiseLine(line)) continue;
    out.push(line.replace(/\s+$/g, ''));
  }
  return out;
}

/** Extract the command line the user ran, if the file preserved it. */
export function findCommand(raw: string): string | undefined {
  const cleaned = stripAnsi(raw);
  const m = cleaned.match(/(?:^|\n)\s*[#$]?\s*(sudo\s+)?nmap\s+[^\n]+/i);
  if (m) {
    return m[0]
      .replace(/^\s*[#$]\s*/, '')
      .replace(/\s*\|\s*tee\s+.*$/i, '')
      .trim();
  }
  return undefined;
}

const CVE_RE = /CVE-\d{4}-\d{3,7}/gi;

/** Pull CVE ids out of an arbitrary block of text (deduped, upper-cased). */
export function extractCves(text: string): string[] {
  const found = text.match(CVE_RE) || [];
  return Array.from(new Set(found.map((c) => c.toUpperCase())));
}

/**
 * Parse a Vulners-style table body into structured CVE/exploit rows.
 * Rows look like:  <id>\t<score>\t<url>\t*EXPLOIT*
 */
export function parseVulnersRows(block: string): Cve[] {
  const rows: Cve[] = [];
  const seen = new Set<string>();
  for (const rawLine of block.split('\n')) {
    const line = rawLine.replace(/^\|?_?\s*/, '').trim();
    if (!line) continue;
    // id  score  url  [*EXPLOIT*]
    const m = line.match(
      /^([A-Z0-9:_\-.]+)\s+(\d+(?:\.\d+)?)\s+(https?:\/\/\S+)(\s+\*EXPLOIT\*)?/i
    );
    if (!m) continue;
    const id = m[1];
    if (seen.has(id)) continue;
    seen.add(id);
    rows.push({
      id,
      score: parseFloat(m[2]),
      url: m[3],
      exploit: Boolean(m[4]),
    });
  }
  return rows;
}

/** Map a CVSS-ish numeric score to a severity band (labelled heuristic by caller). */
export function scoreToSeverity(score?: number) {
  if (score === undefined || Number.isNaN(score)) return 'UNRATED' as const;
  if (score >= 9.0) return 'CRITICAL' as const;
  if (score >= 7.0) return 'HIGH' as const;
  if (score >= 4.0) return 'MEDIUM' as const;
  if (score > 0) return 'LOW' as const;
  return 'INFO' as const;
}

/** Normalize a raw service token to a friendly service-group label. */
export function serviceLabel(service?: string, product?: string): string {
  const s = (service || '').toLowerCase();
  const p = (product || '').toLowerCase();
  const map: Record<string, string> = {
    ftp: 'FTP',
    ssh: 'SSH',
    telnet: 'Telnet',
    smtp: 'SMTP',
    domain: 'DNS',
    http: 'HTTP',
    https: 'HTTPS',
    'ssl/http': 'HTTPS',
    rpcbind: 'RPC / Portmapper',
    'netbios-ssn': 'SMB / NetBIOS',
    'microsoft-ds': 'SMB',
    nfs: 'NFS',
    mysql: 'MySQL',
    postgresql: 'PostgreSQL',
    'ms-sql-s': 'MSSQL',
    oracle: 'Oracle',
    mongodb: 'MongoDB',
    redis: 'Redis',
    vnc: 'VNC',
    x11: 'X11',
    irc: 'IRC',
    'java-rmi': 'Java RMI',
    ajp13: 'AJP',
    distccd: 'distcc',
    exec: 'rexec',
    login: 'rlogin',
    shell: 'rshell',
    drb: 'Ruby DRb',
    bindshell: 'Bind Shell',
    'ccproxy-ftp': 'FTP',
    ident: 'ident',
    imap: 'IMAP',
    pop3: 'POP3',
    ldap: 'LDAP',
    rdp: 'RDP',
    'ms-wbt-server': 'RDP',
    snmp: 'SNMP',
    sip: 'SIP',
    memcached: 'Memcached',
    elasticsearch: 'Elasticsearch',
  };
  if (map[s]) return map[s];
  if (p.includes('tomcat') || s === 'http' ) {
    if (p.includes('tomcat')) return 'Tomcat';
  }
  if (p.includes('tomcat') || p.includes('coyote')) return 'Tomcat';
  if (s) return s.toUpperCase();
  return 'Unknown';
}

/** True if a service/port pair is web-facing. */
export function isWebService(service?: string, product?: string, port?: number): boolean {
  const s = (service || '').toLowerCase();
  const p = (product || '').toLowerCase();
  if (/https?/.test(s) || s.includes('http')) return true;
  if (p.includes('apache') || p.includes('nginx') || p.includes('tomcat') || p.includes('coyote') || p.includes('httpd') || p.includes('iis') || p.includes('jetty') || p.includes('lighttpd'))
    return true;
  if (port && [80, 443, 8080, 8000, 8180, 8443, 8888, 8009, 3000, 5000].includes(port)) return true;
  return false;
}
