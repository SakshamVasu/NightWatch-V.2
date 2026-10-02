/**
 * Core section parser.
 *
 * Walks the normalized lines once, maintaining "current host" and "current
 * port" context, and dispatches to small helpers for each region:
 *   - scan metadata          (Starting Nmap / Nmap done / report header)
 *   - host discovery         (report + Host is up + Not shown)
 *   - port table + services  (NN/proto state service version)
 *   - NSE script blocks       (| script-id: ... |_)
 *   - OS detection           (Running / OS details / CPE / MAC)
 *   - traceroute             (TRACEROUTE block)
 *   - pre/post-scan scripts  (Pre-scan / Post-scan script results)
 *
 * Each NSE block is captured verbatim so nothing useful is discarded. Blocks
 * that cannot be tied to a host/port are still kept under `unparsed`.
 */
import type {
  Host,
  Port,
  ScanMeta,
  UnparsedBlock,
} from './types';
import { extractCves, normalizeLines, parseVulnersRows, findCommand } from './util';

interface RawScript {
  id: string;
  body: string;
  scope: 'prescript' | 'port' | 'host' | 'postscript';
  host: string;
  port?: number;
  protocol?: string;
}

interface CoreResult {
  scan: ScanMeta;
  hosts: Host[];
  ports: Port[];
  rawScripts: RawScript[];
  unparsed: UnparsedBlock[];
  osBlocks: Record<string, string[]>; // host -> OS/detail lines
  traceroute: Record<string, string[]>; // host -> traceroute lines
}

const PORT_RE =
  /^(\d{1,5})\/(tcp|udp|sctp)\s+(open|closed|filtered|unfiltered|open\|filtered|closed\|filtered)\s*(\S+)?\s*(.*)$/;

/** A script header line: "| script-id: ..." or "|_script-id: ..." */
function scriptHeader(line: string): { id: string; rest: string } | null {
  const m = line.match(/^\|_?\s?([a-z0-9][a-z0-9_.\-]*):\s?(.*)$/i);
  if (!m) return null;
  // Guard against matching generic "|   Key: value" body lines: real script
  // ids contain a hyphen or a known-word shape and sit at the top pipe level.
  return { id: m[1], rest: m[2] };
}

function isScriptContinuation(line: string): boolean {
  return /^\|[_ ]?/.test(line) || /^\|/.test(line);
}

export function parseCore(raw: string): CoreResult {
  const lines = normalizeLines(raw);
  const scan: ScanMeta = { command: findCommand(raw) };
  if (scan.command) {
    const am = scan.command.match(/nmap\s+(.*)$/i);
    if (am) scan.arguments = am[1].replace(/\s+\d+(?:\.\d+){3}.*$/, '').trim() || am[1];
  }

  const hosts: Host[] = [];
  const ports: Port[] = [];
  const rawScripts: RawScript[] = [];
  const unparsed: UnparsedBlock[] = [];
  const osBlocks: Record<string, string[]> = {};
  const traceroute: Record<string, string[]> = {};

  let curHost = '';
  let curPort: Port | null = null;
  let section:
    | 'none'
    | 'prescan'
    | 'ports'
    | 'hostscripts'
    | 'traceroute'
    | 'postscan' = 'none';

  // Accumulator for the script block currently being read.
  let scriptId = '';
  let scriptBody: string[] = [];
  let scriptScope: RawScript['scope'] = 'port';

  const flushScript = () => {
    if (!scriptId) return;
    rawScripts.push({
      id: scriptId,
      body: scriptBody.join('\n').trim(),
      scope: scriptScope,
      host: curHost,
      port: scriptScope === 'port' ? curPort?.port : undefined,
      protocol: scriptScope === 'port' ? curPort?.protocol : undefined,
    });
    scriptId = '';
    scriptBody = [];
  };

  const getHost = (ip: string): Host => {
    let h = hosts.find((x) => x.ip === ip);
    if (!h) {
      h = { ip, hostnames: [], osCpe: [] };
      hosts.push(h);
    }
    return h;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const t = line.trim();

    // ---- scan metadata ------------------------------------------------
    let m: RegExpMatchArray | null;
    if ((m = t.match(/^Starting Nmap\s+(\S+).*?at\s+(.+)$/i))) {
      scan.nmapVersion = m[1];
      scan.startTime = m[2].trim();
      continue;
    }
    if ((m = t.match(/^Nmap done:.*scanned in\s+([\d.]+\s*\w+)/i))) {
      scan.duration = m[1].trim();
      // capture end time if present on a nearby line handled elsewhere
    }
    if ((m = t.match(/^Nmap scan report for\s+(.+)$/i))) {
      flushScript();
      const target = m[1].trim();
      // "hostname (1.2.3.4)" or just an IP/hostname
      const ipm = target.match(/^(.*?)\s*\(([\d.:a-f]+)\)$/i);
      const ip = ipm ? ipm[2] : target;
      curHost = ip;
      const h = getHost(ip);
      if (ipm && ipm[1]) h.hostnames.push(ipm[1].trim());
      curPort = null;
      section = 'ports';
      continue;
    }
    if ((m = t.match(/^Host is up\s*(?:\(([^)]*)\))?/i))) {
      const h = getHost(curHost);
      h.status = 'up';
      if (m[1]) h.latency = m[1].replace(/latency/i, '').trim();
      continue;
    }
    if (/^Host is down/i.test(t)) {
      const h = getHost(curHost);
      h.status = 'down';
      continue;
    }
    if ((m = t.match(/^Not shown:\s*(.+)$/i))) {
      // "65505 closed tcp ports (reset)" possibly comma-joined
      const h = getHost(curHost);
      (h as unknown as { notShown?: string }).notShown = m[1].trim();
      continue;
    }

    // ---- pre/post-scan script sections --------------------------------
    if (/^Pre-scan script results:/i.test(t)) {
      flushScript();
      section = 'prescan';
      scriptScope = 'prescript';
      curHost = '(pre-scan)';
      continue;
    }
    if (/^Post-scan script results:/i.test(t)) {
      flushScript();
      section = 'postscan';
      scriptScope = 'postscript';
      curHost = '(post-scan)';
      continue;
    }
    if (/^Host script results:/i.test(t)) {
      flushScript();
      section = 'hostscripts';
      scriptScope = 'host';
      curPort = null;
      continue;
    }

    // ---- traceroute ---------------------------------------------------
    if (/^TRACEROUTE/i.test(t)) {
      flushScript();
      section = 'traceroute';
      traceroute[curHost] = traceroute[curHost] || [];
      continue;
    }
    if (section === 'traceroute') {
      if (t === '' || /^NSE:/i.test(t) || /^OS and Service/i.test(t)) {
        section = 'none';
      } else {
        traceroute[curHost] = traceroute[curHost] || [];
        traceroute[curHost].push(t);
        continue;
      }
    }

    // ---- port table row ----------------------------------------------
    const pm = t.match(PORT_RE);
    if (pm && section !== 'prescan' && section !== 'postscan') {
      flushScript();
      const p: Port = {
        port: parseInt(pm[1], 10),
        protocol: pm[2],
        state: pm[3],
        service: pm[4] || undefined,
        host: curHost,
        scripts: {},
      };
      const versionText = (pm[5] || '').trim();
      if (versionText) parseVersionColumn(p, versionText);
      ports.push(p);
      curPort = p;
      section = 'ports';
      scriptScope = 'port'; // scripts that follow belong to this port
      continue;
    }

    // ---- OS detection lines ------------------------------------------
    if (
      /^(Device type|Running|OS CPE|OS details|OS fingerprint|Aggressive OS guesses|Uptime guess|Network Distance|TCP Sequence Prediction|IP ID Sequence Generation|Service Info):/i.test(
        t
      )
    ) {
      flushScript();
      osBlocks[curHost] = osBlocks[curHost] || [];
      osBlocks[curHost].push(t);
      const h = getHost(curHost);
      applyOsLine(h, t);
      continue;
    }
    if ((m = t.match(/^MAC Address:\s*([0-9A-F:]+)\s*(?:\(([^)]*)\))?/i))) {
      const h = getHost(curHost);
      h.mac = m[1];
      h.vendor = m[2];
      continue;
    }
    if (/^Warning: OSScan results may be unreliable/i.test(t)) continue;

    // ---- NSE script blocks -------------------------------------------
    if (isScriptContinuation(line)) {
      const hdr = scriptHeader(line);
      const looksLikeNewScript =
        hdr && (hdr.id.includes('-') || KNOWN_SCRIPT_IDS.has(hdr.id));
      if (looksLikeNewScript) {
        flushScript();
        scriptId = hdr!.id;
        scriptBody = hdr!.rest ? [hdr!.rest] : [];
      } else {
        // continuation body line
        scriptBody.push(line.replace(/^\|_?/, '').replace(/^\s/, ''));
      }
      continue;
    }

    // A non-pipe line ends any open script block.
    if (scriptId) flushScript();

    // ---- leftover: keep anything that looks meaningful ---------------
    if (
      t &&
      !/^Starting NSE/i.test(t) &&
      !/^Completed NSE/i.test(t) &&
      !/^Initiating/i.test(t) &&
      !/^Scanning/i.test(t) &&
      !/^Discovered open port/i.test(t) &&
      !/^Completed/i.test(t) &&
      !/^NSE:/i.test(t) &&
      !/^Read data files/i.test(t) &&
      !/^OS and Service detection/i.test(t) &&
      !/^Nmap done/i.test(t) &&
      !/^\s*Raw packets sent/i.test(t) &&
      !/^Service detection performed/i.test(t) &&
      !/^No profinet devices/i.test(t)
    ) {
      // Unrecognized but non-trivial — retain for the Raw/Unparsed view.
      if (t.length > 3 && section === 'none') {
        unparsed.push({ reason: 'unrecognized line', content: t });
      }
    }
  }
  flushScript();

  return { scan, hosts, ports, rawScripts, unparsed, osBlocks, traceroute };
}

/** Break the VERSION column into product / version / extra. */
function parseVersionColumn(p: Port, text: string) {
  // Examples:
  //  "vsftpd 2.3.4"
  //  "OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)"
  //  "Apache httpd 2.2.8 ((Ubuntu) DAV/2)"
  //  "MySQL 5.0.51a-3ubuntu5"
  //  "Samba smbd 3.X - 4.X (workgroup: WORKGROUP)"
  //  "netkit-rsh rexecd"
  // Product = text up to the first token that looks like a version number.
  const words = text.split(/\s+/);
  let splitIdx = -1;
  for (let i = 0; i < words.length; i++) {
    if (/^\d/.test(words[i]) || /^v\d/.test(words[i])) {
      splitIdx = i;
      break;
    }
  }
  if (splitIdx === -1) {
    // No numeric version — everything is product (e.g. "Linux telnetd").
    p.product = text.replace(/\s*\(.*$/, '').trim() || text;
    const extra = text.match(/(\(.*\))\s*$/);
    if (extra) p.extra = cleanExtra(extra[1]);
    return;
  }
  p.product = words.slice(0, splitIdx).join(' ');
  // version is the numeric token plus following tokens until a parenthesis.
  const rest = words.slice(splitIdx).join(' ');
  const parenIdx = rest.indexOf('(');
  if (parenIdx >= 0) {
    p.version = rest.slice(0, parenIdx).trim();
    p.extra = cleanExtra(rest.slice(parenIdx));
  } else {
    p.version = rest.trim();
  }
}

/** Strip the outer balanced parentheses Nmap wraps the extra-info column in. */
function cleanExtra(text: string): string {
  let s = text.trim();
  // Nmap often double-wraps: "((Ubuntu) DAV/2)". Peel one balanced outer layer.
  if (s.startsWith('(') && s.endsWith(')')) {
    let depth = 0;
    let balancedOuter = true;
    for (let i = 0; i < s.length; i++) {
      if (s[i] === '(') depth++;
      else if (s[i] === ')') depth--;
      if (depth === 0 && i < s.length - 1) {
        balancedOuter = false;
        break;
      }
    }
    if (balancedOuter) s = s.slice(1, -1).trim();
  }
  return s;
}

function applyOsLine(h: Host, line: string) {
  let m: RegExpMatchArray | null;
  if ((m = line.match(/^OS details:\s*(.+)$/i))) h.os = m[1].trim();
  else if ((m = line.match(/^Running:\s*(.+)$/i))) {
    h.osFamily = m[1].trim();
    if (!h.os) h.os = m[1].trim();
  } else if ((m = line.match(/^Aggressive OS guesses:\s*(.+)$/i))) {
    if (!h.os) h.os = m[1].trim();
  } else if ((m = line.match(/^OS CPE:\s*(.+)$/i))) {
    h.osCpe = m[1].trim().split(/\s+/);
  } else if ((m = line.match(/^Uptime guess:\s*(.+)$/i))) h.uptime = m[1].trim();
  else if ((m = line.match(/^Network Distance:\s*(.+)$/i))) h.distance = m[1].trim();
}

/** A small set of single-word (hyphen-less) script ids so headers parse right. */
const KNOWN_SCRIPT_IDS = new Set([
  'vulners',
  'fingerprint-strings',
  'banner',
  'nbstat',
  'rpcinfo',
  'qscan',
  'fcrdns',
  'clock',
]);

export { parseVulnersRows, extractCves };
