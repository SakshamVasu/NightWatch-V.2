/**
 * Multi-format input support: normal text (-oN), grepable (-oG/.gnmap),
 * and XML (-oX/.xml). Each parser produces a CoreLike, fed to analyzeCore.
 */
import type { CoreLike } from './analyze';
import { analyze, analyzeCore } from './analyze';
import type { Host, Port } from './types';

/** Detect which nmap output format the text is. */
export function detectFormat(raw: string): 'xml' | 'gnmap' | 'normal' {
  const head = raw.slice(0, 4000);
  if (/<\?xml|<nmaprun\b/.test(head)) return 'xml';
  // grepable: "Host: <ip> (...)\tPorts:" or "Status:" lines, no "Nmap scan report"
  if (/^Host:\s+\S+.*\t(Ports|Status):/m.test(raw) && !/Nmap scan report for/.test(raw)) return 'gnmap';
  return 'normal';
}

/** Top-level dispatcher used by the app. */
export function parseAny(raw: string): ReturnType<typeof analyze> {
  const fmt = detectFormat(raw);
  if (fmt === 'xml') return analyzeCore(parseXmlCore(raw), raw);
  if (fmt === 'gnmap') return analyzeCore(parseGnmapCore(raw), raw);
  return analyze(raw);
}

// ---------------------------------------------------------------------------
// Grepable (.gnmap)
// ---------------------------------------------------------------------------
function parseGnmapCore(raw: string): CoreLike {
  const hosts: Host[] = [];
  const ports: Port[] = [];
  const osBlocks: Record<string, string[]> = {};
  const getHost = (ip: string): Host => {
    let h = hosts.find((x) => x.ip === ip);
    if (!h) {
      h = { ip, hostnames: [], osCpe: [] };
      hosts.push(h);
    }
    return h;
  };

  const scan: CoreLike['scan'] = {};
  const vm = raw.match(/#\s*Nmap\s+(\S+)\s+scan initiated\s+(.+?)\s+as:/i);
  if (vm) {
    scan.nmapVersion = vm[1];
    scan.startTime = vm[2].trim();
  }
  const cm = raw.match(/as:\s*(.+)/);
  if (cm) scan.command = cm[1].trim();

  for (const line of raw.split('\n')) {
    const hm = line.match(/^Host:\s+(\S+)\s+\(([^)]*)\)\s*\t(.*)$/);
    if (!hm) continue;
    const ip = hm[1];
    const hostname = hm[2];
    const rest = hm[3];
    const h = getHost(ip);
    if (hostname && !h.hostnames.includes(hostname)) h.hostnames.push(hostname);

    if (/Status:\s*Up/i.test(rest)) h.status = 'up';
    else if (/Status:\s*Down/i.test(rest)) h.status = 'down';

    const osm = rest.match(/OS:\s*([^\t]+)/);
    if (osm) {
      h.os = osm[1].trim();
      osBlocks[ip] = osBlocks[ip] || [];
      osBlocks[ip].push(`OS details: ${osm[1].trim()}`);
    }

    const pm = rest.match(/Ports:\s*([^\t]+)/);
    if (pm) {
      h.status = h.status || 'up';
      for (const entry of pm[1].split(/,\s*/)) {
        // port/state/proto/owner/service/rpc/version/
        const f = entry.split('/');
        if (f.length < 3) continue;
        const port = parseInt(f[0], 10);
        if (!Number.isFinite(port)) continue;
        const state = f[1] || 'open';
        const proto = f[2] || 'tcp';
        const service = (f[4] || '').trim() || undefined;
        const versionRaw = (f[6] || '').trim();
        const p: Port = { port, protocol: proto, state, service, host: ip, scripts: {} };
        if (versionRaw) splitProductVersion(p, versionRaw);
        ports.push(p);
      }
    }
  }
  return { scan, hosts, ports, rawScripts: [], unparsed: [], osBlocks, traceroute: {} };
}

/** gnmap/xml version string → product + version + extra. */
function splitProductVersion(p: Port, text: string) {
  const words = text.split(/\s+/);
  let idx = -1;
  for (let i = 0; i < words.length; i++) {
    if (/^\d/.test(words[i]) || /^v\d/.test(words[i])) {
      idx = i;
      break;
    }
  }
  if (idx === -1) {
    p.product = text.replace(/\s*\(.*$/, '').trim() || text;
    const extra = text.match(/\((.*)\)\s*$/);
    if (extra) p.extra = extra[1];
    return;
  }
  p.product = words.slice(0, idx).join(' ');
  const rest = words.slice(idx).join(' ');
  const paren = rest.indexOf('(');
  if (paren >= 0) {
    p.version = rest.slice(0, paren).trim();
    p.extra = rest.slice(paren).replace(/^\(+|\)+$/g, '').trim();
  } else {
    p.version = rest.trim();
  }
}

// ---------------------------------------------------------------------------
// XML (-oX)
// ---------------------------------------------------------------------------
function decode(s: string): string {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(parseInt(d, 10)))
    .replace(/&amp;/g, '&');
}
const attr = (tag: string, name: string): string | undefined => {
  const m = tag.match(new RegExp(`\\b${name}="([^"]*)"`));
  return m ? decode(m[1]) : undefined;
};

function parseXmlCore(raw: string): CoreLike {
  const hosts: Host[] = [];
  const ports: Port[] = [];
  const rawScripts: CoreLike['rawScripts'] = [];
  const osBlocks: Record<string, string[]> = {};
  const traceroute: Record<string, string[]> = {};

  const scan: CoreLike['scan'] = {};
  const runOpen = raw.match(/<nmaprun\b[^>]*>/);
  if (runOpen) {
    scan.nmapVersion = attr(runOpen[0], 'version');
    scan.command = attr(runOpen[0], 'args');
    if (scan.command) {
      const am = scan.command.match(/nmap\s+(.*)$/i);
      if (am) scan.arguments = am[1];
    }
    const st = attr(runOpen[0], 'startstr');
    if (st) scan.startTime = st;
  }
  const fin = raw.match(/<finished\b[^>]*>/);
  if (fin) {
    const el = attr(fin[0], 'elapsed');
    if (el) scan.duration = `${el} seconds`;
    const ts = attr(fin[0], 'timestr');
    if (ts) scan.endTime = ts;
  }

  const hostBlocks = raw.match(/<host\b[\s\S]*?<\/host>/g) || [];
  for (const hb of hostBlocks) {
    const addrM = hb.match(/<address\b[^>]*addrtype="ipv4"[^>]*>/) || hb.match(/<address\b[^>]*>/);
    const ip = addrM ? attr(addrM[0], 'addr') || '?' : '?';
    const h: Host = { ip, hostnames: [], osCpe: [] };
    hosts.push(h);

    const statusM = hb.match(/<status\b[^>]*>/);
    if (statusM) h.status = attr(statusM[0], 'state');

    // MAC / vendor
    const macM = hb.match(/<address\b[^>]*addrtype="mac"[^>]*>/);
    if (macM) {
      h.mac = attr(macM[0], 'addr');
      h.vendor = attr(macM[0], 'vendor');
    }

    for (const hn of hb.match(/<hostname\b[^>]*>/g) || []) {
      const n = attr(hn, 'name');
      if (n) h.hostnames.push(n);
    }

    // latency (times) — srtt in <times/> is not human; skip. distance:
    const distM = hb.match(/<distance\b[^>]*>/);
    if (distM) h.distance = `${attr(distM[0], 'value')} hop(s)`;
    const upM = hb.match(/<uptime\b[^>]*>/);
    if (upM) h.uptime = `${attr(upM[0], 'lastboot') || attr(upM[0], 'seconds') || ''}`.trim();

    // OS
    const osBlk = hb.match(/<os>[\s\S]*?<\/os>/);
    if (osBlk) {
      osBlocks[ip] = osBlocks[ip] || [];
      const match = osBlk[0].match(/<osmatch\b[^>]*>/);
      if (match) {
        h.os = attr(match[0], 'name');
        const acc = attr(match[0], 'accuracy');
        osBlocks[ip].push(`OS details: ${h.os || ''}`);
        if (acc) osBlocks[ip].push(`accuracy: ${acc}`);
      }
      const cpes = osBlk[0].match(/<cpe>([^<]+)<\/cpe>/g) || [];
      h.osCpe = cpes.map((c) => decode(c.replace(/<\/?cpe>/g, '')));
      const cls = osBlk[0].match(/<osclass\b[^>]*>/);
      if (cls) h.osFamily = [attr(cls[0], 'vendor'), attr(cls[0], 'osfamily'), attr(cls[0], 'osgen')].filter(Boolean).join(' ');
    }

    // Ports
    const portBlocks = hb.match(/<port\b[\s\S]*?<\/port>/g) || [];
    for (const pb of portBlocks) {
      const openTag = pb.match(/<port\b[^>]*>/)![0];
      const protocol = attr(openTag, 'protocol') || 'tcp';
      const portid = parseInt(attr(openTag, 'portid') || '0', 10);
      const stateM = pb.match(/<state\b[^>]*>/);
      const state = stateM ? attr(stateM[0], 'state') || 'open' : 'open';
      const p: Port = { port: portid, protocol, state, host: ip, scripts: {} };
      const svcM = pb.match(/<service\b[^>]*\/?>/);
      if (svcM) {
        p.service = attr(svcM[0], 'name');
        p.product = attr(svcM[0], 'product');
        p.version = attr(svcM[0], 'version');
        const extra = attr(svcM[0], 'extrainfo');
        if (extra) p.extra = extra;
      }
      ports.push(p);
      // port scripts
      for (const sc of pb.match(/<script\b[^>]*(?:\/>|>[\s\S]*?<\/script>)/g) || []) {
        const openScript = sc.match(/<script\b[^>]*?>/)![0];
        const id = attr(openScript, 'id') || 'script';
        const out = attr(openScript, 'output') || '';
        rawScripts.push({ id, body: out, scope: 'port', host: ip, port: portid, protocol });
      }
    }

    // Host scripts
    const hostScriptBlk = hb.match(/<hostscript>[\s\S]*?<\/hostscript>/);
    if (hostScriptBlk) {
      for (const sc of hostScriptBlk[0].match(/<script\b[^>]*(?:\/>|>[\s\S]*?<\/script>)/g) || []) {
        const openScript = sc.match(/<script\b[^>]*?>/)![0];
        rawScripts.push({
          id: attr(openScript, 'id') || 'script',
          body: attr(openScript, 'output') || '',
          scope: 'host',
          host: ip,
        });
      }
    }

    // Traceroute
    const traceBlk = hb.match(/<trace\b[\s\S]*?<\/trace>/);
    if (traceBlk) {
      traceroute[ip] = ['HOP RTT ADDRESS'];
      for (const hop of traceBlk[0].match(/<hop\b[^>]*>/g) || []) {
        const ttl = attr(hop, 'ttl') || '';
        const rtt = attr(hop, 'rtt') || '';
        const ipaddr = attr(hop, 'ipaddr') || '';
        const host = attr(hop, 'host');
        traceroute[ip].push(`${ttl} ${rtt ? rtt + ' ms' : ''} ${ipaddr}${host ? ` (${host})` : ''}`.trim());
      }
    }
  }

  return { scan, hosts, ports, rawScripts, unparsed: [], osBlocks, traceroute };
}
