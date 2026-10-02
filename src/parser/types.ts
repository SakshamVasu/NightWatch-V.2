/**
 * Nmap Analyzer — shared data model.
 *
 * Every parsing module produces objects that fit this model. The UI consumes
 * this model and nothing else, so the parser and the UI stay decoupled.
 */

/** How much the scan actually proves about a finding. */
export type Confidence =
  | 'CONFIRMED' // NSE explicitly reported VULNERABLE / demonstrated a result
  | 'POTENTIAL' // version-associated CVE (e.g. Vulners) — association, not proof
  | 'INFORMATIONAL' // open port, banner, directory, anonymous FTP, TRACE, etc.
  | 'UNKNOWN'; // something we captured but could not classify

/** Severity. Only ever set when the scan gives us a basis for it. */
export type Severity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFO'
  | 'UNRATED';

export interface ScanMeta {
  nmapVersion?: string;
  startTime?: string;
  endTime?: string;
  duration?: string;
  command?: string;
  arguments?: string;
  scannerAddress?: string;
  portsScanned?: number; // total ports the scan covered, if stated
}

export interface Port {
  port: number;
  protocol: string; // tcp | udp
  state: string; // open | closed | filtered | open|filtered ...
  service?: string;
  product?: string;
  version?: string;
  extra?: string; // remaining VERSION column text
  host: string; // owning host IP
  /** script-id -> raw output, for scripts attached to this port */
  scripts: Record<string, string>;
}

export interface Host {
  ip: string;
  status?: string; // up / down
  latency?: string;
  hostnames: string[];
  os?: string; // best OS guess line
  osFamily?: string;
  osCpe?: string[];
  mac?: string;
  vendor?: string;
  uptime?: string;
  distance?: string;
}

export interface ServiceGroup {
  name: string; // normalized service label, e.g. "HTTP", "MySQL"
  ports: {
    port: number;
    protocol: string;
    product?: string;
    version?: string;
    extra?: string;
    scripts: string[]; // script ids attached to this port
  }[];
}

export interface Cve {
  id: string; // CVE-2011-2523, or a vulners identifier
  score?: number; // CVSS-ish number when the source gives one
  url?: string;
  exploit?: boolean; // *EXPLOIT* flag present
}

export interface NseScript {
  id: string; // script name, e.g. ftp-vsftpd-backdoor
  host: string;
  port?: number; // undefined => host script
  protocol?: string;
  scope: 'prescript' | 'port' | 'host' | 'postscript';
  state?: string; // VULNERABLE / LIKELY VULNERABLE / NOT VULNERABLE ...
  output: string; // full raw script body
  cves: Cve[];
}

export interface Vulnerability {
  id: string;
  title: string;
  host: string;
  port?: number;
  protocol?: string;
  service?: string;
  severity: Severity;
  severitySource: 'nse' | 'heuristic' | 'none';
  confidence: Confidence;
  cves: Cve[];
  evidence: string; // quoted from the scan
  source: string; // which script / section produced it
  explanation: string; // generated from parsed data, never invented
  disclosureDate?: string;
  exploitation?: Exploitation; // named tools + learning links (no attack commands)
  remediation?: Remediation; // how to fix / prevent it (for client reports)
}

/**
 * Defensive guidance for a finding: the impact in plain terms and concrete
 * steps to fix or mitigate it. Used in the exported client report.
 */
export interface Remediation {
  impact: string; // what an employer should understand is at risk
  fixes: string[]; // concrete remediation steps
  priority: 'Immediate' | 'High' | 'Medium' | 'Low';
}

/** Reference link with a human label. */
export interface RefLink {
  label: string;
  url: string;
}

/**
 * Non-weaponized guidance for a finding: which known tools/frameworks target
 * it, a plain-English note on the technique, verification steps, and reference
 * / learning links. Deliberately contains NO ready-to-run attack commands.
 */
export interface Exploitation {
  summary: string; // how it's exploited, conceptually
  tools: string[]; // named tools/modules, e.g. "Metasploit: exploit/unix/ftp/vsftpd_234_backdoor"
  verify: string[]; // verification checklist steps
  references: RefLink[]; // CVE/NVD, ExploitDB, Metasploit/Rapid7, HackTricks
  learning: RefLink[]; // video search + tutorial links
}

export interface WebFinding {
  port: number;
  protocol: string;
  server?: string; // Server header / product
  technologies: string[]; // PHP x.y, DAV, etc.
  headers: Record<string, string>;
  directories: string[]; // discovered paths
  urls: string[]; // interesting absolute URLs
  methods: string[]; // allowed HTTP methods
  auth: string[]; // auth requirements found
  securityNotes: string[]; // security-header / TRACE / xss notes
  tls: string[]; // SSL/TLS findings summarized
  scripts: string[]; // web-related script ids
}

export interface TracerouteHop {
  hop: number;
  address?: string;
  hostname?: string;
  rtt?: string;
}

export interface OsNetwork {
  host: string;
  os?: string;
  osDetails?: string;
  osCpe: string[];
  osFamily?: string;
  accuracy?: string;
  mac?: string;
  vendor?: string;
  latency?: string;
  uptime?: string;
  distance?: string;
  tcpSequence?: string;
  ipIdSequence?: string;
  traceroute: TracerouteHop[];
}

export interface Finding {
  id: string;
  category: string; // FTP, SMB, DNS, TLS, HTTP, RPC, Database, Info, ...
  title: string;
  detail: string;
  host: string;
  port?: number;
  protocol?: string;
  confidence: Confidence;
  source: string;
}

export interface UnparsedBlock {
  reason: string;
  content: string;
}

export interface ParsedScan {
  scan: ScanMeta;
  hosts: Host[];
  ports: Port[];
  services: ServiceGroup[];
  vulnerabilities: Vulnerability[];
  nseScripts: NseScript[];
  webFindings: WebFinding[];
  osNetwork: OsNetwork[];
  findings: Finding[];
  unparsed: UnparsedBlock[];
  rawOutput: string;
  stats: {
    hostsTotal: number;
    hostsUp: number;
    openPorts: number;
    closedPorts: number;
    filteredPorts: number;
    services: number;
    confirmed: number;
    potential: number;
    informational: number;
    unknown: number;
    cves: number;
  };
}
