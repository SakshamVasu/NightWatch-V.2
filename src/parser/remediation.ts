/**
 * Remediation knowledge base — defensive, client-report guidance.
 *
 * For a finding, returns the business impact in plain terms, concrete fix
 * steps, and a remediation priority. Specific entries for well-known issues;
 * a sensible generic fallback for everything else, derived from the parsed
 * confidence/severity so nothing is invented.
 */
import type { Cve, Confidence, Remediation, Severity } from './types';

interface RemEntry {
  match: (scriptId: string, title: string, cves: string[]) => boolean;
  rem: Remediation;
}

const REM_KB: RemEntry[] = [
  {
    match: (id) => id === 'ftp-vsftpd-backdoor',
    rem: {
      impact:
        'The FTP service is a backdoored build that grants an unauthenticated attacker a root shell — full control of the host. This is a critical compromise of confidentiality, integrity and availability.',
      fixes: [
        'Immediately remove or replace the vsftpd 2.3.4 package; install a current, vendor-supported FTP server from trusted repositories.',
        'Rebuild the host if there is any chance it was already compromised — a backdoored binary means trust in the system is gone.',
        'If FTP is not required, disable it entirely.',
        'Prefer SFTP/FTPS over plaintext FTP going forward.',
      ],
      priority: 'Immediate',
    },
  },
  {
    match: (id) => id === 'distcc-cve2004-2687',
    rem: {
      impact:
        'The distccd service allows remote command execution, letting an attacker run code as the service account and pivot further into the host.',
      fixes: [
        'Disable distccd if distributed compilation is not needed.',
        'If required, restrict it to trusted build hosts only via firewall rules and the DISTCC_HOSTS allow-list; never expose it to untrusted networks.',
        'Run the service as an unprivileged, sandboxed account.',
      ],
      priority: 'Immediate',
    },
  },
  {
    match: (id) => id === 'rmi-vuln-classloader' || id.includes('java-rmi'),
    rem: {
      impact:
        'The Java RMI registry permits remote class loading, enabling remote code execution on the host.',
      fixes: [
        'Disable remote class loading (set the RMI server not to fetch classes from remote codebases).',
        'Restrict RMI ports to trusted management networks with firewall rules.',
        'Upgrade the Java runtime and application to versions with secure RMI defaults; avoid exposing RMI to untrusted clients.',
      ],
      priority: 'Immediate',
    },
  },
  {
    match: (id) => id === 'irc-unrealircd-backdoor',
    rem: {
      impact:
        'The IRC daemon is a trojaned build containing a backdoor that allows arbitrary command execution on the host.',
      fixes: [
        'Remove the compromised UnrealIRCd build and reinstall from a verified, checksum-validated source.',
        'Rebuild the host if compromise is suspected.',
        'Disable the IRC service if it is not a required business function.',
      ],
      priority: 'Immediate',
    },
  },
  {
    match: (id) => id === 'ssl-poodle',
    rem: {
      impact:
        'The service supports SSLv3, which is vulnerable to POODLE. An attacker positioned between client and server could decrypt small sensitive values such as session cookies.',
      fixes: [
        'Disable SSLv3 entirely on this service.',
        'Disable CBC-mode ciphers where possible and prefer TLS 1.2/1.3 with modern cipher suites.',
        'Re-test with an SSL/TLS scanner after changes.',
      ],
      priority: 'High',
    },
  },
  {
    match: (id) => id === 'ssl-ccs-injection',
    rem: {
      impact:
        'The OpenSSL version is vulnerable to CCS Injection, allowing a man-in-the-middle to weaken and potentially decrypt or tamper with the encrypted session.',
      fixes: [
        'Upgrade OpenSSL to a patched version (0.9.8za / 1.0.0m / 1.0.1h or later).',
        'Restart all services that link against OpenSSL after upgrading.',
      ],
      priority: 'High',
    },
  },
  {
    match: (id) => id === 'ssl-dh-params',
    rem: {
      impact:
        'The service uses weak or export-grade Diffie-Hellman parameters, allowing a capable attacker to downgrade and break the encrypted session (Logjam).',
      fixes: [
        'Disable export cipher suites entirely.',
        'Use a strong, unique 2048-bit-or-larger DH group (or switch to ECDHE key exchange).',
        'Prefer TLS 1.2/1.3 with modern cipher suites and re-test.',
      ],
      priority: 'High',
    },
  },
  {
    match: (id) => id === 'http-slowloris-check',
    rem: {
      impact:
        'The web server is likely susceptible to Slowloris, a low-bandwidth denial-of-service that can make the site unavailable.',
      fixes: [
        'Set connection and request timeouts; limit concurrent connections per client.',
        'Deploy a reverse proxy / WAF (e.g. nginx, mod_reqtimeout, cloud WAF) that buffers slow requests.',
        'Keep the web server software current.',
      ],
      priority: 'Medium',
    },
  },
  {
    match: (id) => id.startsWith('smb-vuln-ms17-010'),
    rem: {
      impact:
        'The host is exposed to MS17-010 (EternalBlue), enabling wormable remote code execution — the flaw behind WannaCry and NotPetya.',
      fixes: [
        'Apply the MS17-010 security update immediately.',
        'Disable SMBv1 entirely.',
        'Restrict SMB (TCP 445) to trusted internal networks with firewall rules.',
      ],
      priority: 'Immediate',
    },
  },
  // ---- informational / hygiene patterns keyed by title text ----
  {
    match: (_id, title) => /anonymous ftp/i.test(title),
    rem: {
      impact:
        'Anonymous FTP is enabled, allowing anyone to access files without credentials. Depending on permissions this can leak data or allow uploads.',
      fixes: [
        'Disable anonymous FTP access unless it is an explicit, reviewed business requirement.',
        'If anonymous access is needed, tightly restrict it to a read-only, non-sensitive directory.',
        'Move to authenticated SFTP/FTPS.',
      ],
      priority: 'Medium',
    },
  },
  {
    match: (_id, title) => /empty password/i.test(title),
    rem: {
      impact:
        'A database/service account has no password, allowing trivial unauthorized access to data.',
      fixes: [
        'Set a strong, unique password for the account immediately.',
        'Restrict the service to listen only on required interfaces and networks.',
        'Review accounts for least-privilege and remove unused ones.',
      ],
      priority: 'Immediate',
    },
  },
  {
    match: (_id, title) => /trace/i.test(title) && /http/i.test(title),
    rem: {
      impact:
        'HTTP TRACE is enabled, which can aid cross-site tracing attacks and information disclosure.',
      fixes: ['Disable the TRACE method at the web server or proxy.', 'Allow only the HTTP methods the application needs.'],
      priority: 'Low',
    },
  },
  {
    match: (_id, title) => /anonymous read\/write|anonymous access/i.test(title),
    rem: {
      impact:
        'A network share allows anonymous read/write access, exposing data and providing a foothold for attackers to plant files.',
      fixes: [
        'Require authentication on all shares; remove anonymous/guest access.',
        'Apply least-privilege permissions and restrict shares to required users.',
        'Restrict SMB to trusted networks.',
      ],
      priority: 'High',
    },
  },
];

const sevToPriority: Record<Severity, Remediation['priority']> = {
  CRITICAL: 'Immediate',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Low',
  UNRATED: 'Medium',
};

/** Build remediation guidance for a finding (specific entry, else generic). */
export function buildRemediation(
  scriptId: string,
  title: string,
  cves: Cve[],
  confidence: Confidence,
  severity: Severity,
  service?: string,
  product?: string
): Remediation {
  const id = scriptId.replace(/^NSE:\s*/i, '').trim();
  const cveIds = cves.map((c) => c.id);
  for (const e of REM_KB) if (e.match(id, title, cveIds)) return e.rem;

  // Generic, derived from what the scan actually says.
  const subject = product || service || 'this service';
  if (confidence === 'POTENTIAL') {
    return {
      impact:
        `The detected version of ${subject} is associated with known CVEs. Whether any are exploitable here depends on the exact build and configuration, but running outdated software materially increases risk.`,
      fixes: [
        `Upgrade ${subject} to the current vendor-supported version and apply all security patches.`,
        'Confirm which associated CVEs remain unpatched for this exact build (some may be fixed via distro backports).',
        'If the service is not required, disable it to reduce attack surface.',
        'Restrict access to the service to trusted networks where possible.',
      ],
      priority: sevToPriority[severity],
    };
  }
  return {
    impact:
      `An open service (${subject}) was identified. On its own this is informational, but every exposed service expands the attack surface and should be justified.`,
    fixes: [
      'Confirm this service needs to be exposed; disable it if not.',
      'Keep it patched and restrict access with host/network firewalls.',
      'Enforce strong authentication and encryption for the service.',
    ],
    priority: 'Low',
  };
}
