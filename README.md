# Night Watch

> Turns raw Nmap scan output into a security dashboard, PDF report, and chat assistant — 100% in your browser.

Turn raw Nmap scan output into a clean, professional security dashboard —
**parsed entirely in your browser**. Upload normal (`-oN`), grepable (`-oG`), or XML (`-oX`) Nmap output, or paste terminal output,
and get an interactive report: hosts, ports, services, vulnerabilities (with an
honest confidence model), web findings, NSE script output, OS/network details
and a consolidated findings view.

No backend is required. In Local mode, scans stay in your browser and no API key is needed. Optional AI mode sends scan context and conversation to the provider you choose.

---

## Two ways to run it

### 1. The full app (React + Vite + TypeScript + Tailwind)

```bash
npm install
npm run dev      # opens http://localhost:5173
```

Then upload an Nmap `.txt` / `.nmap` file (or paste the raw output) and the
dashboard appears.

Build a static production bundle:

```bash
npm run build    # outputs to dist/
npm run preview  # serve the built bundle locally
```

### 2. The zero-build standalone (`standalone.html`)

Just open **`standalone.html`** in any modern browser. It uses the *same*
parser as the app (transpiled from `src/parser/*.ts`) and pulls React /
React from a CDN at runtime, so it needs internet the first time but no npm
and no build step. Handy for quick use or sharing a single file.

Regenerate it after changing the parser:

```bash
npm run build:standalone
```

---

## Run the parser tests

The parser is covered by a dependency-free test suite that runs on Node's
built-in test runner against two real-shaped fixtures:

```bash
npm test
```

You can also parse a file straight from the CLI (prints the structured result):

```bash
npm run parse -- samples/metasploitable2.nmap.txt
```

> Requires Node 18.19+ / 20.6+ / 22+ (uses `--experimental-strip-types` to run
> the TypeScript sources directly). The **app** build itself has no such
> requirement — that flag is only for running tests/CLI without a compile step.

---

## What it parses

The parser is tolerant of real terminal captures — ANSI codes, `sudo` output,
Kali prompt boxes, `tee` decorations, live `Stats:`/NSE-timing progress lines,
and wrapped script output are all stripped or re-joined before parsing. It
recognizes:

- **Scan metadata** — Nmap version, command, arguments, start time, duration
- **Hosts** — status, latency, hostnames, OS, MAC/vendor, uptime, distance
  (multiple hosts supported)
- **Ports** — number, protocol, state (open/closed/filtered), service, product,
  version, extra info — with per-host attribution
- **Services** — grouped and normalized (FTP, SSH, HTTP, MySQL, PostgreSQL,
  Tomcat, SMB, NFS, Java RMI, …)
- **NSE scripts** — every script block captured verbatim, attributed to its
  host/port, with detected state and CVEs
- **Vulnerabilities** — classified by confidence (see below)
- **Web** — server, technologies, headers, discovered directories, HTTP
  methods, auth points, SSL/TLS findings, web NSE scripts
- **OS & network** — OS detection, CPE, MAC/vendor, TCP/IP sequence, traceroute
- **Findings** — a consolidated, categorized view (FTP, SMB, DNS, TLS, HTTP,
  Database, NFS, …)
- **Raw output** — the original file, searchable, with line numbers and download

Anything non-trivial the parser can't confidently classify is preserved under
`unparsed` rather than dropped or guessed at.

Uploads are limited to 25 MB. Large port, vulnerability, NSE, findings, and raw
output lists render in batches so the interface does not mount every row at once.

---

## The confidence model (the important part)

Nmap output mixes proof with association. This tool never blurs the two:

| Confidence | Meaning | Example |
|---|---|---|
| **CONFIRMED** | An NSE script explicitly reported a `VULNERABLE` state (or demonstrated a result). | `ftp-vsftpd-backdoor` → `State: VULNERABLE (Exploitable)`, returned `uid=0(root)`. |
| **POTENTIAL** | A CVE is *associated* with a detected software version (e.g. Vulners), or a check reported `LIKELY VULNERABLE`. It is a lead to verify — **not** proof of exploitability. | Vulners lists 320 CVEs for `Apache httpd 2.2.8`. |
| **INFORMATIONAL** | An observation: open port, banner, old version, anonymous FTP, `TRACE` enabled, a discovered directory. | `21/tcp open ftp`, anonymous FTP login allowed. |
| **UNKNOWN** | Captured but not classifiable. | (rare) |

**Severity** is likewise never invented:

- If an NSE script states a risk factor or CVSS score, that is used.
- Otherwise a severity may be **derived** from the maximum associated CVSS score
  and is explicitly labelled **`heuristic`** in the UI.
- If there is no basis at all, severity is **`UNRATED`**.

`NOT VULNERABLE` results are recorded as informational reassurance and are
**never** promoted to a vulnerability.

---

## Reports & the Scan Assistant

**Export Report** (header button) generates a client-ready security report —
executive summary, prioritized remediation, per-finding business impact + fix
steps, and an optional open-ports appendix — then opens it with the browser's print
dialog so you can **Save as PDF**. You can add assessment and report identifiers
and choose which confidence sections to include. All content is derived from the parsed scan.

**Scan Assistant** (floating chat button, bottom-right) has two modes:

- **Local (default)** — answers questions about your scan by querying the
  parsed data (“most critical issue?”, “is port 3306 open?”, “how do I fix
  vsftpd?”, a CVE id, …). No AI, no API key, nothing leaves the browser.
- **AI (bring-your-own-key)** — switch the toggle, pick **OpenAI / Anthropic /
  Gemini**, paste your own API key (stored in this browser's localStorage), and
  chat freely. The scan context is sent to your chosen provider for grounding —
  a conscious trade-off the UI makes explicit. Browser-to-provider calls can be
  blocked by CORS on some setups; if so, the assistant says to use the full app
  on localhost or fall back to Local mode. The app works fully without any key. AI mode requires an explicit in-panel acknowledgement before scan context is sent; API keys are stored in browser local storage and can be forgotten in settings.

---

## Architecture

```
src/
  parser/                 # framework-free, fully tested; the UI depends on this
    types.ts              # the shared data model (ParsedScan and its parts)
    util.ts               # preprocessing: ANSI/tee stripping, CVE + Vulners
                          #   extraction, service normalization, severity mapping
    core.ts               # single-pass section parser: metadata, hosts, port
                          #   table, NSE blocks, OS lines, traceroute
    analyze.ts            # analysis layer: NSE classification, vulnerability
                          #   confidence/severity, services, web, OS/network,
                          #   findings, stats
    index.ts              # public entry — `import { parseNmap } from './parser'`
    __tests__/parser.test.ts
  components/
    UploadPage.tsx        # drag/drop + paste, loading & error states
    GlobalSearch.tsx      # "/" search across everything
    Badges.tsx, ui.tsx, StatCard.tsx
    tabs/                 # Overview, Hosts, Ports, Services, Vulnerabilities,
                          #   Web, NseScripts, OsNetwork, Findings, RawOutput
  App.tsx                 # sidebar shell, routing between tabs (no page reload)
  main.tsx, index.css
samples/                  # test fixtures (real Metasploitable2 + a small
                          #   multi-host scan)
scripts/                  # test runner glue + standalone builder
standalone.html           # generated single-file app
```

**Data flow:** `raw text → preprocess (util) → core section parse → analyze
(classify) → ParsedScan → React tabs`. The parser is deliberately split into
small, per-section functions (not one giant regex) so new Nmap variants can be
supported by extending one module. The UI reads only the `ParsedScan` model, so
parser and UI evolve independently.

**Design:** dark SOC/pentest aesthetic (Tailwind), inline SVG charts for the
confidence
donut and CVE-exposure bar chart, Lucide icons, responsive down to mobile
(collapsible sidebar). Everything runs client-side; the upload page states this
explicitly.

---

## Safety / scope

This is an **analysis and reporting** tool for Nmap output you already have. It
does not scan, exploit, brute-force, or contact discovered hosts. It only reads
the file you give it.

---

## Adding support for new output

1. Add or extend a parsing function in `src/parser/core.ts` (structural
   extraction) or `src/parser/analyze.ts` (classification).
2. Drop a representative capture in `samples/`.
3. Add assertions in `src/parser/__tests__/parser.test.ts` and run `npm test`.
4. `npm run build:standalone` to refresh the single-file build.
