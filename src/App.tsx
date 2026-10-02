import { useEffect, useMemo, useState } from 'react';
import {
  LayoutDashboard,
  Server,
  Network,
  Boxes,
  ShieldAlert,
  Globe,
  Terminal,
  Cpu,
  ListChecks,
  FileCode,
  Search,
  RotateCcw,
  Menu,
  FileDown,
} from 'lucide-react';
import { parseNmap, type ParsedScan } from './parser';
import UploadPage from './components/UploadPage';
import LandingPage from './components/LandingPage';
import SpaceBackground from './components/SpaceBackground';
import WolfLogo from './components/WolfLogo';
import Overview from './components/tabs/Overview';
import Hosts from './components/tabs/Hosts';
import Ports from './components/tabs/Ports';
import Services from './components/tabs/Services';
import Vulnerabilities from './components/tabs/Vulnerabilities';
import Web from './components/tabs/Web';
import NseScripts from './components/tabs/NseScripts';
import OsNetworkTab from './components/tabs/OsNetwork';
import Findings from './components/tabs/Findings';
import RawOutput from './components/tabs/RawOutput';
import { GlobalSearch } from './components/GlobalSearch';
import { ReportDialog } from './components/ReportDialog';
import { ChatPanel } from './components/ChatPanel';

type TabId =
  | 'overview'
  | 'hosts'
  | 'ports'
  | 'services'
  | 'vulns'
  | 'web'
  | 'nse'
  | 'os'
  | 'findings'
  | 'raw';

const TABS: { id: TabId; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'hosts', label: 'Hosts', icon: Server },
  { id: 'ports', label: 'Ports', icon: Network },
  { id: 'services', label: 'Services', icon: Boxes },
  { id: 'vulns', label: 'Vulnerabilities', icon: ShieldAlert },
  { id: 'web', label: 'Web', icon: Globe },
  { id: 'nse', label: 'NSE Scripts', icon: Terminal },
  { id: 'os', label: 'OS & Network', icon: Cpu },
  { id: 'findings', label: 'Findings', icon: ListChecks },
  { id: 'raw', label: 'Raw Output', icon: FileCode },
];

export default function App() {
  const [started, setStarted] = useState(false);
  const [scan, setScan] = useState<ParsedScan | null>(null);
  const [fileName, setFileName] = useState('');
  const [tab, setTab] = useState<TabId>('overview');
  const [error, setError] = useState<string | undefined>();
  const [searchOpen, setSearchOpen] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const analyze = (name: string, text: string): boolean => {
    try {
      const result = parseNmap(text);
      if (result.hosts.length === 0 && result.ports.length === 0 && !result.scan.nmapVersion) {
        setError(
          "This doesn't look like Nmap output — no scan header, hosts or ports were found. Paste the full terminal text of an Nmap scan."
        );
        return false;
      }
      setError(undefined);
      setScan(result);
      setFileName(name);
      setTab('overview');
      return true;
    } catch (e) {
      setError(`Failed to parse: ${(e as Error).message}`);
      return false;
    }
  };

  const badge = useMemo(() => {
    if (!scan) return {} as Record<TabId, number | undefined>;
    return {
      overview: undefined,
      hosts: scan.stats.hostsTotal,
      ports: scan.stats.openPorts,
      services: scan.stats.services,
      vulns: scan.stats.confirmed + scan.stats.potential,
      web: scan.webFindings.length,
      nse: scan.nseScripts.length,
      os: scan.osNetwork.length,
      findings: scan.findings.length,
      raw: undefined,
    } as Record<TabId, number | undefined>;
  }, [scan]);

  if (!started) return <LandingPage onStart={() => setStarted(true)} />;
  if (!scan) return <UploadPage onAnalyze={analyze} error={error} />;

  const reset = () => {
    setScan(null);
    setFileName('');
    setError(undefined);
  };

  return (
    <div className="relative flex min-h-screen">
      <SpaceBackground variant="app" />
      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-30 w-60 shrink-0 border-r border-edge bg-base-900/70 backdrop-blur-md transition-transform lg:static lg:translate-x-0 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex items-center gap-2 border-b border-edge px-4 py-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/10">
            <WolfLogo size={26} />
          </div>
          <div>
            <p className="text-sm font-bold text-white">Night Watch</p>
            <p className="truncate text-[10px] text-slate-500" title={fileName}>
              {fileName}
            </p>
          </div>
        </div>
        <nav aria-label="Scan report sections" className="p-2">
          {TABS.map((t) => {
            const Icon = t.icon;
            const n = badge[t.id];
            return (
              <button
                key={t.id}
                onClick={() => {
                  setTab(t.id);
                  setSidebarOpen(false);
                }}
                aria-current={tab === t.id ? 'page' : undefined}
                className={`mb-0.5 flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                  tab === t.id
                    ? 'bg-accent/15 font-medium text-accent'
                    : 'text-slate-400 hover:bg-base-800 hover:text-slate-200'
                }`}
              >
                <Icon size={16} />
                <span className="flex-1 text-left">{t.label}</span>
                {n !== undefined && n > 0 && (
                  <span className="rounded-full bg-base-800 px-1.5 text-[10px] tabular-nums text-slate-400">
                    {n}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
        <div className="absolute bottom-0 w-full border-t border-edge p-2">
          <button className="btn w-full justify-center" onClick={reset}>
            <RotateCcw size={14} /> New scan
          </button>
        </div>
      </aside>

      {sidebarOpen && (
        <div className="fixed inset-0 z-20 bg-black/50 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      {/* Main */}
      <div className="relative z-10 flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex items-center gap-3 border-b border-edge bg-base-900/60 px-4 py-3 backdrop-blur-md">
          <button
            className="rounded-md p-1.5 text-slate-400 hover:bg-base-800 lg:hidden"
            onClick={() => setSidebarOpen(true)}
            aria-label="Open scan sections"
            aria-expanded={sidebarOpen}
          >
            <Menu size={20} />
          </button>
          <div className="flex items-center gap-2 text-sm text-slate-400">
            <span className="text-slate-500">Night Watch</span>
            <span className="text-slate-700">/</span>
            <span className="font-medium text-white">{TABS.find((t) => t.id === tab)?.label}</span>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <button
              className="btn"
              onClick={() => setSearchOpen(true)}
              title="Global search (everything)"
            >
              <Search size={14} aria-hidden="true" />
              <span className="hidden sm:inline">Search</span>
              <kbd className="hidden rounded bg-base-700 px-1.5 text-[10px] text-slate-400 sm:inline">
                /
              </kbd>
            </button>
            <button
              className="btn-primary"
              onClick={() => setReportOpen(true)}
              title="Export a client-ready PDF report"
            >
              <FileDown size={14} aria-hidden="true" />
              <span className="hidden sm:inline">Export Report</span>
            </button>
          </div>
        </header>

        <main id="main-content" tabIndex={-1} className="min-w-0 flex-1 p-4 sm:p-6">
          {tab === 'overview' && <Overview scan={scan} />}
          {tab === 'hosts' && <Hosts scan={scan} />}
          {tab === 'ports' && <Ports scan={scan} />}
          {tab === 'services' && <Services scan={scan} />}
          {tab === 'vulns' && <Vulnerabilities scan={scan} />}
          {tab === 'web' && <Web scan={scan} />}
          {tab === 'nse' && <NseScripts scan={scan} />}
          {tab === 'os' && <OsNetworkTab scan={scan} />}
          {tab === 'findings' && <Findings scan={scan} />}
          {tab === 'raw' && <RawOutput scan={scan} fileName={fileName} />}
        </main>
      </div>

      {searchOpen && (
        <GlobalSearch
          scan={scan}
          onClose={() => setSearchOpen(false)}
          onNavigate={(t) => {
            setTab(t as TabId);
            setSearchOpen(false);
          }}
        />
      )}

      {reportOpen && <ReportDialog scan={scan} onClose={() => setReportOpen(false)} />}

      {/* Floating Scan Assistant (manages its own open/close) */}
      <ChatPanel scan={scan} />

      {/* keyboard: "/" opens search */}
      <KeyBinder onSlash={() => setSearchOpen(true)} />
    </div>
  );
}

function KeyBinder({ onSlash }: { onSlash: () => void }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (e.key === '/' && tag !== 'INPUT' && tag !== 'TEXTAREA') {
        e.preventDefault();
        onSlash();
      }
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onSlash]);
  return null;
}
