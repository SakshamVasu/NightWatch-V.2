import { useCallback, useRef, useState } from 'react';
import { FileText, Loader2, Upload, X, ClipboardPaste, ShieldCheck } from 'lucide-react';
import SpaceBackground from './SpaceBackground';
import WolfLogo from './WolfLogo';

interface Props {
  onAnalyze: (name: string, text: string) => boolean | void;
  error?: string;
}

const ACCEPT = '.txt,.log,.nmap,.gnmap,.xml,.out';
const MAX_INPUT_BYTES = 25 * 1024 * 1024;

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

export default function UploadPage({ onAnalyze, error }: Props) {
  const [drag, setDrag] = useState(false);
  const [file, setFile] = useState<{ name: string; size: number; text: string } | null>(null);
  const [paste, setPaste] = useState('');
  const [mode, setMode] = useState<'file' | 'paste'>('file');
  const [busy, setBusy] = useState(false);
  const [readError, setReadError] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const readFile = useCallback((f: File) => {
    setReadError('');
    if (f.size > MAX_INPUT_BYTES) {
      setReadError(`This file is ${humanSize(f.size)}. Choose a file smaller than 25 MB.`);
      setFile(null);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result !== 'string' || !reader.result.trim()) {
        setReadError('This file is empty or could not be read as text.');
        setFile(null);
        return;
      }
      setFile({ name: f.name, size: f.size, text: reader.result });
    };
    reader.onerror = () => {
      setReadError('Could not read this file. Try another text export or paste the Nmap output.');
      setFile(null);
    };
    reader.readAsText(f);
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDrag(false);
      const f = e.dataTransfer.files?.[0];
      if (f) readFile(f);
    },
    [readFile]
  );

  const run = () => {
    const text = mode === 'file' ? file?.text : paste;
    const name = mode === 'file' ? file?.name || 'scan.txt' : 'pasted-scan.txt';
    if (!text || !text.trim()) return;
    if (new Blob([text]).size > MAX_INPUT_BYTES) {
      setReadError('Pasted output is larger than 25 MB. Use a smaller scan file.');
      return;
    }
    setReadError('');
    setBusy(true);
    setTimeout(() => {
      if (onAnalyze(name, text) === false) setBusy(false);
    }, 30);
  };

  const canRun = mode === 'file' ? !!file : paste.trim().length > 0;

  return (
    <div className="nw-space relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-12">
      <SpaceBackground variant="hero" />

      <div className="relative z-10 w-full max-w-xl">
        {/* brand */}
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="nw-badge mb-5 flex h-16 w-16 items-center justify-center rounded-2xl">
            <WolfLogo size={42} />
          </div>
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.4em] text-accent/80">
            Ingest scan
          </p>
          <h1 className="nw-title text-5xl font-black tracking-tight">
            NIGHT<span className="text-accent"> WATCH</span>
          </h1>
          <p className="mt-3 max-w-sm text-sm text-slate-400">
            Drop your Nmap scan below to map the attack surface — parsed entirely in your browser.
          </p>
        </div>

        {/* console-style card */}
        <div className="nw-card overflow-hidden rounded-2xl">
          <div className="flex items-center gap-2 border-b border-accent/15 bg-base-950/60 px-4 py-2.5">
            <span className="h-2.5 w-2.5 rounded-full bg-sev-critical/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-sev-medium/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
            <span className="ml-2 font-mono text-[11px] text-slate-500">nightwatch://ingest</span>
          </div>

          <div className="p-1.5">
            <div className="flex gap-1 rounded-xl bg-base-950/40 p-1">
              <button
                className={`flex-1 rounded-lg px-3 py-2 text-sm font-medium transition ${
                  mode === 'file' ? 'bg-accent/15 text-accent' : 'text-slate-400 hover:text-slate-200'
                }`}
                aria-pressed={mode === 'file'}
                onClick={() => setMode('file')}
              >
                <Upload size={14} className="mr-1.5 inline" />
                Upload file
              </button>
              <button
                className={`flex-1 rounded-lg px-3 py-2 text-sm font-medium transition ${
                  mode === 'paste' ? 'bg-accent/15 text-accent' : 'text-slate-400 hover:text-slate-200'
                }`}
                aria-pressed={mode === 'paste'}
                onClick={() => setMode('paste')}
              >
                <ClipboardPaste size={14} className="mr-1.5 inline" />
                Paste output
              </button>
            </div>
          </div>

          <div className="p-5 pt-3">
            {mode === 'file' ? (
              file ? (
                <div className="flex items-center justify-between rounded-xl border border-accent/25 bg-base-950/50 px-4 py-3">
                  <div className="flex items-center gap-3">
                    <FileText className="text-accent" size={22} />
                    <div>
                      <p className="text-sm font-medium text-white">{file.name}</p>
                      <p className="text-xs text-slate-500">
                        {humanSize(file.size)} · ready to analyze
                      </p>
                    </div>
                  </div>
                  <button
                    className="rounded-md p-1.5 text-slate-500 hover:bg-base-700 hover:text-white"
                    onClick={() => setFile(null)}
                    title="Remove file"
                  >
                    <X size={18} />
                  </button>
                </div>
              ) : (
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDrag(true);
                  }}
                  onDragLeave={() => setDrag(false)}
                  onDrop={onDrop}
                  onClick={() => inputRef.current?.click()}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      inputRef.current?.click();
                    }
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label="Choose an Nmap scan file"
                  className={`nw-drop group flex cursor-pointer flex-col items-center justify-center rounded-xl py-12 transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent ${
                    drag ? 'nw-drop-active' : ''
                  }`}
                >
                  <div className="nw-ring mb-3 flex h-14 w-14 items-center justify-center rounded-full">
                    <Upload className="text-accent transition group-hover:scale-110" size={26} />
                  </div>
                  <p className="text-sm font-medium text-slate-200">Drop Nmap scan here</p>
                  <p className="mt-1 text-xs text-slate-500">or click to browse</p>
                  <input
                    ref={inputRef}
                    type="file"
                    accept={ACCEPT}
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) readFile(f);
                      e.currentTarget.value = '';
                    }}
                  />
                </div>
              )
            ) : (
              <textarea
                className="input h-52 resize-none border-accent/20 bg-base-950/50 font-mono text-xs leading-relaxed"
                aria-label="Paste Nmap output"
                placeholder="Paste raw Nmap output here (the full terminal text, tee/sudo lines and all)…"
                value={paste}
                onChange={(e) => setPaste(e.target.value)}
              />
            )}

            <button className="nw-cta mt-5 w-full" disabled={!canRun || busy} onClick={run}>
              {busy ? <Loader2 size={16} className="animate-spin" /> : <WolfLogo size={18} />}
              {busy ? 'Analyzing…' : "Let's start analyzing"}
            </button>
            {busy && <p role="status" aria-live="polite" className="mt-2 text-center text-xs text-slate-400">Analyzing locally… larger scans can take a few seconds.</p>}

            <p className="mt-3 text-center text-[11px] text-slate-500">
              Normal, grepable, or XML output · up to 25 MB
            </p>

            {(readError || error) && (
              <div role="alert" className="mt-3 rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical">
                {readError || error}
              </div>
            )}
          </div>
        </div>

        <p className="mt-6 flex items-center justify-center gap-1.5 text-xs text-slate-500">
          <ShieldCheck size={12} className="text-accent/70" />
          Scan parsing stays in this browser. Optional AI mode can send scan context to a provider after you enable sharing.
        </p>
      </div>
    </div>
  );
}
