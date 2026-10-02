import { useEffect, useRef, useState } from 'react';
import { MessageSquare, X, Send, Bot, Cpu, KeyRound, Trash2, Loader2 } from 'lucide-react';
import {
  answerLocally,
  askAi,
  PROVIDERS,
  type ChatMsg,
  type Provider,
  type ParsedScan,
} from '../parser';

const LS_KEY = 'nmap-analyzer.ai';

interface StoredAi {
  provider: Provider;
  keys: Partial<Record<Provider, string>>;
  model?: string;
}

function loadAi(): StoredAi {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) return JSON.parse(raw);
  } catch {
    /* ignore */
  }
  return { provider: 'openai', keys: {} };
}
function saveAi(v: StoredAi) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(v));
  } catch {
    /* ignore */
  }
}

export function ChatPanel({ scan }: { scan: ParsedScan }) {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<'local' | 'ai'>('local');
  const [aiConsent, setAiConsent] = useState(false);
  const [ai, setAi] = useState<StoredAi>(() => loadAi());
  const [showSettings, setShowSettings] = useState(false);
  const [msgs, setMsgs] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => saveAi(ai), [ai]);
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [msgs, busy]);

  const currentKey = ai.keys[ai.provider] || '';
  const canAi = mode === 'ai' && aiConsent && currentKey.trim().length > 0;

  const send = async () => {
    const text = input.trim();
    if (!text || busy) return;
    setInput('');
    const next = [...msgs, { role: 'user' as const, content: text }];
    setMsgs(next);

    if (mode === 'local') {
      const reply = answerLocally(scan, text);
      setMsgs([...next, { role: 'assistant', content: reply }]);
      return;
    }
    // AI mode
    if (!aiConsent) {
      setMsgs([...next, { role: 'assistant', content: 'AI sharing is off. Review and accept the data-sharing notice above before sending scan context to a provider.' }]);
      return;
    }
    if (!currentKey.trim()) {
      setShowSettings(true);
      setMsgs([
        ...next,
        { role: 'assistant', content: 'Add your API key in settings (gear icon) to use AI mode.' },
      ]);
      return;
    }
    setBusy(true);
    try {
      const reply = await askAi(
        { provider: ai.provider, apiKey: currentKey, model: ai.model },
        scan,
        msgs,
        text
      );
      setMsgs([...next, { role: 'assistant', content: reply }]);
    } catch (e) {
      setMsgs([
        ...next,
        {
          role: 'assistant',
          content:
            `⚠ ${(e as Error).message}\n\nIf this is a network/CORS error, browser-to-provider calls can be ` +
            `blocked — try the full app on localhost, or switch back to Local mode (always works).`,
        },
      ]);
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-5 right-5 z-40 flex h-12 w-12 items-center justify-center rounded-full bg-accent text-base-950 shadow-lg transition hover:bg-accent-dim"
        title="Ask about your scan"
      >
        <MessageSquare size={22} />
      </button>
    );
  }

  return (
    <div className="fixed bottom-5 right-5 z-40 flex h-[560px] max-h-[85vh] w-[380px] max-w-[calc(100vw-2rem)] flex-col overflow-hidden rounded-xl border border-edge bg-base-850 shadow-2xl">
      {/* header */}
      <div className="flex items-center justify-between border-b border-edge bg-base-900 px-3 py-2.5">
        <div className="flex items-center gap-2">
          {mode === 'local' ? <Cpu size={16} className="text-accent" /> : <Bot size={16} className="text-accent" />}
          <span className="text-sm font-semibold text-white">Scan Assistant</span>
        </div>
        <div className="flex items-center gap-1">
          <button
            className="rounded p-1.5 text-slate-500 hover:bg-base-700 hover:text-white"
            onClick={() => setShowSettings((s) => !s)}
            title="AI settings"
          >
            <KeyRound size={15} />
          </button>
          <button
            className="rounded p-1.5 text-slate-500 hover:bg-base-700 hover:text-white"
            onClick={() => setMsgs([])}
            title="Clear conversation"
          >
            <Trash2 size={15} />
          </button>
          <button
            className="rounded p-1.5 text-slate-500 hover:bg-base-700 hover:text-white"
            onClick={() => setOpen(false)}
          >
            <X size={16} />
          </button>
        </div>
      </div>

      {/* mode toggle */}
      <div className="flex gap-1 border-b border-edge bg-base-900/60 p-1.5">
        <ModeBtn active={mode === 'local'} onClick={() => { setMode('local'); setAiConsent(false); }} icon={<Cpu size={13} />} label="Local" />
        <ModeBtn active={mode === 'ai'} onClick={() => { setMode('ai'); setAiConsent(false); }} icon={<Bot size={13} />} label="AI (your key)" />
      </div>

      {mode === 'ai' && (
        <div className="border-b border-amber-500/30 bg-amber-500/10 p-3" role="note">
          <p className="text-xs leading-relaxed text-amber-100">
            AI mode sends scan details and this conversation to {PROVIDERS.find((p) => p.id === ai.provider)?.label}. Your API key is saved in this browser’s local storage.
          </p>
          {!aiConsent ? (
            <button className="mt-2 rounded-md bg-amber-300 px-2.5 py-1.5 text-xs font-semibold text-base-950" onClick={() => setAiConsent(true)}>
              I understand — enable sharing
            </button>
          ) : (
            <button className="mt-2 text-xs text-amber-200 underline" onClick={() => { setAiConsent(false); setMode('local'); }}>
              Turn off sharing and return to Local
            </button>
          )}
        </div>
      )}

      {/* settings */}
      {showSettings && (
        <div className="space-y-2 border-b border-edge bg-base-900 p-3">
          <p className="text-[11px] text-slate-400">
            The scan and conversation are sent to the selected provider when you use AI mode. The key is stored in this browser’s local storage.
          </p>
          <select
            className="input !py-1.5 text-sm"
            value={ai.provider}
            onChange={(e) => {
              const provider = e.target.value as Provider;
              if (provider !== ai.provider) setAiConsent(false);
              setAi({ ...ai, provider, model: undefined });
            }}
          >
            {PROVIDERS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label} — {p.defaultModel}
              </option>
            ))}
          </select>
          <input
            type="password"
            className="input !py-1.5 text-sm"
            placeholder={`API key (${PROVIDERS.find((p) => p.id === ai.provider)?.keyHint})`}
            value={ai.keys[ai.provider] || ''}
            onChange={(e) => setAi({ ...ai, keys: { ...ai.keys, [ai.provider]: e.target.value } })}
          />
          <input
            className="input !py-1.5 text-sm"
            placeholder={`Model (optional, default ${PROVIDERS.find((p) => p.id === ai.provider)?.defaultModel})`}
            value={ai.model || ''}
            onChange={(e) => setAi({ ...ai, model: e.target.value || undefined })}
          />
          {ai.keys[ai.provider] && (
            <button
              className="text-[11px] text-slate-500 hover:text-sev-critical"
              onClick={() => setAi({ ...ai, keys: { ...ai.keys, [ai.provider]: '' } })}
            >
              Forget {PROVIDERS.find((p) => p.id === ai.provider)?.label} key
            </button>
          )}
        </div>
      )}

      {/* messages */}
      <div className="flex-1 space-y-3 overflow-y-auto p-3">
        {msgs.length === 0 && (
          <div className="mt-2 text-xs text-slate-400">
            <p className="mb-2">
              {mode === 'local'
                ? "I answer from your parsed scan — nothing leaves this browser. Ask me anything about it."
                : canAi
                  ? 'AI mode active. Ask open-ended questions about your scan.'
                  : 'AI mode selected — add your API key (key icon above) to start.'}
            </p>
            <div className="flex flex-wrap gap-1.5">
              {['Most critical issue?', 'Is port 445 open?', 'How do I fix vsftpd?', 'Show confirmed findings'].map(
                (s) => (
                  <button
                    key={s}
                    onClick={() => setInput(s)}
                    className="rounded-md border border-edge bg-base-800 px-2 py-1 text-[11px] text-slate-300 hover:border-accent"
                  >
                    {s}
                  </button>
                )
              )}
            </div>
          </div>
        )}
        {msgs.map((m, i) => (
          <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className={`max-w-[85%] whitespace-pre-wrap rounded-lg px-3 py-2 text-sm ${
                m.role === 'user'
                  ? 'bg-accent text-base-950'
                  : 'border border-edge bg-base-900 text-slate-200'
              }`}
            >
              {renderText(m.content)}
            </div>
          </div>
        ))}
        {busy && (
          <div className="flex justify-start">
            <div className="flex items-center gap-2 rounded-lg border border-edge bg-base-900 px-3 py-2 text-sm text-slate-400">
              <Loader2 size={14} className="animate-spin" /> Thinking…
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>

      {/* input */}
      <div className="border-t border-edge p-2">
        <div className="flex items-end gap-2">
          <textarea
            className="input max-h-24 min-h-[38px] flex-1 resize-none text-sm"
            rows={1}
            placeholder={mode === 'local' ? 'Ask about your scan…' : 'Ask your AI…'}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                send();
              }
            }}
          />
          <button className="btn-primary !px-3" onClick={send} disabled={busy || !input.trim()}>
            <Send size={15} />
          </button>
        </div>
      </div>
    </div>
  );
}

function ModeBtn({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex flex-1 items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-medium transition ${
        active ? 'bg-base-700 text-white' : 'text-slate-400 hover:text-slate-200'
      }`}
    >
      {icon}
      {label}
    </button>
  );
}

/** Minimal markdown: **bold** only, kept simple and safe (no HTML injection). */
function renderText(text: string): React.ReactNode {
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((p, i) =>
    p.startsWith('**') && p.endsWith('**') ? (
      <strong key={i} className="font-semibold">
        {p.slice(2, -2)}
      </strong>
    ) : (
      <span key={i}>{p}</span>
    )
  );
}
