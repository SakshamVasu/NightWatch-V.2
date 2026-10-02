import { useEffect, useState } from 'react';
import { ChevronDown } from 'lucide-react';
import SpaceBackground from './SpaceBackground';
import WolfLogo from './WolfLogo';

const TITLE = 'NIGHT WATCH';

/** Space-themed intro: galaxy + planets + typewriter title; scroll to start. */
export default function LandingPage({ onStart }: { onStart: () => void }) {
  const [typed, setTyped] = useState(0);

  useEffect(() => {
    if (typed >= TITLE.length) return;
    const t = setTimeout(() => setTyped((n) => n + 1), 140);
    return () => clearTimeout(t);
  }, [typed]);

  const done = typed >= TITLE.length;

  return (
    <div className="nw-space">
      <SpaceBackground variant="hero" />

      {/* hero (first screen) */}
      <section className="nw-hero-screen">
        <div className="nw-badge mb-6 flex h-16 w-16 items-center justify-center rounded-2xl">
          <WolfLogo size={42} />
        </div>
        <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.5em] text-accent/80">
          Welcome to
        </p>
        <h1 className="nw-type-title">
          {TITLE.slice(0, typed).split('').map((ch, i) => (
            <span key={i} className={i >= 6 ? 'text-accent' : 'text-white'}>
              {ch === ' ' ? ' ' : ch}
            </span>
          ))}
          <span className={`nw-caret ${done ? 'nw-caret-done' : ''}`}>▋</span>
        </h1>
        <p
          className={`mt-4 max-w-md text-center text-sm text-slate-400 transition-opacity duration-700 ${
            done ? 'opacity-100' : 'opacity-0'
          }`}
        >
          The watchtower for your network. It sees every open port, every service, every weakness.
        </p>

        <div className={`nw-scroll-hint ${done ? 'nw-scroll-show' : ''}`}>
          <span className="text-[11px] uppercase tracking-widest text-slate-500">Scroll</span>
          <ChevronDown size={20} className="text-accent" />
        </div>
      </section>

      {/* start (revealed on scroll) */}
      <section className="nw-start-screen">
        <div className="text-center">
          <h2 className="mb-2 text-2xl font-bold text-white">Ready when you are.</h2>
          <p className="mb-8 max-w-sm text-sm text-slate-400">
            Feed Night Watch your Nmap scan and it will map the attack surface, flag the
            vulnerabilities, and brief you on every finding.
          </p>
          <button className="nw-cta nw-cta-lg" onClick={onStart}>
            <WolfLogo size={20} />
            Let's start analyzing
          </button>
        </div>
      </section>
    </div>
  );
}
