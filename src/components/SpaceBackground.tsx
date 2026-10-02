import { useMemo } from 'react';

/**
 * Persistent space backdrop rendered behind the whole app (dashboard + tabs).
 * Subtle by default so content stays readable; `variant="hero"` is brighter
 * for the landing screen.
 */
export default function SpaceBackground({ variant = 'app' }: { variant?: 'app' | 'hero' }) {
  const count = variant === 'hero' ? 140 : 90;
  const stars = useMemo(
    () =>
      Array.from({ length: count }, () => ({
        top: Math.random() * 100,
        left: Math.random() * 100,
        size: Math.random() * 2 + 0.5,
        delay: Math.random() * 4,
        dur: Math.random() * 3 + 2,
      })),
    [count]
  );
  const dim = variant === 'app';
  return (
    <div className={`nw-bg ${dim ? 'nw-bg-dim' : ''}`} aria-hidden>
      <div className="nw-stars">
        {stars.map((s, i) => (
          <span
            key={i}
            style={{
              top: `${s.top}%`,
              left: `${s.left}%`,
              width: `${s.size}px`,
              height: `${s.size}px`,
              animationDelay: `${s.delay}s`,
              animationDuration: `${s.dur}s`,
            }}
          />
        ))}
      </div>
      <div className="nw-nebula nw-nebula-1" />
      <div className="nw-nebula nw-nebula-2" />
      <div className="nw-galaxy" />
      <div className="nw-planet nw-planet-a" />
      <div className="nw-planet nw-planet-b" />
      <div className="nw-planet nw-planet-c" />
      <div className="nw-shoot nw-shoot-1" />
      <div className="nw-shoot nw-shoot-2" />
      <div className="nw-shoot nw-shoot-3" />
    </div>
  );
}
