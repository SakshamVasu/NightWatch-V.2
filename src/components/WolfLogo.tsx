/** Night Watch logo — the wolf-howling image. */
import { LOGO_URI } from './logo';

export default function WolfLogo({ size = 32, className }: { size?: number; className?: string }) {
  return (
    <img
      src={LOGO_URI}
      width={size}
      height={size}
      className={className}
      alt="Night Watch"
      style={{ borderRadius: '6px', objectFit: 'cover', display: 'block' }}
    />
  );
}
