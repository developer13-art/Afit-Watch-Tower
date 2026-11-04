/**
 * Brand artwork.
 *
 * `afit-emblem.png` is AFIT's own emblem, supplied on 2026-11-03. It is carried at 512px with the
 * dark surround around its rounded frame made transparent, so it reads correctly on the night
 * photograph behind the entry screens; `python scripts/make_brand_assets.py <official file>`
 * regenerates it and every launcher, adaptive-icon, favicon and splash derivative from the
 * artwork, which is the only brand binary worth keeping. `campus-night.generated.jpg` is still an
 * AI-generated placeholder, not AFIT property, exported at 720x1280 because it is only ever drawn
 * full-bleed behind dimmed type. Both are served from `public/` rather than imported
 * so the JS bundle stays small and the picture is fetched once, on the two screens that show it.
 *
 * The emblem has "AFIT WATCH TOWER" lettered inside its own frame. The screens below still print
 * the name as text, because at the sizes the emblem is drawn (104-132px) that internal lettering
 * is barely legible and the name has to survive being read at a glance.
 */
import type { ReactNode } from 'react';

const BASE = import.meta.env.BASE_URL ?? '/';

const asset = (name: string) => `${BASE}brand/${name}`;

export const EMBLEM_SRC = asset('afit-emblem.png');
export const CAMPUS_NIGHT_SRC = asset('campus-night.generated.jpg');

export function Emblem({ size = 96, className = '' }: { size?: number; className?: string }) {
  return (
    <img
      src={EMBLEM_SRC}
      width={size}
      height={size}
      alt="AFIT WATCH TOWER emblem"
      className={`rounded-tile object-contain ${className}`}
      style={{ width: size, height: size, background: 'transparent' }}
      draggable={false}
    />
  );
}

/** Full-bleed photograph behind a screen, dimmed so white type stays readable. */
export function BrandBackdrop({ children }: { children: ReactNode }) {
  return (
    <div className="relative min-h-full overflow-hidden">
      <img
        src={CAMPUS_NIGHT_SRC}
        alt=""
        aria-hidden
        className="pointer-events-none absolute inset-0 h-full w-full object-cover opacity-45"
        style={{ background: 'transparent' }}
        draggable={false}
      />
      <div aria-hidden className="pointer-events-none absolute inset-0 bg-gradient-to-b from-surface-base/30 via-surface-base/70 to-surface-base" />
      <div className="relative">{children}</div>
    </div>
  );
}
