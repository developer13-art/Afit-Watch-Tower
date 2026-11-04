/**
 * Inline SVG icon set.
 *
 * Hand-drawn paths rather than an icon package: the Android build is assembled on a
 * restricted network, and a 30KB dependency pulled in for twenty glyphs is a supply
 * chain decision, not a design one. Every glyph inherits `currentColor`, so severity
 * and status colouring stays with the tokens in `tailwind.config.mjs` and never with
 * the icon.
 */
import type { ReactNode, SVGProps } from 'react';

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Svg({ size = 20, children, ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg
      aria-hidden
      focusable="false"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      {...rest}
    >
      {children}
    </svg>
  );
}

export function IconHome(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M3 10.5 12 3l9 7.5" />
      <path d="M5.5 9.5V20h13V9.5" />
      <path d="M10 20v-5h4v5" />
    </Svg>
  );
}

export function IconBell(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M18 15V10a6 6 0 1 0-12 0v5l-1.5 2.5h15L18 15Z" />
      <path d="M10 20a2 2 0 0 0 4 0" />
    </Svg>
  );
}

export function IconShield(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M12 3 5 5.5V12c0 4.2 2.9 7.4 7 9 4.1-1.6 7-4.8 7-9V5.5L12 3Z" />
      <path d="M12 8.5v4" />
      <path d="M12 15.5h.01" />
    </Svg>
  );
}

export function IconUser(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="12" cy="8.5" r="3.5" />
      <path d="M5.5 20c1.2-3.2 3.7-4.8 6.5-4.8s5.3 1.6 6.5 4.8" />
    </Svg>
  );
}

export function IconCamera(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M3 8.5 15 5v9L3 15.5V8.5Z" />
      <path d="M15 8.5h3.5L21 11v3l-2.5 1.5H15" />
      <path d="M6.5 15.5 8 20" />
    </Svg>
  );
}

export function IconPin(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M12 21s6-5.2 6-10a6 6 0 1 0-12 0c0 4.8 6 10 6 10Z" />
      <circle cx="12" cy="11" r="2.2" />
    </Svg>
  );
}

export function IconClock(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </Svg>
  );
}

export function IconGauge(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M4 17a8 8 0 1 1 16 0" />
      <path d="M12 17l3.5-4.5" />
      <circle cx="12" cy="17" r="1.2" />
    </Svg>
  );
}

export function IconAlert(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M12 4.5 21 19H3l9-14.5Z" />
      <path d="M12 10v4" />
      <path d="M12 16.5h.01" />
    </Svg>
  );
}

export function IconInfo(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5.5" />
      <path d="M12 7.8h.01" />
    </Svg>
  );
}

export function IconCheck(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M5 12.5 9.5 17 19 7" />
    </Svg>
  );
}

export function IconCheckCircle(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M8.2 12.2 11 15l5-5.8" />
    </Svg>
  );
}

export function IconChevronLeft(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M14.5 6 9 12l5.5 6" />
    </Svg>
  );
}

export function IconChevronRight(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M9.5 6 15 12l-5.5 6" />
    </Svg>
  );
}

export function IconShare(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M12 4v10" />
      <path d="M8.5 7.5 12 4l3.5 3.5" />
      <path d="M6 13v6h12v-6" />
    </Svg>
  );
}

export function IconNote(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M6 4.5h9L19 8v11.5H6V4.5Z" />
      <path d="M14.5 4.5V8H19" />
      <path d="M9 12h6M9 15.5h4" />
    </Svg>
  );
}

export function IconEscalate(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M6 18 18 6" />
      <path d="M9.5 6H18v8.5" />
    </Svg>
  );
}

export function IconSearch(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4 4" />
    </Svg>
  );
}

export function IconLogout(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M14 5.5H6.5V19H14" />
      <path d="M11 12h9" />
      <path d="m17 8.5 3.5 3.5L17 15.5" />
    </Svg>
  );
}

export function IconKey(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="8.5" cy="12" r="3.5" />
      <path d="M12 12h8.5" />
      <path d="M17 12v3M20 12v2.5" />
    </Svg>
  );
}

export function IconDevice(p: IconProps) {
  return (
    <Svg {...p}>
      <rect x="7.5" y="3.5" width="9" height="17" rx="2" />
      <path d="M11 18h2" />
    </Svg>
  );
}

export function IconSliders(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M5 8h9M18 8h1M5 16h1M10 16h9" />
      <circle cx="16" cy="8" r="2" />
      <circle cx="8" cy="16" r="2" />
    </Svg>
  );
}

export function IconEye(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M2.5 12S6 6.5 12 6.5 21.5 12 21.5 12 18 17.5 12 17.5 2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="2.5" />
    </Svg>
  );
}

export function IconEyeOff(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M4 4.5 20 20" />
      <path d="M9.5 7.2A9.7 9.7 0 0 1 12 6.9c6 0 9.5 5.5 9.5 5.5a17 17 0 0 1-3.2 3.7" />
      <path d="M6.4 8.9A16.6 16.6 0 0 0 2.5 12.4S6 17.9 12 17.9c1.3 0 2.5-.3 3.5-.7" />
    </Svg>
  );
}

export function IconRefresh(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M19 12a7 7 0 1 1-2.6-5.5" />
      <path d="M19 4.5V8h-3.5" />
    </Svg>
  );
}

export function IconClose(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M6 6 18 18M18 6 6 18" />
    </Svg>
  );
}

export function IconSignal(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M4 18h2.5M9 18V13h2.5v5M14 18V9h2.5v9M19 18V5h1.5v13" />
    </Svg>
  );
}

export function IconMenu(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M4 7h16M4 12h16M4 17h16" />
    </Svg>
  );
}

export function IconMail(p: IconProps) {
  return (
    <Svg {...p}>
      <rect x="3" y="5.5" width="18" height="13" rx="2" />
      <path d="M3.5 7 12 12.5 20.5 7" />
    </Svg>
  );
}
