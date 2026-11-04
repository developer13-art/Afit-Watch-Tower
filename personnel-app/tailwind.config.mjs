/** @type {import('tailwindcss').Config} */
// AFIT WATCH TOWER design system (Tailwind v3, ESM config — package type is "module").
//
// Dark-mode-first: the palette below is the default (dark) surface, and `dark`
// is driven by the data-theme attribute so a future daylight build for outdoor
// guards is a token swap, not a rewrite.
//
// Severity colours are reserved and used nowhere else. A critical alert must
// look identical on every screen and on every operator's phone.
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          // Navy rather than near-black: the screens sit on a blue-lit gradient, and a
          // flat #000 card next to a #e0344b alert reads as a broken render on an AMOLED phone.
          base: '#060d1c',
          raised: '#0a152b',
          card: '#101f3c',
          overlay: '#16294a',
          line: '#1e3a67',
          'line-strong': '#2b4d85',
        },
        ink: {
          DEFAULT: '#eaf1fb',
          muted: '#a3b4cd',
          faint: '#6d81a3',
        },
        brand: {
          DEFAULT: '#2f80ff',
          strong: '#1c63d6',
          soft: '#12294f',
        },
        // The only decorative colour in the system: switches and the unread dot. It is
        // deliberately outside `sev.*` so a teal toggle can never be read as a severity.
        accent: {
          DEFAULT: '#35d6e8',
          soft: '#0e3540',
        },
        sev: {
          critical: '#ef4557',
          high: '#f8981d',
          medium: '#f0b429',
          low: '#6f8ba8',
        },
        status: {
          open: '#ef4557',
          investigating: '#f0b429',
          assigned: '#2f80ff',
          resolved: '#33c37f',
          closed: '#6d81a3',
          'false-positive': '#6f8ba8',
        },
        state: {
          ok: '#33c37f',
          warn: '#f0b429',
          bad: '#ef4557',
          info: '#2f80ff',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
      borderRadius: {
        wt: '4px',
        // The mockup's card language: generous corners on a phone, still square enough
        // that a severity rail or a status chip reads as data rather than as a bubble.
        card: '16px',
        tile: '20px',
      },
      backgroundImage: {
        app: 'linear-gradient(180deg, #0b1a38 0%, #060d1c 55%, #04080f 100%)',
        tile: 'linear-gradient(150deg, rgba(255,255,255,0.14) 0%, rgba(255,255,255,0) 60%)',
      },
      boxShadow: {
        card: '0 1px 0 0 rgba(255,255,255,0.05) inset, 0 12px 28px -16px rgba(0,0,0,0.95)',
        tile: '0 10px 26px -14px rgba(0,0,0,0.9)',
      },
      spacing: {
        tab: '64px',
      },
      keyframes: {
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        'slide-up': {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'none' },
        },
        'pop-in': {
          '0%': { opacity: '0', transform: 'scale(0.86)' },
          '60%': { opacity: '1', transform: 'scale(1.04)' },
          '100%': { transform: 'scale(1)' },
        },
      },
      animation: {
        'fade-in': 'fade-in 140ms ease-out',
        'slide-up': 'slide-up 180ms ease-out',
        'pop-in': 'pop-in 260ms ease-out',
      },
    },
  },
  plugins: [],
};
