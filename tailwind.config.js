/** Tailwind config — dark SOC/pentest palette. */
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Pure-black space base with bright-white outlines. No blue anywhere.
        base: {
          950: '#000000',
          900: '#080808',
          850: '#0d0d0d',
          800: '#161616',
          700: '#242424',
          600: '#333333',
        },
        edge: 'rgba(255,255,255,0.22)',
        accent: {
          DEFAULT: '#ffffff',
          dim: '#cbd5e1',
        },
        sev: {
          critical: '#f43f5e',
          high: '#fb923c',
          medium: '#facc15',
          low: '#e5e7eb',
          info: '#9ca3af',
          unrated: '#6b7280',
        },
        conf: {
          confirmed: '#f43f5e',
          potential: '#facc15',
          info: '#e5e7eb',
          unknown: '#9ca3af',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
