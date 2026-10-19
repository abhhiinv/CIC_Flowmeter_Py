/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        tui: {
          bg: '#0a0a0a',
          surface: '#1a1a1a',
          border: '#2a2a2a',
          text: '#ffffff',
          muted: '#888888',
          accent: '#00c853',
        },
        soc: {
          950: '#0a0a0a',
          900: '#1a1a1a',
          850: '#151515',
          800: '#1f1f1f',
          700: '#2a2a2a',
          600: '#3a3a3a',
        },
        severity: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#EAB308',
          normal: '#00c853',
        },
      },
      fontFamily: {
        mono: [
          'JetBrains Mono',
          'Fira Code',
          'Cascadia Code',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'Liberation Mono',
          'Courier New',
          'monospace',
        ],
      },
    },
  },
  plugins: [],
};
