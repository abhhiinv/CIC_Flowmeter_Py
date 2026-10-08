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
        soc: {
          950: '#06090e',
          900: '#0B0F17',
          850: '#0F172A',
          800: '#151E32',
          700: '#1E293B',
          600: '#334155',
        },
        severity: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#EAB308',
          normal: '#10B981',
        },
      },
    },
  },
  plugins: [],
};
