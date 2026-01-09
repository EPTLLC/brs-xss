/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Cyberpunk-inspired dark theme
        'cyber': {
          'bg': '#0a0a0f',
          'surface': '#12121a',
          'elevated': '#1a1a25',
          'border': '#2a2a3a',
          'text': '#e0e0e8',
          'muted': '#8888a0',
          'accent': '#00ff9f',
          'accent-dim': '#00cc7f',
          'danger': '#ff4757',
          'warning': '#ffa502',
          'info': '#3742fa',
          'success': '#2ed573',
        },
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'monospace'],
        'sans': ['Outfit', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scan-line': 'scanLine 2s linear infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px #00ff9f, 0 0 10px #00ff9f' },
          '100%': { boxShadow: '0 0 10px #00ff9f, 0 0 20px #00ff9f, 0 0 30px #00ff9f' },
        },
        scanLine: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
      },
    },
  },
  plugins: [],
}

