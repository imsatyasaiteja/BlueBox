/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        'bluebox-dark': '#06111C',
        'bluebox-panel': '#0E2A43',
        'bluebox-cyan': '#39D8FF',
        'bluebox-aqua': '#16F0C5',
        'bluebox-red': '#FF6478',
        'bluebox-yellow': '#FFD166',
        'bluebox-green': '#49E38F',
        'bluebox-text': '#E8F7FF',
        'bluebox-muted': '#91AEC5',
      },
      fontFamily: {
        'sans': ['Segoe UI', 'system-ui', 'sans-serif'],
        'mono': ['Consolas', 'Monaco', 'monospace'],
      },
      boxShadow: {
        'bluebox-subtle': '0 0 16px rgba(0,0,0,0.2)',
        'bluebox-glow': '0 10px 24px rgba(22,240,197,0.1)',
      }
    },
  },
  plugins: [],
}
