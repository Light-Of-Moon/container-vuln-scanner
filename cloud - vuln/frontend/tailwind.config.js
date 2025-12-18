/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      // Cyber-Security Dashboard Color Palette
      colors: {
        // Background colors
        'cyber-black': '#0b1121',
        'cyber-dark': '#1e293b',
        'cyber-gray': '#334155',
        'cyber-border': '#475569',
        
        // Severity levels (CVSS-aligned)
        'severity-critical': '#ef4444',
        'severity-high': '#f97316',
        'severity-medium': '#eab308',
        'severity-low': '#22c55e',
        'severity-unknown': '#6b7280',
        
        // Accent colors
        'neon-blue': '#3b82f6',
        'neon-cyan': '#06b6d4',
        'neon-green': '#10b981',
        'neon-purple': '#8b5cf6',
        
        // Status colors
        'status-scanning': '#3b82f6',
        'status-pending': '#f59e0b',
        'status-completed': '#10b981',
        'status-failed': '#ef4444',
      },
      
      // Custom font families
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'Monaco', 'Consolas', 'monospace'],
        'display': ['Inter', 'system-ui', 'sans-serif'],
      },
      
      // Custom animations
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'pulse-fast': 'pulse 1s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line': 'scan-line 2s ease-in-out infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'fade-in': 'fade-in 0.3s ease-out',
        'slide-up': 'slide-up 0.3s ease-out',
        'slide-down': 'slide-down 0.3s ease-out',
      },
      
      keyframes: {
        'scan-line': {
          '0%, 100%': { transform: 'translateX(-100%)' },
          '50%': { transform: 'translateX(100%)' },
        },
        'glow': {
          '0%': { boxShadow: '0 0 5px currentColor, 0 0 10px currentColor' },
          '100%': { boxShadow: '0 0 10px currentColor, 0 0 20px currentColor, 0 0 30px currentColor' },
        },
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'slide-up': {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'slide-down': {
          '0%': { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
      
      // Custom spacing for data-dense layouts
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '112': '28rem',
        '128': '32rem',
      },
      
      // Box shadows with cyber glow effect
      boxShadow: {
        'cyber': '0 0 0 1px rgba(59, 130, 246, 0.5), 0 0 15px rgba(59, 130, 246, 0.3)',
        'cyber-lg': '0 0 0 1px rgba(59, 130, 246, 0.5), 0 0 30px rgba(59, 130, 246, 0.4)',
        'critical': '0 0 0 1px rgba(239, 68, 68, 0.5), 0 0 15px rgba(239, 68, 68, 0.3)',
        'success': '0 0 0 1px rgba(16, 185, 129, 0.5), 0 0 15px rgba(16, 185, 129, 0.3)',
        'warning': '0 0 0 1px rgba(245, 158, 11, 0.5), 0 0 15px rgba(245, 158, 11, 0.3)',
      },
      
      // Border radius
      borderRadius: {
        'cyber': '0.375rem',
      },
      
      // Custom backdrop blur
      backdropBlur: {
        'xs': '2px',
      },
      
      // Grid template for dashboard layouts
      gridTemplateColumns: {
        'dashboard': 'repeat(auto-fit, minmax(280px, 1fr))',
        'stats': 'repeat(auto-fit, minmax(200px, 1fr))',
      },
    },
  },
  plugins: [],
}
