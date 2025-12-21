/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      // Cyberpunk color palette
      colors: {
        // Background colors
        'cyber-black': '#0a0a0f',
        'cyber-dark': '#12121a',
        'cyber-gray': '#1a1a2e',
        'cyber-border': '#2a2a3e',
        
        // Severity levels (CVSS-aligned)
        'severity-critical': '#ff3366',
        'severity-high': '#ff6b35',
        'severity-medium': '#ffcc00',
        'severity-low': '#00ccff',
        'severity-unknown': '#6b7280',
        
        // Accent colors
        'neon-blue': '#00d4ff',
        'neon-cyan': '#00fff5',
        'neon-green': '#00ff88',
        'neon-purple': '#bf00ff',
        
        // Status colors
        'status-scanning': '#3b82f6',
        'status-pending': '#f59e0b',
        'status-completed': '#10b981',
        'status-failed': '#ef4444',
      },
      
      // Custom font families
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'monospace'],
        'display': ['Inter', 'system-ui', 'sans-serif'],
      },
      
      // Custom animations
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.2s ease-out',
      },
      
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 212, 255, 0.5)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 212, 255, 0.8)' },
        },
        slideIn: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
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
