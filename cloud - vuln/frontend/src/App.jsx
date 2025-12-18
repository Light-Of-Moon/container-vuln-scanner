import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import {
  Shield,
  Search,
  RefreshCw,
  Settings,
  Bell,
  Terminal,
  Wifi,
  WifiOff,
  ChevronRight,
  Zap,
  AlertTriangle,
  X,
  CheckCircle,
  Command,
} from 'lucide-react';
import StatsGrid, { SeverityBreakdown, StatsHUD } from './components/StatsGrid';
import ScanTable from './components/ScanTable';

// =============================================================================
// API CONFIGURATION
// =============================================================================

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const POLL_INTERVAL = 3000; // 3 seconds

// Axios instance with defaults
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// =============================================================================
// TOAST NOTIFICATION COMPONENT
// =============================================================================

const Toast = ({ message, type = 'info', onClose }) => {
  const styles = {
    success: 'bg-neon-green/10 border-neon-green/30 text-neon-green',
    error: 'bg-severity-critical/10 border-severity-critical/30 text-severity-critical',
    warning: 'bg-severity-medium/10 border-severity-medium/30 text-severity-medium',
    info: 'bg-neon-blue/10 border-neon-blue/30 text-neon-blue',
  };

  const icons = {
    success: CheckCircle,
    error: AlertTriangle,
    warning: AlertTriangle,
    info: Zap,
  };

  const Icon = icons[type];

  useEffect(() => {
    const timer = setTimeout(onClose, 5000);
    return () => clearTimeout(timer);
  }, [onClose]);

  return (
    <div className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${styles[type]} animate-slide-up`}>
      <Icon className="w-4 h-4 flex-shrink-0" />
      <p className="text-sm flex-1">{message}</p>
      <button onClick={onClose} className="p-1 hover:bg-white/10 rounded">
        <X className="w-3 h-3" />
      </button>
    </div>
  );
};

// =============================================================================
// MAIN APP COMPONENT
// =============================================================================

function App() {
  // ---------------------------------------------------------------------------
  // STATE
  // ---------------------------------------------------------------------------
  
  // Data state
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState({
    totalScans: 0,
    activeScans: 0,
    criticalRisks: 0,
    highRisks: 0,
    mediumRisks: 0,
    lowRisks: 0,
    fixableRate: 0,
    complianceRate: 0,
  });
  
  // UI state
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(null);
  
  // Quick scan form state
  const [targetImage, setTargetImage] = useState('');
  const [scanSubmitting, setScanSubmitting] = useState(false);
  
  // Notifications
  const [toasts, setToasts] = useState([]);

  // Refs
  const pollRef = useRef(null);
  const inputRef = useRef(null);

  // ---------------------------------------------------------------------------
  // TOAST HELPERS
  // ---------------------------------------------------------------------------

  const addToast = useCallback((message, type = 'info') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  // ---------------------------------------------------------------------------
  // API FUNCTIONS
  // ---------------------------------------------------------------------------

  // Fetch scans list
  const fetchScans = useCallback(async () => {
    try {
      const response = await api.get('/api/v1/scans', {
        params: { page: 1, page_size: 50 },
      });
      
      const data = response.data;
      setScans(data.items || []);
      setConnected(true);
      setLastUpdate(new Date());
      
      return data.items || [];
    } catch (error) {
      console.error('Failed to fetch scans:', error);
      setConnected(false);
      throw error;
    }
  }, []);

  // Fetch dashboard stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await api.get('/api/v1/dashboard/stats');
      const data = response.data;
      
      setStats({
        totalScans: data.total_scans || 0,
        activeScans: data.active_scans || 0,
        criticalRisks: data.critical_count || 0,
        highRisks: data.high_count || 0,
        mediumRisks: data.medium_count || 0,
        lowRisks: data.low_count || 0,
        fixableRate: data.fixable_rate || 0,
        complianceRate: data.compliance_rate || 0,
        scansToday: data.scans_today || 0,
        totalVulnerabilities: data.total_vulnerabilities || 0,
      });
      
      setConnected(true);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
      // Fall back to calculating stats from scans
      calculateStatsFromScans();
    }
  }, []);

  // Calculate stats from scans as fallback
  const calculateStatsFromScans = useCallback(() => {
    const activeStatuses = ['pending', 'pulling', 'scanning', 'parsing'];
    const completedScans = scans.filter(s => s.status === 'completed');
    
    const totalVulns = completedScans.reduce((sum, s) => sum + (s.total_vulnerabilities || 0), 0);
    const fixableVulns = completedScans.reduce((sum, s) => sum + (s.fixable_count || 0), 0);
    const compliantScans = completedScans.filter(s => s.is_compliant).length;
    
    setStats({
      totalScans: scans.length,
      activeScans: scans.filter(s => activeStatuses.includes(s.status?.toLowerCase())).length,
      criticalRisks: scans.reduce((sum, s) => sum + (s.critical_count || 0), 0),
      highRisks: scans.reduce((sum, s) => sum + (s.high_count || 0), 0),
      mediumRisks: scans.reduce((sum, s) => sum + (s.medium_count || 0), 0),
      lowRisks: scans.reduce((sum, s) => sum + (s.low_count || 0), 0),
      fixableRate: totalVulns > 0 ? Math.round((fixableVulns / totalVulns) * 100) : 100,
      complianceRate: completedScans.length > 0 ? Math.round((compliantScans / completedScans.length) * 100) : 100,
      totalVulnerabilities: totalVulns,
    });
  }, [scans]);

  // Fetch all data
  const fetchAllData = useCallback(async () => {
    try {
      await Promise.all([fetchScans(), fetchStats()]);
    } catch (error) {
      // Individual functions handle their own errors
    } finally {
      setLoading(false);
    }
  }, [fetchScans, fetchStats]);

  // ---------------------------------------------------------------------------
  // SCAN ACTIONS
  // ---------------------------------------------------------------------------

  // Submit new scan
  const handleScanSubmit = async (e) => {
    e?.preventDefault();
    
    if (!targetImage.trim()) {
      addToast('Please enter an image name', 'warning');
      inputRef.current?.focus();
      return;
    }

    setScanSubmitting(true);

    try {
      // Parse image reference (e.g., "nginx:latest" or "gcr.io/project/image:tag")
      const input = targetImage.trim();
      let registry = 'docker.io';
      let imageName = input;
      let imageTag = 'latest';

      // Check if contains tag
      if (input.includes(':')) {
        const lastColon = input.lastIndexOf(':');
        const potentialTag = input.substring(lastColon + 1);
        // Make sure it's not a port number in registry
        if (!potentialTag.includes('/')) {
          imageTag = potentialTag;
          imageName = input.substring(0, lastColon);
        }
      }

      // Check if contains registry
      if (imageName.includes('/')) {
        const parts = imageName.split('/');
        if (parts[0].includes('.') || parts[0].includes(':')) {
          registry = parts[0];
          imageName = parts.slice(1).join('/');
        }
      }

      const response = await api.post('/api/v1/scan', {
        image_name: imageName,
        image_tag: imageTag,
        registry: registry,
        force_rescan: false,
      });

      const cacheHit = response.headers['x-cache'] === 'HIT';
      
      if (cacheHit) {
        addToast(`Cache hit! Returning existing scan for ${input}`, 'info');
      } else {
        addToast(`Scan queued for ${input}`, 'success');
      }
      
      setTargetImage('');
      await fetchAllData();
      
    } catch (error) {
      console.error('Scan submission failed:', error);
      const errorMsg = error.response?.data?.detail || 
                       error.response?.data?.error?.message ||
                       error.message ||
                       'Failed to submit scan';
      addToast(errorMsg, 'error');
    } finally {
      setScanSubmitting(false);
    }
  };

  // Rescan an image
  const handleRescan = async (scan) => {
    try {
      await api.post('/api/v1/scan', {
        image_name: scan.image_name,
        image_tag: scan.image_tag,
        registry: scan.registry || 'docker.io',
        force_rescan: true,
      });
      
      addToast(`Rescan queued for ${scan.image_name}:${scan.image_tag}`, 'success');
      await fetchAllData();
      
    } catch (error) {
      console.error('Rescan failed:', error);
      const errorMsg = error.response?.data?.detail || 'Failed to queue rescan';
      addToast(errorMsg, 'error');
    }
  };

  // ---------------------------------------------------------------------------
  // EFFECTS
  // ---------------------------------------------------------------------------

  // Initial fetch and polling setup
  useEffect(() => {
    fetchAllData();
    
    // Setup polling interval
    pollRef.current = setInterval(fetchAllData, POLL_INTERVAL);
    
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
      }
    };
  }, [fetchAllData]);

  // Keyboard shortcut for quick scan (Cmd/Ctrl + K)
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // ---------------------------------------------------------------------------
  // HELPERS
  // ---------------------------------------------------------------------------

  const formatLastUpdate = () => {
    if (!lastUpdate) return 'Never';
    return lastUpdate.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  // ---------------------------------------------------------------------------
  // RENDER
  // ---------------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-cyber-black flex flex-col">
      {/* ===================================================================
          NAVBAR - Mission Control Header
          =================================================================== */}
      <header className="bg-cyber-dark/90 backdrop-blur-md border-b border-cyber-gray sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-14">
            {/* Logo & Title */}
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="p-2 bg-neon-blue/20 rounded-lg border border-neon-blue/30">
                  <Shield className="w-5 h-5 text-neon-blue" />
                </div>
                {stats.activeScans > 0 && (
                  <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-neon-cyan rounded-full animate-pulse" />
                )}
              </div>
              <div>
                <h1 className="text-sm font-bold text-white tracking-wide">
                  MISSION CONTROL
                </h1>
                <p className="text-[10px] text-slate-500 uppercase tracking-widest">
                  Container Security
                </p>
              </div>
            </div>

            {/* Connection Status & Actions */}
            <div className="flex items-center gap-4">
              {/* Live indicator */}
              <div className={`
                flex items-center gap-1.5 px-2 py-1 rounded-full text-[10px] font-medium uppercase tracking-wider
                ${connected 
                  ? 'bg-neon-green/10 text-neon-green border border-neon-green/30' 
                  : 'bg-severity-critical/10 text-severity-critical border border-severity-critical/30'
                }
              `}>
                {connected ? (
                  <>
                    <span className="w-1.5 h-1.5 bg-neon-green rounded-full animate-pulse" />
                    Live
                  </>
                ) : (
                  <>
                    <WifiOff className="w-3 h-3" />
                    Offline
                  </>
                )}
              </div>
              
              {/* Last update */}
              <div className="text-[10px] text-slate-500 font-mono">
                {formatLastUpdate()}
              </div>

              {/* Action buttons */}
              <div className="flex items-center gap-1">
                <button 
                  onClick={fetchAllData}
                  className="p-2 text-slate-400 hover:text-white hover:bg-cyber-gray rounded-md transition-colors"
                  title="Refresh"
                >
                  <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                </button>
                
                <button 
                  className="p-2 text-slate-400 hover:text-white hover:bg-cyber-gray rounded-md transition-colors relative"
                  title="Alerts"
                >
                  <Bell className="w-4 h-4" />
                  {stats.criticalRisks > 0 && (
                    <span className="absolute top-1 right-1 w-2 h-2 bg-severity-critical rounded-full animate-pulse" />
                  )}
                </button>
                
                <button 
                  className="p-2 text-slate-400 hover:text-white hover:bg-cyber-gray rounded-md transition-colors"
                  title="Settings"
                >
                  <Settings className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* ===================================================================
          MAIN CONTENT
          =================================================================== */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {/* -----------------------------------------------------------------
            QUICK SCAN BAR - Command Line Style
            ----------------------------------------------------------------- */}
        <div className="mb-6">
          <form onSubmit={handleScanSubmit}>
            <div className="relative">
              {/* Terminal prompt styling */}
              <div className="absolute left-0 top-0 bottom-0 flex items-center pl-4 pointer-events-none">
                <span className="text-neon-green font-mono text-sm mr-1">❯</span>
                <span className="text-slate-500 font-mono text-sm">scan</span>
              </div>
              
              <input
                ref={inputRef}
                type="text"
                value={targetImage}
                onChange={(e) => setTargetImage(e.target.value)}
                placeholder="nginx:latest"
                className="
                  w-full h-12 pl-24 pr-36
                  bg-cyber-dark border border-cyber-gray rounded-lg
                  font-mono text-sm text-neon-blue placeholder-slate-600
                  focus:outline-none focus:border-neon-blue focus:ring-1 focus:ring-neon-blue
                  transition-all duration-200
                "
                disabled={scanSubmitting}
              />
              
              {/* Keyboard shortcut hint */}
              <div className="absolute right-28 top-1/2 -translate-y-1/2 hidden sm:flex items-center gap-1 text-slate-600">
                <kbd className="px-1.5 py-0.5 text-[10px] font-mono bg-cyber-gray rounded border border-cyber-border">
                  ⌘K
                </kbd>
              </div>
              
              {/* Submit button */}
              <button
                type="submit"
                disabled={scanSubmitting || !targetImage.trim()}
                className="
                  absolute right-2 top-1/2 -translate-y-1/2
                  flex items-center gap-2 px-4 py-2
                  bg-neon-blue text-white text-sm font-medium rounded-md
                  hover:bg-neon-blue/90 disabled:opacity-50 disabled:cursor-not-allowed
                  transition-all duration-200
                  shadow-lg shadow-neon-blue/25
                "
              >
                {scanSubmitting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span className="hidden sm:inline">Scanning...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    <span className="hidden sm:inline">Execute</span>
                  </>
                )}
              </button>
            </div>
          </form>
          
          {/* Quick suggestions */}
          <div className="flex items-center gap-2 mt-2 text-xs text-slate-500">
            <span>Try:</span>
            {['nginx:latest', 'python:3.11-slim', 'node:20-alpine'].map((img) => (
              <button
                key={img}
                onClick={() => setTargetImage(img)}
                className="font-mono text-slate-400 hover:text-neon-blue transition-colors"
              >
                {img}
              </button>
            ))}
          </div>
        </div>

        {/* -----------------------------------------------------------------
            STATS GRID
            ----------------------------------------------------------------- */}
        <section className="mb-6">
          <StatsGrid stats={stats} />
        </section>

        {/* -----------------------------------------------------------------
            MAIN CONTENT GRID
            ----------------------------------------------------------------- */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          
          {/* Scan Table (3 columns) */}
          <div className="lg:col-span-3">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
                Recent Scans
              </h2>
              <div className="flex items-center gap-2 text-[10px] text-slate-500">
                <span className="w-1.5 h-1.5 bg-neon-cyan rounded-full animate-pulse" />
                Auto-refresh 3s
              </div>
            </div>
            <ScanTable 
              scans={scans}
              onRescan={handleRescan}
              loading={loading}
              emptyMessage="No scans yet. Enter an image above to start."
            />
          </div>

          {/* Sidebar (1 column) */}
          <div className="space-y-6">
            {/* Severity Breakdown */}
            <SeverityBreakdown
              critical={stats.criticalRisks}
              high={stats.highRisks}
              medium={stats.mediumRisks}
              low={stats.lowRisks}
            />

            {/* Quick Actions */}
            <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-4">
              <h3 className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-3">
                Quick Actions
              </h3>
              <div className="space-y-2">
                <button className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-cyber-gray rounded-md transition-colors">
                  <Search className="w-4 h-4 text-slate-500" />
                  Search CVEs
                </button>
                <button className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-cyber-gray rounded-md transition-colors">
                  <Settings className="w-4 h-4 text-slate-500" />
                  Scan Policies
                </button>
                <a 
                  href={`${API_BASE_URL}/docs`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-cyber-gray rounded-md transition-colors"
                >
                  <Terminal className="w-4 h-4 text-slate-500" />
                  API Docs
                </a>
              </div>
            </div>

            {/* Critical Alert Banner */}
            {stats.criticalRisks > 0 && (
              <div className="bg-severity-critical/5 border border-severity-critical/30 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-severity-critical" />
                  <h3 className="text-[10px] font-semibold text-severity-critical uppercase tracking-wider">
                    Critical Alert
                  </h3>
                </div>
                <p className="text-sm text-slate-300 mb-3">
                  <span className="font-bold text-severity-critical">{stats.criticalRisks}</span> critical 
                  {stats.criticalRisks === 1 ? ' vulnerability' : ' vulnerabilities'} detected.
                </p>
                <button className="w-full py-2 bg-severity-critical text-white text-xs font-medium rounded-md hover:bg-severity-critical/90 transition-colors">
                  View Critical Issues
                </button>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* ===================================================================
          FOOTER
          =================================================================== */}
      <footer className="border-t border-cyber-gray py-3 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between text-[10px] text-slate-500">
            <div className="flex items-center gap-4">
              <span>Container Vulnerability Scanner v1.0.0</span>
              <span className="text-cyber-gray">|</span>
              <span>Powered by Trivy</span>
            </div>
            <div className="font-mono">
              {scans.length} scans • {stats.totalVulnerabilities || 0} vulnerabilities tracked
            </div>
          </div>
        </div>
      </footer>

      {/* ===================================================================
          TOAST NOTIFICATIONS
          =================================================================== */}
      <div className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm">
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            message={toast.message}
            type={toast.type}
            onClose={() => removeToast(toast.id)}
          />
        ))}
      </div>
    </div>
  );
}

export default App;
