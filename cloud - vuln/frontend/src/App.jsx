import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Shield,
  ShieldAlert,
  Activity,
  RefreshCw,
  Search,
  Terminal,
  Wifi,
  WifiOff,
  AlertTriangle,
  CheckCircle,
  X,
  Upload,
  Eye,
} from 'lucide-react';

// Components
import ScanTable from './components/ScanTable';
import { StatsHUD, SeverityBreakdown } from './components/StatsGrid';
import ScanDetailsModal from './components/ScanDetailsModal';
import ImageUploader from './components/ImageUploader';

const API_URL = import.meta.env.VITE_API_URL || '';

// Toast notification component
const Toast = ({ message, type, onClose }) => {
  useEffect(() => {
    const timer = setTimeout(onClose, 5000);
    return () => clearTimeout(timer);
  }, [onClose]);

  const styles = {
    success: 'bg-neon-green/10 border-neon-green/30 text-neon-green',
    error: 'bg-severity-critical/10 border-severity-critical/30 text-severity-critical',
    info: 'bg-neon-blue/10 border-neon-blue/30 text-neon-blue',
  };

  const icons = {
    success: <CheckCircle className="w-4 h-4" />,
    error: <AlertTriangle className="w-4 h-4" />,
    info: <Activity className="w-4 h-4" />,
  };

  return (
    <div className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${styles[type]} animate-slide-in`}>
      {icons[type]}
      <span className="text-sm font-medium">{message}</span>
      <button onClick={onClose} className="ml-auto hover:opacity-70">
        <X className="w-4 h-4" />
      </button>
    </div>
  );
};

function App() {
  // State
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState({
    totalScans: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    fixablePercentage: 0,
    activeScans: 0,
  });
  const [loading, setLoading] = useState(true);
  const [targetImage, setTargetImage] = useState('');
  const [connected, setConnected] = useState(true);
  const [toasts, setToasts] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [showUploader, setShowUploader] = useState(false);
  
  const inputRef = useRef(null);

  // Toast helper
  const addToast = useCallback((message, type = 'info') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  // Parse complex image reference (e.g., gcr.io/project/image:tag)
  const parseImageRef = (input) => {
    const trimmed = input.trim();
    
    // Pattern: [registry/][namespace/]image[:tag][@digest]
    let registry = 'docker.io';
    let imageName = trimmed;
    let tag = 'latest';

    // Check for digest
    if (imageName.includes('@')) {
      const [img, digest] = imageName.split('@');
      imageName = img;
      // Handle digest separately if needed
    }

    // Check for tag
    if (imageName.includes(':')) {
      const parts = imageName.split(':');
      tag = parts.pop();
      imageName = parts.join(':');
    }

    // Check for registry (contains . or :port or is localhost)
    const parts = imageName.split('/');
    if (parts.length > 1) {
      const firstPart = parts[0];
      if (firstPart.includes('.') || firstPart.includes(':') || firstPart === 'localhost') {
        registry = parts.shift();
        imageName = parts.join('/');
      }
    }

    return { registry, imageName, tag };
  };

  // Fetch scans
  const fetchScans = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/v1/scans?page=1&page_size=50`);
      if (!response.ok) {
        throw new Error(`Failed to fetch scans: ${response.status}`);
      }
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        throw new Error('Invalid response format');
      }
      const data = await response.json();
      setScans(data.items || []);
      setConnected(true);
    } catch (err) {
      console.error('Failed to fetch scans:', err);
      setConnected(false);
    }
  }, []);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/v1/dashboard/stats`);
      if (!response.ok) {
        throw new Error(`Failed to fetch stats: ${response.status}`);
      }
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        throw new Error('Invalid response format');
      }
      const data = await response.json();
      setStats({
        totalScans: data.total_scans || 0,
        criticalCount: data.critical_count || 0,
        highCount: data.high_count || 0,
        mediumCount: data.medium_count || 0,
        lowCount: data.low_count || 0,
        fixablePercentage: data.fixable_percentage || 0,
        activeScans: data.active_scans || 0,
      });
    } catch (err) {
      console.error('Failed to fetch stats:', err);
      // Calculate from scans as fallback
      if (scans.length > 0) {
        setStats({
          totalScans: scans.length,
          criticalCount: scans.reduce((sum, s) => sum + (s.critical_count || 0), 0),
          highCount: scans.reduce((sum, s) => sum + (s.high_count || 0), 0),
          mediumCount: scans.reduce((sum, s) => sum + (s.medium_count || 0), 0),
          lowCount: scans.reduce((sum, s) => sum + (s.low_count || 0), 0),
          fixablePercentage: Math.round(
            (scans.filter(s => s.fixable_count > 0).length / scans.length) * 100
          ),
          activeScans: scans.filter(s => 
            ['pending', 'pulling', 'scanning', 'parsing'].includes(s.status)
          ).length,
        });
      }
    }
  }, [scans]);

  // Submit scan
  const handleScanSubmit = async (e) => {
    e?.preventDefault();
    if (!targetImage.trim()) return;

    const { registry, imageName, tag } = parseImageRef(targetImage);

    try {
      const response = await fetch(`${API_URL}/api/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          image_name: imageName,
          image_tag: tag,
          registry: registry,
        }),
      });

      if (!response.ok) {
        let errorMsg = 'Scan request failed';
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          try {
            const error = await response.json();
            errorMsg = error.detail || error.message || errorMsg;
          } catch {}
        } else {
          errorMsg = `Server error: ${response.status} ${response.statusText}`;
        }
        throw new Error(errorMsg);
      }

      const data = await response.json();
      addToast(`Scan queued: ${imageName}:${tag}`, 'success');
      setTargetImage('');
      fetchScans();
    } catch (err) {
      addToast(err.message, 'error');
    }
  };

  // Rescan
  const handleRescan = async (scan) => {
    try {
      const response = await fetch(`${API_URL}/api/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          image_name: scan.image_name,
          image_tag: scan.image_tag,
          registry: scan.registry,
          force_rescan: true,
        }),
      });

      if (!response.ok) {
        let errorMsg = 'Rescan failed';
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          try {
            const error = await response.json();
            errorMsg = error.detail || error.message || errorMsg;
          } catch {}
        } else {
          errorMsg = `Server error: ${response.status} ${response.statusText}`;
        }
        throw new Error(errorMsg);
      }
      addToast(`Rescan queued: ${scan.image_name}:${scan.image_tag}`, 'success');
      fetchScans();
    } catch (err) {
      addToast(err.message, 'error');
    }
  };

  // View scan details
  const handleViewDetails = async (scan) => {
    // If we don't have the raw_report, fetch the full scan
    if (!scan.raw_report) {
      try {
        const response = await fetch(`${API_URL}/api/v1/scans/${scan.id}`);
        if (!response.ok) {
          let errorMsg = 'Failed to fetch scan details';
          const contentType = response.headers.get('content-type');
          if (contentType && contentType.includes('application/json')) {
            try {
              const error = await response.json();
              errorMsg = error.detail || error.message || errorMsg;
            } catch {}
          } else {
            errorMsg = `Server error: ${response.status} ${response.statusText}`;
          }
          throw new Error(errorMsg);
        }
        const fullScan = await response.json();
        setSelectedScan(fullScan);
      } catch (err) {
        addToast(err.message || 'Failed to load scan details', 'error');
      }
    } else {
      setSelectedScan(scan);
    }
  };

  // Delete scan
  const handleDeleteScan = async (scan) => {
    try {
      const response = await fetch(`${API_URL}/api/v1/scans/${scan.id}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        let errorMsg = 'Failed to delete scan';
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          try {
            const error = await response.json();
            errorMsg = error.detail || error.message || errorMsg;
          } catch {}
        } else {
          errorMsg = `Server error: ${response.status} ${response.statusText}`;
        }
        throw new Error(errorMsg);
      }

      addToast(`Deleted scan: ${scan.image_name}:${scan.image_tag}`, 'success');
      fetchScans();
      fetchStats();
    } catch (err) {
      addToast(err.message, 'error');
    }
  };

  // Handle upload complete
  const handleUploadComplete = (response) => {
    setShowUploader(false);
    addToast(`Upload scan queued: ${response.image_name || 'uploaded image'}`, 'success');
    fetchScans();
  };

  // Keyboard shortcut
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

  // Polling
  useEffect(() => {
    fetchScans();
    fetchStats();
    setLoading(false);

    const interval = setInterval(() => {
      fetchScans();
      fetchStats();
    }, 3000);

    return () => clearInterval(interval);
  }, [fetchScans, fetchStats]);

  // Quick scan suggestions
  const suggestions = ['nginx:latest', 'python:3.11-slim', 'node:18-alpine', 'redis:7'];

  return (
    <div className="min-h-screen bg-cyber-black text-white">
      {/* Navbar */}
      <nav className="sticky top-0 z-40 bg-cyber-dark/95 backdrop-blur border-b border-cyber-gray">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-neon-blue" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-neon-green rounded-full animate-pulse" />
              </div>
              <div>
                <h1 className="text-lg font-bold tracking-tight">
                  <span className="text-white">MISSION</span>
                  <span className="text-neon-blue ml-1">CONTROL</span>
                </h1>
                <p className="text-[10px] text-slate-500 uppercase tracking-widest">
                  Container Security Scanner
                </p>
              </div>
            </div>

            {/* Status indicator */}
            <div className="flex items-center gap-4">
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium ${
                connected 
                  ? 'bg-neon-green/10 text-neon-green border border-neon-green/30' 
                  : 'bg-severity-critical/10 text-severity-critical border border-severity-critical/30'
              }`}>
                {connected ? (
                  <>
                    <Wifi className="w-3 h-3" />
                    <span>LIVE</span>
                  </>
                ) : (
                  <>
                    <WifiOff className="w-3 h-3" />
                    <span>OFFLINE</span>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Command line scan bar */}
      <div className="bg-cyber-dark border-b border-cyber-gray">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <form onSubmit={handleScanSubmit} className="flex items-center gap-4">
            <div className="flex-1 flex items-center gap-2 bg-cyber-black border border-cyber-gray rounded-lg px-4 py-2 focus-within:border-neon-blue transition-colors">
              <Terminal className="w-4 h-4 text-neon-green" />
              <span className="text-neon-green font-mono text-sm">❯</span>
              <span className="text-slate-500 font-mono text-sm">scan</span>
              <input
                ref={inputRef}
                type="text"
                value={targetImage}
                onChange={(e) => setTargetImage(e.target.value)}
                placeholder="nginx:latest or gcr.io/project/image:tag"
                className="flex-1 bg-transparent text-white font-mono text-sm placeholder-slate-600 focus:outline-none"
              />
              <kbd className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 text-xs text-slate-500 bg-cyber-gray rounded">
                <span className="text-xs">⌘</span>K
              </kbd>
            </div>
            
            <button
              type="submit"
              disabled={!targetImage.trim()}
              className="px-4 py-2 bg-neon-blue text-white font-medium rounded-lg hover:bg-neon-blue/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Search className="w-4 h-4" />
            </button>

            <button
              type="button"
              onClick={() => setShowUploader(true)}
              className="flex items-center gap-2 px-4 py-2 bg-cyber-gray text-white font-medium rounded-lg hover:bg-cyber-border transition-colors"
            >
              <Upload className="w-4 h-4" />
              <span className="hidden sm:inline">Upload</span>
            </button>
          </form>

          {/* Quick suggestions */}
          <div className="flex items-center gap-2 mt-3">
            <span className="text-xs text-slate-500">Quick scan:</span>
            {suggestions.map((img) => (
              <button
                key={img}
                onClick={() => setTargetImage(img)}
                className="px-2 py-1 text-xs font-mono text-slate-400 bg-cyber-gray/50 hover:bg-cyber-gray hover:text-white rounded transition-colors"
              >
                {img}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Stats HUD */}
        <div className="mb-6">
          <StatsHUD stats={stats} />
        </div>

        {/* Content grid */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Main table */}
          <div className="lg:col-span-3">
            <div className="bg-cyber-dark border border-cyber-gray rounded-lg overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-cyber-gray">
                <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
                  Recent Scans
                </h2>
                <button
                  onClick={() => { fetchScans(); fetchStats(); }}
                  className="p-1.5 text-slate-400 hover:text-white hover:bg-cyber-gray rounded transition-colors"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              </div>
              <ScanTable 
                scans={scans} 
                loading={loading}
                onRescan={handleRescan}
                onViewDetails={handleViewDetails}
                onDelete={handleDeleteScan}
              />
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Severity breakdown */}
            <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-4">
              <SeverityBreakdown
                critical={stats.criticalCount}
                high={stats.highCount}
                medium={stats.mediumCount}
                low={stats.lowCount}
              />
            </div>

            {/* Quick actions */}
            <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-4">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                Quick Actions
              </h3>
              <div className="space-y-2">
                <button
                  onClick={() => setShowUploader(true)}
                  className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-cyber-gray rounded-lg transition-colors"
                >
                  <Upload className="w-4 h-4" />
                  Upload Docker Image
                </button>
                <button
                  onClick={() => inputRef.current?.focus()}
                  className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-cyber-gray rounded-lg transition-colors"
                >
                  <Terminal className="w-4 h-4" />
                  Quick Scan (⌘K)
                </button>
              </div>
            </div>

            {/* Critical alert */}
            {stats.criticalCount > 0 && (
              <div className="bg-severity-critical/10 border border-severity-critical/30 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <ShieldAlert className="w-5 h-5 text-severity-critical" />
                  <span className="text-sm font-semibold text-severity-critical">
                    Critical Alert
                  </span>
                </div>
                <p className="text-xs text-slate-300">
                  {stats.criticalCount} critical {stats.criticalCount === 1 ? 'vulnerability' : 'vulnerabilities'} detected. 
                  Immediate remediation recommended.
                </p>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Toasts */}
      <div className="fixed bottom-4 right-4 z-50 space-y-2">
        {toasts.map(toast => (
          <Toast
            key={toast.id}
            message={toast.message}
            type={toast.type}
            onClose={() => removeToast(toast.id)}
          />
        ))}
      </div>

      {/* Scan Details Modal */}
      {selectedScan && (
        <ScanDetailsModal
          scan={selectedScan}
          onClose={() => setSelectedScan(null)}
        />
      )}

      {/* Image Uploader Modal */}
      {showUploader && (
        <ImageUploader
          onUploadComplete={handleUploadComplete}
          onClose={() => setShowUploader(false)}
        />
      )}
    </div>
  );
}

export default App;
