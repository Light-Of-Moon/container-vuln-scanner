import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  RefreshCw,
  ExternalLink,
  Clock,
  AlertCircle,
  CheckCircle,
  XCircle,
  Loader2,
  Package,
  Shield,
  Copy,
  Check,
  Eye,
  Trash2,
} from 'lucide-react';

/**
 * ScanTable - Data-dense vulnerability scan results table
 * Features: Status badges, risk score bars, expandable rows, action buttons
 */

// Status badge component with animations
const StatusBadge = ({ status }) => {
  const statusConfig = {
    pending: {
      label: 'Pending',
      className: 'badge-pending',
      icon: Clock,
      pulse: true,
    },
    pulling: {
      label: 'Pulling',
      className: 'badge-scanning',
      icon: Loader2,
      pulse: true,
      spin: true,
    },
    scanning: {
      label: 'Scanning',
      className: 'badge-scanning',
      icon: Loader2,
      pulse: true,
      spin: true,
    },
    parsing: {
      label: 'Parsing',
      className: 'badge-scanning',
      icon: Loader2,
      pulse: true,
      spin: true,
    },
    completed: {
      label: 'Completed',
      className: 'badge-completed',
      icon: CheckCircle,
    },
    failed: {
      label: 'Failed',
      className: 'badge-failed',
      icon: XCircle,
    },
  };

  const config = statusConfig[status?.toLowerCase()] || statusConfig.pending;
  const Icon = config.icon;

  return (
    <span className={`${config.className} ${config.pulse ? 'animate-pulse' : ''}`}>
      <Icon className={`w-3 h-3 mr-1 ${config.spin ? 'animate-spin' : ''}`} />
      {config.label}
    </span>
  );
};

// Risk score bar visualization
// 0-30: Green, 30-70: Yellow, 70+: Red
const RiskScoreBar = ({ score, maxScore = 100 }) => {
  const percentage = Math.min((score / maxScore) * 100, 100);
  
  // Color based on score thresholds (0-30 green, 30-70 yellow, 70+ red)
  let colorClass = 'bg-severity-low'; // Green
  let textColorClass = 'text-severity-low';
  
  if (score >= 70) {
    colorClass = 'bg-severity-critical'; // Red
    textColorClass = 'text-severity-critical';
  } else if (score >= 30) {
    colorClass = 'bg-severity-medium'; // Yellow
    textColorClass = 'text-severity-medium';
  }

  return (
    <div className="flex items-center gap-2 min-w-[140px]">
      <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
        <div 
          className={`h-full rounded-full transition-all duration-500 ${colorClass}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className={`text-xs font-mono font-bold min-w-[32px] text-right ${textColorClass}`}>
        {score}
      </span>
    </div>
  );
};

// Severity counts display
const SeverityCounts = ({ critical = 0, high = 0, medium = 0, low = 0 }) => {
  return (
    <div className="flex items-center gap-1.5">
      {critical > 0 && (
        <span className="px-1.5 py-0.5 bg-severity-critical/20 text-severity-critical text-xs font-bold rounded">
          {critical}C
        </span>
      )}
      {high > 0 && (
        <span className="px-1.5 py-0.5 bg-severity-high/20 text-severity-high text-xs font-bold rounded">
          {high}H
        </span>
      )}
      {medium > 0 && (
        <span className="px-1.5 py-0.5 bg-severity-medium/20 text-severity-medium text-xs font-bold rounded">
          {medium}M
        </span>
      )}
      {low > 0 && (
        <span className="px-1.5 py-0.5 bg-severity-low/20 text-severity-low text-xs font-bold rounded">
          {low}L
        </span>
      )}
      {critical === 0 && high === 0 && medium === 0 && low === 0 && (
        <span className="text-xs text-slate-500">Clean</span>
      )}
    </div>
  );
};

// Expanded row details
const ExpandedDetails = ({ scan }) => {
  const [copied, setCopied] = useState(false);

  const copyImageRef = () => {
    navigator.clipboard.writeText(scan.full_image || `${scan.image_name}:${scan.image_tag}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <tr>
      <td colSpan="6" className="px-4 py-4 bg-cyber-black/50">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Image Details */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Image Details
            </h4>
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-slate-500 text-xs">Registry:</span>
                <span className="mono text-slate-300">{scan.registry || 'docker.io'}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 text-xs">Digest:</span>
                <span className="mono text-slate-300 text-xs truncate max-w-[200px]">
                  {scan.image_digest || 'N/A'}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button 
                  onClick={copyImageRef}
                  className="flex items-center gap-1 text-xs text-neon-blue hover:text-neon-cyan transition-colors"
                >
                  {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copied ? 'Copied!' : 'Copy image reference'}
                </button>
              </div>
            </div>
          </div>

          {/* Vulnerability Summary */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Vulnerability Summary
            </h4>
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-cyber-dark rounded p-2">
                <p className="text-xs text-slate-500">Total</p>
                <p className="text-lg font-bold text-slate-200">{scan.total_vulnerabilities || 0}</p>
              </div>
              <div className="bg-cyber-dark rounded p-2">
                <p className="text-xs text-slate-500">Fixable</p>
                <p className="text-lg font-bold text-neon-green">{scan.fixable_count || 0}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 mt-2">
              <Shield className={`w-4 h-4 ${scan.is_compliant ? 'text-neon-green' : 'text-severity-critical'}`} />
              <span className={`text-xs font-medium ${scan.is_compliant ? 'text-neon-green' : 'text-severity-critical'}`}>
                {scan.is_compliant ? 'Compliant' : 'Non-Compliant'}
              </span>
            </div>
          </div>

          {/* Timing & Metadata */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Scan Metadata
            </h4>
            <div className="space-y-1 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-500">Duration:</span>
                <span className="text-slate-300">{scan.scan_duration ? `${scan.scan_duration}s` : 'N/A'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Worker:</span>
                <span className="mono text-slate-300">{scan.worker_id || 'N/A'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Trivy Version:</span>
                <span className="mono text-slate-300">{scan.trivy_version || 'N/A'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Scan ID:</span>
                <span className="mono text-slate-300 text-xs">{scan.id?.slice(0, 8) || 'N/A'}...</span>
              </div>
            </div>
          </div>
        </div>

        {/* Error message if failed */}
        {scan.status === 'failed' && scan.error_message && (
          <div className="mt-4 p-3 bg-severity-critical/10 border border-severity-critical/30 rounded">
            <div className="flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-severity-critical mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-xs font-semibold text-severity-critical">Error Details</p>
                <p className="text-xs text-slate-400 mt-1 mono">{scan.error_message}</p>
              </div>
            </div>
          </div>
        )}
      </td>
    </tr>
  );
};

// Single table row
const ScanRow = ({ scan, isExpanded, onToggle, onRescan, onViewDetails, onDelete }) => {
  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const isScanning = ['pending', 'pulling', 'scanning', 'parsing'].includes(scan.status?.toLowerCase());

  return (
    <>
      <tr 
        className={`
          cursor-pointer transition-colors
          ${isExpanded ? 'bg-cyber-dark/70' : ''}
        `}
        onClick={onToggle}
      >
        {/* Expand indicator */}
        <td className="px-4 py-3 w-10">
          {isExpanded ? (
            <ChevronDown className="w-4 h-4 text-slate-400" />
          ) : (
            <ChevronRight className="w-4 h-4 text-slate-400" />
          )}
        </td>

        {/* Status */}
        <td className="px-4 py-3">
          <StatusBadge status={scan.status} />
        </td>

        {/* Image Name */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <Package className="w-4 h-4 text-slate-500 flex-shrink-0" />
            <div className="min-w-0">
              <p className="font-mono text-sm text-neon-blue truncate max-w-[250px]">
                {scan.image_name}
              </p>
              <p className="font-mono text-xs text-slate-500">
                :{scan.image_tag || 'latest'}
              </p>
            </div>
          </div>
        </td>

        {/* Risk Score */}
        <td className="px-4 py-3">
          <RiskScoreBar score={scan.risk_score || 0} />
        </td>

        {/* Findings */}
        <td className="px-4 py-3">
          <SeverityCounts 
            critical={scan.critical_count}
            high={scan.high_count}
            medium={scan.medium_count}
            low={scan.low_count}
          />
        </td>

        {/* Actions */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
            <button
              onClick={() => onRescan(scan)}
              disabled={isScanning}
              className={`
                btn-icon
                ${isScanning ? 'opacity-50 cursor-not-allowed' : ''}
              `}
              title="Rescan"
            >
              <RefreshCw className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
            </button>
            <a
              href={`/scan/${scan.id}`}
              className="btn-icon"
              title="View Details"
              onClick={(e) => e.stopPropagation()}
            >
              <ExternalLink className="w-4 h-4" />
            </a>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onViewDetails(scan);
              }}
              className="p-1.5 text-slate-400 hover:text-neon-blue hover:bg-neon-blue/10 rounded transition-colors"
              title="View Details"
            >
              <Eye className="w-4 h-4" />
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                if (window.confirm(`Are you sure you want to delete scan for ${scan.image_name}:${scan.image_tag}?`)) {
                  onDelete(scan);
                }
              }}
              className="p-1.5 text-slate-400 hover:text-severity-critical hover:bg-severity-critical/10 rounded transition-colors"
              title="Delete Scan"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </td>
      </tr>

      {/* Expanded details */}
      {isExpanded && <ExpandedDetails scan={scan} />}
    </>
  );
};

// Main ScanTable component
const ScanTable = ({ 
  scans = [], 
  onRescan,
  onViewDetails,
  onDelete,
  loading = false,
  emptyMessage = "No scans found",
}) => {
  const [expandedId, setExpandedId] = useState(null);

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  if (loading) {
    return (
      <div className="card flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 text-neon-blue animate-spin" />
        <span className="ml-3 text-slate-400">Loading scans...</span>
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <div className="card flex flex-col items-center justify-center py-12">
        <Package className="w-12 h-12 text-slate-600 mb-4" />
        <p className="text-slate-400">{emptyMessage}</p>
        <p className="text-xs text-slate-600 mt-1">Submit a scan to get started</p>
      </div>
    );
  }

  return (
    <div className="card p-0 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="table-cyber">
          <thead>
            <tr>
              <th className="w-10"></th>
              <th>Status</th>
              <th>Image</th>
              <th>Risk Score</th>
              <th>Findings</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <ScanRow
                key={scan.id}
                scan={scan}
                isExpanded={expandedId === scan.id}
                onToggle={() => toggleExpand(scan.id)}
                onRescan={onRescan}
                onViewDetails={onViewDetails}
                onDelete={onDelete}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ScanTable;
