import React, { useState, useEffect } from 'react';
import {
  X,
  Shield,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Package,
  Clock,
  Tag,
  Server,
  FileText,
  ChevronDown,
  ChevronRight,
  Search,
  Filter,
  Download,
  Copy,
  Check,
} from 'lucide-react';

/**
 * ScanDetailsModal - Full vulnerability report viewer
 * Shows detailed CVE information for a completed scan
 */

// Severity badge component
const SeverityBadge = ({ severity, size = 'md' }) => {
  const styles = {
    CRITICAL: 'bg-severity-critical/20 text-severity-critical border-severity-critical/30',
    HIGH: 'bg-severity-high/20 text-severity-high border-severity-high/30',
    MEDIUM: 'bg-severity-medium/20 text-severity-medium border-severity-medium/30',
    LOW: 'bg-severity-low/20 text-severity-low border-severity-low/30',
    UNKNOWN: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
  };

  const sizes = {
    sm: 'px-1.5 py-0.5 text-[10px]',
    md: 'px-2 py-1 text-xs',
    lg: 'px-3 py-1.5 text-sm',
  };

  return (
    <span className={`
      inline-flex items-center font-medium rounded border
      ${styles[severity] || styles.UNKNOWN}
      ${sizes[size]}
    `}>
      {severity}
    </span>
  );
};

// CVSS Score indicator
const CVSSScore = ({ score }) => {
  if (!score && score !== 0) return <span className="text-slate-500">N/A</span>;
  
  let color = 'text-severity-low';
  if (score >= 9.0) color = 'text-severity-critical';
  else if (score >= 7.0) color = 'text-severity-high';
  else if (score >= 4.0) color = 'text-severity-medium';

  return (
    <span className={`font-mono font-bold ${color}`}>
      {score.toFixed(1)}
    </span>
  );
};

// Copy button component
const CopyButton = ({ text }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="p-1 text-slate-500 hover:text-white transition-colors"
      title="Copy to clipboard"
    >
      {copied ? <Check className="w-3 h-3 text-neon-green" /> : <Copy className="w-3 h-3" />}
    </button>
  );
};

// Vulnerability row component
const VulnerabilityRow = ({ vuln, isExpanded, onToggle }) => {
  return (
    <div className="border-b border-cyber-gray last:border-b-0">
      {/* Summary row */}
      <div
        onClick={onToggle}
        className="flex items-center gap-4 p-3 hover:bg-cyber-gray/30 cursor-pointer transition-colors"
      >
        <button className="text-slate-500">
          {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm text-neon-blue font-medium">
              {vuln.VulnerabilityID}
            </span>
            <CopyButton text={vuln.VulnerabilityID} />
          </div>
          <p className="text-xs text-slate-500 truncate mt-0.5">
            {vuln.Title || vuln.Description?.substring(0, 100) || 'No description available'}
          </p>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-right">
            <p className="text-xs text-slate-500">Package</p>
            <p className="text-sm font-mono text-white">{vuln.PkgName}</p>
          </div>
          
          <div className="text-right min-w-[80px]">
            <p className="text-xs text-slate-500">CVSS</p>
            <CVSSScore score={vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score} />
          </div>

          <SeverityBadge severity={vuln.Severity} />
          
          {vuln.FixedVersion && (
            <span className="px-2 py-1 text-xs bg-neon-green/10 text-neon-green rounded border border-neon-green/30">
              Fix Available
            </span>
          )}
        </div>
      </div>

      {/* Expanded details */}
      {isExpanded && (
        <div className="px-12 pb-4 space-y-4 bg-cyber-dark/50">
          {/* Description */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Description
            </h4>
            <p className="text-sm text-slate-300 leading-relaxed">
              {vuln.Description || 'No description available.'}
            </p>
          </div>

          {/* Package details */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-xs text-slate-500">Installed Version</p>
              <p className="text-sm font-mono text-severity-high">{vuln.InstalledVersion}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Fixed Version</p>
              <p className="text-sm font-mono text-neon-green">
                {vuln.FixedVersion || 'No fix available'}
              </p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Package Type</p>
              <p className="text-sm text-white">{vuln.PkgType || 'Unknown'}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Published</p>
              <p className="text-sm text-white">
                {vuln.PublishedDate 
                  ? new Date(vuln.PublishedDate).toLocaleDateString() 
                  : 'Unknown'}
              </p>
            </div>
          </div>

          {/* References */}
          {vuln.References && vuln.References.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                References
              </h4>
              <div className="flex flex-wrap gap-2">
                {vuln.References.slice(0, 5).map((ref, i) => (
                  <a
                    key={i}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 px-2 py-1 text-xs text-neon-blue hover:text-white bg-neon-blue/10 hover:bg-neon-blue/20 rounded transition-colors"
                  >
                    <ExternalLink className="w-3 h-3" />
                    {new URL(ref).hostname}
                  </a>
                ))}
                {vuln.References.length > 5 && (
                  <span className="px-2 py-1 text-xs text-slate-500">
                    +{vuln.References.length - 5} more
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Main modal component
const ScanDetailsModal = ({ scan, onClose }) => {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [filteredVulns, setFilteredVulns] = useState([]);
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [fixableFilter, setFixableFilter] = useState('ALL');

  // Parse vulnerabilities from raw report
  useEffect(() => {
    if (scan?.raw_report?.Results) {
      const allVulns = [];
      scan.raw_report.Results.forEach(result => {
        if (result.Vulnerabilities) {
          result.Vulnerabilities.forEach(vuln => {
            allVulns.push({
              ...vuln,
              Target: result.Target,
              Type: result.Type,
            });
          });
        }
      });
      // Sort by severity
      const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
      allVulns.sort((a, b) => (severityOrder[a.Severity] || 5) - (severityOrder[b.Severity] || 5));
      setVulnerabilities(allVulns);
      setFilteredVulns(allVulns);
    }
  }, [scan]);

  // Apply filters
  useEffect(() => {
    let filtered = [...vulnerabilities];

    // Search filter
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(v => 
        v.VulnerabilityID?.toLowerCase().includes(term) ||
        v.PkgName?.toLowerCase().includes(term) ||
        v.Title?.toLowerCase().includes(term) ||
        v.Description?.toLowerCase().includes(term)
      );
    }

    // Severity filter
    if (severityFilter !== 'ALL') {
      filtered = filtered.filter(v => v.Severity === severityFilter);
    }

    // Fixable filter
    if (fixableFilter === 'FIXABLE') {
      filtered = filtered.filter(v => v.FixedVersion);
    } else if (fixableFilter === 'UNFIXABLE') {
      filtered = filtered.filter(v => !v.FixedVersion);
    }

    setFilteredVulns(filtered);
  }, [vulnerabilities, searchTerm, severityFilter, fixableFilter]);

  const toggleRow = (vulnId) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      if (next.has(vulnId)) {
        next.delete(vulnId);
      } else {
        next.add(vulnId);
      }
      return next;
    });
  };

  const severityCounts = {
    CRITICAL: vulnerabilities.filter(v => v.Severity === 'CRITICAL').length,
    HIGH: vulnerabilities.filter(v => v.Severity === 'HIGH').length,
    MEDIUM: vulnerabilities.filter(v => v.Severity === 'MEDIUM').length,
    LOW: vulnerabilities.filter(v => v.Severity === 'LOW').length,
  };

  if (!scan) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-cyber-dark border border-cyber-gray rounded-xl w-full max-w-6xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-cyber-gray bg-cyber-dark/80">
          <div className="flex items-center gap-4">
            <div className={`p-2 rounded-lg ${scan.is_compliant ? 'bg-neon-green/20' : 'bg-severity-critical/20'}`}>
              {scan.is_compliant ? (
                <Shield className="w-6 h-6 text-neon-green" />
              ) : (
                <ShieldAlert className="w-6 h-6 text-severity-critical" />
              )}
            </div>
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span className="font-mono text-neon-blue">{scan.image_name}</span>
                <span className="text-slate-500">:</span>
                <span className="text-slate-300">{scan.image_tag}</span>
              </h2>
              <div className="flex items-center gap-4 text-xs text-slate-500 mt-1">
                <span className="flex items-center gap-1">
                  <Server className="w-3 h-3" />
                  {scan.registry || 'docker.io'}
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {new Date(scan.created_at).toLocaleString()}
                </span>
                {scan.scan_duration && (
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {scan.scan_duration.toFixed(1)}s
                  </span>
                )}
              </div>
            </div>
          </div>
          
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-cyber-gray rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Stats bar */}
        <div className="flex items-center gap-6 px-4 py-3 border-b border-cyber-gray bg-cyber-black/50">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 uppercase">Risk Score</span>
            <span className={`text-xl font-bold ${
              scan.risk_score > 500 ? 'text-severity-critical' :
              scan.risk_score > 100 ? 'text-severity-high' :
              scan.risk_score > 0 ? 'text-severity-medium' : 'text-neon-green'
            }`}>
              {scan.risk_score}
            </span>
          </div>
          
          <div className="h-8 w-px bg-cyber-gray" />
          
          <div className="flex items-center gap-4">
            {Object.entries(severityCounts).map(([severity, count]) => (
              <button
                key={severity}
                onClick={() => setSeverityFilter(severityFilter === severity ? 'ALL' : severity)}
                className={`flex items-center gap-1.5 px-2 py-1 rounded transition-colors ${
                  severityFilter === severity ? 'bg-cyber-gray' : 'hover:bg-cyber-gray/50'
                }`}
              >
                <SeverityBadge severity={severity} size="sm" />
                <span className="text-sm font-bold text-white">{count}</span>
              </button>
            ))}
          </div>

          <div className="h-8 w-px bg-cyber-gray" />

          <div className="flex items-center gap-2 text-sm">
            <CheckCircle className="w-4 h-4 text-neon-green" />
            <span className="text-neon-green font-medium">{scan.fixable_count || 0}</span>
            <span className="text-slate-500">fixable</span>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-4 px-4 py-3 border-b border-cyber-gray">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search CVE, package, or description..."
              className="w-full h-9 pl-10 pr-4 bg-cyber-black border border-cyber-gray rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-neon-blue"
            />
          </div>
          
          <select
            value={fixableFilter}
            onChange={(e) => setFixableFilter(e.target.value)}
            className="h-9 px-3 bg-cyber-black border border-cyber-gray rounded-lg text-sm text-white focus:outline-none focus:border-neon-blue"
          >
            <option value="ALL">All Vulnerabilities</option>
            <option value="FIXABLE">Fixable Only</option>
            <option value="UNFIXABLE">No Fix Available</option>
          </select>

          <button
            onClick={() => {
              setSearchTerm('');
              setSeverityFilter('ALL');
              setFixableFilter('ALL');
            }}
            className="h-9 px-3 text-sm text-slate-400 hover:text-white hover:bg-cyber-gray rounded-lg transition-colors"
          >
            Clear Filters
          </button>
          
          <span className="text-sm text-slate-500">
            {filteredVulns.length} of {vulnerabilities.length} vulnerabilities
          </span>
        </div>

        {/* Vulnerability list */}
        <div className="flex-1 overflow-y-auto">
          {filteredVulns.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-slate-500">
              {vulnerabilities.length === 0 ? (
                <>
                  <CheckCircle className="w-12 h-12 text-neon-green mb-4" />
                  <p className="text-lg font-medium text-neon-green">No vulnerabilities found!</p>
                  <p className="text-sm mt-1">This image passed the security scan.</p>
                </>
              ) : (
                <>
                  <Search className="w-12 h-12 mb-4" />
                  <p className="text-lg font-medium">No matching vulnerabilities</p>
                  <p className="text-sm mt-1">Try adjusting your filters.</p>
                </>
              )}
            </div>
          ) : (
            <div>
              {filteredVulns.map((vuln, index) => (
                <VulnerabilityRow
                  key={`${vuln.VulnerabilityID}-${vuln.PkgName}-${index}`}
                  vuln={vuln}
                  isExpanded={expandedRows.has(`${vuln.VulnerabilityID}-${vuln.PkgName}`)}
                  onToggle={() => toggleRow(`${vuln.VulnerabilityID}-${vuln.PkgName}`)}
                />
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-cyber-gray bg-cyber-dark/80">
          <div className="text-xs text-slate-500">
            Scanned with Trivy {scan.trivy_version || 'latest'}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(scan.raw_report, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${scan.image_name}-${scan.image_tag}-scan.json`;
                a.click();
                URL.revokeObjectURL(url);
              }}
              className="flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-cyber-gray rounded-lg transition-colors"
            >
              <Download className="w-4 h-4" />
              Export JSON
            </button>
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-white bg-neon-blue hover:bg-neon-blue/80 rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanDetailsModal;
