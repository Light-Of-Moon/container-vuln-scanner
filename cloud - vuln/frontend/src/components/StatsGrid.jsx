import React from 'react';
import {
  Shield,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Activity,
  TrendingUp,
  Clock,
  Target,
  Zap,
  BarChart3,
} from 'lucide-react';

/**
 * StatsGrid - HUD-style statistics display
 * Shows key metrics in a mission-control layout
 */

// HUD Card with glowing top border
const HUDCard = ({ children, glowColor = 'neon-blue', className = '' }) => {
  const glowStyles = {
    'neon-blue': 'before:bg-neon-blue before:shadow-[0_0_15px_rgba(59,130,246,0.8),0_0_30px_rgba(59,130,246,0.4)]',
    'severity-critical': 'before:bg-severity-critical before:shadow-[0_0_15px_rgba(239,68,68,0.8),0_0_30px_rgba(239,68,68,0.4)]',
    'severity-high': 'before:bg-severity-high before:shadow-[0_0_15px_rgba(249,115,22,0.8),0_0_30px_rgba(249,115,22,0.4)]',
    'neon-green': 'before:bg-neon-green before:shadow-[0_0_15px_rgba(16,185,129,0.8),0_0_30px_rgba(16,185,129,0.4)]',
    'neon-cyan': 'before:bg-neon-cyan before:shadow-[0_0_15px_rgba(6,182,212,0.8),0_0_30px_rgba(6,182,212,0.4)]',
  };

  return (
    <div 
      className={`
        relative bg-cyber-dark border border-cyber-gray rounded-lg p-4 overflow-hidden
        before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:rounded-t-lg
        ${glowStyles[glowColor] || glowStyles['neon-blue']}
        hover:border-cyber-border transition-all duration-300
        ${className}
      `}
    >
      {children}
    </div>
  );
};

// Individual stat widget component
const StatWidget = ({ 
  title, 
  value, 
  subtitle, 
  icon: Icon, 
  trend, 
  trendDirection,
  color = 'neon-blue',
  pulse = false,
}) => {
  const colorMap = {
    'neon-blue': {
      bg: 'bg-neon-blue/10',
      border: 'border-neon-blue/30',
      text: 'text-neon-blue',
      glow: 'neon-blue',
    },
    'severity-critical': {
      bg: 'bg-severity-critical/10',
      border: 'border-severity-critical/30',
      text: 'text-severity-critical',
      glow: 'severity-critical',
    },
    'severity-high': {
      bg: 'bg-severity-high/10',
      border: 'border-severity-high/30',
      text: 'text-severity-high',
      glow: 'severity-high',
    },
    'neon-green': {
      bg: 'bg-neon-green/10',
      border: 'border-neon-green/30',
      text: 'text-neon-green',
      glow: 'neon-green',
    },
    'neon-cyan': {
      bg: 'bg-neon-cyan/10',
      border: 'border-neon-cyan/30',
      text: 'text-neon-cyan',
      glow: 'neon-cyan',
    },
  };

  const colors = colorMap[color] || colorMap['neon-blue'];

  return (
    <HUDCard glowColor={colors.glow} className="group">

      <div className="flex items-start justify-between">
        <div className="flex-1">
          {/* Title */}
          <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">
            {title}
          </p>
          
          {/* Value */}
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-bold ${colors.text} ${pulse ? 'animate-pulse-slow' : ''}`}>
              {typeof value === 'number' ? value.toLocaleString() : value}
            </span>
            {trend && (
              <span className={`
                text-xs font-medium flex items-center gap-0.5
                ${trendDirection === 'up' ? 'text-severity-critical' : 'text-neon-green'}
              `}>
                <TrendingUp 
                  className={`w-3 h-3 ${trendDirection === 'down' ? 'rotate-180' : ''}`}
                />
                {trend}
              </span>
            )}
          </div>
          
          {/* Subtitle */}
          {subtitle && (
            <p className="text-xs text-slate-500 mt-1">
              {subtitle}
            </p>
          )}
        </div>
        
        {/* Icon */}
        <div className={`
          p-2 rounded-lg ${colors.bg}
          group-hover:scale-110 transition-transform duration-300
        `}>
          <Icon className={`w-5 h-5 ${colors.text}`} />
        </div>
      </div>
    </HUDCard>
  );
};

// Compact 3-card HUD row (as requested)
export const StatsHUD = ({ stats }) => {
  const data = {
    totalScans: 0,
    criticalCount: 0,
    fixablePercentage: 0,
    ...stats,
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {/* Total Scans */}
      <HUDCard glowColor="neon-blue">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">
              Total Scans
            </p>
            <p className="text-3xl font-bold text-neon-blue mt-1">
              {data.totalScans.toLocaleString()}
            </p>
            <p className="text-xs text-slate-500 mt-1">All time scans</p>
          </div>
          <div className="p-3 bg-neon-blue/10 rounded-lg">
            <Activity className="w-6 h-6 text-neon-blue" />
          </div>
        </div>
      </HUDCard>

      {/* Critical Vulnerabilities */}
      <HUDCard glowColor="severity-critical">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">
              Critical Risks
            </p>
            <p className={`text-3xl font-bold mt-1 ${data.criticalCount > 0 ? 'text-severity-critical animate-pulse' : 'text-neon-green'}`}>
              {data.criticalCount}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              {data.criticalCount > 0 ? 'Immediate action required' : 'No critical issues'}
            </p>
          </div>
          <div className={`p-3 rounded-lg ${data.criticalCount > 0 ? 'bg-severity-critical/10' : 'bg-neon-green/10'}`}>
            <ShieldAlert className={`w-6 h-6 ${data.criticalCount > 0 ? 'text-severity-critical' : 'text-neon-green'}`} />
          </div>
        </div>
      </HUDCard>

      {/* Fixable Percentage */}
      <HUDCard glowColor="neon-green">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">
              Fixable Rate
            </p>
            <p className="text-3xl font-bold text-neon-green mt-1">
              {data.fixablePercentage}%
            </p>
            <p className="text-xs text-slate-500 mt-1">Vulnerabilities with patches</p>
          </div>
          <div className="p-3 bg-neon-green/10 rounded-lg">
            <CheckCircle className="w-6 h-6 text-neon-green" />
          </div>
        </div>
        {/* Mini progress bar */}
        <div className="mt-3 h-1.5 bg-cyber-gray rounded-full overflow-hidden">
          <div 
            className="h-full bg-neon-green rounded-full transition-all duration-500"
            style={{ width: `${data.fixablePercentage}%` }}
          />
        </div>
      </HUDCard>
    </div>
  );
};

// Main StatsGrid component
const StatsGrid = ({ stats }) => {
  // Default stats if none provided
  const defaultStats = {
    totalScans: 0,
    activeScans: 0,
    criticalRisks: 0,
    highRisks: 0,
    fixableRate: 0,
    complianceRate: 0,
    avgScanTime: 0,
    scansToday: 0,
  };

  const data = { ...defaultStats, ...stats };

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-4 gap-4">
      {/* Total Scans */}
      <StatWidget
        title="Total Scans"
        value={data.totalScans}
        subtitle="All time"
        icon={Target}
        color="neon-blue"
      />

      {/* Active Scans */}
      <StatWidget
        title="Active Scans"
        value={data.activeScans}
        subtitle={data.activeScans > 0 ? "Processing..." : "Queue empty"}
        icon={Activity}
        color="neon-cyan"
        pulse={data.activeScans > 0}
      />

      {/* Critical Risks */}
      <StatWidget
        title="Critical Risks"
        value={data.criticalRisks}
        subtitle="Immediate action required"
        icon={ShieldAlert}
        color="severity-critical"
        trend={data.criticalTrend}
        trendDirection={data.criticalTrendDirection}
      />

      {/* Fixable Rate */}
      <StatWidget
        title="Fixable Rate"
        value={`${data.fixableRate}%`}
        subtitle="Vulnerabilities with patches"
        icon={CheckCircle}
        color="neon-green"
      />
    </div>
  );
};

// Extended stats grid with more metrics
export const StatsGridExtended = ({ stats }) => {
  const defaultStats = {
    totalScans: 0,
    activeScans: 0,
    criticalRisks: 0,
    highRisks: 0,
    mediumRisks: 0,
    lowRisks: 0,
    fixableRate: 0,
    complianceRate: 0,
    avgScanTime: 0,
    scansToday: 0,
    imagesScanned: 0,
    totalVulnerabilities: 0,
  };

  const data = { ...defaultStats, ...stats };

  return (
    <div className="space-y-4">
      {/* Primary Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatWidget
          title="Total Scans"
          value={data.totalScans}
          subtitle={`${data.scansToday} today`}
          icon={Target}
          color="neon-blue"
        />

        <StatWidget
          title="Active Scans"
          value={data.activeScans}
          subtitle={data.activeScans > 0 ? "In progress" : "Idle"}
          icon={Activity}
          color="neon-cyan"
          pulse={data.activeScans > 0}
        />

        <StatWidget
          title="Critical + High"
          value={data.criticalRisks + data.highRisks}
          subtitle={`${data.criticalRisks} critical, ${data.highRisks} high`}
          icon={AlertTriangle}
          color="severity-critical"
        />

        <StatWidget
          title="Compliance Rate"
          value={`${data.complianceRate}%`}
          subtitle="Images passing policy"
          icon={Shield}
          color="neon-green"
        />
      </div>

      {/* Secondary Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatWidget
          title="Total Vulnerabilities"
          value={data.totalVulnerabilities}
          subtitle="Across all scans"
          icon={Zap}
          color="severity-high"
        />

        <StatWidget
          title="Images Scanned"
          value={data.imagesScanned}
          subtitle="Unique images"
          icon={Target}
          color="neon-blue"
        />

        <StatWidget
          title="Fixable Rate"
          value={`${data.fixableRate}%`}
          subtitle="With available patches"
          icon={CheckCircle}
          color="neon-green"
        />

        <StatWidget
          title="Avg Scan Time"
          value={`${data.avgScanTime}s`}
          subtitle="Per image"
          icon={Clock}
          color="neon-cyan"
        />
      </div>
    </div>
  );
};

// Severity breakdown mini-chart
export const SeverityBreakdown = ({ critical = 0, high = 0, medium = 0, low = 0 }) => {
  const total = critical + high + medium + low || 1;
  
  const segments = [
    { label: 'Critical', value: critical, color: 'bg-severity-critical', textColor: 'text-severity-critical' },
    { label: 'High', value: high, color: 'bg-severity-high', textColor: 'text-severity-high' },
    { label: 'Medium', value: medium, color: 'bg-severity-medium', textColor: 'text-severity-medium' },
    { label: 'Low', value: low, color: 'bg-severity-low', textColor: 'text-severity-low' },
  ];

  return (
    <div className="stat-widget">
      <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-3">
        Severity Distribution
      </p>
      
      {/* Stacked bar */}
      <div className="h-3 rounded-full bg-cyber-gray overflow-hidden flex mb-4">
        {segments.map((seg, i) => (
          <div
            key={seg.label}
            className={`${seg.color} transition-all duration-500`}
            style={{ width: `${(seg.value / total) * 100}%` }}
          />
        ))}
      </div>

      {/* Legend */}
      <div className="grid grid-cols-4 gap-2">
        {segments.map((seg) => (
          <div key={seg.label} className="text-center">
            <p className={`text-lg font-bold ${seg.textColor}`}>
              {seg.value}
            </p>
            <p className="text-xs text-slate-500">{seg.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export { HUDCard };
export default StatsGrid;
