import React from 'react';
import { Globe, AlertTriangle, Shield, Clock, ChevronRight, Zap, Target } from 'lucide-react';

interface DomainProfile {
  id: string;
  domain: string;
  total_scans: number;
  total_vulns: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  waf_detected: string | null;
  waf_bypass_methods: string[];
  successful_payloads: string[];
  successful_contexts: string[];
  technologies: string[];
  last_scan_at: string | null;
  first_scan_at: string | null;
}

interface RecentScan {
  id: string;
  url: string;
  status: string;
  started_at: string | null;
  vulnerability_count: number;
  critical_count: number;
  high_count: number;
}

interface DomainHistoryProps {
  profile: DomainProfile | null;
  recentScans: RecentScan[];
  onUsePayloads?: (payloads: string[]) => void;
  onViewScan?: (scanId: string) => void;
  loading?: boolean;
}

export const DomainHistory: React.FC<DomainHistoryProps> = ({
  profile,
  recentScans,
  onUsePayloads,
  onViewScan,
  loading = false,
}) => {
  if (loading) {
    return (
      <div className="bg-zinc-900/50 border border-zinc-800 rounded-lg p-4 animate-pulse">
        <div className="h-4 bg-zinc-800 rounded w-1/3 mb-3"></div>
        <div className="h-3 bg-zinc-800 rounded w-2/3 mb-2"></div>
        <div className="h-3 bg-zinc-800 rounded w-1/2"></div>
      </div>
    );
  }

  if (!profile) {
    return null;
  }

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  const hasCritical = profile.critical_count > 0;
  const hasHigh = profile.high_count > 0;

  return (
    <div className="bg-zinc-900/50 border border-zinc-800 rounded-lg overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <span className="text-sm font-medium text-zinc-200">
            Domain History: {profile.domain}
          </span>
        </div>
        <span className="text-xs text-zinc-500">
          {profile.total_scans} scan{profile.total_scans !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-px bg-zinc-800">
        <div className="bg-zinc-900 p-3 text-center">
          <div className={`text-lg font-bold ${hasCritical ? 'text-red-400' : 'text-zinc-400'}`}>
            {profile.critical_count}
          </div>
          <div className="text-xs text-zinc-500">Critical</div>
        </div>
        <div className="bg-zinc-900 p-3 text-center">
          <div className={`text-lg font-bold ${hasHigh ? 'text-orange-400' : 'text-zinc-400'}`}>
            {profile.high_count}
          </div>
          <div className="text-xs text-zinc-500">High</div>
        </div>
        <div className="bg-zinc-900 p-3 text-center">
          <div className="text-lg font-bold text-yellow-400">
            {profile.medium_count}
          </div>
          <div className="text-xs text-zinc-500">Medium</div>
        </div>
        <div className="bg-zinc-900 p-3 text-center">
          <div className="text-lg font-bold text-zinc-400">
            {profile.low_count}
          </div>
          <div className="text-xs text-zinc-500">Low</div>
        </div>
      </div>

      {/* Info Section */}
      <div className="p-4 space-y-3">
        {/* WAF Info */}
        {profile.waf_detected && (
          <div className="flex items-center gap-2 text-sm">
            <Shield className="w-4 h-4 text-amber-400" />
            <span className="text-zinc-400">WAF Detected:</span>
            <span className="text-amber-400 font-medium">{profile.waf_detected}</span>
            {profile.waf_bypass_methods.length > 0 && (
              <span className="text-xs text-green-400 ml-2">
                ({profile.waf_bypass_methods.length} bypass{profile.waf_bypass_methods.length !== 1 ? 'es' : ''} known)
              </span>
            )}
          </div>
        )}

        {/* Technologies */}
        {profile.technologies.length > 0 && (
          <div className="flex items-start gap-2 text-sm">
            <Target className="w-4 h-4 text-cyan-400 mt-0.5" />
            <span className="text-zinc-400">Tech:</span>
            <div className="flex flex-wrap gap-1">
              {profile.technologies.slice(0, 5).map((tech, i) => (
                <span key={i} className="px-1.5 py-0.5 bg-zinc-800 rounded text-xs text-zinc-300">
                  {tech}
                </span>
              ))}
              {profile.technologies.length > 5 && (
                <span className="text-xs text-zinc-500">+{profile.technologies.length - 5} more</span>
              )}
            </div>
          </div>
        )}

        {/* Successful Contexts */}
        {profile.successful_contexts.length > 0 && (
          <div className="flex items-start gap-2 text-sm">
            <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5" />
            <span className="text-zinc-400">Vulnerable contexts:</span>
            <div className="flex flex-wrap gap-1">
              {profile.successful_contexts.slice(0, 4).map((ctx, i) => (
                <span key={i} className="px-1.5 py-0.5 bg-red-900/30 border border-red-800/50 rounded text-xs text-red-300">
                  {ctx}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Last Scan */}
        <div className="flex items-center gap-2 text-sm text-zinc-500">
          <Clock className="w-4 h-4" />
          <span>Last scan: {formatDate(profile.last_scan_at)}</span>
        </div>
      </div>

      {/* Successful Payloads */}
      {profile.successful_payloads.length > 0 && (
        <div className="px-4 pb-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-zinc-500 uppercase tracking-wider">
              Successful Payloads ({profile.successful_payloads.length})
            </span>
            {onUsePayloads && (
              <button
                onClick={() => onUsePayloads(profile.successful_payloads)}
                className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                <Zap className="w-3 h-3" />
                Use All
              </button>
            )}
          </div>
          <div className="space-y-1 max-h-24 overflow-y-auto">
            {profile.successful_payloads.slice(0, 5).map((payload, i) => (
              <div
                key={i}
                className="font-mono text-xs text-green-400 bg-zinc-800/50 px-2 py-1 rounded truncate"
                title={payload}
              >
                {payload}
              </div>
            ))}
            {profile.successful_payloads.length > 5 && (
              <div className="text-xs text-zinc-500 text-center py-1">
                +{profile.successful_payloads.length - 5} more payloads
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recent Scans */}
      {recentScans.length > 0 && (
        <div className="border-t border-zinc-800">
          <div className="px-4 py-2 text-xs text-zinc-500 uppercase tracking-wider">
            Recent Scans
          </div>
          <div className="divide-y divide-zinc-800/50">
            {recentScans.slice(0, 3).map((scan) => (
              <div
                key={scan.id}
                className="px-4 py-2 flex items-center justify-between hover:bg-zinc-800/30 cursor-pointer transition-colors"
                onClick={() => onViewScan?.(scan.id)}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-2 h-2 rounded-full ${
                    scan.status === 'completed' ? 'bg-green-400' :
                    scan.status === 'failed' ? 'bg-red-400' :
                    scan.status === 'running' ? 'bg-cyan-400 animate-pulse' :
                    'bg-zinc-500'
                  }`} />
                  <div>
                    <div className="text-xs text-zinc-300 truncate max-w-[200px]">
                      {scan.url}
                    </div>
                    <div className="text-xs text-zinc-500">
                      {formatDate(scan.started_at)}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {scan.critical_count > 0 && (
                    <span className="text-xs text-red-400 font-medium">
                      {scan.critical_count}C
                    </span>
                  )}
                  {scan.high_count > 0 && (
                    <span className="text-xs text-orange-400 font-medium">
                      {scan.high_count}H
                    </span>
                  )}
                  {scan.vulnerability_count === 0 && (
                    <span className="text-xs text-zinc-500">Clean</span>
                  )}
                  <ChevronRight className="w-4 h-4 text-zinc-600" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default DomainHistory;
