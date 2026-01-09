/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Thu 25 Dec 2025 UTC
 * Status: Updated - Live Terminal Output
 * Telegram: https://t.me/EasyProTech
 */

import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, useEffect, useRef } from 'react';
import { 
  ArrowLeft, 
  Download, 
  AlertTriangle,
  Shield,
  Clock,
  Target,
  Code,
  ExternalLink,
  Terminal,
  Database,
  Zap,
  CheckCircle,
  XCircle,
  Loader2,
  X,
  Tag,
  Info,
  FileText,
  Eye,
  Ghost,
  Leaf,
  Gauge,
  Flame,
  Rocket,
  StopCircle
} from 'lucide-react';
import { api } from '../api/client';
import { TargetIntelligence } from '../components/TargetIntelligence';

interface Vulnerability {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  context_type: string;
  payload: string;
  payload_id?: string;
  payload_name?: string;
  payload_description?: string;
  payload_contexts?: string[];
  payload_tags?: string[];
  url: string;
  parameter: string;
  evidence?: string;
}

interface WAFInfo {
  name: string;
  type: string;
  confidence: number;
  bypass_available: boolean;
}

interface ScanResult {
  id: string;
  url: string;
  mode: string;
  performance_mode?: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  vulnerabilities: Vulnerability[];
  waf_detected: WAFInfo | null;
  urls_scanned?: number;
  parameters_tested?: number;
  payloads_sent?: number;
  duration_seconds?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  error_message?: string;
}

interface KBStats {
  version: string;
  total_payloads: number;
  contexts: number;
  waf_bypass_count?: number;
  repo_url?: string;
}

// Format duration nicely
const formatDuration = (seconds?: number): string => {
  if (!seconds && seconds !== 0) return '-';
  if (seconds < 0.001) return '<1ms';
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return `${mins}m ${secs}s`;
};

// Format date
const formatDate = (dateStr?: string): string => {
  if (!dateStr) return '-';
  try {
    const date = new Date(dateStr);
    return date.toLocaleString('ru-RU', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  } catch {
    return '-';
  }
};

export function ScanDetails() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const terminalRef = useRef<HTMLDivElement>(null);
  const [terminalLines, setTerminalLines] = useState<string[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  
  const { data: scan, isLoading } = useQuery<ScanResult>({
    queryKey: ['scan', id],
    queryFn: () => api.get(`/scans/${id}`).then(res => res.data),
    refetchInterval: (query) => query.state.data?.status === 'running' ? 1000 : false,
  });

  const { data: kbStats } = useQuery<KBStats>({
    queryKey: ['kb-stats'],
    queryFn: () => api.get('/kb/stats').then(res => res.data),
  });

  // Fetch reconnaissance data
  const { data: reconProfile } = useQuery({
    queryKey: ['scan-recon', id],
    queryFn: () => api.get(`/scans/${id}/recon`).then(res => res.data).catch(() => null),
    enabled: !!id,
    staleTime: 60000, // Cache for 1 minute
  });

  // Cancel scan mutation
  const cancelMutation = useMutation({
    mutationFn: () => api.post(`/scans/${id}/cancel`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan', id] });
    },
  });

  // Generate terminal output based on scan state
  useEffect(() => {
    if (!scan) return;
    
    const lines: string[] = [
      `\x1b[36m[BRS-XSS v4.0.0]\x1b[0m Initializing scanner...`,
      `\x1b[32m[KB]\x1b[0m Loaded ${kbStats?.total_payloads?.toLocaleString() || '...'} payloads from BRS-KB v${kbStats?.version || '...'}`,
      `\x1b[32m[KB]\x1b[0m ${kbStats?.contexts || '...'} context types, ${kbStats?.waf_bypass_count?.toLocaleString() || '...'} WAF bypasses available`,
      ``,
      `\x1b[33m[TARGET]\x1b[0m ${scan.url}`,
      `\x1b[33m[MODE]\x1b[0m ${scan.mode.toUpperCase()}`,
      `\x1b[33m[STARTED]\x1b[0m ${formatDate(scan.started_at)}`,
      ``,
    ];

    if (scan.status === 'running') {
      // Show reconnaissance info if available
      if (reconProfile) {
        lines.push(`\x1b[35m[RECON]\x1b[0m Target intelligence gathered`);
        if (reconProfile.ip?.ipv4) {
          lines.push(`\x1b[35m[RECON]\x1b[0m IP: ${reconProfile.ip.ipv4}`);
        }
        if (reconProfile.technology?.backend_framework || reconProfile.technology?.backend_language) {
          lines.push(`\x1b[35m[RECON]\x1b[0m Stack: ${reconProfile.technology?.backend_framework || reconProfile.technology?.backend_language || 'Unknown'}`);
        }
        if (reconProfile.waf?.detected) {
          lines.push(`\x1b[35m[RECON]\x1b[0m WAF: ${reconProfile.waf.name} (${((reconProfile.waf.confidence || 0) * 100).toFixed(0)}%)`);
        }
        if (reconProfile.risk?.estimated_payloads) {
          lines.push(`\x1b[35m[RECON]\x1b[0m Optimized payloads: ${reconProfile.risk.estimated_payloads}`);
        }
        lines.push(``);
      }
      
      lines.push(`\x1b[36m[SCAN]\x1b[0m Analyzing target...`);
      lines.push(`\x1b[36m[SCAN]\x1b[0m Detecting injection points...`);
      if (scan.urls_scanned) {
        lines.push(`\x1b[36m[CRAWL]\x1b[0m Scanned ${scan.urls_scanned} URLs`);
      }
      if (scan.parameters_tested) {
        lines.push(`\x1b[36m[TEST]\x1b[0m Testing ${scan.parameters_tested} parameters...`);
      }
      if (scan.payloads_sent) {
        lines.push(`\x1b[36m[PAYLOAD]\x1b[0m Sent ${scan.payloads_sent} payloads...`);
      }
      lines.push(`\x1b[33m[...]\x1b[0m Scan in progress...`);
    } else if (scan.status === 'completed') {
      if (scan.waf_detected) {
        lines.push(`\x1b[35m[WAF]\x1b[0m Detected: ${scan.waf_detected.name}`);
        lines.push(`\x1b[35m[WAF]\x1b[0m Applying bypass techniques...`);
      } else {
        lines.push(`\x1b[32m[WAF]\x1b[0m No WAF detected`);
      }
      lines.push(``);
      lines.push(`\x1b[36m[CRAWL]\x1b[0m URLs scanned: ${scan.urls_scanned || 0}`);
      lines.push(`\x1b[36m[TEST]\x1b[0m Parameters tested: ${scan.parameters_tested || 0}`);
      lines.push(`\x1b[36m[PAYLOAD]\x1b[0m Payloads sent: ${scan.payloads_sent || 0}`);
      lines.push(``);
      
      const vulnCount = (scan.critical_count || 0) + (scan.high_count || 0) + 
                        (scan.medium_count || 0) + (scan.low_count || 0);
      
      if (vulnCount > 0) {
        lines.push(`\x1b[31m[ALERT]\x1b[0m Found ${vulnCount} vulnerabilities!`);
        if (scan.critical_count) lines.push(`  \x1b[31m- Critical: ${scan.critical_count}\x1b[0m`);
        if (scan.high_count) lines.push(`  \x1b[91m- High: ${scan.high_count}\x1b[0m`);
        if (scan.medium_count) lines.push(`  \x1b[33m- Medium: ${scan.medium_count}\x1b[0m`);
        if (scan.low_count) lines.push(`  \x1b[36m- Low: ${scan.low_count}\x1b[0m`);
      } else {
        lines.push(`\x1b[32m[OK]\x1b[0m No vulnerabilities found`);
      }
      
      lines.push(``);
      lines.push(`\x1b[32m[DONE]\x1b[0m Scan completed in ${formatDuration(scan.duration_seconds)}`);
      lines.push(`\x1b[32m[DONE]\x1b[0m Finished at ${formatDate(scan.completed_at || undefined)}`);
    } else if (scan.status === 'failed') {
      lines.push(`\x1b[31m[ERROR]\x1b[0m Scan failed`);
      if (scan.error_message) {
        lines.push(`\x1b[31m[ERROR]\x1b[0m ${scan.error_message}`);
      }
    }

    setTerminalLines(lines);
  }, [scan, kbStats, reconProfile]);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLines]);

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getStatusIcon = () => {
    switch (scan?.status) {
      case 'running': return <Loader2 className="w-5 h-5 animate-spin text-[var(--color-primary)]" />;
      case 'completed': return <CheckCircle className="w-5 h-5 text-[var(--color-success)]" />;
      case 'failed': return <XCircle className="w-5 h-5 text-[var(--color-danger)]" />;
      default: return <Clock className="w-5 h-5 text-[var(--color-text-muted)]" />;
    }
  };

  // Parse ANSI colors for terminal
  const parseAnsi = (text: string) => {
    return text
      .replace(/\x1b\[36m/g, '<span class="text-cyan-400">')
      .replace(/\x1b\[32m/g, '<span class="text-green-400">')
      .replace(/\x1b\[33m/g, '<span class="text-yellow-400">')
      .replace(/\x1b\[31m/g, '<span class="text-red-500">')
      .replace(/\x1b\[91m/g, '<span class="text-orange-400">')
      .replace(/\x1b\[35m/g, '<span class="text-purple-400">')
      .replace(/\x1b\[0m/g, '</span>');
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-12 h-12 text-[var(--color-primary)] animate-spin" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="brs-empty h-full">
        <Shield className="brs-empty-icon" />
        <h3 className="brs-empty-title">Scan not found</h3>
        <Link to="/" className="brs-btn brs-btn-primary mt-6">
          Back to Dashboard
        </Link>
      </div>
    );
  }

  const vulnCount = (scan.critical_count || 0) + (scan.high_count || 0) + 
                    (scan.medium_count || 0) + (scan.low_count || 0);

  return (
    <>
      {/* Header */}
      <header className="brs-header">
        <div className="flex items-center gap-4">
          <Link to="/" className="p-2 rounded-lg hover:bg-[var(--color-surface-hover)] transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div className="flex items-center gap-3">
            {getStatusIcon()}
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-semibold font-mono truncate max-w-md">
                  {scan.url || 'Unknown target'}
                </h1>
                <a 
                  href="https://github.com/EPTLLC/brs-xss"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs text-[var(--color-primary)] hover:underline font-mono"
                >
                  BRS-XSS
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
              <p className="text-xs text-[var(--color-text-muted)] font-mono">
                {scan.id}
              </p>
            </div>
          </div>
        </div>
        <div className="flex gap-3">
          {scan.status === 'running' && (
            <button 
              onClick={() => cancelMutation.mutate()}
              disabled={cancelMutation.isPending}
              className="brs-btn bg-orange-600 hover:bg-orange-700 text-white"
            >
              <StopCircle className="w-4 h-4" />
              {cancelMutation.isPending ? 'Stopping...' : 'Stop Scan'}
            </button>
          )}
          <button className="brs-btn brs-btn-secondary">
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </header>

      {/* Content */}
      <div className="brs-content">
        {/* Stats Row */}
        <div className="grid grid-cols-5 gap-3 mb-4">
          <div className="brs-card p-3">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="w-4 h-4 text-[var(--color-info)]" />
              <span className="text-xs text-[var(--color-text-muted)]">Duration</span>
            </div>
            <div className="text-xl font-bold font-mono text-[var(--color-info)]">
              {formatDuration(scan.duration_seconds)}
            </div>
          </div>
          
          <div className="brs-card p-3">
            <div className="flex items-center gap-2 mb-1">
              <Target className="w-4 h-4 text-[var(--color-primary)]" />
              <span className="text-xs text-[var(--color-text-muted)]">URLs</span>
            </div>
            <div className="text-xl font-bold font-mono">
              {scan.urls_scanned || 0}
            </div>
          </div>
          
          <div className="brs-card p-3">
            <div className="flex items-center gap-2 mb-1">
              <Zap className="w-4 h-4 text-[var(--color-warning)]" />
              <span className="text-xs text-[var(--color-text-muted)]">Payloads</span>
            </div>
            <div className="text-xl font-bold font-mono">
              {scan.payloads_sent || 0}
            </div>
          </div>
          
          <div className="brs-card p-3">
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-4 h-4 text-[var(--color-purple)]" />
              <span className="text-xs text-[var(--color-text-muted)]">WAF</span>
            </div>
            <div className="text-sm font-bold truncate">
              {scan.waf_detected?.name || 'None'}
            </div>
          </div>
          
          <div className="brs-card p-3">
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className={`w-4 h-4 ${vulnCount > 0 ? 'text-[var(--color-danger)]' : 'text-[var(--color-success)]'}`} />
              <span className="text-xs text-[var(--color-text-muted)]">Vulns</span>
            </div>
            <div className={`text-xl font-bold font-mono ${vulnCount > 0 ? 'text-[var(--color-danger)]' : 'text-[var(--color-success)]'}`}>
              {vulnCount}
            </div>
          </div>
        </div>

        {/* Terminal Output */}
        <div className="brs-card mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Terminal className="w-4 h-4 text-[var(--color-primary)]" />
            <span className="text-sm font-medium">Scanner Output</span>
            {scan.status === 'running' && (
              <span className="ml-auto flex items-center gap-2 text-xs text-[var(--color-primary)]">
                <span className="w-2 h-2 bg-[var(--color-primary)] rounded-full animate-pulse" />
                Live
              </span>
            )}
          </div>
          <div 
            ref={terminalRef}
            className="bg-black/80 rounded-lg p-4 font-mono text-sm h-64 overflow-y-auto border border-[var(--color-border)]"
            style={{ 
              fontFamily: 'JetBrains Mono, monospace',
              lineHeight: '1.6'
            }}
          >
            {terminalLines.map((line, i) => (
              <div 
                key={i} 
                className="text-gray-300"
                dangerouslySetInnerHTML={{ __html: parseAnsi(line) || '&nbsp;' }}
              />
            ))}
            {scan.status === 'running' && (
              <div className="text-[var(--color-primary)] animate-pulse">_</div>
            )}
          </div>
        </div>

        {/* Target Intelligence (Reconnaissance Data) */}
        {reconProfile && (
          <div className="mb-4">
            <TargetIntelligence profile={reconProfile} />
          </div>
        )}

        {/* KB Info + Scan Mode Info */}
        <div className="brs-card mb-4 p-3">
          <div className="flex items-center justify-between flex-wrap gap-4 text-sm">
            {/* Left: KB Info */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[var(--color-primary)]" />
                <span className="text-[var(--color-text-muted)]">Knowledge Base:</span>
                <a 
                  href={kbStats?.repo_url || 'https://github.com/EPTLLC/BRS-KB'}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-[var(--color-primary)] hover:underline"
                >
                  BRS-KB v{kbStats?.version || '4.0.0'}
                </a>
              </div>
              <div className="text-[var(--color-text-muted)]">|</div>
              <div>
                <span className="text-[var(--color-text-muted)]">Payloads:</span>
                <span className="font-mono ml-1">{kbStats?.total_payloads?.toLocaleString() || '—'}</span>
              </div>
              <div className="text-[var(--color-text-muted)]">|</div>
              <div>
                <span className="text-[var(--color-text-muted)]">Contexts:</span>
                <span className="font-mono ml-1">{kbStats?.contexts || '—'}</span>
              </div>
              <div className="text-[var(--color-text-muted)]">|</div>
              <div>
                <span className="text-[var(--color-text-muted)]">WAF Bypasses:</span>
                <span className="font-mono ml-1">{kbStats?.waf_bypass_count?.toLocaleString() || '—'}</span>
              </div>
            </div>

            {/* Right: Scan Mode + Performance Mode */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                {scan.mode === 'quick' && <Zap className="w-4 h-4 text-[var(--color-warning)]" />}
                {scan.mode === 'standard' && <Target className="w-4 h-4 text-[var(--color-primary)]" />}
                {scan.mode === 'deep' && <Eye className="w-4 h-4 text-[var(--color-info)]" />}
                {scan.mode === 'stealth' && <Ghost className="w-4 h-4 text-[var(--color-text-muted)]" />}
                <span className="text-[var(--color-text-muted)]">Mode:</span>
                <span className="font-medium capitalize">{scan.mode || 'standard'}</span>
              </div>
              <div className="text-[var(--color-text-muted)]">|</div>
              <div className="flex items-center gap-2">
                {scan.performance_mode === 'light' && <Leaf className="w-4 h-4 text-[var(--color-success)]" />}
                {scan.performance_mode === 'standard' && <Gauge className="w-4 h-4 text-[var(--color-info)]" />}
                {scan.performance_mode === 'turbo' && <Flame className="w-4 h-4 text-[var(--color-warning)]" />}
                {scan.performance_mode === 'maximum' && <Rocket className="w-4 h-4 text-[var(--color-danger)]" />}
                {!scan.performance_mode && <Gauge className="w-4 h-4 text-[var(--color-info)]" />}
                <span className="text-[var(--color-text-muted)]">Performance:</span>
                <span className="font-medium capitalize">{scan.performance_mode || 'standard'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Vulnerabilities */}
        {vulnCount > 0 && (
          <div className="brs-card">
            <h3 className="flex items-center gap-2 text-sm font-medium mb-4">
              <AlertTriangle className="w-4 h-4 text-[var(--color-danger)]" />
              Detected Vulnerabilities ({vulnCount})
            </h3>
            
            <div className="space-y-3">
              {scan.vulnerabilities?.map((vuln, index) => (
                <div 
                  key={vuln.id || index}
                  className="p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)] hover:border-[var(--color-primary)]/50 transition-colors cursor-pointer"
                  onClick={() => setSelectedVuln(vuln)}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-xs font-bold rounded border ${getSeverityBadge(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      {vuln.payload_name ? (
                        <span className="font-medium text-sm">{vuln.payload_name}</span>
                      ) : (
                        <span className="font-medium text-sm text-[var(--color-text-muted)]">XSS Injection</span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-[var(--color-text-muted)] px-2 py-0.5 bg-black/30 rounded">
                        {vuln.context_type || 'html'}
                      </span>
                      <Info className="w-4 h-4 text-[var(--color-text-muted)] hover:text-[var(--color-primary)]" />
                    </div>
                  </div>
                  
                  {/* Short description */}
                  {vuln.payload_description && (
                    <p className="text-xs text-[var(--color-text-muted)] mb-2 line-clamp-1">
                      {vuln.payload_description}
                    </p>
                  )}
                  
                  <div className="flex items-center gap-4 text-xs">
                    <div className="flex items-center gap-1">
                      <Target className="w-3 h-3 text-[var(--color-text-muted)]" />
                      <span className="font-mono text-[var(--color-primary)]">{vuln.parameter}</span>
                    </div>
                    <div className="flex items-center gap-1 flex-1 min-w-0">
                      <Code className="w-3 h-3 text-[var(--color-text-muted)] flex-shrink-0" />
                      <code className="font-mono text-[var(--color-warning)] truncate">
                        {vuln.payload.substring(0, 60)}{vuln.payload.length > 60 ? '...' : ''}
                      </code>
                    </div>
                  </div>
                  
                  {/* Tags */}
                  {vuln.payload_tags && vuln.payload_tags.length > 0 && (
                    <div className="flex items-center gap-1 mt-2 flex-wrap">
                      {vuln.payload_tags.slice(0, 4).map((tag, i) => (
                        <span key={i} className="text-[10px] px-1.5 py-0.5 bg-[var(--color-primary)]/10 text-[var(--color-primary)] rounded">
                          {tag}
                        </span>
                      ))}
                      {vuln.payload_tags.length > 4 && (
                        <span className="text-[10px] text-[var(--color-text-muted)]">
                          +{vuln.payload_tags.length - 4}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Vulnerability Details Modal */}
        {selectedVuln && (
          <div 
            className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4"
            onClick={() => setSelectedVuln(null)}
          >
            <div 
              className="bg-[var(--color-surface)] rounded-xl border border-[var(--color-border)] max-w-2xl w-full max-h-[90vh] overflow-y-auto"
              onClick={e => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between p-4 border-b border-[var(--color-border)]">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-1 text-xs font-bold rounded border ${getSeverityBadge(selectedVuln.severity)}`}>
                    {selectedVuln.severity.toUpperCase()}
                  </span>
                  <h3 className="font-semibold">
                    {selectedVuln.payload_name || 'XSS Vulnerability'}
                  </h3>
                </div>
                <button 
                  onClick={() => setSelectedVuln(null)}
                  className="p-2 rounded-lg hover:bg-[var(--color-surface-hover)] transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
              
              {/* Modal Content */}
              <div className="p-4 space-y-4">
                {/* Description */}
                {selectedVuln.payload_description && (
                  <div>
                    <div className="flex items-center gap-2 text-sm font-medium mb-2">
                      <FileText className="w-4 h-4 text-[var(--color-primary)]" />
                      Description
                    </div>
                    <p className="text-sm text-[var(--color-text-secondary)] bg-[var(--color-surface-hover)] p-3 rounded-lg">
                      {selectedVuln.payload_description}
                    </p>
                  </div>
                )}
                
                {/* Location */}
                <div>
                  <div className="flex items-center gap-2 text-sm font-medium mb-2">
                    <ExternalLink className="w-4 h-4 text-[var(--color-primary)]" />
                    Location
                  </div>
                  <div className="bg-[var(--color-surface-hover)] p-3 rounded-lg space-y-2 text-sm">
                    <div className="flex items-center gap-2">
                      <span className="text-[var(--color-text-muted)] w-20">URL:</span>
                      <span className="font-mono text-[var(--color-primary)] break-all">{selectedVuln.url}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[var(--color-text-muted)] w-20">Parameter:</span>
                      <span className="font-mono">{selectedVuln.parameter}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[var(--color-text-muted)] w-20">Context:</span>
                      <span className="px-2 py-0.5 bg-black/30 rounded text-xs">{selectedVuln.context_type || 'html'}</span>
                    </div>
                  </div>
                </div>
                
                {/* Payload */}
                <div>
                  <div className="flex items-center gap-2 text-sm font-medium mb-2">
                    <Code className="w-4 h-4 text-[var(--color-warning)]" />
                    Payload
                  </div>
                  <code className="block p-3 bg-black/80 rounded-lg text-[var(--color-danger)] font-mono text-sm break-all border border-[var(--color-border)]">
                    {selectedVuln.payload}
                  </code>
                </div>
                
                {/* Applicable Contexts */}
                {selectedVuln.payload_contexts && selectedVuln.payload_contexts.length > 0 && (
                  <div>
                    <div className="flex items-center gap-2 text-sm font-medium mb-2">
                      <Target className="w-4 h-4 text-[var(--color-info)]" />
                      Applicable Contexts
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {selectedVuln.payload_contexts.map((ctx, i) => (
                        <span key={i} className="text-xs px-2 py-1 bg-[var(--color-info)]/10 text-[var(--color-info)] rounded border border-[var(--color-info)]/20">
                          {ctx}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Tags */}
                {selectedVuln.payload_tags && selectedVuln.payload_tags.length > 0 && (
                  <div>
                    <div className="flex items-center gap-2 text-sm font-medium mb-2">
                      <Tag className="w-4 h-4 text-[var(--color-primary)]" />
                      Tags
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {selectedVuln.payload_tags.map((tag, i) => (
                        <span key={i} className="text-xs px-2 py-1 bg-[var(--color-primary)]/10 text-[var(--color-primary)] rounded border border-[var(--color-primary)]/20">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* KB Reference */}
                {selectedVuln.payload_id && (
                  <div className="pt-2 border-t border-[var(--color-border)]">
                    <div className="flex items-center gap-2 text-xs text-[var(--color-text-muted)]">
                      <Database className="w-3 h-3" />
                      <span>KB Reference:</span>
                      <code className="font-mono">{selectedVuln.payload_id}</code>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* No vulnerabilities message */}
        {scan.status === 'completed' && vulnCount === 0 && (
          <div className="brs-card text-center py-8">
            <Shield className="w-12 h-12 mx-auto mb-3 text-[var(--color-success)]" />
            <h3 className="text-lg font-medium text-[var(--color-success)]">Target appears secure</h3>
            <p className="text-sm text-[var(--color-text-muted)] mt-1">
              No XSS vulnerabilities detected with current payload set
            </p>
          </div>
        )}
      </div>
    </>
  );
}
