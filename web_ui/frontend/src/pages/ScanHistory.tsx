/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Thu 26 Dec 2025 UTC
 * Status: Updated - Added delete, bulk actions, improved UX
 * Telegram: https://t.me/EasyProTech
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { 
  History, 
  ArrowRight, 
  Search,
  Download,
  Trash2,
  CheckSquare,
  Square,
  AlertCircle,
  CheckCircle,
  Loader,
  XCircle,
  Copy,
  RotateCw,
  Check,
  Zap,
  Target,
  Eye,
  Ghost,
  Leaf,
  Gauge,
  Flame,
  Rocket,
  ExternalLink,
  Globe,
  AlertTriangle,
  Send,
  Hash
} from 'lucide-react';
import { api } from '../api/client';

interface ProxyUsed {
  enabled: boolean;
  ip?: string;
  country?: string;
  country_code?: string;
}

interface Scan {
  id: string;
  url: string;
  mode: string;
  performance_mode?: string;
  status: string;
  vulnerability_count: number;
  critical_count: number;
  high_count: number;
  duration_seconds: number;
  started_at: string;
  proxy_used?: ProxyUsed;
}

// Convert country code to flag emoji
function getFlagEmoji(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return '';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

// Icons for scan modes
const scanModeIcons: Record<string, typeof Zap> = {
  quick: Zap,
  standard: Target,
  deep: Eye,
  stealth: Ghost,
};

// Icons for performance modes
const perfModeIcons: Record<string, typeof Leaf> = {
  light: Leaf,
  standard: Gauge,
  turbo: Flame,
  maximum: Rocket,
};

// Rescan modal component
function RescanModal({ 
  url,
  defaultMode,
  onConfirm, 
  onCancel,
  isScanning
}: { 
  url: string;
  defaultMode: string;
  onConfirm: (mode: string) => void;
  onCancel: () => void;
  isScanning: boolean;
}) {
  const [selectedMode, setSelectedMode] = useState(defaultMode);
  
  const modes = [
    { value: 'quick', label: 'Quick', desc: '~30s, 50 payloads' },
    { value: 'standard', label: 'Standard', desc: '~2min, 200 payloads' },
    { value: 'deep', label: 'Deep', desc: '~10min, all payloads' },
    { value: 'stealth', label: 'Stealth', desc: '~3min, slow & careful' },
  ];

  // Get clean display URL
  const displayUrl = (() => {
    try {
      const parsed = new URL(url);
      let display = parsed.hostname;
      if (parsed.pathname && parsed.pathname !== '/') {
        display += parsed.pathname.replace(/\/$/, '');
      }
      return display;
    } catch {
      return url.replace(/\/$/, '');
    }
  })();

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 backdrop-blur-sm">
      <div className="brs-card max-w-md w-full mx-4 p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-[var(--color-primary)]/20 flex items-center justify-center">
            <RotateCw className="w-5 h-5 text-[var(--color-primary)]" />
          </div>
          <div>
            <h3 className="text-lg font-semibold">Rescan Target</h3>
            <p className="text-sm font-mono text-[var(--color-primary)]">{displayUrl}</p>
          </div>
        </div>
        
        <div className="mb-4">
          <label className="block text-sm text-[var(--color-text-muted)] mb-2">Scan Mode</label>
          <div className="grid grid-cols-2 gap-2">
            {modes.map((mode) => (
              <button
                key={mode.value}
                onClick={() => setSelectedMode(mode.value)}
                className={`p-3 rounded-lg border text-left transition-all ${
                  selectedMode === mode.value
                    ? 'border-[var(--color-primary)] bg-[var(--color-primary)]/10'
                    : 'border-[var(--color-border)] hover:border-[var(--color-primary)]/50'
                }`}
              >
                <div className="font-medium text-sm">{mode.label}</div>
                <div className="text-xs text-[var(--color-text-muted)]">{mode.desc}</div>
              </button>
            ))}
          </div>
        </div>
        
        <div className="flex gap-3 justify-end">
          <button 
            onClick={onCancel}
            className="brs-btn brs-btn-secondary"
            disabled={isScanning}
          >
            Cancel
          </button>
          <button 
            onClick={() => onConfirm(selectedMode)}
            className="brs-btn brs-btn-primary"
            disabled={isScanning}
          >
            {isScanning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Starting...
              </>
            ) : (
              <>
                <RotateCw className="w-4 h-4" />
                Start Scan
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

// Delete confirmation modal
function DeleteConfirmModal({ 
  scanIds,
  onConfirm, 
  onCancel,
  isDeleting
}: { 
  scanIds: string[];
  onConfirm: () => void;
  onCancel: () => void;
  isDeleting: boolean;
}) {
  const count = scanIds.length;
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 backdrop-blur-sm">
      <div className="brs-card max-w-md w-full mx-4 p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center">
            <Trash2 className="w-5 h-5 text-red-500" />
          </div>
          <h3 className="text-lg font-semibold">
            Delete {count} Scan{count > 1 ? 's' : ''}
          </h3>
        </div>
        
        <p className="text-[var(--color-text-secondary)] mb-4">
          Are you sure you want to delete {count > 1 ? 'these scans' : 'this scan'}? 
          This action cannot be undone.
        </p>
        
        <div className="flex gap-3 justify-end">
          <button 
            onClick={onCancel}
            className="brs-btn brs-btn-secondary"
            disabled={isDeleting}
          >
            Cancel
          </button>
          <button 
            onClick={onConfirm}
            className="brs-btn bg-red-600 hover:bg-red-700 text-white"
            disabled={isDeleting}
          >
            {isDeleting ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Deleting...
              </>
            ) : (
              <>
                <Trash2 className="w-4 h-4" />
                Delete {count > 1 ? `(${count})` : ''}
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

// Status icon component
function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'completed':
      return <CheckCircle className="w-4 h-4 text-green-500" />;
    case 'running':
      return <Loader className="w-4 h-4 text-blue-500 animate-spin" />;
    case 'failed':
      return <XCircle className="w-4 h-4 text-red-500" />;
    default:
      return <AlertCircle className="w-4 h-4 text-yellow-500" />;
  }
}

// Format duration
function formatDuration(seconds: number): string {
  if (!seconds || seconds < 0) return '-';
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins}m ${secs}s`;
}

// Format date
function formatDate(dateStr?: string): string {
  if (!dateStr) return '-';
  try {
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return '-';
    return date.toLocaleString('ru-RU', {
      day: '2-digit',
      month: '2-digit',
      year: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch {
    return '-';
  }
}

// Truncate URL - remove trailing slash
function truncateUrl(url: string, maxLen: number = 40): string {
  if (!url) return '-';
  try {
    const parsed = new URL(url);
    let display = parsed.hostname + parsed.pathname;
    // Remove trailing slash
    if (display.endsWith('/') && display.length > 1) {
      display = display.slice(0, -1);
    }
    return display.length > maxLen ? display.slice(0, maxLen) + '...' : display;
  } catch {
    let clean = url.endsWith('/') ? url.slice(0, -1) : url;
    return clean.length > maxLen ? clean.slice(0, maxLen) + '...' : clean;
  }
}

export function ScanHistory() {
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [deleteTarget, setDeleteTarget] = useState<string[] | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedScanId, setCopiedScanId] = useState<string | null>(null);
  const [rescanTarget, setRescanTarget] = useState<{url: string, mode: string} | null>(null);
  const [sendingToTg, setSendingToTg] = useState<string | null>(null);

  // Copy scan ID to clipboard
  const copyScanId = async (e: React.MouseEvent, scanId: string) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(scanId);
      setCopiedScanId(scanId);
      setTimeout(() => setCopiedScanId(null), 2000);
    } catch (err) {
      // Fallback for older browsers or when clipboard API is not available
      try {
        const textArea = document.createElement('textarea');
        textArea.value = scanId;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        setCopiedScanId(scanId);
        setTimeout(() => setCopiedScanId(null), 2000);
      } catch (fallbackErr) {
        console.error('Failed to copy scan ID:', fallbackErr);
      }
    }
  };

  // Telegram status query
  const { data: telegramStatus } = useQuery({
    queryKey: ['telegram-status'],
    queryFn: () => api.get('/telegram').then(res => res.data),
    staleTime: 60000,
  });

  // Send to Telegram mutation
  const sendToTelegramMutation = useMutation({
    mutationFn: async (scanId: string) => {
      setSendingToTg(scanId);
      return api.post(`/scans/${scanId}/telegram`);
    },
    onSuccess: () => {
      setSendingToTg(null);
    },
    onError: () => {
      setSendingToTg(null);
    }
  });

  // Copy full URL to clipboard
  const copyUrl = async (e: React.MouseEvent, url: string, scanId: string) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(url);
      setCopiedId(scanId);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = url;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopiedId(scanId);
      setTimeout(() => setCopiedId(null), 2000);
    }
  };

  const { data: scans, isLoading } = useQuery<Scan[]>({
    queryKey: ['scans'],
    queryFn: () => api.get('/scans?limit=100').then(res => res.data),
  });

  const deleteMutation = useMutation({
    mutationFn: async (scanIds: string[]) => {
      await Promise.all(scanIds.map(id => api.delete(`/scans/${id}`)));
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      setDeleteTarget(null);
      setSelectedIds(new Set());
    },
  });

  const rescanMutation = useMutation({
    mutationFn: async ({ url, mode }: { url: string; mode: string }) => {
      return api.post('/scans', { url, mode });
    },
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      setRescanTarget(null);
      // Navigate to the new scan
      window.location.href = `/scan/${response.data.scan_id}`;
    },
  });

  // Filter scans
  const filteredScans = scans?.filter(scan => {
    const matchesSearch = !searchTerm || 
      scan.url?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      scan.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
    return matchesSearch && matchesStatus;
  }) || [];

  // Selection handlers
  const toggleSelect = (id: string) => {
    const newSet = new Set(selectedIds);
    if (newSet.has(id)) {
      newSet.delete(id);
    } else {
      newSet.add(id);
    }
    setSelectedIds(newSet);
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === filteredScans.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredScans.map(s => s.id)));
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return 'brs-badge-success';
      case 'running':
        return 'brs-badge-info';
      case 'failed':
        return 'brs-badge-danger';
      default:
        return 'brs-badge-warning';
    }
  };

  const getVulnBadge = (count: number, critical: number = 0) => {
    if (count === 0) return 'brs-badge-success';
    if (critical > 0) return 'brs-badge-critical';
    if (count <= 10) return 'brs-badge-high';
    return 'brs-badge-critical';
  };

  return (
    <>
      {/* Rescan Modal */}
      {rescanTarget && (
        <RescanModal
          url={rescanTarget.url}
          defaultMode={rescanTarget.mode}
          onConfirm={(mode) => rescanMutation.mutate({ url: rescanTarget.url, mode })}
          onCancel={() => setRescanTarget(null)}
          isScanning={rescanMutation.isPending}
        />
      )}

      {/* Delete Confirmation Modal */}
      {deleteTarget && (
        <DeleteConfirmModal
          scanIds={deleteTarget}
          onConfirm={() => deleteMutation.mutate(deleteTarget)}
          onCancel={() => setDeleteTarget(null)}
          isDeleting={deleteMutation.isPending}
        />
      )}

      {/* Header */}
      <header className="brs-header">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="brs-header-title">Scan History</h1>
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
          <p className="brs-header-subtitle">
            {scans?.length || 0} total scans
            {selectedIds.size > 0 && ` | ${selectedIds.size} selected`}
          </p>
        </div>
        <div className="flex gap-3">
          {selectedIds.size > 0 && (
            <button 
              onClick={() => setDeleteTarget(Array.from(selectedIds))}
              className="brs-btn bg-red-600 hover:bg-red-700 text-white"
            >
              <Trash2 className="w-4 h-4" />
              Delete ({selectedIds.size})
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
        {/* Filters */}
        <div className="flex gap-4 mb-6">
          <div className="brs-input-group flex-1">
            <Search className="brs-input-icon w-5 h-5" />
            <input
              type="text"
              className="brs-input"
              placeholder="Search by URL or ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <select 
            className="brs-input w-40"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all">All Status</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>

        {/* Table */}
        <div className="brs-card">
          {isLoading ? (
            <div className="brs-empty">
              <div className="w-8 h-8 border-2 border-[var(--color-primary)] border-t-transparent rounded-full animate-spin" />
            </div>
          ) : !filteredScans?.length ? (
            <div className="brs-empty">
              <History className="brs-empty-icon" />
              <h3 className="brs-empty-title">
                {searchTerm || statusFilter !== 'all' ? 'No matching scans' : 'No scans yet'}
              </h3>
              <p className="brs-empty-desc">
                {searchTerm || statusFilter !== 'all' 
                  ? 'Try adjusting your search or filters'
                  : 'Your scan history will appear here after you run your first scan'
                }
              </p>
              {!searchTerm && statusFilter === 'all' && (
                <Link to="/scan/new" className="brs-btn brs-btn-primary mt-6">
                  Start First Scan
                </Link>
              )}
            </div>
          ) : (
            <table className="brs-table">
              <thead>
                <tr>
                  <th className="w-10">
                    <button
                      onClick={toggleSelectAll}
                      className="p-1 hover:bg-[var(--color-surface-hover)] rounded"
                    >
                      {selectedIds.size === filteredScans.length ? (
                        <CheckSquare className="w-4 h-4 text-[var(--color-primary)]" />
                      ) : (
                        <Square className="w-4 h-4 text-[var(--color-text-muted)]" />
                      )}
                    </button>
                  </th>
                  <th>Target</th>
                  <th>Scan</th>
                  <th>Perf</th>
                  <th>Via</th>
                  <th>Status</th>
                  <th>Vulns</th>
                  <th>Duration</th>
                  <th>Date</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => (
                  <tr key={scan.id} className="group">
                    <td>
                      <button
                        onClick={() => toggleSelect(scan.id)}
                        className="p-1 hover:bg-[var(--color-surface-hover)] rounded"
                      >
                        {selectedIds.has(scan.id) ? (
                          <CheckSquare className="w-4 h-4 text-[var(--color-primary)]" />
                        ) : (
                          <Square className="w-4 h-4 text-[var(--color-text-muted)] opacity-0 group-hover:opacity-100 transition-opacity" />
                        )}
                      </button>
                    </td>
                    <td>
                      <div className="flex items-center gap-1">
                        <span 
                          className="font-mono text-sm text-[var(--color-primary)]"
                        >
                          {truncateUrl(scan.url)}
                        </span>
                        <button
                          onClick={(e) => copyUrl(e, scan.url, scan.id)}
                          className="brs-tooltip p-1.5 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all"
                          data-tooltip={copiedId === scan.id ? "Copied!" : "Copy URL"}
                        >
                          {copiedId === scan.id ? (
                            <Check className="w-3.5 h-3.5 text-green-500" />
                          ) : (
                            <Copy className="w-3.5 h-3.5 text-[var(--color-text-muted)]" />
                          )}
                        </button>
                        <button
                          onClick={(e) => copyScanId(e, scan.id)}
                          className="brs-tooltip p-1.5 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all"
                          data-tooltip={copiedScanId === scan.id ? "Copied!" : "Copy ID"}
                        >
                          {copiedScanId === scan.id ? (
                            <Check className="w-3.5 h-3.5 text-green-500" />
                          ) : (
                            <Hash className="w-3.5 h-3.5 text-[var(--color-text-muted)]" />
                          )}
                        </button>
                        <button
                          onClick={() => setRescanTarget({ url: scan.url, mode: scan.mode })}
                          className="brs-tooltip p-1.5 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all"
                          data-tooltip="Rescan"
                        >
                          <RotateCw className="w-3.5 h-3.5 text-[var(--color-text-muted)]" />
                        </button>
                        {telegramStatus?.configured && scan.status === 'completed' && (
                          <button
                            onClick={() => sendToTelegramMutation.mutate(scan.id)}
                            disabled={sendingToTg === scan.id}
                            className="brs-tooltip p-1.5 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all"
                            data-tooltip="Send to Telegram"
                          >
                            {sendingToTg === scan.id ? (
                              <Loader className="w-3.5 h-3.5 text-[var(--color-primary)] animate-spin" />
                            ) : (
                              <Send className="w-3.5 h-3.5 text-[var(--color-primary)]" />
                            )}
                          </button>
                        )}
                      </div>
                    </td>
                    <td>
                      {(() => {
                        const ScanIcon = scanModeIcons[scan.mode] || Target;
                        return (
                          <div className="flex items-center gap-1.5 brs-tooltip" data-tooltip={scan.mode}>
                            <ScanIcon className="w-4 h-4 text-[var(--color-primary)]" />
                            <span className="text-[var(--color-text-secondary)] capitalize text-xs">
                              {scan.mode}
                            </span>
                          </div>
                        );
                      })()}
                    </td>
                    <td>
                      {(() => {
                        const perfMode = scan.performance_mode || 'standard';
                        const PerfIcon = perfModeIcons[perfMode] || Gauge;
                        return (
                          <div className="flex items-center gap-1.5 brs-tooltip" data-tooltip={perfMode}>
                            <PerfIcon className="w-4 h-4 text-[var(--color-success)]" />
                            <span className="text-[var(--color-text-secondary)] capitalize text-xs">
                              {perfMode}
                            </span>
                          </div>
                        );
                      })()}
                    </td>
                    <td>
                      {/* Proxy/IP used for scan */}
                      {scan.proxy_used?.enabled ? (
                        <div className="brs-tooltip flex items-center gap-1" data-tooltip={`${scan.proxy_used.ip || 'Proxy'}`}>
                          {scan.proxy_used.country_code && (
                            <span className="text-sm">{getFlagEmoji(scan.proxy_used.country_code)}</span>
                          )}
                          <Globe className="w-3.5 h-3.5 text-[var(--color-success)]" />
                        </div>
                      ) : (
                        <div className="brs-tooltip flex items-center gap-1" data-tooltip="Scanned from real IP">
                          <AlertTriangle className="w-3.5 h-3.5 text-[var(--color-warning)]" />
                        </div>
                      )}
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <StatusIcon status={scan.status} />
                        <span className={`brs-badge ${getStatusBadge(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className={`brs-badge ${getVulnBadge(scan.vulnerability_count, scan.critical_count)}`}>
                        {scan.vulnerability_count}
                      </span>
                    </td>
                    <td className="text-[var(--color-text-secondary)] font-mono text-sm">
                      {formatDuration(scan.duration_seconds)}
                    </td>
                    <td className="text-[var(--color-text-secondary)] text-sm">
                      {formatDate(scan.started_at)}
                    </td>
                    <td>
                      <div className="flex items-center justify-end gap-1">
                        <Link 
                          to={`/scan/${scan.id}`}
                          className="brs-btn brs-btn-ghost text-sm"
                        >
                          View
                          <ArrowRight className="w-4 h-4" />
                        </Link>
                        <button
                          onClick={() => setDeleteTarget([scan.id])}
                          className="brs-tooltip brs-btn brs-btn-ghost text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 opacity-0 group-hover:opacity-100 transition-opacity"
                          data-tooltip="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
