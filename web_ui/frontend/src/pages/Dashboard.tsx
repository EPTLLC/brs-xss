/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Thu 26 Dec 2025 UTC
 * Status: Updated - System Profile block, GitHub branding
 * Telegram: https://t.me/EasyProTech
 */

import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { 
  Shield, 
  AlertTriangle, 
  Clock, 
  Activity,
  Crosshair,
  ArrowRight,
  Target,
  Zap,
  Database,
  Trash2,
  Cpu,
  HardDrive,
  Gauge,
  ExternalLink,
  Leaf,
  Flame,
  Rocket,
  Settings,
  StopCircle,
  Copy,
  RotateCw,
  Check,
  Globe,
  Wifi,
  WifiOff,
  X,
  Loader,
  MapPin,
  Save,
  Plus,
  Send,
  Hash,
  Eye
} from 'lucide-react';
import { api } from '../api/client';

interface RecentScan {
  id: string;
  url: string;
  mode: string;
  performance_mode?: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  vulnerability_count: number;
  critical_count: number;
  high_count: number;
  duration_seconds: number;
}

interface DashboardData {
  total_scans: number;
  scans_today: number;
  scans_this_week: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  most_common_context: string | null;
  most_common_waf: string | null;
  avg_scan_duration_seconds: number;
  recent_scans: RecentScan[];
}

interface KBStats {
  version?: string | null;
  total_payloads?: number | null;
  contexts?: number | null;
  waf_bypass_count?: number | null;
  repo_url?: string;
  error?: boolean;
  error_message?: string;
  available?: boolean;
}

interface LiveStats {
  cpu_percent: number;
  ram_used_gb: number;
  ram_total_gb: number;
  ram_percent: number;
  load_1m: number;
  load_5m: number;
  load_15m: number;
  performance_mode: string;
  active_scans: number;
}

interface SystemInfo {
  system: {
    cpu_model: string;
    cpu_threads: number;
    ram_total_gb: number;
    ram_available_gb: number;
    os_name: string;
    os_version: string;
  };
  modes: Record<string, {
    label: string;
    threads: number;
    requests_per_second: number;
    recommended?: boolean;
  }>;
  saved_mode: string | null;
  recommended_mode: string;
}

interface VersionInfo {
  version: string;
  name: string;
  github: string;
}

interface SavedProxy {
  id: string;
  name: string;
  host: string;
  port: number;
  protocol: string;
  country?: string;
  country_code?: string;
  is_working?: boolean;
}

interface ProxySettings {
  enabled: boolean;
  active_proxy_id?: string;
  host: string;
  port: number;
  username: string | null;
  password: string | null;
  protocol: string;
  proxy_string: string | null;
  country?: string;
  country_code?: string;
  saved_proxies: SavedProxy[];
}

interface ProxyTestResult {
  success: boolean;
  ip?: string;
  country?: string;
  country_code?: string;
  latency_ms?: number;
  error?: string;
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

// Live duration component for running scans
function LiveDuration({ startedAt }: { startedAt: string }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    // Parse startedAt as UTC (server sends UTC timestamps)
    // Append 'Z' if not present to ensure UTC parsing
    const utcStartedAt = startedAt.endsWith('Z') ? startedAt : startedAt + 'Z';
    const startTime = new Date(utcStartedAt).getTime();
    
    const updateElapsed = () => {
      const now = Date.now();
      const diff = Math.floor((now - startTime) / 1000);
      // Sanity check: if negative or > 24 hours, something is wrong
      setElapsed(diff >= 0 && diff < 86400 ? diff : 0);
    };

    updateElapsed();
    const interval = setInterval(updateElapsed, 1000);
    return () => clearInterval(interval);
  }, [startedAt]);

  return (
    <span className="text-[var(--color-accent)] animate-pulse">
      {formatDuration(elapsed)}
    </span>
  );
}

// Proxy modal component
function ProxyModal({
  proxySettings,
  onClose,
  onSave,
  onSelect,
  onDelete,
  onDisable
}: {
  proxySettings: ProxySettings | null;
  onClose: () => void;
  onSave: (proxyString: string, protocol: string, country?: string, countryCode?: string) => void;
  onSelect: (proxyId: string) => void;
  onDelete: (proxyId: string) => void;
  onDisable: () => void;
}) {
  const [proxyString, setProxyString] = useState('');
  const [protocol, setProtocol] = useState('socks5');
  const [testResult, setTestResult] = useState<ProxyTestResult | null>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [showAddNew, setShowAddNew] = useState(false);

  const savedProxies = proxySettings?.saved_proxies || [];
  const hasProxies = savedProxies.length > 0;

  const handleTest = async () => {
    if (!proxyString.trim()) return;
    setIsTesting(true);
    setTestResult(null);
    try {
      const response = await api.post(`/proxy/test?proxy_string=${encodeURIComponent(proxyString)}&protocol=${protocol}`);
      setTestResult(response.data);
    } catch {
      setTestResult({ success: false, error: 'Connection failed' });
    } finally {
      setIsTesting(false);
    }
  };

  const handleSave = async () => {
    if (!proxyString.trim()) return;
    setIsSaving(true);
    try {
      await onSave(
        proxyString, 
        protocol, 
        testResult?.country, 
        testResult?.country_code
      );
      setProxyString('');
      setTestResult(null);
      setShowAddNew(false);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 backdrop-blur-sm">
      <div className="brs-card max-w-lg w-full mx-4 p-6 max-h-[80vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-[var(--color-info)]/20 flex items-center justify-center">
              <Globe className="w-5 h-5 text-[var(--color-info)]" />
            </div>
            <div>
              <h3 className="text-lg font-semibold">Proxy Settings</h3>
              <p className="text-xs text-[var(--color-text-muted)]">
                {savedProxies.length}/10 proxies saved
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-[var(--color-surface-hover)] rounded-lg">
            <X className="w-5 h-5 text-[var(--color-text-muted)]" />
          </button>
        </div>

        {/* Saved Proxies List */}
        {hasProxies && !showAddNew && (
          <div className="space-y-2 mb-4">
            <div className="text-xs uppercase tracking-wider text-[var(--color-text-muted)] mb-2">
              Select Proxy
            </div>
            {savedProxies.map((proxy) => (
              <div 
                key={proxy.id}
                className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  proxySettings?.active_proxy_id === proxy.id && proxySettings?.enabled
                    ? 'border-[var(--color-success)] bg-[var(--color-success)]/10'
                    : 'border-[var(--color-border)] hover:border-[var(--color-primary)]/50 bg-[var(--color-surface-hover)]'
                }`}
                onClick={() => onSelect(proxy.id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {proxy.country_code && (
                      <span className="text-lg">{getFlagEmoji(proxy.country_code)}</span>
                    )}
                    <div>
                      <div className="text-sm font-medium flex items-center gap-2">
                        {proxy.name || `${proxy.host}:${proxy.port}`}
                        {proxySettings?.active_proxy_id === proxy.id && proxySettings?.enabled && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--color-success)] text-black">ACTIVE</span>
                        )}
                      </div>
                      <div className="text-xs text-[var(--color-text-muted)] font-mono">
                        {proxy.host}:{proxy.port} ({proxy.protocol.toUpperCase()})
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onDelete(proxy.id);
                    }}
                    className="p-1.5 rounded hover:bg-red-500/20 text-[var(--color-text-muted)] hover:text-red-400 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
            
            {/* Disable Proxy Option */}
            {proxySettings?.enabled && (
              <button
                onClick={onDisable}
                className="w-full p-3 rounded-lg border border-[var(--color-border)] hover:border-[var(--color-warning)]/50 bg-[var(--color-surface-hover)] transition-all text-left"
              >
                <div className="flex items-center gap-2 text-[var(--color-warning)]">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="text-sm">Disable Proxy (use Real IP)</span>
                </div>
              </button>
            )}
          </div>
        )}

        {/* Add New Proxy Button or Form */}
        {!showAddNew && savedProxies.length < 10 && (
          <button
            onClick={() => setShowAddNew(true)}
            className="w-full p-3 rounded-lg border border-dashed border-[var(--color-border)] hover:border-[var(--color-primary)] bg-[var(--color-surface-hover)] transition-all mb-4"
          >
            <div className="flex items-center justify-center gap-2 text-[var(--color-text-muted)]">
              <Plus className="w-4 h-4" />
              <span className="text-sm">Add New Proxy</span>
            </div>
          </button>
        )}

        {/* Add New Proxy Form */}
        {(showAddNew || !hasProxies) && (
          <div className="space-y-4">
            {hasProxies && (
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider text-[var(--color-text-muted)]">
                  Add New Proxy
                </span>
                <button 
                  onClick={() => setShowAddNew(false)}
                  className="text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
                >
                  Cancel
                </button>
              </div>
            )}
            
            <div>
              <label className="block text-sm text-[var(--color-text-muted)] mb-2">Proxy String</label>
              <input
                type="text"
                className="brs-input font-mono text-sm"
                placeholder="host:port:username:password"
                value={proxyString}
                onChange={(e) => setProxyString(e.target.value)}
              />
              <p className="text-xs text-[var(--color-text-muted)] mt-1">
                Format: host:port:user:pass
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm text-[var(--color-text-muted)] mb-2">Protocol</label>
                <select
                  className="brs-select text-sm"
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value)}
                >
                  <option value="socks5">SOCKS5</option>
                  <option value="socks4">SOCKS4</option>
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                </select>
              </div>
              <div className="flex items-end">
                <button
                  onClick={handleTest}
                  disabled={isTesting || !proxyString.trim()}
                  className="brs-btn brs-btn-secondary w-full"
                >
                  {isTesting ? (
                    <>
                      <Loader className="w-4 h-4 animate-spin" />
                      Testing...
                    </>
                  ) : (
                    <>
                      <Wifi className="w-4 h-4" />
                      Test
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Test Result */}
            {testResult && (
              <div className={`p-3 rounded-lg border ${
                testResult.success 
                  ? 'bg-[var(--color-success)]/10 border-[var(--color-success)]/30' 
                  : 'bg-red-500/10 border-red-500/30'
              }`}>
                {testResult.success ? (
                  <div className="flex items-center gap-3">
                    <Check className="w-5 h-5 text-[var(--color-success)]" />
                    <div className="flex-1">
                      <div className="text-sm font-medium text-[var(--color-success)]">Connected</div>
                      <div className="flex items-center gap-3 text-xs text-[var(--color-text-muted)]">
                        <span className="font-mono">{testResult.ip}</span>
                        <span className="flex items-center gap-1">
                          {testResult.country_code && (
                            <span className="text-base">{getFlagEmoji(testResult.country_code)}</span>
                          )}
                          <MapPin className="w-3 h-3" />
                          {testResult.country}
                        </span>
                        <span>{testResult.latency_ms?.toFixed(0)}ms</span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-red-400">
                    <WifiOff className="w-4 h-4" />
                    <span className="text-sm">{testResult.error}</span>
                  </div>
                )}
              </div>
            )}

            {/* Save Button */}
            <button
              onClick={handleSave}
              disabled={isSaving || !proxyString.trim()}
              className="brs-btn brs-btn-primary w-full"
            >
              {isSaving ? (
                <>
                  <Loader className="w-4 h-4 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  Save & Activate Proxy
                </>
              )}
            </button>
          </div>
        )}

        {/* Close button */}
        {hasProxies && !showAddNew && (
          <button onClick={onClose} className="brs-btn brs-btn-secondary w-full mt-4">
            Close
          </button>
        )}
      </div>
    </div>
  );
}

// Rescan modal component
function RescanModal({ 
  url,
  defaultMode,
  defaultPerfMode,
  onConfirm, 
  onCancel,
  isScanning
}: { 
  url: string;
  defaultMode: string;
  defaultPerfMode: string;
  onConfirm: (mode: string, perfMode: string) => void;
  onCancel: () => void;
  isScanning: boolean;
}) {
  const [selectedMode, setSelectedMode] = useState(defaultMode);
  const [selectedPerfMode, setSelectedPerfMode] = useState(defaultPerfMode);
  
  const modes = [
    { value: 'quick', label: 'Quick', desc: '~15s, 50 payloads' },
    { value: 'standard', label: 'Standard', desc: '~30s, 200 payloads' },
    { value: 'deep', label: 'Deep', desc: '~2min, all payloads' },
    { value: 'stealth', label: 'Stealth', desc: '~1min, slow & careful' },
  ];

  const perfModes = [
    { value: 'light', label: 'Light', icon: Leaf },
    { value: 'standard', label: 'Standard', icon: Gauge },
    { value: 'turbo', label: 'Turbo', icon: Flame },
    { value: 'maximum', label: 'Maximum', icon: Rocket },
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
      <div className="brs-card max-w-lg w-full mx-4 p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-[var(--color-primary)]/20 flex items-center justify-center">
            <RotateCw className="w-5 h-5 text-[var(--color-primary)]" />
          </div>
          <div>
            <h3 className="text-lg font-semibold">Rescan Target</h3>
            <p className="text-sm font-mono text-[var(--color-primary)]">{displayUrl}</p>
          </div>
        </div>
        
        {/* Scan Mode */}
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

        {/* Performance Mode */}
        <div className="mb-4">
          <label className="block text-sm text-[var(--color-text-muted)] mb-2">Performance</label>
          <div className="grid grid-cols-4 gap-2">
            {perfModes.map((perf) => {
              const Icon = perf.icon;
              return (
                <button
                  key={perf.value}
                  onClick={() => setSelectedPerfMode(perf.value)}
                  className={`p-2 rounded-lg border text-center transition-all ${
                    selectedPerfMode === perf.value
                      ? 'border-[var(--color-success)] bg-[var(--color-success)]/10'
                      : 'border-[var(--color-border)] hover:border-[var(--color-success)]/50'
                  }`}
                >
                  <Icon className={`w-4 h-4 mx-auto mb-1 ${
                    selectedPerfMode === perf.value ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'
                  }`} />
                  <div className={`text-xs font-medium ${
                    selectedPerfMode === perf.value ? 'text-[var(--color-success)]' : ''
                  }`}>{perf.label}</div>
                </button>
              );
            })}
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
            onClick={() => onConfirm(selectedMode, selectedPerfMode)}
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
  scanUrl, 
  onConfirm, 
  onCancel,
  isDeleting
}: { 
  scanUrl: string;
  onConfirm: () => void;
  onCancel: () => void;
  isDeleting: boolean;
}) {
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 backdrop-blur-sm">
      <div className="brs-card max-w-md w-full mx-4 p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center">
            <Trash2 className="w-5 h-5 text-red-500" />
          </div>
          <h3 className="text-lg font-semibold">Delete Scan</h3>
        </div>
        
        <p className="text-[var(--color-text-secondary)] mb-2">
          Are you sure you want to delete this scan?
        </p>
        <p className="font-mono text-sm text-[var(--color-primary)] bg-[var(--color-surface-hover)] p-2 rounded mb-4 break-all">
          {scanUrl}
        </p>
        <p className="text-[var(--color-text-muted)] text-sm mb-6">
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
                Delete
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

// Format date nicely
const formatDate = (dateStr?: string): string => {
  if (!dateStr) return '-';
  try {
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return '-';
    return date.toLocaleString('ru-RU', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch {
    return '-';
  }
};

// Truncate URL for display - remove trailing slash
const truncateUrl = (url: string, maxLen: number = 35): string => {
  if (!url) return '-';
  try {
    const parsed = new URL(url);
    let display = parsed.hostname + parsed.pathname;
    if (display.endsWith('/') && display.length > 1) {
      display = display.slice(0, -1);
    }
    return display.length > maxLen ? display.slice(0, maxLen) + '...' : display;
  } catch {
    let clean = url.endsWith('/') ? url.slice(0, -1) : url;
    return clean.length > maxLen ? clean.slice(0, maxLen) + '...' : clean;
  }
};

// Performance mode labels
const perfModeLabels: Record<string, string> = {
  light: 'Light',
  standard: 'Standard',
  turbo: 'Turbo',
  maximum: 'Maximum',
};

// Convert country code to flag emoji
function getFlagEmoji(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return '';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

export function Dashboard() {
  const queryClient = useQueryClient();
  const [deleteTarget, setDeleteTarget] = useState<{id: string, url: string} | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedScanId, setCopiedScanId] = useState<string | null>(null);
  const [rescanTarget, setRescanTarget] = useState<{url: string, mode: string, perfMode: string} | null>(null);
  const [showProxyModal, setShowProxyModal] = useState(false);
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

  // Proxy settings query
  const { data: proxySettings, refetch: refetchProxy } = useQuery<ProxySettings>({
    queryKey: ['proxy-settings'],
    queryFn: () => api.get('/proxy').then(res => res.data),
  });

  // Proxy mutations
  const saveProxyMutation = useMutation({
    mutationFn: async ({ proxyString, protocol, country, countryCode }: { 
      proxyString: string; 
      protocol: string;
      country?: string;
      countryCode?: string;
    }) => {
      let url = `/proxy?proxy_string=${encodeURIComponent(proxyString)}&protocol=${protocol}&enabled=true`;
      if (country) url += `&country=${encodeURIComponent(country)}`;
      if (countryCode) url += `&country_code=${encodeURIComponent(countryCode)}`;
      await api.post(url);
    },
    onSuccess: () => {
      refetchProxy();
      setShowProxyModal(false);
    },
  });

  const disableProxyMutation = useMutation({
    mutationFn: () => api.delete('/proxy'),
    onSuccess: () => {
      refetchProxy();
      setShowProxyModal(false);
    },
  });

  const selectProxyMutation = useMutation({
    mutationFn: (proxyId: string) => api.post(`/proxy/select/${proxyId}`),
    onSuccess: () => {
      refetchProxy();
      setShowProxyModal(false);
    },
  });

  const deleteProxyMutation = useMutation({
    mutationFn: (proxyId: string) => api.delete(`/proxy/saved/${proxyId}`),
    onSuccess: () => {
      refetchProxy();
    },
  });

  // Copy full URL to clipboard
  const copyTarget = async (e: React.MouseEvent, url: string, scanId: string) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(url);
      setCopiedId(scanId);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
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

  const { data, isLoading } = useQuery<DashboardData>({
    queryKey: ['dashboard'],
    queryFn: () => api.get('/dashboard').then(res => res.data),
    refetchInterval: 5000,
  });

  const { data: kbStats } = useQuery<KBStats>({
    queryKey: ['kb-stats'],
    queryFn: () => api.get('/kb/stats').then(res => res.data).catch(() => ({
      error: true,
      error_message: 'Connection to Knowledge Base failed',
      available: false
    })),
  });

  // System info (static hardware data)
  const { data: systemInfo } = useQuery<SystemInfo>({
    queryKey: ['system-info'],
    queryFn: () => api.get('/system/info').then(res => res.data),
  });

  // Version info
  const { data: versionInfo } = useQuery<VersionInfo>({
    queryKey: ['version-info'],
    queryFn: () => api.get('/version').then(res => res.data),
    staleTime: Infinity,
  });

  // Live stats - uses same queryKey as Layout to avoid duplicate requests
  const { data: liveStats } = useQuery<LiveStats>({
    queryKey: ['global-live-stats'],
    queryFn: () => api.get('/system/stats').then(res => res.data),
    refetchInterval: 5000,
  });

  const deleteMutation = useMutation({
    mutationFn: (scanId: string) => api.delete(`/scans/${scanId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      setDeleteTarget(null);
    },
  });

  const cancelMutation = useMutation({
    mutationFn: (scanId: string) => api.post(`/scans/${scanId}/cancel`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });

  const rescanMutation = useMutation({
    mutationFn: async ({ url, mode, performance_mode }: { url: string; mode: string; performance_mode: string }) => {
      return api.post('/scans', { url, mode, performance_mode });
    },
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      setRescanTarget(null);
      window.location.href = `/scan/${response.data.scan_id}`;
    },
  });

  const stats = [
    {
      label: 'Total Scans',
      value: data?.total_scans ?? 0,
      meta: `${data?.scans_today ?? 0} today`,
      icon: Target,
      color: 'var(--color-primary)',
      bg: 'var(--color-primary-muted)',
    },
    {
      label: 'Vulnerabilities',
      value: data?.total_vulnerabilities ?? 0,
      meta: `${data?.critical_vulnerabilities ?? 0} critical`,
      icon: AlertTriangle,
      color: 'var(--color-danger)',
      bg: 'var(--color-danger-muted)',
    },
    {
      label: 'Avg Duration',
      value: data?.avg_scan_duration_seconds 
        ? data.avg_scan_duration_seconds < 1 
          ? `${Math.round(data.avg_scan_duration_seconds * 1000)}ms`
          : `${data.avg_scan_duration_seconds.toFixed(1)}s`
        : '0s',
      meta: `${data?.scans_this_week ?? 0} this week`,
      icon: Clock,
      color: 'var(--color-info)',
      bg: 'var(--color-info-muted)',
    },
    {
      label: 'Top Context',
      value: data?.most_common_context ?? 'N/A',
      meta: data?.most_common_waf ? `WAF: ${data.most_common_waf}` : 'No WAF detected',
      icon: Activity,
      color: 'var(--color-warning)',
      bg: 'var(--color-warning-muted)',
    },
  ];

  return (
    <>
      {/* Proxy Modal */}
      {showProxyModal && (
        <ProxyModal
          proxySettings={proxySettings || null}
          onClose={() => setShowProxyModal(false)}
          onSave={(proxyString, protocol, country, countryCode) => 
            saveProxyMutation.mutate({ proxyString, protocol, country, countryCode })
          }
          onSelect={(proxyId) => selectProxyMutation.mutate(proxyId)}
          onDelete={(proxyId) => deleteProxyMutation.mutate(proxyId)}
          onDisable={() => disableProxyMutation.mutate()}
        />
      )}

      {/* Rescan Modal */}
      {rescanTarget && (
        <RescanModal
          url={rescanTarget.url}
          defaultMode={rescanTarget.mode}
          defaultPerfMode={rescanTarget.perfMode}
          onConfirm={(mode, perfMode) => rescanMutation.mutate({ url: rescanTarget.url, mode, performance_mode: perfMode })}
          onCancel={() => setRescanTarget(null)}
          isScanning={rescanMutation.isPending}
        />
      )}

      {/* Delete Confirmation Modal */}
      {deleteTarget && (
        <DeleteConfirmModal
          scanUrl={deleteTarget.url}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
          isDeleting={deleteMutation.isPending}
        />
      )}

      {/* Header with BRS-XSS branding */}
      <header className="brs-header">
        <div className="flex-1">
          <div className="flex items-center gap-4">
            <div>
              <div className="flex items-center gap-2">
                <h1 className="brs-header-title">Dashboard</h1>
                <a 
                  href="https://github.com/EPTLLC/brs-xss"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs text-[var(--color-primary)] hover:opacity-80 transition-opacity font-mono"
                >
                  BRS-XSS
                  {versionInfo?.version && (
                    <span className="text-[10px] opacity-70">v{versionInfo.version}</span>
                  )}
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
              <p className="brs-header-subtitle">XSS scanning overview</p>
            </div>
            {/* KB Info - compact in header */}
            <div className="hidden md:flex items-center gap-4 ml-6 pl-6 border-l border-[var(--color-border)]">
              <Database className={`w-5 h-5 ${kbStats?.error ? 'text-[var(--color-danger)]' : 'text-[var(--color-primary)]'}`} />
              {kbStats?.error ? (
                <span className="text-sm text-[var(--color-danger)]" title={kbStats?.error_message}>
                  Connection to KB failed
                </span>
              ) : (
                <>
                  <a 
                    href={kbStats?.repo_url || 'https://github.com/EPTLLC/BRS-KB'}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-sm text-[var(--color-primary)] hover:opacity-80 transition-opacity"
                  >
                    BRS-KB {kbStats?.version ? `v${kbStats.version}` : ''}
                  </a>
                  {kbStats?.total_payloads !== null && kbStats?.total_payloads !== undefined && (
                    <span className="text-sm text-[var(--color-text-muted)]">
                      <strong className="text-[var(--color-text)]">{kbStats.total_payloads.toLocaleString()}</strong> payloads
                    </span>
                  )}
                  {kbStats?.contexts !== null && kbStats?.contexts !== undefined && (
                    <span className="text-sm text-[var(--color-text-muted)]">
                      <strong className="text-[var(--color-text)]">{kbStats.contexts}</strong> contexts
                    </span>
                  )}
                  {kbStats?.waf_bypass_count !== null && kbStats?.waf_bypass_count !== undefined && (
                    <span className="text-sm text-[var(--color-text-muted)]">
                      <strong className="text-[var(--color-text)]">{kbStats.waf_bypass_count.toLocaleString()}</strong> WAF bypasses
                    </span>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
        <Link to="/scan/new" className="brs-btn brs-btn-primary">
          <Crosshair className="w-4 h-4" />
          New Scan
        </Link>
      </header>

      {/* Content */}
      <div className="brs-content">
        {/* System Profile - Compact bar */}
        <div className="brs-card mb-4 p-3">
          <div className="flex items-center justify-between flex-wrap gap-3">
            {/* Left: Hardware info */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-[var(--color-text-muted)]" />
                <span className="text-sm font-medium truncate max-w-[200px]" title={systemInfo?.system?.cpu_model}>
                  {systemInfo?.system?.cpu_model?.split(' ').slice(0, 3).join(' ') || 'CPU'}
                </span>
                <span className="text-xs text-[var(--color-text-muted)]">
                  {systemInfo?.system?.cpu_threads || 0}t
                </span>
                <span className={`text-xs font-mono ${
                  (liveStats?.cpu_percent || 0) > 80 ? 'text-[var(--color-danger)]' :
                  (liveStats?.cpu_percent || 0) > 50 ? 'text-[var(--color-warning)]' :
                  'text-[var(--color-success)]'
                }`}>
                  {liveStats?.cpu_percent?.toFixed(0) || 0}%
                </span>
              </div>
              
              <div className="flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-[var(--color-text-muted)]" />
                <span className={`text-xs font-mono ${
                  (liveStats?.ram_percent || 0) > 80 ? 'text-[var(--color-danger)]' :
                  (liveStats?.ram_percent || 0) > 60 ? 'text-[var(--color-warning)]' :
                  'text-[var(--color-success)]'
                }`}>
                  {liveStats?.ram_used_gb?.toFixed(0) || 0}
                </span>
                <span className="text-xs text-[var(--color-text-muted)]">
                  / {systemInfo?.system?.ram_total_gb?.toFixed(0) || 0} GB
                </span>
              </div>
              
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-[var(--color-text-muted)]" />
                <span className="text-xs font-mono">
                  {liveStats?.load_1m?.toFixed(2) || '0.00'}
                </span>
              </div>
            </div>

            {/* Right: Proxy Status first, then Performance Mode */}
            <div className="flex items-center gap-3">
              {/* Proxy Status */}
              <button
                onClick={() => setShowProxyModal(true)}
                className="brs-tooltip brs-tooltip-bottom flex items-center gap-1.5 hover:opacity-80 transition-opacity cursor-pointer"
                data-tooltip={proxySettings?.enabled 
                  ? `Proxy: ${proxySettings.host}:${proxySettings.port}` 
                  : 'Your real IP is exposed! Click to configure proxy'
                }
              >
                {proxySettings?.enabled ? (
                  <>
                    <div className="w-2 h-2 rounded-full bg-[var(--color-success)]" />
                    {proxySettings.country_code && (
                      <span className="text-sm">
                        {getFlagEmoji(proxySettings.country_code)}
                      </span>
                    )}
                    <Globe className="w-3.5 h-3.5 text-[var(--color-success)]" />
                    <span className="text-xs font-mono text-[var(--color-success)]">
                      {proxySettings.host?.split('.').slice(-2).join('.')}
                    </span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-3.5 h-3.5 text-[var(--color-warning)]" />
                    <span className="text-xs text-[var(--color-warning)]">
                      Real IP
                    </span>
                  </>
                )}
              </button>

              {/* Performance Mode */}
              <div className="flex items-center gap-2 pl-3 border-l border-[var(--color-border)]">
                {liveStats?.performance_mode === 'light' && <Leaf className="w-4 h-4 text-[var(--color-success)]" />}
                {liveStats?.performance_mode === 'standard' && <Gauge className="w-4 h-4 text-[var(--color-info)]" />}
                {liveStats?.performance_mode === 'turbo' && <Flame className="w-4 h-4 text-[var(--color-warning)]" />}
                {liveStats?.performance_mode === 'maximum' && <Rocket className="w-4 h-4 text-[var(--color-danger)]" />}
                {(!liveStats?.performance_mode || !['light', 'standard', 'turbo', 'maximum'].includes(liveStats.performance_mode)) && 
                  <Gauge className="w-4 h-4 text-[var(--color-info)]" />
                }
                <span className="text-sm font-medium text-[var(--color-success)]">
                  {perfModeLabels[liveStats?.performance_mode || 'standard'] || 'Standard'}
                </span>
                <Link 
                  to="/settings" 
                  className="brs-tooltip brs-tooltip-bottom flex items-center gap-1 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-primary)] transition-colors"
                  data-tooltip="Configure Performance Mode"
                >
                  <Settings className="w-3.5 h-3.5" />
                  <span className="font-mono">
                    {systemInfo?.modes?.[liveStats?.performance_mode || 'standard']?.threads || 0}t / {systemInfo?.modes?.[liveStats?.performance_mode || 'standard']?.requests_per_second || 0}rps
                  </span>
                </Link>
              </div>

              {/* Active Scans */}
              {(liveStats?.active_scans || 0) > 0 && (
                <div className="flex items-center gap-1.5 pl-3 border-l border-[var(--color-border)]">
                  <div className="w-2 h-2 rounded-full bg-[var(--color-info)] animate-pulse" />
                  <span className="text-xs text-[var(--color-info)]">
                    {liveStats?.active_scans} scanning
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="brs-stats-grid">
          {stats.map((stat, index) => (
            <div key={index} className="brs-card">
              <div className="brs-card-header">
                <span className="brs-card-title">{stat.label}</span>
                <div 
                  className="brs-card-icon" 
                  style={{ background: stat.bg }}
                >
                  <stat.icon className="w-5 h-5" style={{ color: stat.color }} />
                </div>
              </div>
              <div className="brs-card-value" style={{ color: stat.color }}>
                {isLoading ? '—' : stat.value}
              </div>
              <div className="brs-card-meta">{stat.meta}</div>
            </div>
          ))}
        </div>

        {/* Recent Scans */}
        <div className="brs-card">
          <div className="brs-card-header">
            <span className="brs-card-title">Recent Scans</span>
            <Link to="/history" className="brs-btn brs-btn-ghost text-sm">
              View all
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>

          {!data?.recent_scans?.length ? (
            <div className="brs-empty">
              <Shield className="brs-empty-icon" />
              <h3 className="brs-empty-title">No scans yet</h3>
              <p className="brs-empty-desc">
                Start your first XSS vulnerability scan
              </p>
              <Link to="/scan/new" className="brs-btn brs-btn-primary mt-6">
                <Zap className="w-4 h-4" />
                Start Scanning
              </Link>
            </div>
          ) : (
            <table className="brs-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Vulns</th>
                  <th>Duration</th>
                  <th>Date</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_scans.map((scan) => (
                  <tr 
                    key={scan.id} 
                    className="group cursor-pointer hover:bg-[var(--color-surface-hover)]"
                    onClick={() => window.location.href = `/scan/${scan.id}`}
                  >
                    <td>
                      <span 
                        className="font-mono text-sm text-[var(--color-primary)]"
                        title={scan.url}
                      >
                        {truncateUrl(scan.url)}
                      </span>
                    </td>
                    <td>
                      <span className={`brs-badge ${
                        scan.status === 'completed' ? 'brs-badge-success' : 
                        scan.status === 'failed' ? 'brs-badge-danger' :
                        scan.status === 'running' ? 'brs-badge-info' : 'brs-badge-warning'
                      }`}>
                        {scan.status}
                      </span>
                    </td>
                    <td>
                      <span className={`brs-badge ${
                        scan.vulnerability_count > 0 
                          ? scan.critical_count > 0 ? 'brs-badge-critical' : 'brs-badge-high'
                          : 'brs-badge-success'
                      }`}>
                        {scan.vulnerability_count}
                      </span>
                    </td>
                    <td className="text-[var(--color-text-secondary)] font-mono text-sm">
                      {scan.status === 'running' ? (
                        <LiveDuration startedAt={scan.started_at} />
                      ) : (
                        formatDuration(scan.duration_seconds)
                      )}
                    </td>
                    <td className="text-[var(--color-text-secondary)] text-sm">
                      {formatDate(scan.started_at)}
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-start gap-1">
                        <Link 
                          to={`/scan/${scan.id}`}
                          className="brs-tooltip brs-tooltip-top p-2 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all group/btn"
                          data-tooltip="View"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <Eye className="w-4 h-4 text-[var(--color-text-muted)] group-hover/btn:text-[var(--color-primary)] transition-colors" />
                        </Link>
                        <button
                          onClick={(e) => { e.stopPropagation(); copyTarget(e, scan.url, scan.id); }}
                          className="brs-tooltip brs-tooltip-top p-2 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all group/btn"
                          data-tooltip={copiedId === scan.id ? "Copied!" : "Copy URL"}
                        >
                          {copiedId === scan.id ? (
                            <Check className="w-4 h-4 text-green-500" />
                          ) : (
                            <Copy className="w-4 h-4 text-[var(--color-text-muted)] group-hover/btn:text-[var(--color-primary)] transition-colors" />
                          )}
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); copyScanId(e, scan.id); }}
                          className="brs-tooltip brs-tooltip-top p-2 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all group/btn"
                          data-tooltip={copiedScanId === scan.id ? "Copied!" : "Copy ID"}
                        >
                          {copiedScanId === scan.id ? (
                            <Check className="w-4 h-4 text-green-500" />
                          ) : (
                            <Hash className="w-4 h-4 text-[var(--color-text-muted)] group-hover/btn:text-[var(--color-primary)] transition-colors" />
                          )}
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); setRescanTarget({ url: scan.url, mode: scan.mode, perfMode: scan.performance_mode || 'standard' }); }}
                          className="brs-tooltip brs-tooltip-top p-2 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all group/btn"
                          data-tooltip="Rescan"
                        >
                          <RotateCw className="w-4 h-4 text-[var(--color-text-muted)] group-hover/btn:text-[var(--color-primary)] transition-colors" />
                        </button>
                        {telegramStatus?.configured && scan.status === 'completed' && (
                          <button
                            onClick={(e) => { e.stopPropagation(); sendToTelegramMutation.mutate(scan.id); }}
                            disabled={sendingToTg === scan.id}
                            className="brs-tooltip brs-tooltip-top p-2 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all group/btn"
                            data-tooltip="Telegram"
                          >
                            {sendingToTg === scan.id ? (
                              <Loader className="w-4 h-4 text-[var(--color-primary)] animate-spin" />
                            ) : (
                              <Send className="w-4 h-4 text-[var(--color-text-muted)] group-hover/btn:text-[var(--color-primary)] transition-colors" />
                            )}
                          </button>
                        )}
                        {scan.status === 'running' && (
                          <button
                            onClick={(e) => { e.stopPropagation(); cancelMutation.mutate(scan.id); }}
                            className="brs-tooltip brs-tooltip-top p-2 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all group/btn"
                            data-tooltip="Stop"
                            disabled={cancelMutation.isPending}
                          >
                            <StopCircle className="w-4 h-4 text-[var(--color-text-muted)] group-hover/btn:text-orange-400 transition-colors" />
                          </button>
                        )}
                        <button
                          onClick={(e) => { e.stopPropagation(); setDeleteTarget({ id: scan.id, url: scan.url }); }}
                          className="brs-tooltip brs-tooltip-top p-2 rounded hover:bg-[var(--color-surface-hover)] opacity-0 group-hover:opacity-100 transition-all group/btn"
                          data-tooltip="Delete"
                        >
                          <Trash2 className="w-4 h-4 text-[var(--color-text-muted)] group-hover/btn:text-red-400 transition-colors" />
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
