/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Wed 25 Dec 2024 UTC
 * Status: Created - Modern Floating UI
 * Telegram: https://t.me/EasyProTech
 */

import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  Zap, 
  Eye, 
  Bell,
  Palette,
  Save,
  Check,
  Cpu,
  RefreshCw,
  Gauge,
  ExternalLink,
  Globe,
  Wifi,
  WifiOff,
  Loader,
  MapPin,
  Trash2,
  Plus,
  AlertTriangle
} from 'lucide-react';
import { api } from '../api/client';

interface SettingsState {
  defaultMode: string;
  maxCrawlDepth: number;
  requestTimeout: number;
  maxConcurrentScans: number;
  blindXssUrl: string;
  enableBlindXss: boolean;
  enableTelegram: boolean;
  telegramBotToken: string;
  telegramChatId: string;
  theme: string;
  resultsPerPage: number;
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

interface TelegramStatus {
  configured: boolean;
  enabled: boolean;
  channel_id?: number;
  bot_username?: string;
  error?: string;
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

interface PerformanceMode {
  name: string;
  label: string;
  description: string;
  threads: number;
  max_concurrent: number;
  requests_per_second: number;
  request_delay_ms: number;
  recommended: boolean;
}

interface SystemInfo {
  system: {
    cpu_model: string;
    cpu_cores: number;
    cpu_threads: number;
    ram_total_gb: number;
    ram_available_gb: number;
    os_name: string;
    os_version: string;
    detected_at: string;
  };
  modes: Record<string, PerformanceMode>;
  recommended: string;
  saved_mode: string;
}

export function Settings() {
  const queryClient = useQueryClient();
  const [saved, setSaved] = useState(false);
  const [settings, setSettings] = useState<SettingsState>({
    defaultMode: 'standard',
    maxCrawlDepth: 2,
    requestTimeout: 30,
    maxConcurrentScans: 3,
    blindXssUrl: '',
    enableBlindXss: false,
    enableTelegram: false,
    telegramBotToken: '',
    telegramChatId: '',
    theme: 'dark',
    resultsPerPage: 20,
  });

  // Proxy state
  const [proxyString, setProxyString] = useState('');
  const [proxyProtocol, setProxyProtocol] = useState('socks5');
  const [proxyTestResult, setProxyTestResult] = useState<ProxyTestResult | null>(null);
  const [isTestingProxy, setIsTestingProxy] = useState(false);

  // Telegram state
  const [telegramStatus, setTelegramStatus] = useState<TelegramStatus | null>(null);
  const [isTestingTelegram, setIsTestingTelegram] = useState(false);
  const [telegramError, setTelegramError] = useState<string | null>(null);

  // Proxy settings query
  const { data: proxySettings } = useQuery<ProxySettings>({
    queryKey: ['proxy-settings'],
    queryFn: () => api.get('/proxy').then(res => res.data),
  });

  // Update proxy string input when settings load
  useEffect(() => {
    if (proxySettings?.proxy_string) {
      setProxyString(proxySettings.proxy_string);
      setProxyProtocol(proxySettings.protocol || 'socks5');
    }
  }, [proxySettings]);

  // System info query
  const { data: systemInfo, isFetching: isRefetching } = useQuery<SystemInfo>({
    queryKey: ['system-info'],
    queryFn: () => api.get('/system/info').then(res => res.data),
  });

  // Set proxy mutation
  const setProxyMutation = useMutation({
    mutationFn: (params: { proxy_string: string; protocol: string; enabled: boolean }) => 
      api.post(`/proxy?proxy_string=${encodeURIComponent(params.proxy_string)}&protocol=${params.protocol}&enabled=${params.enabled}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-settings'] });
    },
  });

  // Disable proxy mutation
  const disableProxyMutation = useMutation({
    mutationFn: () => api.delete('/proxy'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-settings'] });
      setProxyTestResult(null);
    },
  });

  // Select proxy mutation
  const selectProxyMutation = useMutation({
    mutationFn: (proxyId: string) => api.post(`/proxy/select/${proxyId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-settings'] });
    },
  });

  // Delete saved proxy mutation
  const deleteProxyMutation = useMutation({
    mutationFn: (proxyId: string) => api.delete(`/proxy/saved/${proxyId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-settings'] });
    },
  });

  // Test proxy
  const handleTestProxy = async () => {
    setIsTestingProxy(true);
    setProxyTestResult(null);
    try {
      const params = proxyString 
        ? `?proxy_string=${encodeURIComponent(proxyString)}&protocol=${proxyProtocol}`
        : '';
      const response = await api.post(`/proxy/test${params}`);
      setProxyTestResult(response.data);
    } catch (error) {
      setProxyTestResult({ success: false, error: 'Connection failed' });
    } finally {
      setIsTestingProxy(false);
    }
  };

  // Save proxy
  const handleSaveProxy = () => {
    if (proxyString.trim()) {
      setProxyMutation.mutate({ 
        proxy_string: proxyString, 
        protocol: proxyProtocol, 
        enabled: true 
      });
    }
  };

  // Test Telegram configuration
  const handleTestTelegram = async () => {
    if (!settings.telegramBotToken || !settings.telegramChatId) {
      setTelegramError('Bot token and channel are required');
      return;
    }
    
    setIsTestingTelegram(true);
    setTelegramError(null);
    setTelegramStatus(null);
    
    try {
      const response = await api.post('/telegram/test', null, {
        params: {
          bot_token: settings.telegramBotToken,
          channel_input: settings.telegramChatId
        }
      });
      
      if (response.data.success) {
        setTelegramStatus({
          configured: true,
          enabled: true,
          channel_id: response.data.channel_id,
          bot_username: response.data.bot_username
        });
        setTelegramError(null);
      } else {
        setTelegramError(response.data.error || 'Configuration failed');
        setTelegramStatus(null);
      }
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { detail?: string } } };
      setTelegramError(axiosError.response?.data?.detail || 'Connection failed');
      setTelegramStatus(null);
    } finally {
      setIsTestingTelegram(false);
    }
  };

  // Detect system mutation
  const detectMutation = useMutation({
    mutationFn: () => api.post('/system/detect'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system-info'] });
    },
  });

  // Save performance mode mutation
  const setModeMutation = useMutation({
    mutationFn: (mode: string) => api.post(`/system/mode?mode=${mode}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system-info'] });
    },
  });

  const handleSave = () => {
    // TODO: Save to backend
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const currentMode = systemInfo?.saved_mode || 'standard';

  return (
    <>
      {/* Header */}
      <header className="brs-header">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="brs-header-title">Settings</h1>
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
          <p className="brs-header-subtitle">Configure scanner behavior and preferences</p>
        </div>
        <button 
          className="brs-btn brs-btn-primary"
          onClick={handleSave}
        >
          {saved ? (
            <>
              <Check className="w-4 h-4" />
              Saved!
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              Save Changes
            </>
          )}
        </button>
      </header>

      {/* Content */}
      <div className="brs-content">
        <div className="max-w-3xl mx-auto space-y-6">
          {/* Performance Mode - TOP PRIORITY */}
          <div className="brs-card">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[var(--color-primary-muted)] flex items-center justify-center">
                  <Gauge className="w-5 h-5 text-[var(--color-primary)]" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold">Performance Mode</h2>
                  <p className="text-xs text-[var(--color-text-muted)]">
                    Scanner speed based on your hardware
                  </p>
                </div>
              </div>
              <button
                onClick={() => detectMutation.mutate()}
                disabled={detectMutation.isPending || isRefetching}
                className="brs-btn brs-btn-ghost text-sm brs-tooltip"
                data-tooltip="Re-detect hardware"
              >
                <RefreshCw className={`w-4 h-4 ${(detectMutation.isPending || isRefetching) ? 'animate-spin' : ''}`} />
                Detect System
              </button>
            </div>

            {/* System Info Summary */}
            {systemInfo?.system && (
              <div className="mb-6 p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
                <div className="flex items-center gap-3 mb-3">
                  <Cpu className="w-5 h-5 text-[var(--color-text-muted)]" />
                  <span className="text-sm font-medium">Detected Hardware</span>
                </div>
                <div className="grid grid-cols-3 gap-4 text-sm">
                  <div>
                    <div className="text-[var(--color-text-muted)]">CPU</div>
                    <div className="font-mono text-xs">{systemInfo.system.cpu_model.split(' ').slice(0, 4).join(' ')}</div>
                  </div>
                  <div>
                    <div className="text-[var(--color-text-muted)]">Threads</div>
                    <div className="font-mono text-[var(--color-primary)]">{systemInfo.system.cpu_threads}</div>
                  </div>
                  <div>
                    <div className="text-[var(--color-text-muted)]">RAM Available</div>
                    <div className="font-mono">
                      <span className="text-[var(--color-success)]">{systemInfo.system.ram_available_gb.toFixed(0)}</span>
                      <span className="text-[var(--color-text-muted)]"> / {systemInfo.system.ram_total_gb.toFixed(0)} GB</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Mode Selection */}
            <div className="space-y-3">
              {systemInfo?.modes && Object.entries(systemInfo.modes).map(([key, mode]) => (
                <label
                  key={key}
                  className={`flex items-center justify-between p-4 rounded-lg border cursor-pointer transition-all ${
                    currentMode === key
                      ? 'border-[var(--color-primary)] bg-[var(--color-primary-muted)]'
                      : 'border-[var(--color-border)] bg-[var(--color-surface-hover)] hover:border-[var(--color-text-muted)]'
                  }`}
                  onClick={() => setModeMutation.mutate(key)}
                >
                  <div className="flex items-center gap-4">
                    <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${
                      currentMode === key 
                        ? 'border-[var(--color-primary)]' 
                        : 'border-[var(--color-text-muted)]'
                    }`}>
                      {currentMode === key && (
                        <div className="w-2.5 h-2.5 rounded-full bg-[var(--color-primary)]" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{mode.label}</span>
                        {mode.recommended && (
                          <span className="text-xs bg-[var(--color-success)]/20 text-[var(--color-success)] px-2 py-0.5 rounded">
                            RECOMMENDED
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-[var(--color-text-muted)] mt-0.5">
                        {mode.description}
                      </div>
                    </div>
                  </div>
                  <div className="text-right text-sm">
                    <div className="font-mono text-[var(--color-primary)]">
                      {mode.threads} threads
                    </div>
                    <div className="text-xs text-[var(--color-text-muted)]">
                      ~{mode.requests_per_second} req/s
                    </div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Proxy Settings */}
          <div className="brs-card">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[var(--color-info-muted)] flex items-center justify-center">
                  <Globe className="w-5 h-5 text-[var(--color-info)]" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold">Proxy Settings</h2>
                  <p className="text-xs text-[var(--color-text-muted)]">
                    {proxySettings?.saved_proxies?.length || 0}/10 proxies saved
                  </p>
                </div>
              </div>
              {proxySettings?.enabled ? (
                <div className="flex items-center gap-2">
                  {proxySettings.country_code && (
                    <span className="text-lg">{getFlagEmoji(proxySettings.country_code)}</span>
                  )}
                  <Wifi className="w-4 h-4 text-[var(--color-success)]" />
                  <span className="text-sm text-[var(--color-success)]">Active</span>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-[var(--color-warning)]" />
                  <span className="text-sm text-[var(--color-warning)]">Real IP</span>
                </div>
              )}
            </div>

            {/* Saved Proxies List */}
            {proxySettings?.saved_proxies && proxySettings.saved_proxies.length > 0 && (
              <div className="mb-6 space-y-2">
                <div className="text-xs uppercase tracking-wider text-[var(--color-text-muted)] mb-3">
                  Saved Proxies
                </div>
                {proxySettings.saved_proxies.map((proxy) => (
                  <div 
                    key={proxy.id}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      proxySettings?.active_proxy_id === proxy.id && proxySettings?.enabled
                        ? 'border-[var(--color-success)] bg-[var(--color-success)]/10'
                        : 'border-[var(--color-border)] hover:border-[var(--color-primary)]/50 bg-[var(--color-surface-hover)]'
                    }`}
                    onClick={() => selectProxyMutation.mutate(proxy.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {proxy.country_code ? (
                          <span className="text-xl">{getFlagEmoji(proxy.country_code)}</span>
                        ) : (
                          <Globe className="w-5 h-5 text-[var(--color-text-muted)]" />
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
                            {proxy.country && ` - ${proxy.country}`}
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteProxyMutation.mutate(proxy.id);
                        }}
                        className="p-2 rounded hover:bg-red-500/20 text-[var(--color-text-muted)] hover:text-red-400 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
                
                {/* Disable Proxy Option */}
                {proxySettings?.enabled && (
                  <button
                    onClick={() => disableProxyMutation.mutate()}
                    className="w-full p-3 rounded-lg border border-[var(--color-border)] hover:border-[var(--color-warning)]/50 bg-[var(--color-surface-hover)] transition-all text-left"
                    disabled={disableProxyMutation.isPending}
                  >
                    <div className="flex items-center gap-2 text-[var(--color-warning)]">
                      <AlertTriangle className="w-4 h-4" />
                      <span className="text-sm">Disable Proxy (use Real IP)</span>
                    </div>
                  </button>
                )}
              </div>
            )}

            {/* Add New Proxy */}
            <div className="space-y-4">
              <div className="text-xs uppercase tracking-wider text-[var(--color-text-muted)] flex items-center gap-2">
                <Plus className="w-3 h-3" />
                Add New Proxy
              </div>
              
              <div>
                <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                  Proxy String
                </label>
                <input
                  type="text"
                  className="brs-input font-mono"
                  placeholder="host:port:username:password"
                  value={proxyString}
                  onChange={(e) => setProxyString(e.target.value)}
                />
                <p className="text-xs text-[var(--color-text-muted)] mt-1">
                  Format: host:port:user:pass
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                    Protocol
                  </label>
                  <select
                    className="brs-select"
                    value={proxyProtocol}
                    onChange={(e) => setProxyProtocol(e.target.value)}
                  >
                    <option value="socks5">SOCKS5</option>
                    <option value="socks4">SOCKS4</option>
                    <option value="http">HTTP</option>
                    <option value="https">HTTPS</option>
                  </select>
                </div>
                <div className="flex items-end gap-2">
                  <button
                    onClick={handleTestProxy}
                    disabled={isTestingProxy || !proxyString.trim()}
                    className="brs-btn brs-btn-secondary flex-1"
                  >
                    {isTestingProxy ? (
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
                  <button
                    onClick={handleSaveProxy}
                    disabled={setProxyMutation.isPending || !proxyString.trim() || (proxySettings?.saved_proxies?.length || 0) >= 10}
                    className="brs-btn brs-btn-primary flex-1"
                  >
                    {setProxyMutation.isPending ? (
                      <>
                        <Loader className="w-4 h-4 animate-spin" />
                        Saving...
                      </>
                    ) : (
                      <>
                        <Save className="w-4 h-4" />
                        Save & Activate
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Test Result */}
              {proxyTestResult && (
                <div className={`p-4 rounded-lg border ${
                  proxyTestResult.success 
                    ? 'bg-[var(--color-success)]/10 border-[var(--color-success)]/30' 
                    : 'bg-red-500/10 border-red-500/30'
                }`}>
                  {proxyTestResult.success ? (
                    <div className="flex items-center gap-4">
                      <Check className="w-5 h-5 text-[var(--color-success)]" />
                      <div>
                        <div className="text-sm font-medium text-[var(--color-success)]">
                          Connection Successful
                        </div>
                        <div className="flex items-center gap-4 mt-1 text-xs">
                          <span className="font-mono">IP: {proxyTestResult.ip}</span>
                          <span className="flex items-center gap-1">
                            {proxyTestResult.country_code && (
                              <span className="text-base">{getFlagEmoji(proxyTestResult.country_code)}</span>
                            )}
                            <MapPin className="w-3 h-3" />
                            {proxyTestResult.country}
                          </span>
                          <span>{proxyTestResult.latency_ms?.toFixed(0)}ms</span>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center gap-3">
                      <WifiOff className="w-5 h-5 text-red-400" />
                      <div>
                        <div className="text-sm font-medium text-red-400">
                          Connection Failed
                        </div>
                        <div className="text-xs text-[var(--color-text-muted)]">
                          {proxyTestResult.error}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Scanner Defaults */}
          <div className="brs-card">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-lg bg-[var(--color-primary-muted)] flex items-center justify-center">
                <Zap className="w-5 h-5 text-[var(--color-primary)]" />
              </div>
              <h2 className="text-lg font-semibold">Scanner Defaults</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                  Default Scan Mode
                </label>
                <select
                  className="brs-select"
                  value={settings.defaultMode}
                  onChange={(e) => setSettings({ ...settings, defaultMode: e.target.value })}
                >
                  <option value="quick">Quick</option>
                  <option value="standard">Standard</option>
                  <option value="deep">Deep</option>
                  <option value="stealth">Stealth</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                    Max Crawl Depth
                  </label>
                  <input
                    type="number"
                    className="brs-input"
                    min="1"
                    max="10"
                    value={settings.maxCrawlDepth}
                    onChange={(e) => setSettings({ ...settings, maxCrawlDepth: parseInt(e.target.value) })}
                  />
                </div>
                <div>
                  <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                    Request Timeout (seconds)
                  </label>
                  <input
                    type="number"
                    className="brs-input"
                    min="5"
                    max="120"
                    value={settings.requestTimeout}
                    onChange={(e) => setSettings({ ...settings, requestTimeout: parseInt(e.target.value) })}
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                  Max Concurrent Scans
                </label>
                <input
                  type="number"
                  className="brs-input"
                  min="1"
                  max="10"
                  value={settings.maxConcurrentScans}
                  onChange={(e) => setSettings({ ...settings, maxConcurrentScans: parseInt(e.target.value) })}
                />
              </div>
            </div>
          </div>

          {/* Blind XSS */}
          <div className="brs-card">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-lg bg-[var(--color-info-muted)] flex items-center justify-center">
                <Eye className="w-5 h-5 text-[var(--color-info)]" />
              </div>
              <h2 className="text-lg font-semibold">Blind XSS</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                  Callback Server URL
                </label>
                <input
                  type="url"
                  className="brs-input"
                  placeholder="https://your-blind-xss-server.com"
                  value={settings.blindXssUrl}
                  onChange={(e) => setSettings({ ...settings, blindXssUrl: e.target.value })}
                />
              </div>

              <label className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)] cursor-pointer">
                <span className="text-sm">Enable Blind XSS callbacks</span>
                <div
                  className={`brs-toggle ${settings.enableBlindXss ? 'active' : ''}`}
                  onClick={() => setSettings({ ...settings, enableBlindXss: !settings.enableBlindXss })}
                />
              </label>
            </div>
          </div>

          {/* Notifications */}
          <div className="brs-card">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-lg bg-[var(--color-warning-muted)] flex items-center justify-center">
                <Bell className="w-5 h-5 text-[var(--color-warning)]" />
              </div>
              <div>
              <h2 className="text-lg font-semibold">Telegram Notifications</h2>
                <p className="text-xs text-[var(--color-text-muted)]">
                  Receive scan reports in your Telegram channel
                </p>
              </div>
            </div>

            <div className="space-y-4">
              <label className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)] cursor-pointer">
                <span className="text-sm">Enable Telegram notifications</span>
                <div
                  className={`brs-toggle ${settings.enableTelegram ? 'active' : ''}`}
                  onClick={() => setSettings({ ...settings, enableTelegram: !settings.enableTelegram })}
                />
              </label>

              {settings.enableTelegram && (
                <>
                  <div>
                    <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                      Bot Token
                    </label>
                    <input
                      type="password"
                      className="brs-input font-mono"
                      placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
                      value={settings.telegramBotToken}
                      onChange={(e) => {
                        setSettings({ ...settings, telegramBotToken: e.target.value });
                        setTelegramStatus(null);
                        setTelegramError(null);
                      }}
                    />
                    <p className="text-xs text-[var(--color-text-muted)] mt-1">
                      Get token from <a href="https://t.me/BotFather" target="_blank" rel="noopener noreferrer" className="text-[var(--color-primary)] hover:underline">@BotFather</a>
                    </p>
                  </div>
                  <div>
                    <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                      Channel
                    </label>
                    <input
                      type="text"
                      className="brs-input font-mono"
                      placeholder="@channel or https://t.me/+abc123 or -100123456789"
                      value={settings.telegramChatId}
                      onChange={(e) => {
                        setSettings({ ...settings, telegramChatId: e.target.value });
                        setTelegramStatus(null);
                        setTelegramError(null);
                      }}
                    />
                    <p className="text-xs text-[var(--color-text-muted)] mt-1">
                      Enter channel @username, invite link, or numeric ID. Bot must be admin.
                    </p>
                  </div>

                  {/* Check button */}
                  <button
                    onClick={handleTestTelegram}
                    disabled={isTestingTelegram || !settings.telegramBotToken || !settings.telegramChatId}
                    className={`w-full py-3 px-4 rounded-lg font-medium transition-all flex items-center justify-center gap-2 ${
                      telegramStatus?.configured
                        ? 'bg-[var(--color-success)] text-white'
                        : 'bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white'
                    } disabled:opacity-50 disabled:cursor-not-allowed`}
                  >
                    {isTestingTelegram ? (
                      <>
                        <Loader className="w-4 h-4 animate-spin" />
                        Checking...
                      </>
                    ) : telegramStatus?.configured ? (
                      <>
                        <Check className="w-4 h-4" />
                        Connected to @{telegramStatus.bot_username}
                      </>
                    ) : (
                      <>
                        <Bell className="w-4 h-4" />
                        Check & Send Welcome
                      </>
                    )}
                  </button>

                  {/* Status/Error display */}
                  {telegramError && (
                    <div className="p-3 rounded-lg bg-[var(--color-danger-muted)] border border-[var(--color-danger)] flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-[var(--color-danger)] flex-shrink-0 mt-0.5" />
                      <span className="text-sm text-[var(--color-danger)]">{telegramError}</span>
                    </div>
                  )}

                  {telegramStatus?.configured && (
                    <div className="p-3 rounded-lg bg-[var(--color-success-muted)] border border-[var(--color-success)]">
                      <p className="text-sm text-[var(--color-success)]">
                        Telegram configured. Welcome message with ETHICS and LEGAL sent to channel.
                      </p>
                    </div>
                  )}
                  
                  {/* Quick help */}
                  <div className="p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
                    <div className="text-xs text-[var(--color-text-muted)] space-y-1">
                      <p className="font-medium text-[var(--color-text-secondary)]">Supported formats:</p>
                      <p className="font-mono">@MyChannel</p>
                      <p className="font-mono">https://t.me/+g5wb4aKSgQs1NzJi</p>
                      <p className="font-mono">-1003325111853</p>
                      <p className="mt-2 text-[var(--color-warning)]">
                        For private channels with invite links, use numeric ID.
                        Forward any message to @userinfobot to get it.
                      </p>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* UI Preferences */}
          <div className="brs-card">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-lg bg-[var(--color-success-muted)] flex items-center justify-center">
                <Palette className="w-5 h-5 text-[var(--color-success)]" />
              </div>
              <h2 className="text-lg font-semibold">UI Preferences</h2>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                  Theme
                </label>
                <select
                  className="brs-select"
                  value={settings.theme}
                  onChange={(e) => setSettings({ ...settings, theme: e.target.value })}
                >
                  <option value="dark">Dark (Cyber)</option>
                  <option value="light">Light</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                  Results Per Page
                </label>
                <input
                  type="number"
                  className="brs-input"
                  min="10"
                  max="100"
                  value={settings.resultsPerPage}
                  onChange={(e) => setSettings({ ...settings, resultsPerPage: parseInt(e.target.value) })}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
