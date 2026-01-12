/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Thu 26 Dec 2025 UTC
 * Status: Updated - Performance mode per scan
 * Telegram: https://t.me/EasyProTech
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { 
  Zap, 
  Target, 
  Eye, 
  Ghost,
  Globe,
  ChevronDown,
  ChevronUp,
  Shield,
  Crosshair,
  Loader2,
  Database,
  Info,
  Cpu,
  Gauge,
  Leaf,
  Flame,
  Rocket,
  AlertTriangle,
  Settings
} from 'lucide-react';
import { api } from '../api/client';
import { SavedPayloads } from '../components/SavedPayloads';
import { DomainHistory } from '../components/DomainHistory';
import { WorkflowModal } from '../components/WorkflowModal';
import { PageHeader } from '../components/PageHeader';

type ScanMode = 'quick' | 'standard' | 'deep' | 'stealth';
type PerfMode = 'light' | 'standard' | 'turbo' | 'maximum';

interface ScanConfig {
  target_url: string;
  mode: ScanMode;
  performance_mode: PerfMode;
  follow_redirects: boolean;
  include_subdomains: boolean;
  waf_bypass: boolean;
  dom_analysis: boolean;
  blind_xss: boolean;
  crawl_depth: number;
  max_payloads: number | null; // null = use mode default, number = limit
  custom_payloads: string[]; // Custom XSS payloads
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

interface ProxySettings {
  enabled: boolean;
  host: string;
  port: number;
  protocol: string;
  country?: string;
  country_code?: string;
}

function formatCountryCode(countryCode?: string): string {
  if (!countryCode) return '';
  const cc = countryCode.trim().toUpperCase();
  return cc.length === 2 ? cc : '';
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
  };
  modes: Record<string, PerformanceMode>;
  recommended: string;
  saved_mode: string;
}

const scanModes = [
  {
    id: 'quick' as ScanMode,
    icon: Zap,
    title: 'Quick',
    desc: '~100 payloads',
  },
  {
    id: 'standard' as ScanMode,
    icon: Target,
    title: 'Standard',
    desc: '~500 payloads',
  },
  {
    id: 'deep' as ScanMode,
    icon: Eye,
    title: 'Deep',
    desc: 'All payloads',
  },
  {
    id: 'stealth' as ScanMode,
    icon: Ghost,
    title: 'Stealth',
    desc: 'WAF evasion',
  },
];

const perfModeIcons: Record<string, typeof Leaf> = {
  light: Leaf,
  standard: Gauge,
  turbo: Flame,
  maximum: Rocket,
};

export function NewScan() {
  const navigate = useNavigate();
  const [showAdvanced, setShowAdvanced] = useState(false);
  
  // Get system info for recommended mode
  const { data: systemInfo } = useQuery<SystemInfo>({
    queryKey: ['system-info'],
    queryFn: () => api.get('/system/info').then(res => res.data),
  });

  // Track if we've initialized from systemInfo
  const [initializedFromSystem, setInitializedFromSystem] = useState(false);
  
  const [config, setConfig] = useState<ScanConfig>({
    target_url: '',
    mode: 'standard',
    performance_mode: 'standard',
    follow_redirects: true,
    include_subdomains: false,
    waf_bypass: true,
    dom_analysis: true,
    blind_xss: false,
    crawl_depth: 2,
    max_payloads: null, // null = use mode default
    custom_payloads: [],
  });
  
  const [customPayloadsText, setCustomPayloadsText] = useState('');
  const [selectedSavedPayloads, setSelectedSavedPayloads] = useState<string[]>([]);
  const [saveNewPayloads, setSaveNewPayloads] = useState(true); // Auto-save new payloads
  
  // Workflow modal
  const [showWorkflowModal, setShowWorkflowModal] = useState(false);
  const [selectedWorkflow, setSelectedWorkflow] = useState<any>(null);
  
  // Domain history lookup
  const [domainLookupUrl, setDomainLookupUrl] = useState('');
  const [domainHistory, setDomainHistory] = useState<{
    found: boolean;
    domain: string;
    profile?: any;
    recent_scans?: any[];
  } | null>(null);
  const [domainLoading, setDomainLoading] = useState(false);

  // Update performance_mode when systemInfo loads (only once)
  if (systemInfo?.saved_mode && !initializedFromSystem) {
    setInitializedFromSystem(true);
    setConfig(prev => ({ ...prev, performance_mode: systemInfo.saved_mode as PerfMode }));
  }

  // Debounced domain lookup when URL changes
  const lookupDomain = useCallback(async (url: string) => {
    if (!url || url.length < 3) {
      setDomainHistory(null);
      return;
    }
    
    setDomainLoading(true);
    try {
      const response = await api.get('/api/domains/lookup', { params: { url } });
      setDomainHistory(response.data);
    } catch {
      setDomainHistory(null);
    } finally {
      setDomainLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      if (config.target_url !== domainLookupUrl) {
        setDomainLookupUrl(config.target_url);
        lookupDomain(config.target_url);
      }
    }, 500); // 500ms debounce

    return () => clearTimeout(timer);
  }, [config.target_url, domainLookupUrl, lookupDomain]);

  // Handler to apply workflow settings
  const handleApplyWorkflow = (workflow: any) => {
    setSelectedWorkflow(workflow);
    
    // Apply workflow settings to scan config
    const settings = workflow.settings || {};
    const newConfig = { ...config };
    
    // Map workflow mode to scan mode
    const firstScanStep = workflow.steps.find((s: any) => s.type === 'scan');
    if (firstScanStep?.mode) {
      newConfig.mode = firstScanStep.mode as ScanMode;
    }
    
    // Apply settings
    if (settings.waf_bypass !== undefined) {
      newConfig.waf_bypass = settings.waf_bypass;
    }
    if (settings.dom_analysis !== undefined) {
      newConfig.dom_analysis = settings.dom_analysis;
    }
    
    // Check for blind XSS in steps
    const hasBlind = workflow.steps.some((s: any) => s.blind);
    if (hasBlind) {
      newConfig.blind_xss = true;
    }
    
    // Get crawl depth from workflow
    const crawlStep = workflow.steps.find((s: any) => s.type === 'crawl');
    if (crawlStep?.depth) {
      newConfig.crawl_depth = crawlStep.depth;
    }
    
    setConfig(newConfig);
  };

  // Handler to use successful payloads from domain history
  const handleUseHistoricalPayloads = (payloads: string[]) => {
    const existing = new Set(selectedSavedPayloads);
    const newPayloads = payloads.filter(p => !existing.has(p));
    setSelectedSavedPayloads([...selectedSavedPayloads, ...newPayloads]);
    // Also add to custom payloads text if not already there
    const currentText = customPayloadsText.split('\n').map(p => p.trim()).filter(Boolean);
    const toAdd = newPayloads.filter(p => !currentText.includes(p));
    if (toAdd.length > 0) {
      setCustomPayloadsText(prev => {
        const lines = prev.split('\n').filter(l => l.trim());
        return [...lines, ...toAdd].join('\n');
      });
    }
  };

  // Get KB stats
  const { data: kbStats } = useQuery<KBStats>({
    queryKey: ['kb-stats'],
    queryFn: () => api.get('/kb/stats').then(res => res.data).catch(() => ({
      error: true,
      error_message: 'Connection to Knowledge Base failed',
      available: false
    })),
  });

  // Get proxy settings
  const { data: proxySettings } = useQuery<ProxySettings>({
    queryKey: ['proxy-settings'],
    queryFn: () => api.get('/proxy').then(res => res.data),
  });

  const startScan = useMutation({
    mutationFn: (data: ScanConfig) => api.post('/scans', data),
    onSuccess: async (response) => {
      // Auto-save new custom payloads if enabled
      if (saveNewPayloads && customPayloadsText.trim()) {
        const newPayloads = customPayloadsText
          .split('\n')
          .map(p => p.trim())
          .filter(p => p.length > 0);
        
        for (const payload of newPayloads) {
          try {
            await api.post('/payloads', { payload });
          } catch {
            // Ignore if already exists
          }
        }
      }
      navigate(`/scan/${response.data.scan_id}`);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (config.target_url) {
      let url = config.target_url.trim();
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
      }
      // Parse custom payloads from textarea
      const textPayloads = customPayloadsText
        .split('\n')
        .map(p => p.trim())
        .filter(p => p.length > 0);
      // Combine with selected saved payloads (deduplicate)
      const allPayloads = [...new Set([...selectedSavedPayloads, ...textPayloads])];
      startScan.mutate({ ...config, target_url: url, custom_payloads: allPayloads });
    }
  };

  return (
    <>
      {/* Header */}
      <PageHeader 
        title="New Scan" 
        subtitle="Enter target URL and configure scan"
      />

      {/* Content */}
      <div className="brs-content">
        <form onSubmit={handleSubmit} className="max-w-3xl mx-auto">
          
          {/* KB Info Banner */}
          <div className="brs-card mb-4 p-3 flex items-center gap-4 text-sm">
            <Database className={`w-5 h-5 ${kbStats?.error ? 'text-[var(--color-danger)]' : 'text-[var(--color-primary)]'}`} />
            <div className="flex-1">
              {kbStats?.error ? (
                <span className="text-[var(--color-danger)]" title={kbStats?.error_message}>
                  Connection to Knowledge Base failed
                </span>
              ) : (
                <>
                  <span className="text-[var(--color-text-muted)]">Knowledge Base:</span>
                  <a 
                    href={kbStats?.repo_url || 'https://github.com/EPTLLC/BRS-KB'}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-[var(--color-primary)] ml-2 hover:opacity-80 transition-opacity"
                  >
                    BRS-KB {kbStats?.version ? `v${kbStats.version}` : ''}
                  </a>
                </>
              )}
            </div>
            {!kbStats?.error && (
              <div className="flex items-center gap-4 text-[var(--color-text-muted)]">
                {kbStats?.total_payloads !== null && kbStats?.total_payloads !== undefined && (
                  <span><strong className="text-[var(--color-text)]">{kbStats.total_payloads.toLocaleString()}</strong> payloads</span>
                )}
                {kbStats?.contexts !== null && kbStats?.contexts !== undefined && (
                  <span><strong className="text-[var(--color-text)]">{kbStats.contexts}</strong> contexts</span>
                )}
                {kbStats?.waf_bypass_count !== null && kbStats?.waf_bypass_count !== undefined && (
                  <span><strong className="text-[var(--color-text)]">{kbStats.waf_bypass_count.toLocaleString()}</strong> WAF bypasses</span>
                )}
              </div>
            )}
              
              {/* Proxy Status */}
              <div className={`brs-tooltip brs-tooltip-bottom flex items-center gap-1.5 pl-3 border-l border-[var(--color-border)] ${
                !proxySettings?.enabled ? 'cursor-help' : ''
              }`}
              data-tooltip={proxySettings?.enabled 
                ? `Via ${proxySettings.country || 'Proxy'}` 
                : 'Your real IP is exposed!'
              }>
                {proxySettings?.enabled ? (
                  <>
                    <div className="w-2 h-2 rounded-full bg-[var(--color-success)]" />
                    {proxySettings.country_code && (
                      <span className="text-xs font-mono text-[var(--color-text-muted)] px-1 py-0.5 border border-[var(--color-border)] rounded">
                        {formatCountryCode(proxySettings.country_code)}
                      </span>
                    )}
                    <Globe className="w-3.5 h-3.5 text-[var(--color-success)]" />
                    <span className="text-xs font-mono text-[var(--color-success)]">
                      Proxy
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
              </div>
            </div>

          {/* Workflow Selection */}
          <div className="brs-card mb-4 p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Settings className="w-5 h-5 text-[var(--color-text-muted)]" />
                {selectedWorkflow ? (
                  <div>
                    <span className="text-sm text-[var(--color-text-muted)]">Workflow:</span>
                    <span className="ml-2 text-sm font-medium text-[var(--color-primary)]">
                      {selectedWorkflow.name}
                    </span>
                    {selectedWorkflow.is_preset && (
                      <span className="ml-2 text-[10px] px-1.5 py-0.5 bg-[var(--color-primary)]/20 text-[var(--color-primary)] rounded">
                        PRESET
                      </span>
                    )}
                  </div>
                ) : (
                  <span className="text-sm text-[var(--color-text-muted)]">
                    No workflow selected (manual configuration)
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {selectedWorkflow && (
                  <button
                    type="button"
                    onClick={() => setSelectedWorkflow(null)}
                    className="text-xs text-[var(--color-text-muted)] hover:text-[var(--color-danger)] transition-colors"
                  >
                    Clear
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setShowWorkflowModal(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[var(--color-surface-hover)] hover:bg-[var(--color-surface-active)] border border-[var(--color-border)] rounded-lg transition-colors"
                >
                  <Zap className="w-3.5 h-3.5" />
                  {selectedWorkflow ? 'Change' : 'Select Workflow'}
                </button>
              </div>
            </div>
            {selectedWorkflow && (
              <div className="mt-3 pt-3 border-t border-[var(--color-border)]">
                <div className="flex flex-wrap gap-2">
                  {selectedWorkflow.steps.slice(0, 4).map((step: any, i: number) => (
                    <span key={i} className="text-[10px] px-2 py-1 bg-[var(--color-surface-active)] rounded text-[var(--color-text-muted)]">
                      {step.type === 'crawl' && `Crawl ${step.target || 'all'}`}
                      {step.type === 'scan' && `Scan ${step.context || 'all'} [${step.mode || 'std'}]`}
                      {step.type === 'report' && `Report ${step.format || 'PDF'}`}
                    </span>
                  ))}
                  {selectedWorkflow.steps.length > 4 && (
                    <span className="text-[10px] text-[var(--color-text-muted)]">
                      +{selectedWorkflow.steps.length - 4} more
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Target URL - Main Input */}
          <div className="brs-card mb-4">
            <label className="text-xs uppercase tracking-wider text-[var(--color-text-muted)] mb-3 block">
              Target URL
            </label>
            <div className="relative">
              <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-[var(--color-text-muted)]" />
              <input
                type="text"
                className="w-full bg-[var(--color-surface-hover)] border border-[var(--color-border)] rounded-lg pl-12 pr-4 py-4 text-lg font-mono focus:outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)] transition-all placeholder:text-[var(--color-text-muted)]"
                placeholder="example.com or https://example.com/path"
                value={config.target_url}
                onChange={(e) => setConfig({ ...config, target_url: e.target.value })}
                autoFocus
              />
            </div>
            <p className="text-xs text-[var(--color-text-muted)] mt-2 flex items-center gap-1">
              <Info className="w-3 h-3" />
              Enter domain, IP address, or full URL. HTTPS will be added automatically.
            </p>
          </div>

          {/* Domain History - Shows when URL has previous scans */}
          {(domainLoading || (domainHistory?.found && domainHistory.profile)) && (
            <div className="mb-4">
              <DomainHistory
                profile={domainHistory?.profile || null}
                recentScans={domainHistory?.recent_scans || []}
                onUsePayloads={handleUseHistoricalPayloads}
                onViewScan={(scanId) => navigate(`/scan/${scanId}`)}
                loading={domainLoading}
              />
            </div>
          )}

          {/* Scan Mode + Performance Mode - Side by Side */}
          <div className="grid grid-cols-2 gap-4 mb-4">
            {/* Scan Mode */}
            <div className="brs-card">
              <label className="text-xs uppercase tracking-wider text-[var(--color-text-muted)] mb-3 block">
                Scan Mode
              </label>
              <div className="grid grid-cols-2 gap-2">
                {scanModes.map((mode) => (
                  <button
                    key={mode.id}
                    type="button"
                    className={`p-3 rounded-lg border-2 transition-all text-center ${
                      config.mode === mode.id 
                        ? 'border-[var(--color-primary)] bg-[var(--color-primary)]/10' 
                        : 'border-[var(--color-border)] bg-[var(--color-surface-hover)] hover:border-[var(--color-primary)]/50'
                    }`}
                    onClick={() => setConfig({ ...config, mode: mode.id })}
                  >
                    <mode.icon className={`w-5 h-5 mx-auto mb-1 ${
                      config.mode === mode.id ? 'text-[var(--color-primary)]' : 'text-[var(--color-text-muted)]'
                    }`} />
                    <div className={`text-sm font-medium ${config.mode === mode.id ? 'text-[var(--color-primary)]' : ''}`}>
                      {mode.title}
                    </div>
                    <div className="text-[10px] text-[var(--color-text-muted)]">
                      {mode.desc}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Performance Mode */}
            <div className="brs-card">
              <div className="flex items-center justify-between mb-3">
                <label className="text-xs uppercase tracking-wider text-[var(--color-text-muted)]">
                  Performance
                </label>
                {systemInfo?.system && (
                  <div className="flex items-center gap-1 text-[10px] text-[var(--color-text-muted)]">
                    <Cpu className="w-3 h-3" />
                    <span>{systemInfo.system.cpu_threads}t</span>
                    <span>/</span>
                    <span>{systemInfo.system.ram_available_gb.toFixed(0)}GB</span>
                  </div>
                )}
              </div>
              <div className="grid grid-cols-2 gap-2">
                {systemInfo?.modes && Object.entries(systemInfo.modes).map(([key, mode]) => {
                  const Icon = perfModeIcons[key] || Gauge;
                  return (
                    <button
                      key={key}
                      type="button"
                      className={`p-3 rounded-lg border-2 transition-all text-center ${
                        config.performance_mode === key
                          ? 'border-[var(--color-success)] bg-[var(--color-success)]/10'
                          : 'border-[var(--color-border)] bg-[var(--color-surface-hover)] hover:border-[var(--color-success)]/50'
                      }`}
                      onClick={() => setConfig({ ...config, performance_mode: key as PerfMode })}
                    >
                      <Icon className={`w-5 h-5 mx-auto mb-1 ${
                        config.performance_mode === key ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'
                      }`} />
                      <div className={`text-sm font-medium ${config.performance_mode === key ? 'text-[var(--color-success)]' : ''}`}>
                        {mode.label}
                        {mode.recommended && (
                          <span className="ml-1 text-[8px] bg-[var(--color-success)]/20 text-[var(--color-success)] px-1 rounded align-top">REC</span>
                        )}
                      </div>
                      <div className="text-[10px] text-[var(--color-text-muted)] font-mono">
                        {mode.threads}t / {mode.requests_per_second}rps
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Advanced Options - Collapsed by default */}
          <div className="brs-card mb-6">
            <button
              type="button"
              className="flex items-center justify-between w-full text-left"
              onClick={() => setShowAdvanced(!showAdvanced)}
            >
              <span className="text-xs uppercase tracking-wider text-[var(--color-text-muted)] flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Advanced Options
              </span>
              {showAdvanced ? (
                <ChevronUp className="w-4 h-4 text-[var(--color-text-muted)]" />
              ) : (
                <ChevronDown className="w-4 h-4 text-[var(--color-text-muted)]" />
              )}
            </button>

            {showAdvanced && (
              <div className="mt-4 pt-4 border-t border-[var(--color-border)] space-y-4">
                {/* Toggle Options */}
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { key: 'follow_redirects', label: 'Follow Redirects', desc: 'Follow HTTP redirects' },
                    { key: 'include_subdomains', label: 'Include Subdomains', desc: 'Scan subdomains too' },
                    { key: 'waf_bypass', label: 'WAF Bypass', desc: 'Use evasion techniques' },
                    { key: 'dom_analysis', label: 'DOM Analysis', desc: 'Analyze JavaScript DOM' },
                    { key: 'blind_xss', label: 'Blind XSS', desc: 'Out-of-band detection' },
                  ].map((option) => (
                    <label 
                      key={option.key}
                      className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)] cursor-pointer hover:bg-[var(--color-surface-active)] transition-colors"
                    >
                      <div>
                        <span className="text-sm font-medium">{option.label}</span>
                        <span className="text-xs text-[var(--color-text-muted)] block">{option.desc}</span>
                      </div>
                      <div
                        className={`w-10 h-6 rounded-full transition-colors relative ${
                          config[option.key as keyof ScanConfig] 
                            ? 'bg-[var(--color-primary)]' 
                            : 'bg-[var(--color-surface-active)]'
                        }`}
                        onClick={(e) => {
                          e.preventDefault();
                          setConfig({ 
                            ...config, 
                            [option.key]: !config[option.key as keyof ScanConfig] 
                          });
                        }}
                      >
                        <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${
                          config[option.key as keyof ScanConfig] ? 'translate-x-5' : 'translate-x-1'
                        }`} />
                      </div>
                    </label>
                  ))}
                </div>

                {/* Crawl Depth */}
                <div>
                  <label className="block text-sm text-[var(--color-text-muted)] mb-2">
                    Crawl Depth: <span className="text-[var(--color-primary)] font-mono">{config.crawl_depth}</span>
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="5"
                    value={config.crawl_depth}
                    onChange={(e) => setConfig({ ...config, crawl_depth: parseInt(e.target.value) })}
                    className="w-full h-2 bg-[var(--color-surface-active)] rounded-lg appearance-none cursor-pointer accent-[var(--color-primary)]"
                  />
                  <div className="flex justify-between text-xs text-[var(--color-text-muted)] mt-1">
                    <span>Single page</span>
                    <span>Deep crawl</span>
                  </div>
                </div>

                {/* Payload Limit */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-sm text-[var(--color-text-muted)]">
                      Payload Limit: <span className="text-[var(--color-warning)] font-mono">
                        {config.max_payloads === null ? 'Auto (mode default)' : config.max_payloads}
                      </span>
                    </label>
                    <button
                      type="button"
                      onClick={() => setConfig({ ...config, max_payloads: config.max_payloads === null ? 50 : null })}
                      className={`text-xs px-2 py-1 rounded ${
                        config.max_payloads === null 
                          ? 'bg-[var(--color-surface-active)] text-[var(--color-text-muted)]' 
                          : 'bg-[var(--color-warning)]/20 text-[var(--color-warning)]'
                      }`}
                    >
                      {config.max_payloads === null ? 'Set Custom' : 'Use Auto'}
                    </button>
                  </div>
                  {config.max_payloads !== null && (
                    <>
                      <input
                        type="range"
                        min="1"
                        max={kbStats?.total_payloads || 5000}
                        value={config.max_payloads}
                        onChange={(e) => setConfig({ ...config, max_payloads: parseInt(e.target.value) })}
                        className="w-full h-2 bg-[var(--color-surface-active)] rounded-lg appearance-none cursor-pointer accent-[var(--color-warning)]"
                      />
                      <div className="flex justify-between text-xs text-[var(--color-text-muted)] mt-1">
                        <span>1 payload</span>
                        <span>{kbStats?.total_payloads?.toLocaleString() || '...'} (all)</span>
                      </div>
                      <div className="mt-2 flex gap-2">
                        {[1, 5, 10, 50, 100, 500].map(n => (
                          <button
                            key={n}
                            type="button"
                            onClick={() => setConfig({ ...config, max_payloads: n })}
                            className={`text-xs px-2 py-1 rounded transition-colors ${
                              config.max_payloads === n
                                ? 'bg-[var(--color-warning)] text-black'
                                : 'bg-[var(--color-surface-active)] text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]'
                            }`}
                          >
                            {n}
                          </button>
                        ))}
                      </div>
                    </>
                  )}
                </div>

                {/* Saved Payloads */}
                <SavedPayloads
                  selectedPayloads={selectedSavedPayloads}
                  onSelect={setSelectedSavedPayloads}
                />

                {/* Custom Payloads */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-sm text-[var(--color-text-muted)]">
                      Custom Payloads
                      {customPayloadsText.split('\n').filter(p => p.trim()).length > 0 && (
                        <span className="ml-2 text-[var(--color-primary)] font-mono">
                          ({customPayloadsText.split('\n').filter(p => p.trim()).length})
                        </span>
                      )}
                    </label>
                    <span className="text-xs text-[var(--color-text-muted)]">One per line</span>
                  </div>
                  <textarea
                    value={customPayloadsText}
                    onChange={(e) => setCustomPayloadsText(e.target.value)}
                    placeholder={"<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>"}
                    className="w-full h-24 bg-[var(--color-surface-hover)] border border-[var(--color-border)] rounded-lg p-3 font-mono text-sm focus:outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)] transition-all placeholder:text-[var(--color-text-muted)]/50 resize-none"
                  />
                  <div className="flex items-center justify-between mt-2">
                    <p className="text-xs text-[var(--color-text-muted)]">
                      Add your own XSS payloads to include in the scan.
                    </p>
                    <label className="flex items-center gap-2 text-xs text-[var(--color-text-muted)] cursor-pointer">
                      <input
                        type="checkbox"
                        checked={saveNewPayloads}
                        onChange={(e) => setSaveNewPayloads(e.target.checked)}
                        className="w-3.5 h-3.5 rounded border-[var(--color-border)] text-[var(--color-primary)] focus:ring-[var(--color-primary)]"
                      />
                      Save for later
                    </label>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="flex justify-between items-center">
            <button
              type="button"
              className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
              onClick={() => navigate('/')}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="brs-btn brs-btn-primary px-8 py-3 text-base"
              disabled={!config.target_url.trim() || startScan.isPending}
            >
              {startScan.isPending ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Starting...
                </>
              ) : (
                <>
                  <Crosshair className="w-5 h-5" />
                  Start Scan
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Workflow Modal */}
      <WorkflowModal
        isOpen={showWorkflowModal}
        onClose={() => setShowWorkflowModal(false)}
        onSelect={handleApplyWorkflow}
      />
    </>
  );
}
