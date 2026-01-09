/**
 * Project: BRS-XSS Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 */

export type ScanMode = 'quick' | 'standard' | 'deep' | 'stealth'
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface VulnerabilityInfo {
  id: string
  url: string
  parameter: string
  context_type: string
  severity: SeverityLevel
  confidence: number
  payload: string
  evidence?: string
  waf_detected?: string
  bypass_used?: string
  remediation?: string
  cwe_id?: string
  found_at: string
}

export interface WAFInfo {
  name: string
  type: string
  confidence: number
  bypass_available: boolean
}

export interface ScanProgress {
  scan_id: string
  status: ScanStatus
  progress_percent: number
  urls_scanned: number
  urls_total: number
  vulnerabilities_found: number
  current_url?: string
  current_phase: string
  elapsed_seconds: number
  estimated_remaining_seconds?: number
}

export interface ScanResult {
  id: string
  url: string
  mode: ScanMode
  status: ScanStatus
  started_at: string
  completed_at?: string
  vulnerabilities: VulnerabilityInfo[]
  waf_detected?: WAFInfo
  urls_scanned: number
  parameters_tested: number
  payloads_sent: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  duration_seconds: number
  notes?: string
  error_message?: string
}

export interface ScanSummary {
  id: string
  url: string
  mode: ScanMode
  status: ScanStatus
  started_at: string
  completed_at?: string
  vulnerability_count: number
  critical_count: number
  high_count: number
}

export interface DashboardStats {
  total_scans: number
  scans_today: number
  scans_this_week: number
  total_vulnerabilities: number
  critical_vulnerabilities: number
  high_vulnerabilities: number
  most_common_context?: string
  most_common_waf?: string
  avg_scan_duration_seconds: number
  recent_scans: ScanSummary[]
}

export interface ScanRequest {
  url: string
  mode: ScanMode
  follow_redirects: boolean
  max_depth: number
  include_subdomains: boolean
  custom_headers?: Record<string, string>
  custom_cookies?: Record<string, string>
  excluded_paths?: string[]
  blind_xss_enabled: boolean
  waf_bypass_enabled: boolean
  dom_analysis_enabled: boolean
}

export interface SettingsModel {
  default_mode: ScanMode
  default_max_depth: number
  default_timeout_seconds: number
  max_concurrent_scans: number
  blind_xss_server_url?: string
  blind_xss_webhook_enabled: boolean
  telegram_enabled: boolean
  telegram_bot_token?: string
  telegram_chat_id?: string
  theme: string
  language: string
  results_per_page: number
}

export interface WSMessage {
  type: 'progress' | 'vulnerability' | 'complete' | 'pong'
  scan_id?: string
  data?: unknown
}

