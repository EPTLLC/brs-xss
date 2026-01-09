/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Fri 26 Dec 2025 UTC
 * Status: Created
 * Telegram: https://t.me/EasyProTech
 */

import { useState } from 'react';
import {
  Globe,
  Server,
  Shield,
  Lock,
  Code,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  CheckCircle,
  XCircle,
  MinusCircle,
  Database,
  Eye,
  Filter,
  Zap,
  MapPin,
  Clock
} from 'lucide-react';

interface TargetProfile {
  url: string;
  domain: string;
  timestamp: string;
  recon_duration_seconds: number;
  
  dns?: {
    domain: string;
    nameservers?: string[];
    txt_records?: string[];
    has_dnssec?: boolean;
  };
  
  ip?: {
    ipv4?: string;
    ipv6?: string;
    ptr_record?: string;
    is_cloudflare?: boolean;
    is_cdn?: boolean;
    cdn_provider?: string;
    hosting_provider?: string;
    geo?: {
      country?: string;
      region?: string;
      city?: string;
      isp?: string;
      organization?: string;
    };
  };
  
  ssl?: {
    enabled?: boolean;
    protocol?: string;
    cipher_suite?: string;
    subject?: string;
    issuer?: string;
    valid_until?: string;
    days_until_expiry?: number;
    is_expired?: boolean;
    grade?: string;
    san_domains?: string[];
  };
  
  server?: {
    server_name?: string;
    server_version?: string;
    powered_by?: string;
    compression_gzip?: boolean;
    compression_brotli?: boolean;
    response_time_total_ms?: number;
  };
  
  security_headers?: {
    csp_present?: boolean;
    csp_analysis?: string;
    csp_has_unsafe_inline?: boolean;
    x_frame_options?: string;
    x_content_type_options?: string;
    hsts_enabled?: boolean;
    hsts_max_age?: number;
    cors_enabled?: boolean;
    cors_is_permissive?: boolean;
    missing_headers?: string[];
    score?: number;
    grade?: string;
  };
  
  technology?: {
    backend_language?: string;
    backend_framework?: string;
    cms?: string;
    frontend_framework?: string;
    cdn?: string;
    analytics?: string[];
    javascript_libraries?: Array<{name: string; version: string}>;
  };
  
  waf?: {
    detected?: boolean;
    name?: string;
    vendor?: string;
    waf_type?: string;
    confidence?: number;
    evidence?: string[];
    known_bypasses?: string[];
  };
  
  filter_profile?: {
    filter_type?: string;
    filter_strength?: string;
    is_bypassable?: boolean;
    bypass_techniques?: string[];
    best_vector?: string;
    best_encoding?: string;
  };
  
  cookies?: Array<{
    name: string;
    secure?: boolean;
    http_only?: boolean;
    same_site?: string;
    purpose?: string;
  }>;
  
  risk?: {
    overall_score?: number;
    risk_level?: string;
    waf_bypass_chance?: number;
    filter_bypass_chance?: number;
    csp_bypass_chance?: number;
    recommended_strategy?: string;
    primary_vector?: string;
    recommended_encoding?: string;
    evasion_techniques?: string[];
    estimated_payloads?: number;
  };
}

interface Props {
  profile: TargetProfile;
  isLoading?: boolean;
}

function StatusIcon({ status }: { status: 'good' | 'warning' | 'bad' | 'neutral' }) {
  switch (status) {
    case 'good':
      return <CheckCircle className="w-4 h-4 text-green-400" />;
    case 'warning':
      return <MinusCircle className="w-4 h-4 text-yellow-400" />;
    case 'bad':
      return <XCircle className="w-4 h-4 text-red-400" />;
    default:
      return <MinusCircle className="w-4 h-4 text-gray-400" />;
  }
}

function Section({ 
  title, 
  icon: Icon, 
  children, 
  defaultOpen = true,
  badge
}: { 
  title: string; 
  icon: React.ElementType; 
  children: React.ReactNode; 
  defaultOpen?: boolean;
  badge?: React.ReactNode;
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  
  return (
    <div className="border border-[var(--color-border)] rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-3 bg-[var(--color-surface-hover)] hover:bg-[var(--color-surface-active)] transition-colors"
      >
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4 text-[var(--color-primary)]" />
          <span className="font-medium text-sm">{title}</span>
          {badge}
        </div>
        {isOpen ? (
          <ChevronDown className="w-4 h-4 text-[var(--color-text-muted)]" />
        ) : (
          <ChevronRight className="w-4 h-4 text-[var(--color-text-muted)]" />
        )}
      </button>
      {isOpen && (
        <div className="p-3 space-y-2 text-sm">
          {children}
        </div>
      )}
    </div>
  );
}

function InfoRow({ label, value, status }: { label: string; value?: string | React.ReactNode; status?: 'good' | 'warning' | 'bad' | 'neutral' }) {
  if (!value && value !== 0) return null;
  
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-[var(--color-text-muted)] flex-shrink-0">{label}:</span>
      <div className="flex items-center gap-2 text-right">
        {status && <StatusIcon status={status} />}
        <span className="font-mono break-all">{value}</span>
      </div>
    </div>
  );
}

export function TargetIntelligence({ profile, isLoading }: Props) {
  if (isLoading) {
    return (
      <div className="brs-card animate-pulse">
        <div className="h-4 bg-[var(--color-surface-hover)] rounded w-1/3 mb-4" />
        <div className="space-y-3">
          <div className="h-12 bg-[var(--color-surface-hover)] rounded" />
          <div className="h-12 bg-[var(--color-surface-hover)] rounded" />
          <div className="h-12 bg-[var(--color-surface-hover)] rounded" />
        </div>
      </div>
    );
  }

  const getRiskColor = (level?: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'text-red-500';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const getGradeColor = (grade?: string) => {
    if (!grade) return 'bg-gray-500';
    if (grade.startsWith('A')) return 'bg-green-500';
    if (grade === 'B') return 'bg-yellow-500';
    if (grade === 'C') return 'bg-orange-500';
    return 'bg-red-500';
  };

  return (
    <div className="brs-card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="flex items-center gap-2 font-medium">
          <Eye className="w-5 h-5 text-[var(--color-primary)]" />
          Target Intelligence
        </h3>
        <div className="flex items-center gap-2 text-xs text-[var(--color-text-muted)]">
          <Clock className="w-3 h-3" />
          <span>{profile.recon_duration_seconds?.toFixed(2)}s</span>
        </div>
      </div>

      <div className="space-y-3">
        {/* Network & Location */}
        <Section title="Network Information" icon={Globe}>
          <InfoRow label="Domain" value={profile.domain} />
          <InfoRow label="IPv4" value={profile.ip?.ipv4} />
          {profile.ip?.ipv6 && <InfoRow label="IPv6" value={profile.ip.ipv6} />}
          <InfoRow label="Reverse DNS" value={profile.ip?.ptr_record} />
          <InfoRow 
            label="CDN" 
            value={profile.ip?.is_cdn ? (profile.ip.cdn_provider || 'Detected') : 'None'}
            status={profile.ip?.is_cdn ? 'neutral' : 'neutral'}
          />
          <InfoRow label="Hosting" value={profile.ip?.hosting_provider} />
          {profile.ip?.geo && (
            <>
              <InfoRow 
                label="Location" 
                value={
                  <span className="flex items-center gap-1">
                    <MapPin className="w-3 h-3" />
                    {[profile.ip.geo.city, profile.ip.geo.region, profile.ip.geo.country]
                      .filter(Boolean).join(', ') || 'Unknown'}
                  </span>
                } 
              />
              <InfoRow label="ISP" value={profile.ip.geo.isp} />
            </>
          )}
          {profile.dns?.nameservers && profile.dns.nameservers.length > 0 && (
            <InfoRow label="Nameservers" value={profile.dns.nameservers.slice(0, 2).join(', ')} />
          )}
        </Section>

        {/* SSL/TLS */}
        {profile.ssl?.enabled && (
          <Section 
            title="SSL/TLS Certificate" 
            icon={Lock}
            badge={
              profile.ssl.grade && (
                <span className={`text-xs px-2 py-0.5 rounded font-bold text-white ${getGradeColor(profile.ssl.grade)}`}>
                  {profile.ssl.grade}
                </span>
              )
            }
          >
            <InfoRow label="Protocol" value={profile.ssl.protocol} />
            <InfoRow label="Cipher" value={profile.ssl.cipher_suite} />
            <InfoRow label="Issuer" value={profile.ssl.issuer} />
            <InfoRow 
              label="Expires" 
              value={profile.ssl.days_until_expiry !== undefined ? `${profile.ssl.days_until_expiry} days` : undefined}
              status={
                profile.ssl.is_expired ? 'bad' : 
                (profile.ssl.days_until_expiry || 0) < 30 ? 'warning' : 'good'
              }
            />
            {profile.ssl.san_domains && profile.ssl.san_domains.length > 0 && (
              <InfoRow label="SAN Domains" value={profile.ssl.san_domains.length.toString()} />
            )}
          </Section>
        )}

        {/* Server & Technology */}
        <Section title="Technology Stack" icon={Code}>
          {profile.server?.server_name && (
            <InfoRow 
              label="Server" 
              value={`${profile.server.server_name}${profile.server.server_version ? ' ' + profile.server.server_version : ''}`} 
            />
          )}
          {profile.server?.powered_by && (
            <InfoRow label="Powered By" value={profile.server.powered_by} />
          )}
          {profile.technology?.backend_language && (
            <InfoRow 
              label="Backend" 
              value={`${profile.technology.backend_language}${profile.technology.backend_framework ? ' / ' + profile.technology.backend_framework : ''}`} 
            />
          )}
          {profile.technology?.cms && (
            <InfoRow label="CMS" value={profile.technology.cms} />
          )}
          {profile.technology?.frontend_framework && (
            <InfoRow label="Frontend" value={profile.technology.frontend_framework} />
          )}
          {profile.technology?.cdn && (
            <InfoRow label="CDN" value={profile.technology.cdn} />
          )}
          {profile.technology?.analytics && profile.technology.analytics.length > 0 && (
            <InfoRow label="Analytics" value={profile.technology.analytics.join(', ')} />
          )}
          {profile.server?.compression_gzip || profile.server?.compression_brotli ? (
            <InfoRow 
              label="Compression" 
              value={[
                profile.server.compression_gzip && 'gzip',
                profile.server.compression_brotli && 'brotli'
              ].filter(Boolean).join(', ')} 
            />
          ) : null}
        </Section>

        {/* Security Headers */}
        <Section 
          title="Security Headers" 
          icon={Shield}
          badge={
            profile.security_headers?.grade && (
              <span className={`text-xs px-2 py-0.5 rounded font-bold text-white ${getGradeColor(profile.security_headers.grade)}`}>
                {profile.security_headers.grade}
              </span>
            )
          }
        >
          <InfoRow 
            label="CSP" 
            value={profile.security_headers?.csp_present ? 'Present' : 'Missing'}
            status={profile.security_headers?.csp_present ? 
              (profile.security_headers.csp_has_unsafe_inline ? 'warning' : 'good') : 'bad'}
          />
          {profile.security_headers?.csp_analysis && (
            <div className="text-xs text-[var(--color-text-muted)] bg-[var(--color-surface-hover)] p-2 rounded">
              {profile.security_headers.csp_analysis}
            </div>
          )}
          <InfoRow 
            label="HSTS" 
            value={profile.security_headers?.hsts_enabled ? 
              `Enabled (${Math.floor((profile.security_headers.hsts_max_age || 0) / 86400)} days)` : 'Disabled'}
            status={profile.security_headers?.hsts_enabled ? 'good' : 'warning'}
          />
          <InfoRow 
            label="X-Frame-Options" 
            value={profile.security_headers?.x_frame_options || 'Not set'}
            status={profile.security_headers?.x_frame_options ? 'good' : 'warning'}
          />
          <InfoRow 
            label="CORS" 
            value={profile.security_headers?.cors_enabled ? 
              (profile.security_headers.cors_is_permissive ? 'Permissive (*)' : 'Restricted') : 'Disabled'}
            status={profile.security_headers?.cors_is_permissive ? 'warning' : 'good'}
          />
          {profile.security_headers?.missing_headers && profile.security_headers.missing_headers.length > 0 && (
            <div className="mt-2">
              <span className="text-[var(--color-text-muted)]">Missing headers:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {profile.security_headers.missing_headers.slice(0, 5).map((h, i) => (
                  <span key={i} className="text-xs px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded">
                    {h}
                  </span>
                ))}
              </div>
            </div>
          )}
        </Section>

        {/* WAF Detection */}
        {profile.waf && (
          <Section 
            title="WAF Detection" 
            icon={Server}
            badge={
              profile.waf.detected && (
                <span className="text-xs px-2 py-0.5 rounded bg-purple-500/20 text-purple-400">
                  {profile.waf.name}
                </span>
              )
            }
          >
            <InfoRow 
              label="WAF Detected" 
              value={profile.waf.detected ? 'Yes' : 'No'}
              status={profile.waf.detected ? 'warning' : 'good'}
            />
            {profile.waf.detected && (
              <>
                <InfoRow label="Type" value={profile.waf.waf_type} />
                <InfoRow label="Vendor" value={profile.waf.vendor} />
                <InfoRow 
                  label="Confidence" 
                  value={`${((profile.waf.confidence || 0) * 100).toFixed(0)}%`} 
                />
                {profile.waf.known_bypasses && profile.waf.known_bypasses.length > 0 && (
                  <div className="mt-2">
                    <span className="text-[var(--color-text-muted)]">Known bypasses:</span>
                    <ul className="list-disc list-inside text-xs text-[var(--color-primary)] mt-1">
                      {profile.waf.known_bypasses.slice(0, 3).map((b, i) => (
                        <li key={i}>{b}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            )}
          </Section>
        )}

        {/* Filter Analysis */}
        {profile.filter_profile && (
          <Section title="Filter Analysis" icon={Filter}>
            <InfoRow label="Filter Type" value={profile.filter_profile.filter_type} />
            <InfoRow 
              label="Strength" 
              value={profile.filter_profile.filter_strength}
              status={
                profile.filter_profile.filter_strength === 'strong' ? 'bad' :
                profile.filter_profile.filter_strength === 'medium' ? 'warning' : 'good'
              }
            />
            <InfoRow 
              label="Bypassable" 
              value={profile.filter_profile.is_bypassable ? 'Yes' : 'No'}
              status={profile.filter_profile.is_bypassable ? 'good' : 'bad'}
            />
            {profile.filter_profile.best_vector && (
              <InfoRow label="Best Vector" value={
                <code className="text-[var(--color-warning)]">{profile.filter_profile.best_vector}</code>
              } />
            )}
            {profile.filter_profile.best_encoding && (
              <InfoRow label="Best Encoding" value={profile.filter_profile.best_encoding} />
            )}
            {profile.filter_profile.bypass_techniques && profile.filter_profile.bypass_techniques.length > 0 && (
              <div className="mt-2">
                <span className="text-[var(--color-text-muted)]">Bypass techniques:</span>
                <ul className="list-disc list-inside text-xs text-[var(--color-success)] mt-1">
                  {profile.filter_profile.bypass_techniques.slice(0, 4).map((t, i) => (
                    <li key={i}>{t}</li>
                  ))}
                </ul>
              </div>
            )}
          </Section>
        )}

        {/* Risk Assessment */}
        {profile.risk && (
          <Section 
            title="Risk Assessment" 
            icon={AlertTriangle}
            badge={
              <span className={`text-xs px-2 py-0.5 rounded font-bold ${getRiskColor(profile.risk.risk_level)}`}>
                {profile.risk.overall_score?.toFixed(1)}/10
              </span>
            }
          >
            <InfoRow 
              label="Risk Level" 
              value={
                <span className={`font-bold uppercase ${getRiskColor(profile.risk.risk_level)}`}>
                  {profile.risk.risk_level}
                </span>
              }
            />
            <InfoRow 
              label="WAF Bypass Chance" 
              value={`${((profile.risk.waf_bypass_chance || 0) * 100).toFixed(0)}%`}
            />
            <InfoRow 
              label="Filter Bypass Chance" 
              value={`${((profile.risk.filter_bypass_chance || 0) * 100).toFixed(0)}%`}
            />
            <InfoRow 
              label="CSP Bypass Chance" 
              value={`${((profile.risk.csp_bypass_chance || 0) * 100).toFixed(0)}%`}
            />
            <div className="mt-3 p-2 bg-[var(--color-surface-hover)] rounded">
              <div className="flex items-center gap-2 mb-2">
                <Zap className="w-4 h-4 text-[var(--color-warning)]" />
                <span className="text-sm font-medium">Recommended Strategy</span>
              </div>
              <p className="text-xs text-[var(--color-text-muted)]">
                {profile.risk.recommended_strategy}
              </p>
              {profile.risk.primary_vector && (
                <p className="text-xs mt-1">
                  <span className="text-[var(--color-text-muted)]">Primary vector: </span>
                  <code className="text-[var(--color-warning)]">{profile.risk.primary_vector}</code>
                </p>
              )}
              {profile.risk.estimated_payloads && (
                <p className="text-xs mt-1">
                  <span className="text-[var(--color-text-muted)]">Optimized payloads: </span>
                  <span className="text-[var(--color-primary)] font-bold">{profile.risk.estimated_payloads}</span>
                </p>
              )}
            </div>
          </Section>
        )}

        {/* Cookies */}
        {profile.cookies && profile.cookies.length > 0 && (
          <Section title={`Cookies (${profile.cookies.length})`} icon={Database} defaultOpen={false}>
            <div className="space-y-2">
              {profile.cookies.slice(0, 10).map((cookie, i) => (
                <div key={i} className="flex items-center justify-between text-xs">
                  <span className="font-mono">{cookie.name}</span>
                  <div className="flex items-center gap-1">
                    {cookie.secure && (
                      <span className="px-1 py-0.5 bg-green-500/20 text-green-400 rounded text-[10px]">Secure</span>
                    )}
                    {cookie.http_only && (
                      <span className="px-1 py-0.5 bg-blue-500/20 text-blue-400 rounded text-[10px]">HttpOnly</span>
                    )}
                    {cookie.purpose && (
                      <span className="px-1 py-0.5 bg-gray-500/20 text-gray-400 rounded text-[10px]">{cookie.purpose}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </Section>
        )}
      </div>
    </div>
  );
}

