/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Sun 12 Jan 2026 UTC
 * Status: Created - Unified page header with GitHub link and version
 * Telegram: https://t.me/EasyProTech
 */

import { useQuery } from '@tanstack/react-query';
import { ExternalLink } from 'lucide-react';
import { api } from '../api/client';

interface VersionInfo {
  version: string;
  name: string;
  github: string;
}

interface PageHeaderProps {
  title: string;
  subtitle: string;
  badge?: {
    text: string;
    className?: string;
  };
  children?: React.ReactNode;
}

export function PageHeader({ title, subtitle, badge, children }: PageHeaderProps) {
  // Get version info
  const { data: versionInfo } = useQuery<VersionInfo>({
    queryKey: ['version-info'],
    queryFn: () => api.get('/version').then(res => res.data),
    staleTime: Infinity,
  });

  return (
    <header className="brs-header">
      <div className="flex-1">
        <div className="flex items-center gap-4">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="brs-header-title">{title}</h1>
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
              {badge && (
                <span className={`text-xs px-2 py-0.5 rounded ${badge.className || 'bg-cyan-500/20 text-cyan-400'}`}>
                  {badge.text}
                </span>
              )}
            </div>
            <p className="brs-header-subtitle">{subtitle}</p>
          </div>
          {children}
        </div>
      </div>
    </header>
  );
}
