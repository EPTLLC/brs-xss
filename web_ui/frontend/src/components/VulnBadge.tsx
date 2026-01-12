/**
 * Project: BRS-XSS Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Fri 10 Jan 2026 UTC
 * Status: Created
 * Telegram: https://t.me/EasyProTech
 *
 * Vulnerability count badge with hover tooltip showing severity breakdown.
 */

import { useState } from 'react';
import { AlertTriangle, ShieldAlert, AlertCircle, Info } from 'lucide-react';

interface VulnBadgeProps {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  className?: string;
}

export function VulnBadge({ 
  critical = 0, 
  high = 0, 
  medium = 0, 
  low = 0,
  className = ''
}: VulnBadgeProps) {
  const [show, setShow] = useState(false);
  const total = critical + high + medium + low;

  // Determine color based on highest severity
  const getColor = () => {
    if (critical > 0) return 'text-red-400';
    if (high > 0) return 'text-orange-400';
    if (medium > 0) return 'text-yellow-400';
    if (low > 0) return 'text-blue-400';
    return 'text-zinc-500';
  };

  // No tooltip if no vulnerabilities
  if (total === 0) {
    return <span className={`font-mono ${getColor()} ${className}`}>0</span>;
  }

  return (
    <div 
      className="relative inline-block"
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
    >
      <span className={`font-mono cursor-default ${getColor()} ${className}`}>
        {total}
      </span>
      
      {show && (
        <div className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2">
          <div className="px-3 py-2 bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg shadow-xl min-w-[130px]">
            <div className="text-xs space-y-1.5">
              {critical > 0 && (
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-1.5">
                    <ShieldAlert className="w-3 h-3 text-red-400" />
                    <span className="text-red-400">Critical</span>
                  </div>
                  <span className="font-mono text-red-400 font-medium">{critical}</span>
                </div>
              )}
              {high > 0 && (
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-1.5">
                    <AlertTriangle className="w-3 h-3 text-orange-400" />
                    <span className="text-orange-400">High</span>
                  </div>
                  <span className="font-mono text-orange-400 font-medium">{high}</span>
                </div>
              )}
              {medium > 0 && (
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-1.5">
                    <AlertCircle className="w-3 h-3 text-yellow-400" />
                    <span className="text-yellow-400">Medium</span>
                  </div>
                  <span className="font-mono text-yellow-400 font-medium">{medium}</span>
                </div>
              )}
              {low > 0 && (
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-1.5">
                    <Info className="w-3 h-3 text-blue-400" />
                    <span className="text-blue-400">Low</span>
                  </div>
                  <span className="font-mono text-blue-400 font-medium">{low}</span>
                </div>
              )}
            </div>
          </div>
          {/* Arrow pointing down */}
          <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-[1px]">
            <div className="border-[6px] border-transparent border-t-[var(--color-border)]" />
            <div className="absolute top-0 left-1/2 -translate-x-1/2 -mt-[1px] border-[5px] border-transparent border-t-[var(--color-surface)]" />
          </div>
        </div>
      )}
    </div>
  );
}
