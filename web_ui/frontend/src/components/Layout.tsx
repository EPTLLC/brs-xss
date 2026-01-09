/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Thu 26 Dec 2025 UTC
 * Status: Updated - Draggable live stats bar
 * Telegram: https://t.me/EasyProTech
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { Outlet, NavLink } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import { 
  LayoutDashboard, 
  Crosshair, 
  History, 
  Settings,
  Shield,
  Cpu,
  HardDrive,
  Activity,
  X,
  GripVertical,
  Power
} from 'lucide-react';
import { api } from '../api/client';

interface LiveStats {
  cpu_percent: number;
  ram_used_gb: number;
  ram_total_gb: number;
  ram_percent: number;
  load_1m: number;
  active_scans: number;
  net_sent_mbps: number;
  net_recv_mbps: number;
  // Parallelism info
  max_parallel: number;
  cpu_cores: number;
  targets_total: number;
  targets_scanned: number;
}

interface Position {
  x: number;
  y: number;
}

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scan/new', icon: Crosshair, label: 'New Scan' },
  { to: '/history', icon: History, label: 'History' },
];

const bottomItems = [
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export function Layout() {
  // Stats bar visibility - persist to localStorage
  const [showStatsBar, setShowStatsBar] = useState(() => {
    const saved = localStorage.getItem('brs-stats-bar-visible');
    return saved !== 'false'; // Default to visible
  });

  // Stats bar position - persist to localStorage (default: bottom-right)
  const [position, setPosition] = useState<Position>(() => {
    const saved = localStorage.getItem('brs-stats-bar-position');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return { x: -1, y: -1 }; // -1,-1 means bottom-right
      }
    }
    return { x: -1, y: -1 }; // Default to bottom-right
  });

  const [isDragging, setIsDragging] = useState(false);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const statsBarRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    localStorage.setItem('brs-stats-bar-visible', String(showStatsBar));
  }, [showStatsBar]);

  useEffect(() => {
    if (position.x !== -1 || position.y !== -1) {
      localStorage.setItem('brs-stats-bar-position', JSON.stringify(position));
    }
  }, [position]);

  // Handle drag start
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    // Don't start drag if clicking on close button
    if ((e.target as HTMLElement).closest('button')) return;
    
    if (statsBarRef.current) {
      const rect = statsBarRef.current.getBoundingClientRect();
      setDragOffset({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top
      });
      setIsDragging(true);
    }
  }, []);

  // Handle drag
  useEffect(() => {
    if (!isDragging) return;

    const handleMouseMove = (e: MouseEvent) => {
      const newX = e.clientX - dragOffset.x;
      const newY = e.clientY - dragOffset.y;
      
      // Keep within viewport bounds
      const maxX = window.innerWidth - (statsBarRef.current?.offsetWidth || 300);
      const maxY = window.innerHeight - (statsBarRef.current?.offsetHeight || 40);
      
      setPosition({
        x: Math.max(0, Math.min(newX, maxX)),
        y: Math.max(0, Math.min(newY, maxY))
      });
    };

    const handleMouseUp = () => {
      setIsDragging(false);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isDragging, dragOffset]);

  // Live stats - refresh every 5 seconds
  const { data: liveStats } = useQuery<LiveStats>({
    queryKey: ['global-live-stats'],
    queryFn: () => api.get('/system/stats').then(res => res.data),
    refetchInterval: 5000,
  });

  // Backend restart mutation
  const restartMutation = useMutation({
    mutationFn: () => api.post('/system/restart').then(res => res.data),
    onSuccess: () => {
      // Wait a bit then reload page to reconnect to restarted backend
      setTimeout(() => {
        window.location.reload();
      }, 2000);
    },
    onError: () => {
      // Even on error, try to reload after delay
      setTimeout(() => {
        window.location.reload();
      }, 2000);
    }
  });

  // Calculate style for stats bar position
  // -1,-1 = bottom-right (default), otherwise use exact position
  const statsBarStyle = position.x === -1 && position.y === -1
    ? { bottom: '16px', right: '16px', top: 'auto', left: 'auto' }
    : { top: `${position.y}px`, left: `${position.x}px` };

  return (
    <div className="brs-app">
      {/* Sidebar */}
      <aside className="brs-sidebar">
        {/* Logo with GitHub link */}
        <a 
          href="https://github.com/EPTLLC/brs-xss"
          target="_blank"
          rel="noopener noreferrer"
          className="brs-sidebar-logo brs-tooltip group"
          data-tooltip="BRS-XSS on GitHub"
        >
          <Shield 
            className="w-8 h-8 text-[var(--color-primary)] transition-all duration-300 group-hover:scale-105" 
            style={{ 
              filter: 'drop-shadow(0 0 8px rgba(0, 255, 136, 0.4))',
            }} 
          />
          <style>{`
            .brs-sidebar-logo:hover svg {
              filter: drop-shadow(0 0 12px rgba(0, 255, 136, 0.8)) drop-shadow(0 0 20px rgba(0, 255, 136, 0.5)) !important;
            }
          `}</style>
        </a>

        {/* Navigation */}
        <nav className="brs-sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `brs-sidebar-item brs-tooltip ${isActive ? 'active' : ''}`
              }
              data-tooltip={item.label}
            >
              <item.icon className="w-5 h-5" />
            </NavLink>
          ))}
        </nav>

        {/* Show stats button - appears when stats bar is hidden */}
        {!showStatsBar && (
          <button
            onClick={() => setShowStatsBar(true)}
            className="brs-sidebar-item brs-tooltip mt-2"
            data-tooltip="Show System Stats"
          >
            <Cpu className={`w-5 h-5 ${
              (liveStats?.cpu_percent || 0) > 80 ? 'text-[var(--color-danger)]' :
              (liveStats?.cpu_percent || 0) > 50 ? 'text-[var(--color-warning)]' :
              'text-[var(--color-success)]'
            }`} />
          </button>
        )}

        {/* Footer - settings and restart button */}
        <div className="brs-sidebar-footer">
          {/* Settings button */}
          {bottomItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `brs-sidebar-item brs-tooltip ${isActive ? 'active' : ''}`
              }
              data-tooltip={item.label}
            >
              <item.icon className="w-5 h-5" />
            </NavLink>
          ))}
          
          {/* Restart backend button */}
          <button
            onClick={() => {
              if (window.confirm('Restart backend server? This will disconnect all active scans.')) {
                restartMutation.mutate();
              }
            }}
            disabled={restartMutation.isPending}
            className="brs-sidebar-item brs-tooltip"
            data-tooltip="Restart Backend"
          >
            <Power className={`w-5 h-5 ${restartMutation.isPending ? 'animate-pulse' : ''}`} />
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="brs-main">
        {/* Global Live Stats Bar - Draggable */}
        {showStatsBar && (
          <div 
            ref={statsBarRef}
            onMouseDown={handleMouseDown}
            className={`fixed z-50 flex items-center gap-2 bg-[var(--color-surface)]/90 backdrop-blur-sm border border-[var(--color-border)] rounded-lg px-2 py-1.5 text-xs font-mono select-none ${
              isDragging ? 'cursor-grabbing shadow-lg' : 'cursor-grab'
            }`}
            style={statsBarStyle}
          >
            {/* Active scans indicator with parallelism info - LEFT side */}
            {(liveStats?.active_scans || 0) > 0 && (
              <>
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 bg-[var(--color-info)] rounded-full animate-pulse" />
                  <span className="text-[var(--color-info)]">
                    {liveStats?.active_scans}
                  </span>
                </div>
                <span className="text-[var(--color-border)]">|</span>
                {/* Targets progress */}
                <div className="flex items-center gap-1">
                  <span className="text-[var(--color-success)]">
                    {liveStats?.targets_scanned || 0}
                  </span>
                  <span className="text-[var(--color-text-muted)]">/</span>
                  <span className="text-[var(--color-text)]">
                    {liveStats?.targets_total || 0}
                  </span>
                </div>
                <span className="text-[var(--color-border)]">|</span>
              </>
            )}

            {/* Drag handle indicator */}
            <GripVertical className="w-3 h-3 text-[var(--color-text-muted)] opacity-50" />

            {/* CPU with cores count */}
            <div className="flex items-center gap-1.5">
              <Cpu className={`w-3.5 h-3.5 ${
                (liveStats?.cpu_percent || 0) > 80 ? 'text-[var(--color-danger)]' :
                (liveStats?.cpu_percent || 0) > 50 ? 'text-[var(--color-warning)]' :
                'text-[var(--color-success)]'
              }`} />
              <span className={`${
                (liveStats?.cpu_percent || 0) > 80 ? 'text-[var(--color-danger)]' :
                (liveStats?.cpu_percent || 0) > 50 ? 'text-[var(--color-warning)]' :
                'text-[var(--color-success)]'
              }`}>
                {liveStats?.cpu_percent?.toFixed(0) || 0}%
              </span>
              <span className="text-[var(--color-text-muted)] text-[10px]">
                ({liveStats?.cpu_cores || 0}c)
              </span>
            </div>

            <span className="text-[var(--color-border)]">|</span>

            {/* RAM */}
            <div className="flex items-center gap-1.5">
              <HardDrive className={`w-3.5 h-3.5 ${
                (liveStats?.ram_percent || 0) > 80 ? 'text-[var(--color-danger)]' :
                (liveStats?.ram_percent || 0) > 60 ? 'text-[var(--color-warning)]' :
                'text-[var(--color-success)]'
              }`} />
              <span className={`${
                (liveStats?.ram_percent || 0) > 80 ? 'text-[var(--color-danger)]' :
                (liveStats?.ram_percent || 0) > 60 ? 'text-[var(--color-warning)]' :
                'text-[var(--color-success)]'
              }`}>
                {liveStats?.ram_used_gb?.toFixed(0) || 0}
              </span>
              <span className="text-[var(--color-text-muted)]">
                /{liveStats?.ram_total_gb?.toFixed(0) || 0}G
              </span>
            </div>

            <span className="text-[var(--color-border)]">|</span>

            {/* Load */}
            <div className="flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-[var(--color-text-muted)]" />
              <span className="text-[var(--color-text)]">
                {liveStats?.load_1m?.toFixed(2) || '0.00'}
              </span>
            </div>

            <span className="text-[var(--color-border)]">|</span>

            {/* Network */}
            <div className="flex items-center gap-1.5">
              <span className="text-[var(--color-success)]">↓</span>
              <span className="text-[var(--color-text)]">
                {(liveStats?.net_recv_mbps || 0).toFixed(1)}
              </span>
              <span className="text-[var(--color-info)]">↑</span>
              <span className="text-[var(--color-text)]">
                {(liveStats?.net_sent_mbps || 0).toFixed(1)}
              </span>
              <span className="text-[var(--color-text-muted)] text-[10px]">Mbps</span>
            </div>

            {/* Close button */}
            <button
              onClick={(e) => {
                e.stopPropagation();
                setShowStatsBar(false);
              }}
              className="brs-tooltip brs-tooltip-bottom ml-1 p-0.5 rounded hover:bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
              data-tooltip="Hide stats bar"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        <Outlet />
      </main>
    </div>
  );
}
