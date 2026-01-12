/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Sat 10 Jan 2026 UTC
 * Status: Updated - Added authentication
 * Telegram: https://t.me/EasyProTech
 */

import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { NewScan } from './pages/NewScan';
import { ScanDetails } from './pages/ScanDetails';
import { ScanHistory } from './pages/ScanHistory';
import { Settings } from './pages/Settings';
import { Login } from './pages/Login';
import { Users } from './pages/Users';
import { Strategy } from './pages/Strategy';
import { FirstRunModal } from './components/FirstRunModal';
import { useWebSocket } from './hooks/useWebSocket';
import { api } from './api/client';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

interface AuthConfig {
  auth_enabled: boolean;
  first_run_completed: boolean;
  legal_accepted: boolean;
}

// Auth context check component
function AuthGuard({ children }: { children: React.ReactNode }) {
  const [showFirstRun, setShowFirstRun] = useState(false);
  
  const { data: authConfig, isLoading, refetch } = useQuery<AuthConfig>({
    queryKey: ['auth-config'],
    queryFn: () => api.get('/auth/config').then(res => res.data),
    staleTime: Infinity,
  });

  useEffect(() => {
    if (authConfig && !authConfig.first_run_completed) {
      setShowFirstRun(true);
    }
  }, [authConfig]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[var(--color-bg)]">
        <div className="animate-spin w-8 h-8 border-2 border-[var(--color-primary)] border-t-transparent rounded-full" />
      </div>
    );
  }

  // Show first run modal
  if (showFirstRun) {
    return (
      <FirstRunModal 
        onComplete={() => {
          setShowFirstRun(false);
          refetch();
        }} 
      />
    );
  }

  // Check if auth is enabled and user is not logged in
  if (authConfig?.auth_enabled) {
    const token = localStorage.getItem('brs-token');
    if (!token) {
      return <Login />;
    }
  }

  return <>{children}</>;
}

// Inner component that uses hooks requiring QueryClientProvider
function AppContent() {
  const { connect } = useWebSocket();

  useEffect(() => {
    connect();
  }, [connect]);

  // Get current user for admin check
  const user = JSON.parse(localStorage.getItem('brs-user') || '{}');
  const isAdmin = user.is_admin === true;

  // Check if auth is enabled from query cache
  const { data: authConfig } = useQuery<AuthConfig>({
    queryKey: ['auth-config'],
    queryFn: () => api.get('/auth/config').then(res => res.data),
    staleTime: Infinity,
  });
  const isAuthEnabled = authConfig?.auth_enabled === true;

  return (
    <BrowserRouter>
      <AuthGuard>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="scan/new" element={<NewScan />} />
            <Route path="scan/:id" element={<ScanDetails />} />
            <Route path="history" element={<ScanHistory />} />
            <Route path="strategy" element={<Strategy />} />
            <Route path="settings" element={<Settings />} />
            {/* Users page - for admins, or when auth disabled (to create first admin) */}
            <Route path="users" element={(isAdmin || !isAuthEnabled) ? <Users /> : <Navigate to="/" replace />} />
          </Route>
          <Route path="/login" element={<Login />} />
        </Routes>
      </AuthGuard>
    </BrowserRouter>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}

export default App;
