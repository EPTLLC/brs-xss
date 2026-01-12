/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Sat 10 Jan 2026 UTC
 * Status: Created
 * Telegram: https://t.me/EasyProTech
 */

import { useState } from 'react';
import { Shield, AlertTriangle, Lock, User, Eye, EyeOff } from 'lucide-react';
import { api } from '../api/client';

interface FirstRunModalProps {
  onComplete: () => void;
}

export function FirstRunModal({ onComplete }: FirstRunModalProps) {
  const [step, setStep] = useState<'legal' | 'auth'>('legal');
  const [legalAccepted, setLegalAccepted] = useState(false);
  const [enableAuth, setEnableAuth] = useState(false);
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLegalContinue = () => {
    if (!legalAccepted) {
      setError('You must accept the legal disclaimer to continue');
      return;
    }
    setError('');
    setStep('auth');
  };

  const handleComplete = async () => {
    setError('');

    if (enableAuth) {
      if (!username) {
        setError('Username is required');
        return;
      }
      if (!password) {
        setError('Password is required');
        return;
      }
      if (password !== confirmPassword) {
        setError('Passwords do not match');
        return;
      }
    }

    setLoading(true);
    try {
      await api.post('/auth/config/first-run', null, {
        params: {
          enable_auth: enableAuth,
          legal_accepted: true,
        },
        data: enableAuth ? {
          username,
          password,
          is_admin: true,
        } : undefined,
      });
      
      // If auth enabled, store credentials for auto-login
      if (enableAuth) {
        const loginRes = await api.post('/auth/login', {
          username,
          password,
        });
        localStorage.setItem('brs-token', loginRes.data.access_token);
        localStorage.setItem('brs-user', JSON.stringify(loginRes.data.user));
      }
      
      onComplete();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to complete setup');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <div className="w-full max-w-lg mx-4 bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-[var(--color-border)] bg-gradient-to-r from-[var(--color-surface)] to-[var(--color-surface-hover)]">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-[var(--color-primary)]" />
            <div>
              <h2 className="text-xl font-bold text-[var(--color-text)]">BRS-XSS Scanner</h2>
              <p className="text-sm text-[var(--color-text-muted)]">First Run Setup</p>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="p-6">
          {step === 'legal' && (
            <div className="space-y-4">
              {/* Legal Warning */}
              <div className="p-4 bg-[var(--color-danger)]/10 border border-[var(--color-danger)]/30 rounded-lg">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-6 h-6 text-[var(--color-danger)] flex-shrink-0 mt-0.5" />
                  <div>
                    <h3 className="font-semibold text-[var(--color-danger)] mb-2">
                      Legal Disclaimer & Ethical Use
                    </h3>
                    <div className="text-sm text-[var(--color-text)] space-y-2">
                      <p>
                        BRS-XSS is a professional security testing tool designed for 
                        <strong> authorized penetration testing only</strong>.
                      </p>
                      <p>By using this software, you agree to:</p>
                      <ul className="list-disc list-inside space-y-1 ml-2">
                        <li>Only scan systems you own or have explicit written permission to test</li>
                        <li>Comply with all applicable laws and regulations</li>
                        <li>Not use this tool for malicious purposes</li>
                        <li>Accept full responsibility for your actions</li>
                      </ul>
                      <p className="font-semibold text-[var(--color-warning)]">
                        Unauthorized access to computer systems is a criminal offense.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Accept checkbox */}
              <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg hover:bg-[var(--color-surface-hover)] transition-colors">
                <input
                  type="checkbox"
                  checked={legalAccepted}
                  onChange={(e) => setLegalAccepted(e.target.checked)}
                  className="w-5 h-5 rounded border-[var(--color-border)] text-[var(--color-primary)] focus:ring-[var(--color-primary)]"
                />
                <span className="text-[var(--color-text)]">
                  I understand and accept the legal disclaimer. I will use this tool responsibly and ethically.
                </span>
              </label>

              {error && (
                <p className="text-sm text-[var(--color-danger)]">{error}</p>
              )}

              <button
                onClick={handleLegalContinue}
                disabled={!legalAccepted}
                className="w-full py-3 px-4 bg-[var(--color-primary)] text-black font-semibold rounded-lg hover:bg-[var(--color-primary-hover)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Continue
              </button>
            </div>
          )}

          {step === 'auth' && (
            <div className="space-y-4">
              <p className="text-[var(--color-text-muted)]">
                Configure authentication for BRS-XSS. If your scanner is accessible from the network, 
                we strongly recommend enabling authentication.
              </p>

              {/* Auth toggle */}
              <div className="p-4 bg-[var(--color-surface-hover)] rounded-lg">
                <label className="flex items-center justify-between cursor-pointer">
                  <div className="flex items-center gap-3">
                    <Lock className="w-5 h-5 text-[var(--color-primary)]" />
                    <div>
                      <p className="font-medium text-[var(--color-text)]">Enable Authentication</p>
                      <p className="text-sm text-[var(--color-text-muted)]">
                        Require login to access the scanner
                      </p>
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    checked={enableAuth}
                    onChange={(e) => setEnableAuth(e.target.checked)}
                    className="w-5 h-5 rounded border-[var(--color-border)] text-[var(--color-primary)] focus:ring-[var(--color-primary)]"
                  />
                </label>
              </div>

              {/* Admin credentials */}
              {enableAuth && (
                <div className="space-y-3 p-4 border border-[var(--color-border)] rounded-lg">
                  <h4 className="font-medium text-[var(--color-text)] flex items-center gap-2">
                    <User className="w-4 h-4" />
                    Administrator Account
                  </h4>
                  
                  <div>
                    <label className="block text-sm text-[var(--color-text-muted)] mb-1">
                      Username
                    </label>
                    <input
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="w-full px-3 py-2 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)]"
                      placeholder="admin"
                    />
                  </div>

                  <div>
                    <label className="block text-sm text-[var(--color-text-muted)] mb-1">
                      Password
                    </label>
                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="w-full px-3 py-2 pr-10 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)]"
                        placeholder="Enter password"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm text-[var(--color-text-muted)] mb-1">
                      Confirm Password
                    </label>
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="w-full px-3 py-2 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)]"
                      placeholder="Repeat password"
                    />
                  </div>
                </div>
              )}

              {!enableAuth && (
                <div className="p-3 bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30 rounded-lg">
                  <p className="text-sm text-[var(--color-warning)]">
                    Without authentication, anyone with network access to this scanner can use it.
                    Only disable if running locally or in a trusted environment.
                  </p>
                </div>
              )}

              {error && (
                <p className="text-sm text-[var(--color-danger)]">{error}</p>
              )}

              <div className="flex gap-3">
                <button
                  onClick={() => setStep('legal')}
                  className="px-4 py-3 border border-[var(--color-border)] text-[var(--color-text)] rounded-lg hover:bg-[var(--color-surface-hover)] transition-colors"
                >
                  Back
                </button>
                <button
                  onClick={handleComplete}
                  disabled={loading}
                  className="flex-1 py-3 px-4 bg-[var(--color-primary)] text-black font-semibold rounded-lg hover:bg-[var(--color-primary-hover)] disabled:opacity-50 transition-colors"
                >
                  {loading ? 'Setting up...' : 'Complete Setup'}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-[var(--color-border)] bg-[var(--color-surface-hover)]">
          <p className="text-xs text-[var(--color-text-muted)] text-center">
            BRS-XSS by EasyProTech LLC | MIT License
          </p>
        </div>
      </div>
    </div>
  );
}
