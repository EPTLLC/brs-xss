/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Sat 10 Jan 2026 UTC
 * Status: Created
 * Telegram: https://t.me/EasyProTech
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  Users as UsersIcon, 
  Plus, 
  Trash2, 
  Shield, 
  User,
  Eye,
  EyeOff,
  X,
  Check,
  AlertCircle
} from 'lucide-react';
import { api } from '../api/client';

interface UserData {
  id: string;
  username: string;
  email: string | null;
  is_admin: boolean;
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

export function Users() {
  const queryClient = useQueryClient();
  const [showAddModal, setShowAddModal] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  // Fetch users
  const { data: users, isLoading, error } = useQuery<UserData[]>({
    queryKey: ['users'],
    queryFn: () => api.get('/auth/users').then(res => res.data),
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (userId: string) => api.delete(`/auth/users/${userId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setDeleteConfirm(null);
    },
  });

  // Toggle active mutation
  const toggleActiveMutation = useMutation({
    mutationFn: ({ userId, isActive }: { userId: string; isActive: boolean }) =>
      api.put(`/auth/users/${userId}`, { is_active: isActive }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });

  const currentUser = JSON.parse(localStorage.getItem('brs-user') || '{}');

  if (isLoading) {
    return (
      <div className="p-6 flex items-center justify-center">
        <div className="animate-spin w-8 h-8 border-2 border-[var(--color-primary)] border-t-transparent rounded-full" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="p-4 bg-[var(--color-danger)]/10 border border-[var(--color-danger)]/30 rounded-lg text-[var(--color-danger)]">
          Failed to load users. Make sure you have admin privileges.
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <UsersIcon className="w-6 h-6 text-[var(--color-primary)]" />
          <h1 className="text-2xl font-bold text-[var(--color-text)]">Users</h1>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-[var(--color-primary)] text-black font-medium rounded-lg hover:bg-[var(--color-primary-hover)] transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add User
        </button>
      </div>

      {/* Users Table */}
      <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-hover)]">
              <th className="px-4 py-3 text-left text-sm font-medium text-[var(--color-text-muted)]">User</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-[var(--color-text-muted)]">Role</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-[var(--color-text-muted)]">Status</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-[var(--color-text-muted)]">Last Login</th>
              <th className="px-4 py-3 text-right text-sm font-medium text-[var(--color-text-muted)]">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users?.map((user) => (
              <tr key={user.id} className="border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-surface-hover)] transition-colors">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-[var(--color-primary)]/20 flex items-center justify-center">
                      <User className="w-4 h-4 text-[var(--color-primary)]" />
                    </div>
                    <div>
                      <p className="font-medium text-[var(--color-text)]">
                        {user.username}
                        {user.id === currentUser.id && (
                          <span className="ml-2 text-xs text-[var(--color-text-muted)]">(you)</span>
                        )}
                      </p>
                      {user.email && (
                        <p className="text-sm text-[var(--color-text-muted)]">{user.email}</p>
                      )}
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3">
                  {user.is_admin ? (
                    <span className="inline-flex items-center gap-1 px-2 py-1 bg-[var(--color-primary)]/20 text-[var(--color-primary)] text-xs font-medium rounded">
                      <Shield className="w-3 h-3" />
                      Admin
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2 py-1 bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] text-xs font-medium rounded">
                      User
                    </span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => toggleActiveMutation.mutate({ userId: user.id, isActive: !user.is_active })}
                    disabled={user.id === currentUser.id}
                    className={`inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded transition-colors ${
                      user.is_active
                        ? 'bg-[var(--color-success)]/20 text-[var(--color-success)] hover:bg-[var(--color-success)]/30'
                        : 'bg-[var(--color-danger)]/20 text-[var(--color-danger)] hover:bg-[var(--color-danger)]/30'
                    } ${user.id === currentUser.id ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
                  >
                    {user.is_active ? (
                      <>
                        <Check className="w-3 h-3" />
                        Active
                      </>
                    ) : (
                      <>
                        <X className="w-3 h-3" />
                        Disabled
                      </>
                    )}
                  </button>
                </td>
                <td className="px-4 py-3 text-sm text-[var(--color-text-muted)]">
                  {user.last_login
                    ? new Date(user.last_login).toLocaleString()
                    : 'Never'}
                </td>
                <td className="px-4 py-3 text-right">
                  {deleteConfirm === user.id ? (
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => deleteMutation.mutate(user.id)}
                        className="px-3 py-1 bg-[var(--color-danger)] text-white text-sm rounded hover:bg-[var(--color-danger)]/80 transition-colors"
                      >
                        Confirm
                      </button>
                      <button
                        onClick={() => setDeleteConfirm(null)}
                        className="px-3 py-1 border border-[var(--color-border)] text-[var(--color-text)] text-sm rounded hover:bg-[var(--color-surface-hover)] transition-colors"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setDeleteConfirm(user.id)}
                      disabled={user.id === currentUser.id}
                      className="p-2 text-[var(--color-text-muted)] hover:text-[var(--color-danger)] hover:bg-[var(--color-danger)]/10 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                      title={user.id === currentUser.id ? "Cannot delete yourself" : "Delete user"}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {users?.length === 0 && (
          <div className="p-8 text-center text-[var(--color-text-muted)]">
            No users found
          </div>
        )}
      </div>

      {/* Add User Modal */}
      {showAddModal && (
        <AddUserModal onClose={() => setShowAddModal(false)} />
      )}
    </div>
  );
}

function AddUserModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');

  const createMutation = useMutation({
    mutationFn: (data: { username: string; password: string; email?: string; is_admin: boolean }) =>
      api.post('/auth/users', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      onClose();
    },
    onError: (err: any) => {
      setError(err.response?.data?.detail || 'Failed to create user');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!username) {
      setError('Username is required');
      return;
    }
    if (!password) {
      setError('Password is required');
      return;
    }

    createMutation.mutate({
      username,
      password,
      email: email || undefined,
      is_admin: isAdmin,
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md mx-4 bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl shadow-xl">
        <div className="flex items-center justify-between p-4 border-b border-[var(--color-border)]">
          <h3 className="text-lg font-semibold text-[var(--color-text)]">Add New User</h3>
          <button
            onClick={onClose}
            className="p-1 text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {error && (
            <div className="flex items-center gap-2 p-3 bg-[var(--color-danger)]/10 border border-[var(--color-danger)]/30 rounded-lg text-[var(--color-danger)]">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span className="text-sm">{error}</span>
            </div>
          )}

          <div>
            <label className="block text-sm text-[var(--color-text-muted)] mb-1">Username *</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)]"
              placeholder="Enter username"
            />
          </div>

          <div>
            <label className="block text-sm text-[var(--color-text-muted)] mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)]"
              placeholder="Optional"
            />
          </div>

          <div>
            <label className="block text-sm text-[var(--color-text-muted)] mb-1">Password *</label>
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

          <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg hover:bg-[var(--color-surface-hover)] transition-colors">
            <input
              type="checkbox"
              checked={isAdmin}
              onChange={(e) => setIsAdmin(e.target.checked)}
              className="w-4 h-4 rounded border-[var(--color-border)] text-[var(--color-primary)] focus:ring-[var(--color-primary)]"
            />
            <div>
              <p className="font-medium text-[var(--color-text)]">Administrator</p>
              <p className="text-sm text-[var(--color-text-muted)]">Can manage users and settings</p>
            </div>
          </label>

          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border border-[var(--color-border)] text-[var(--color-text)] rounded-lg hover:bg-[var(--color-surface-hover)] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="flex-1 px-4 py-2 bg-[var(--color-primary)] text-black font-medium rounded-lg hover:bg-[var(--color-primary-hover)] disabled:opacity-50 transition-colors"
            >
              {createMutation.isPending ? 'Creating...' : 'Create User'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
