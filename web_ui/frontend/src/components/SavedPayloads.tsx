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
  Code, 
  Plus, 
  Trash2, 
  Check, 
  Tag,
  TrendingUp,
  ChevronDown,
  ChevronUp,
  Save
} from 'lucide-react';
import { api } from '../api/client';

interface SavedPayload {
  id: string;
  user_id: string | null;
  payload: string;
  name: string | null;
  description: string | null;
  tags: string[];
  context: string | null;
  success_count: number;
  fail_count: number;
  last_used: string | null;
  created_at: string;
}

interface SavedPayloadsProps {
  onSelect: (payloads: string[]) => void;
  selectedPayloads: string[];
}

export function SavedPayloads({ onSelect, selectedPayloads }: SavedPayloadsProps) {
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [newPayload, setNewPayload] = useState('');
  const [newPayloadName, setNewPayloadName] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);

  // Fetch saved payloads
  const { data: payloads = [], isLoading } = useQuery<SavedPayload[]>({
    queryKey: ['saved-payloads'],
    queryFn: () => api.get('/payloads').then(res => res.data),
  });

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: { payload: string; name?: string }) =>
      api.post('/payloads', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saved-payloads'] });
      setNewPayload('');
      setNewPayloadName('');
      setShowAddForm(false);
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/payloads/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saved-payloads'] });
    },
  });

  const handleTogglePayload = (payload: string) => {
    if (selectedPayloads.includes(payload)) {
      onSelect(selectedPayloads.filter(p => p !== payload));
    } else {
      onSelect([...selectedPayloads, payload]);
    }
  };

  const handleSelectAll = () => {
    if (selectedPayloads.length === payloads.length) {
      onSelect([]);
    } else {
      onSelect(payloads.map(p => p.payload));
    }
  };

  const handleSavePayload = () => {
    if (!newPayload.trim()) return;
    createMutation.mutate({
      payload: newPayload.trim(),
      name: newPayloadName.trim() || undefined,
    });
  };

  const successRate = (p: SavedPayload) => {
    const total = p.success_count + p.fail_count;
    if (total === 0) return null;
    return Math.round((p.success_count / total) * 100);
  };

  if (isLoading) {
    return (
      <div className="p-4 text-center text-[var(--color-text-muted)]">
        Loading saved payloads...
      </div>
    );
  }

  return (
    <div className="border border-[var(--color-border)] rounded-lg overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-3 bg-[var(--color-surface-hover)] hover:bg-[var(--color-surface)] transition-colors"
      >
        <div className="flex items-center gap-2">
          <Code className="w-4 h-4 text-[var(--color-primary)]" />
          <span className="font-medium text-[var(--color-text)]">
            My Payloads
          </span>
          {payloads.length > 0 && (
            <span className="px-2 py-0.5 text-xs bg-[var(--color-primary)]/20 text-[var(--color-primary)] rounded-full">
              {payloads.length}
            </span>
          )}
          {selectedPayloads.length > 0 && (
            <span className="px-2 py-0.5 text-xs bg-[var(--color-success)]/20 text-[var(--color-success)] rounded-full">
              {selectedPayloads.length} selected
            </span>
          )}
        </div>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-[var(--color-text-muted)]" />
        ) : (
          <ChevronDown className="w-4 h-4 text-[var(--color-text-muted)]" />
        )}
      </button>

      {/* Content */}
      {expanded && (
        <div className="p-3 space-y-3 bg-[var(--color-bg)]">
          {/* Actions */}
          <div className="flex items-center justify-between">
            <button
              onClick={handleSelectAll}
              className="text-xs text-[var(--color-primary)] hover:opacity-80 transition-opacity"
            >
              {selectedPayloads.length === payloads.length ? 'Deselect All' : 'Select All'}
            </button>
            <button
              onClick={() => setShowAddForm(!showAddForm)}
              className="flex items-center gap-1 text-xs text-[var(--color-primary)] hover:opacity-80 transition-opacity"
            >
              <Plus className="w-3 h-3" />
              Add New
            </button>
          </div>

          {/* Add Form */}
          {showAddForm && (
            <div className="p-3 bg-[var(--color-surface)] rounded-lg space-y-2">
              <input
                type="text"
                value={newPayloadName}
                onChange={(e) => setNewPayloadName(e.target.value)}
                placeholder="Name (optional)"
                className="w-full px-3 py-1.5 text-sm bg-[var(--color-bg)] border border-[var(--color-border)] rounded text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)]"
              />
              <textarea
                value={newPayload}
                onChange={(e) => setNewPayload(e.target.value)}
                placeholder="Payload (e.g. <script>alert(1)</script>)"
                rows={2}
                className="w-full px-3 py-1.5 text-sm bg-[var(--color-bg)] border border-[var(--color-border)] rounded text-[var(--color-text)] font-mono focus:outline-none focus:border-[var(--color-primary)]"
              />
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setShowAddForm(false)}
                  className="px-3 py-1 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSavePayload}
                  disabled={!newPayload.trim() || createMutation.isPending}
                  className="flex items-center gap-1 px-3 py-1 text-xs bg-[var(--color-primary)] text-black rounded hover:opacity-90 disabled:opacity-50"
                >
                  <Save className="w-3 h-3" />
                  Save
                </button>
              </div>
            </div>
          )}

          {/* Payloads List */}
          {payloads.length === 0 ? (
            <div className="text-center py-4 text-[var(--color-text-muted)] text-sm">
              No saved payloads yet. Add your first one!
            </div>
          ) : (
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {payloads.map((p) => (
                <div
                  key={p.id}
                  className={`p-2 rounded-lg border transition-colors cursor-pointer ${
                    selectedPayloads.includes(p.payload)
                      ? 'border-[var(--color-primary)] bg-[var(--color-primary)]/10'
                      : 'border-[var(--color-border)] bg-[var(--color-surface)] hover:border-[var(--color-primary)]/50'
                  }`}
                  onClick={() => handleTogglePayload(p.payload)}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      {/* Name */}
                      {p.name && (
                        <div className="text-sm font-medium text-[var(--color-text)] truncate">
                          {p.name}
                        </div>
                      )}
                      {/* Payload */}
                      <div className="text-xs font-mono text-[var(--color-text-muted)] truncate">
                        {p.payload}
                      </div>
                      {/* Stats */}
                      <div className="flex items-center gap-3 mt-1">
                        {successRate(p) !== null && (
                          <span className="flex items-center gap-1 text-xs text-[var(--color-text-muted)]">
                            <TrendingUp className="w-3 h-3" />
                            {successRate(p)}% success
                          </span>
                        )}
                        {p.tags.length > 0 && (
                          <span className="flex items-center gap-1 text-xs text-[var(--color-text-muted)]">
                            <Tag className="w-3 h-3" />
                            {p.tags.slice(0, 2).join(', ')}
                          </span>
                        )}
                      </div>
                    </div>
                    {/* Actions */}
                    <div className="flex items-center gap-1">
                      {selectedPayloads.includes(p.payload) && (
                        <Check className="w-4 h-4 text-[var(--color-primary)]" />
                      )}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (confirm('Delete this payload?')) {
                            deleteMutation.mutate(p.id);
                          }
                        }}
                        className="p-1 text-[var(--color-text-muted)] hover:text-[var(--color-danger)] transition-colors"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
