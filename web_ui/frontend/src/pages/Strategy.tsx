/*
 * Project: BRS-XSS Scanner Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: Mon 12 Jan 2026 UTC
 * Status: Updated - Full CRUD, A/B testing, import/export
 * Telegram: https://t.me/EasyProTech
 */

import { useState, useMemo, useEffect, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import {
  GitBranch,
  Play,
  ChevronRight,
  ChevronDown,
  Shield,
  Code,
  Globe,
  Zap,
  RefreshCw,
  Info,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ArrowRight,
  RotateCcw,
  Eye,
  Search,
  History,
  ExternalLink,
  Plus,
  Edit3,
  Trash2,
  Copy,
  Download,
  Upload,
  FlaskConical,
  BarChart3,
  X,
  Check,
  Star,
} from 'lucide-react';
import { api } from '../api/client';
import { PageHeader } from '../components/PageHeader';

interface StrategyNode {
  id: string;
  type: string;
  name: string;
  description?: string;
  config: Record<string, any>;
  condition?: string;
  children: StrategyNode[];
  success_count: number;
  failure_count: number;
  success_rate: number;
  priority: number;
  enabled: boolean;
}

interface StrategyTree {
  id: string;
  name: string;
  description?: string;
  version: string;
  author?: string;
  tags: string[];
  total_uses: number;
  total_successes: number;
  success_rate: number;
  is_default: boolean;
  is_active: boolean;
  root?: StrategyNode;
  tree_data?: Record<string, any>;
  created_at?: string;
  updated_at?: string;
}

interface SimulationAction {
  step: number;
  action_type: string;
  payload?: string;
  encoding?: string;
  context?: string;
  node_id?: string;
  metadata: Record<string, any>;
}

interface SimulationResult {
  actions: SimulationAction[];
  statistics: {
    total_attempts: number;
    successful_payloads: number;
    failed_payloads: number;
    success_rate: number;
    current_context: string;
    waf_detected: boolean;
    actions_taken: number;
  };
}

interface ScanStrategyPath {
  id: string;
  scan_id: string;
  strategy_tree_id: string;
  initial_context: string;
  waf_detected: boolean;
  waf_name?: string;
  actions: SimulationAction[];
  visited_nodes: string[];
  node_statuses: Record<string, string>;
  pivots: Array<{
    step: number;
    type: string;
    from_context?: string;
    to_context?: string;
    encoding?: string;
    reason?: string;
  }>;
  statistics: {
    total_actions: number;
    visited_nodes: number;
    success_count: number;
    failed_count: number;
    pivot_count: number;
    initial_context: string;
    waf_detected: boolean;
    waf_name?: string;
  };
  created_at: string;
}

interface ABTest {
  id: string;
  name: string;
  description?: string;
  strategy_a_id: string;
  strategy_b_id: string;
  strategy_a_name?: string;
  strategy_b_name?: string;
  status: 'pending' | 'running' | 'completed' | 'cancelled';
  target_scans: number;
  completed_scans_a: number;
  completed_scans_b: number;
  results_a: Record<string, any>;
  results_b: Record<string, any>;
  winner?: string;
  created_at?: string;
  completed_at?: string;
}

type TabType = 'tree' | 'strategies' | 'ab-tests';

const nodeTypeIcons: Record<string, typeof Code> = {
  root: GitBranch,
  context: Globe,
  payload: Zap,
  encoding: Code,
  waf_bypass: Shield,
  mutation: RefreshCw,
  condition: AlertTriangle,
  success: CheckCircle,
  failure: XCircle,
};

const nodeTypeColors: Record<string, string> = {
  root: 'text-zinc-400',
  context: 'text-cyan-400',
  payload: 'text-green-400',
  encoding: 'text-purple-400',
  waf_bypass: 'text-orange-400',
  mutation: 'text-yellow-400',
  condition: 'text-blue-400',
  success: 'text-emerald-400',
  failure: 'text-red-400',
};

type NodeStatus = 'visited' | 'success' | 'failed' | 'pivot' | 'dead' | null;

interface TreeNodeProps {
  node: StrategyNode;
  depth?: number;
  visitedNodes: Set<string>;
  nodeStatuses: Map<string, NodeStatus>;
  selectedNode: string | null;
  onNodeSelect: (id: string) => void;
}

function TreeNode({ 
  node, 
  depth = 0, 
  visitedNodes, 
  nodeStatuses,
  selectedNode,
  onNodeSelect,
}: TreeNodeProps) {
  const [expanded, setExpanded] = useState(depth < 2);
  const Icon = nodeTypeIcons[node.type] || Code;
  const colorClass = nodeTypeColors[node.type] || 'text-zinc-400';
  const hasChildren = node.children && node.children.length > 0;
  
  const isVisited = visitedNodes.has(node.id);
  const status = nodeStatuses.get(node.id);
  const isSelected = selectedNode === node.id;

  const getStatusStyle = () => {
    if (isSelected) return 'bg-cyan-500/20 border-l-2 border-cyan-400';
    if (status === 'success') return 'bg-green-500/10 border-l-2 border-green-400';
    if (status === 'failed') return 'bg-red-500/10 border-l-2 border-red-400';
    if (status === 'pivot') return 'bg-yellow-500/10 border-l-2 border-yellow-400';
    if (status === 'dead') return 'bg-zinc-800/50 border-l-2 border-zinc-600';
    if (isVisited) return 'bg-cyan-500/5 border-l-2 border-cyan-500/50';
    return '';
  };

  const getStatusBadge = () => {
    if (status === 'success') return <CheckCircle className="w-3 h-3 text-green-400" />;
    if (status === 'failed') return <XCircle className="w-3 h-3 text-red-400" />;
    if (status === 'pivot') return <RotateCcw className="w-3 h-3 text-yellow-400" />;
    if (status === 'dead') return <span className="w-2 h-2 rounded-full bg-zinc-600" />;
    return null;
  };

  return (
    <div className="select-none">
      <div
        className={`flex items-center gap-2 py-1.5 px-2 rounded cursor-pointer transition-all ${
          !node.enabled ? 'opacity-50' : ''
        } ${getStatusStyle()} hover:bg-zinc-800/50`}
        style={{ paddingLeft: `${depth * 20 + 8}px` }}
        onClick={() => {
          if (hasChildren) setExpanded(!expanded);
          onNodeSelect(node.id);
        }}
      >
        {hasChildren ? (
          expanded ? (
            <ChevronDown className="w-4 h-4 text-zinc-500" />
          ) : (
            <ChevronRight className="w-4 h-4 text-zinc-500" />
          )
        ) : (
          <span className="w-4" />
        )}
        <Icon className={`w-4 h-4 ${isVisited ? colorClass : 'text-zinc-600'}`} />
        <span className={`text-sm ${isVisited ? 'text-zinc-200' : 'text-zinc-500'}`}>
          {node.name}
        </span>
        {node.condition && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
            isVisited ? 'bg-zinc-700 text-zinc-400' : 'bg-zinc-800 text-zinc-600'
          }`}>
            {node.condition}
          </span>
        )}
        {getStatusBadge()}
        {node.success_count + node.failure_count > 0 && (
          <span className={`text-[10px] ml-auto ${
            node.success_rate > 0.5 ? 'text-green-400' : 'text-red-400'
          }`}>
            {(node.success_rate * 100).toFixed(0)}%
          </span>
        )}
      </div>
      {expanded && hasChildren && (
        <div>
          {node.children.map((child) => (
            <TreeNode 
              key={child.id} 
              node={child} 
              depth={depth + 1}
              visitedNodes={visitedNodes}
              nodeStatuses={nodeStatuses}
              selectedNode={selectedNode}
              onNodeSelect={onNodeSelect}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function EvolutionTimeline({ actions }: { actions: SimulationAction[] }) {
  const pivots = actions.filter(a => 
    a.action_type === 'switch_context' || 
    a.action_type === 'encode' ||
    a.metadata?.action === 'mutate'
  );

  if (pivots.length === 0) return null;

  return (
    <div className="mt-4 p-3 bg-zinc-800/30 rounded-lg">
      <div className="flex items-center gap-2 mb-3">
        <RotateCcw className="w-4 h-4 text-yellow-400" />
        <span className="text-xs font-semibold text-zinc-300">Strategy Evolution</span>
      </div>
      <div className="relative">
        <div className="absolute left-2 top-0 bottom-0 w-0.5 bg-zinc-700" />
        <div className="space-y-3">
          {pivots.slice(0, 5).map((pivot, idx) => (
            <div key={idx} className="flex items-start gap-3 pl-6 relative">
              <div className={`absolute left-0.5 w-3 h-3 rounded-full border-2 ${
                pivot.action_type === 'switch_context' ? 'bg-cyan-500 border-cyan-400' :
                pivot.action_type === 'encode' ? 'bg-purple-500 border-purple-400' :
                'bg-yellow-500 border-yellow-400'
              }`} />
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-zinc-300">
                    Step {pivot.step}
                  </span>
                  <ArrowRight className="w-3 h-3 text-zinc-600" />
                  <span className={`text-xs font-medium ${
                    pivot.action_type === 'switch_context' ? 'text-cyan-400' :
                    pivot.action_type === 'encode' ? 'text-purple-400' :
                    'text-yellow-400'
                  }`}>
                    {pivot.action_type === 'switch_context' ? 'Context Switch' :
                     pivot.action_type === 'encode' ? 'Encoding Applied' :
                     'Payload Mutation'}
                  </span>
                </div>
                <div className="text-[10px] text-zinc-500 mt-0.5">
                  {pivot.action_type === 'switch_context' && pivot.metadata?.from && (
                    <span>{pivot.metadata.from} → {pivot.metadata.to}</span>
                  )}
                  {pivot.action_type === 'encode' && pivot.encoding && (
                    <span>Applied {pivot.encoding} encoding</span>
                  )}
                  {pivot.metadata?.action === 'mutate' && (
                    <span>{pivot.metadata.mutation_type}: {pivot.metadata.original?.slice(0, 20)}...</span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function NodeExplanation({ node }: { node: StrategyNode | null }) {
  if (!node) {
    return (
      <div className="text-center text-zinc-500 py-8">
        <Eye className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">Click a node to see details</p>
      </div>
    );
  }

  const explanations: Record<string, string> = {
    root: 'Entry point of the strategy tree. All scanning decisions flow from here.',
    context: 'Determines injection context (HTML body, JavaScript, attributes, etc.).',
    condition: 'Checks runtime state (WAF detected, encoding needed) to choose the right path.',
    payload: 'Contains actual XSS payloads to test against the target.',
    encoding: 'Applies transformations (URL, HTML entity, Unicode) to bypass filters.',
    waf_bypass: 'Specialized techniques for specific WAF vendors.',
    mutation: 'Modifies payloads (case swap, function swap) to evade detection.',
  };

  return (
    <div className="space-y-3">
      <div className="p-3 bg-zinc-800/50 rounded-lg">
        <div className="flex items-center gap-2 mb-2">
          {(() => {
            const Icon = nodeTypeIcons[node.type] || Code;
            return <Icon className={`w-5 h-5 ${nodeTypeColors[node.type]}`} />;
          })()}
          <span className="font-medium text-zinc-200">{node.name}</span>
        </div>
        
        <p className="text-xs text-zinc-400 mb-3">
          {explanations[node.type] || node.description || 'Strategy node'}
        </p>

        {node.condition && (
          <div className="mb-2">
            <span className="text-[10px] text-zinc-500 block mb-1">Condition:</span>
            <code className="text-xs bg-zinc-900 px-2 py-1 rounded text-cyan-400 font-mono">
              {node.condition}
            </code>
          </div>
        )}

        {node.config && Object.keys(node.config).length > 0 && (
          <div className="mb-2">
            <span className="text-[10px] text-zinc-500 block mb-1">Configuration:</span>
            <div className="text-xs bg-zinc-900 px-2 py-1 rounded font-mono text-zinc-400">
              {Object.entries(node.config).map(([k, v]) => (
                <div key={k}>
                  <span className="text-purple-400">{k}</span>: {JSON.stringify(v)}
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="flex items-center gap-4 text-[10px] text-zinc-500 mt-3 pt-2 border-t border-zinc-800">
          <span>Priority: {node.priority}</span>
          <span>Children: {node.children?.length || 0}</span>
          {node.success_count + node.failure_count > 0 && (
            <span className={node.success_rate > 0.5 ? 'text-green-400' : 'text-red-400'}>
              Success: {(node.success_rate * 100).toFixed(0)}%
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

// Strategy List Component
function StrategyList({ 
  onSelect, 
  selectedId 
}: { 
  onSelect: (tree: StrategyTree) => void;
  selectedId?: string;
}) {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newStrategyName, setNewStrategyName] = useState('');
  const [newStrategyDesc, setNewStrategyDesc] = useState('');

  const { data: trees, isLoading } = useQuery<StrategyTree[]>({
    queryKey: ['strategy-trees'],
    queryFn: () => api.get('/strategy/trees').then(res => res.data),
  });

  const createMutation = useMutation({
    mutationFn: (data: { name: string; description: string }) =>
      api.post('/strategy/trees', {
        name: data.name,
        description: data.description,
        tree_data: { root: { id: 'root', type: 'root', name: 'Root', children: [] } },
        version: '1.0',
        tags: [],
      }).then(res => res.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['strategy-trees'] });
      setShowCreateModal(false);
      setNewStrategyName('');
      setNewStrategyDesc('');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/strategy/trees/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['strategy-trees'] }),
  });

  const cloneMutation = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) =>
      api.post(`/strategy/trees/${id}/clone?new_name=${encodeURIComponent(name)}`).then(res => res.data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['strategy-trees'] }),
  });

  const activateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/strategy/trees/${id}/activate`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['strategy-trees'] }),
  });

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      await api.post('/strategy/trees/import', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      queryClient.invalidateQueries({ queryKey: ['strategy-trees'] });
    } catch (err) {
      console.error('Import failed:', err);
    }

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleExport = async (treeId: string) => {
    try {
      const res = await api.get(`/strategy/trees/${treeId}/export`);
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `strategy_${treeId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-32">
        <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Actions */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-3 py-2 bg-cyan-500 hover:bg-cyan-400 text-black text-sm font-medium rounded transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Strategy
        </button>
        <button
          onClick={() => fileInputRef.current?.click()}
          className="flex items-center gap-2 px-3 py-2 bg-zinc-700 hover:bg-zinc-600 text-sm rounded transition-colors"
        >
          <Upload className="w-4 h-4" />
          Import
        </button>
        <input
          ref={fileInputRef}
          type="file"
          accept=".json"
          onChange={handleImport}
          className="hidden"
        />
      </div>

      {/* Strategy List */}
      <div className="space-y-2">
        {trees?.map(tree => (
          <div
            key={tree.id}
            className={`p-3 rounded-lg border transition-all cursor-pointer ${
              selectedId === tree.id
                ? 'bg-cyan-500/10 border-cyan-500/50'
                : 'bg-zinc-800/50 border-zinc-800 hover:border-zinc-700'
            }`}
            onClick={() => onSelect(tree)}
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-zinc-200">{tree.name}</span>
                  {tree.is_default && (
                    <span className="text-[10px] px-1.5 py-0.5 bg-zinc-700 text-zinc-400 rounded">
                      Default
                    </span>
                  )}
                  {tree.is_active && (
                    <Star className="w-3 h-3 text-yellow-400" />
                  )}
                </div>
                {tree.description && (
                  <p className="text-xs text-zinc-500 mt-1">{tree.description}</p>
                )}
                <div className="flex items-center gap-3 mt-2 text-[10px] text-zinc-500">
                  <span>v{tree.version}</span>
                  <span>{tree.total_uses} uses</span>
                  <span className={tree.success_rate > 0.5 ? 'text-green-400' : 'text-zinc-400'}>
                    {(tree.success_rate * 100).toFixed(0)}% success
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-1">
                {!tree.is_active && (
                  <button
                    onClick={(e) => { e.stopPropagation(); activateMutation.mutate(tree.id); }}
                    className="p-1.5 text-zinc-500 hover:text-yellow-400 transition-colors"
                    title="Set as active"
                  >
                    <Star className="w-4 h-4" />
                  </button>
                )}
                <button
                  onClick={(e) => { e.stopPropagation(); handleExport(tree.id); }}
                  className="p-1.5 text-zinc-500 hover:text-cyan-400 transition-colors"
                  title="Export"
                >
                  <Download className="w-4 h-4" />
                </button>
                <button
                  onClick={(e) => { 
                    e.stopPropagation(); 
                    const name = prompt('New strategy name:', `${tree.name} (copy)`);
                    if (name) cloneMutation.mutate({ id: tree.id, name });
                  }}
                  className="p-1.5 text-zinc-500 hover:text-purple-400 transition-colors"
                  title="Clone"
                >
                  <Copy className="w-4 h-4" />
                </button>
                {!tree.is_default && (
                  <button
                    onClick={(e) => { 
                      e.stopPropagation(); 
                      if (confirm('Delete this strategy?')) deleteMutation.mutate(tree.id);
                    }}
                    className="p-1.5 text-zinc-500 hover:text-red-400 transition-colors"
                    title="Delete"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold text-zinc-200 mb-4">Create New Strategy</h3>
            <div className="space-y-4">
              <div>
                <label className="text-sm text-zinc-400 block mb-1">Name</label>
                <input
                  type="text"
                  value={newStrategyName}
                  onChange={(e) => setNewStrategyName(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm"
                  placeholder="My Custom Strategy"
                />
              </div>
              <div>
                <label className="text-sm text-zinc-400 block mb-1">Description</label>
                <textarea
                  value={newStrategyDesc}
                  onChange={(e) => setNewStrategyDesc(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm h-24 resize-none"
                  placeholder="Description of your strategy..."
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => createMutation.mutate({ name: newStrategyName, description: newStrategyDesc })}
                disabled={!newStrategyName.trim() || createMutation.isPending}
                className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-black text-sm font-medium rounded disabled:opacity-50 transition-colors"
              >
                {createMutation.isPending ? 'Creating...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// A/B Test Component
function ABTestPanel() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTestName, setNewTestName] = useState('');
  const [newTestDesc, setNewTestDesc] = useState('');
  const [strategyAId, setStrategyAId] = useState('');
  const [strategyBId, setStrategyBId] = useState('');
  const [targetScans, setTargetScans] = useState(10);

  const { data: tests, isLoading: testsLoading } = useQuery<ABTest[]>({
    queryKey: ['ab-tests'],
    queryFn: () => api.get('/strategy/ab-tests').then(res => res.data),
  });

  const { data: trees } = useQuery<StrategyTree[]>({
    queryKey: ['strategy-trees'],
    queryFn: () => api.get('/strategy/trees').then(res => res.data),
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => api.post('/strategy/ab-tests', data).then(res => res.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ab-tests'] });
      setShowCreateModal(false);
      setNewTestName('');
      setNewTestDesc('');
      setStrategyAId('');
      setStrategyBId('');
    },
  });

  const startMutation = useMutation({
    mutationFn: (id: string) => api.post(`/strategy/ab-tests/${id}/start`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['ab-tests'] }),
  });

  const cancelMutation = useMutation({
    mutationFn: (id: string) => api.post(`/strategy/ab-tests/${id}/cancel`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['ab-tests'] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/strategy/ab-tests/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['ab-tests'] }),
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'text-cyan-400 bg-cyan-500/20';
      case 'completed': return 'text-green-400 bg-green-500/20';
      case 'cancelled': return 'text-red-400 bg-red-500/20';
      default: return 'text-zinc-400 bg-zinc-700';
    }
  };

  if (testsLoading) {
    return (
      <div className="flex items-center justify-center h-32">
        <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Create Button */}
      <button
        onClick={() => setShowCreateModal(true)}
        className="flex items-center gap-2 px-3 py-2 bg-cyan-500 hover:bg-cyan-400 text-black text-sm font-medium rounded transition-colors"
      >
        <FlaskConical className="w-4 h-4" />
        New A/B Test
      </button>

      {/* Tests List */}
      <div className="space-y-3">
        {tests?.map(test => (
          <div key={test.id} className="p-4 bg-zinc-800/50 border border-zinc-800 rounded-lg">
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-medium text-zinc-200">{test.name}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded ${getStatusColor(test.status)}`}>
                    {test.status}
                  </span>
                </div>
                {test.description && (
                  <p className="text-xs text-zinc-500 mt-1">{test.description}</p>
                )}
              </div>
              <div className="flex items-center gap-1">
                {test.status === 'pending' && (
                  <button
                    onClick={() => startMutation.mutate(test.id)}
                    className="p-1.5 text-zinc-500 hover:text-green-400 transition-colors"
                    title="Start test"
                  >
                    <Play className="w-4 h-4" />
                  </button>
                )}
                {test.status === 'running' && (
                  <button
                    onClick={() => cancelMutation.mutate(test.id)}
                    className="p-1.5 text-zinc-500 hover:text-red-400 transition-colors"
                    title="Cancel test"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
                <button
                  onClick={() => { if (confirm('Delete this test?')) deleteMutation.mutate(test.id); }}
                  className="p-1.5 text-zinc-500 hover:text-red-400 transition-colors"
                  title="Delete"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Comparison */}
            <div className="grid grid-cols-2 gap-4">
              <div className={`p-3 rounded ${test.winner === 'a' ? 'bg-green-500/10 border border-green-500/30' : 'bg-zinc-900'}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-zinc-300">Strategy A</span>
                  {test.winner === 'a' && <Check className="w-4 h-4 text-green-400" />}
                </div>
                <p className="text-sm text-zinc-400 truncate">{test.strategy_a_name || test.strategy_a_id}</p>
                <div className="mt-2 text-xs text-zinc-500">
                  <span>Scans: {test.completed_scans_a}/{test.target_scans}</span>
                  {test.results_a?.vulns !== undefined && (
                    <span className="ml-2">Vulns: {test.results_a.vulns}</span>
                  )}
                </div>
              </div>
              <div className={`p-3 rounded ${test.winner === 'b' ? 'bg-green-500/10 border border-green-500/30' : 'bg-zinc-900'}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-zinc-300">Strategy B</span>
                  {test.winner === 'b' && <Check className="w-4 h-4 text-green-400" />}
                </div>
                <p className="text-sm text-zinc-400 truncate">{test.strategy_b_name || test.strategy_b_id}</p>
                <div className="mt-2 text-xs text-zinc-500">
                  <span>Scans: {test.completed_scans_b}/{test.target_scans}</span>
                  {test.results_b?.vulns !== undefined && (
                    <span className="ml-2">Vulns: {test.results_b.vulns}</span>
                  )}
                </div>
              </div>
            </div>

            {/* Progress Bar */}
            {test.status === 'running' && (
              <div className="mt-3">
                <div className="h-1 bg-zinc-700 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-cyan-500 transition-all"
                    style={{ 
                      width: `${Math.min(100, ((test.completed_scans_a + test.completed_scans_b) / (test.target_scans * 2)) * 100)}%` 
                    }}
                  />
                </div>
              </div>
            )}
          </div>
        ))}

        {tests?.length === 0 && (
          <div className="text-center text-zinc-500 py-8">
            <FlaskConical className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No A/B tests yet</p>
          </div>
        )}
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold text-zinc-200 mb-4">Create A/B Test</h3>
            <div className="space-y-4">
              <div>
                <label className="text-sm text-zinc-400 block mb-1">Test Name</label>
                <input
                  type="text"
                  value={newTestName}
                  onChange={(e) => setNewTestName(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm"
                  placeholder="Strategy comparison test"
                />
              </div>
              <div>
                <label className="text-sm text-zinc-400 block mb-1">Description</label>
                <input
                  type="text"
                  value={newTestDesc}
                  onChange={(e) => setNewTestDesc(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm"
                  placeholder="Optional description"
                />
              </div>
              <div>
                <label className="text-sm text-zinc-400 block mb-1">Strategy A</label>
                <select
                  value={strategyAId}
                  onChange={(e) => setStrategyAId(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm"
                >
                  <option value="">Select strategy...</option>
                  {trees?.map(t => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-sm text-zinc-400 block mb-1">Strategy B</label>
                <select
                  value={strategyBId}
                  onChange={(e) => setStrategyBId(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm"
                >
                  <option value="">Select strategy...</option>
                  {trees?.filter(t => t.id !== strategyAId).map(t => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-sm text-zinc-400 block mb-1">Target Scans per Strategy</label>
                <input
                  type="number"
                  value={targetScans}
                  onChange={(e) => setTargetScans(parseInt(e.target.value) || 10)}
                  min={1}
                  max={100}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => createMutation.mutate({
                  name: newTestName,
                  description: newTestDesc,
                  strategy_a_id: strategyAId,
                  strategy_b_id: strategyBId,
                  target_scans: targetScans,
                })}
                disabled={!newTestName.trim() || !strategyAId || !strategyBId || createMutation.isPending}
                className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-black text-sm font-medium rounded disabled:opacity-50 transition-colors"
              >
                {createMutation.isPending ? 'Creating...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function Strategy() {
  const [searchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState<TabType>('tree');
  const [simulationContext, setSimulationContext] = useState('html');
  const [simulationWaf, setSimulationWaf] = useState(false);
  const [simulationWafName, setSimulationWafName] = useState('');
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [selectedStrategy, setSelectedStrategy] = useState<StrategyTree | null>(null);
  
  const [scanIdInput, setScanIdInput] = useState('');
  const [loadedScanId, setLoadedScanId] = useState<string | null>(null);
  const [scanPathError, setScanPathError] = useState<string | null>(null);
  
  useEffect(() => {
    const scanIdFromUrl = searchParams.get('scanId');
    if (scanIdFromUrl && !loadedScanId) {
      setScanIdInput(scanIdFromUrl);
      setLoadedScanId(scanIdFromUrl);
    }
  }, [searchParams, loadedScanId]);

  const { data: tree, isLoading: treeLoading } = useQuery<StrategyTree>({
    queryKey: ['strategy-tree'],
    queryFn: () => api.get('/strategy/tree').then((res) => res.data),
  });
  
  const { data: scanPath, isLoading: scanPathLoading } = useQuery<ScanStrategyPath>({
    queryKey: ['scan-strategy-path', loadedScanId],
    queryFn: () => api.get(`/strategy/scan/${loadedScanId}`).then((res) => res.data),
    enabled: !!loadedScanId,
    retry: false,
  });

  const { data: contexts } = useQuery<{ contexts: any[] }>({
    queryKey: ['strategy-contexts'],
    queryFn: () => api.get('/strategy/contexts').then((res) => res.data),
  });

  const { data: encodings } = useQuery<{ encodings: any[] }>({
    queryKey: ['strategy-encodings'],
    queryFn: () => api.get('/strategy/encodings').then((res) => res.data),
  });

  const simulateMutation = useMutation<SimulationResult>({
    mutationFn: () =>
      api
        .post('/strategy/simulate', null, {
          params: {
            context_type: simulationContext,
            waf_detected: simulationWaf,
            waf_name: simulationWafName || undefined,
            max_actions: 15,
          },
        })
        .then((res) => res.data),
  });
  
  const handleScanSearch = async () => {
    if (!scanIdInput.trim()) return;
    setScanPathError(null);
    
    try {
      const res = await api.get(`/strategy/scan/${scanIdInput.trim()}`);
      if (res.data && res.data.id) {
        setLoadedScanId(scanIdInput.trim());
      } else {
        setScanPathError('No strategy data for this scan');
      }
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      if (typeof detail === 'object' && detail.reason) {
        setScanPathError(detail.reason === 'scan_not_found' 
          ? 'Scan not found' 
          : 'No strategy data for this scan');
      } else {
        setScanPathError(detail || 'Failed to load scan strategy');
      }
      setLoadedScanId(null);
    }
  };
  
  const clearLoadedScan = () => {
    setLoadedScanId(null);
    setScanIdInput('');
    setScanPathError(null);
  };

  const { visitedNodes, nodeStatuses, activeActions } = useMemo(() => {
    const visited = new Set<string>();
    const statuses = new Map<string, NodeStatus>();
    let actions: SimulationAction[] = [];
    
    if (scanPath) {
      actions = scanPath.actions || [];
      (scanPath.visited_nodes || []).forEach(nodeId => visited.add(nodeId));
      Object.entries(scanPath.node_statuses || {}).forEach(([nodeId, status]) => {
        statuses.set(nodeId, status as NodeStatus);
      });
    } else if (simulateMutation.data) {
      actions = simulateMutation.data.actions;
      actions.forEach(action => {
        if (action.node_id) {
          visited.add(action.node_id);
        }
      });
      actions.forEach((action, idx) => {
        if (!action.node_id) return;
        if (action.action_type === 'switch_context' || 
            action.action_type === 'encode' ||
            action.metadata?.action === 'mutate') {
          statuses.set(action.node_id, 'pivot');
        } else if (action.action_type === 'test_payload') {
          const nextAction = actions[idx + 1];
          if (nextAction?.action_type === 'switch_context') {
            statuses.set(action.node_id, 'failed');
          } else {
            statuses.set(action.node_id, 'visited');
          }
        }
      });
    }

    return { 
      visitedNodes: visited, 
      nodeStatuses: statuses,
      activeActions: actions,
    };
  }, [simulateMutation.data, scanPath]);

  const findNode = (node: StrategyNode, id: string): StrategyNode | null => {
    if (node.id === id) return node;
    for (const child of node.children || []) {
      const found = findNode(child, id);
      if (found) return found;
    }
    return null;
  };

  const selectedNodeData = selectedNode && tree?.root 
    ? findNode(tree.root, selectedNode) 
    : null;

  const tabs = [
    { id: 'tree' as const, label: 'Decision Tree', icon: GitBranch },
    { id: 'strategies' as const, label: 'My Strategies', icon: Edit3 },
    { id: 'ab-tests' as const, label: 'A/B Tests', icon: FlaskConical },
  ];

  return (
    <>
      <PageHeader 
        title="Strategy" 
        subtitle="Pentesting Task Trees - Adaptive scanning strategy"
        badge={{ text: 'PTT', className: 'bg-cyan-500/20 text-cyan-400' }}
      />

      {/* Tabs */}
      <div className="px-6 border-b border-zinc-800">
        <div className="flex gap-1">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'text-cyan-400 border-cyan-400'
                  : 'text-zinc-500 border-transparent hover:text-zinc-300'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <div className="brs-content">
        {activeTab === 'tree' && (
          <div className="grid grid-cols-3 gap-6">
            {/* Strategy Tree */}
            <div className="col-span-2 brs-card">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-zinc-200 flex items-center gap-2">
                  <GitBranch className="w-5 h-5 text-cyan-400" />
                  Decision Tree
                </h2>
                {tree && (
                  <div className="flex items-center gap-4 text-sm text-zinc-500">
                    <span>v{tree.version}</span>
                    <span>{tree.total_uses} uses</span>
                    <span className={tree.success_rate > 0.5 ? 'text-green-400' : 'text-zinc-400'}>
                      {(tree.success_rate * 100).toFixed(0)}% success
                    </span>
                  </div>
                )}
              </div>

              {treeLoading ? (
                <div className="flex items-center justify-center h-64">
                  <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
                </div>
              ) : tree?.root ? (
                <div className="border border-zinc-800 rounded-lg p-2 max-h-[400px] overflow-y-auto">
                  <TreeNode 
                    node={tree.root}
                    visitedNodes={visitedNodes}
                    nodeStatuses={nodeStatuses}
                    selectedNode={selectedNode}
                    onNodeSelect={setSelectedNode}
                  />
                </div>
              ) : (
                <div className="text-center text-zinc-500 py-12">
                  No strategy tree loaded
                </div>
              )}

              {/* Legend */}
              <div className="mt-4 pt-4 border-t border-zinc-800">
                <div className="flex flex-wrap gap-4 text-xs">
                  {Object.entries(nodeTypeIcons).map(([type, Icon]) => (
                    <div key={type} className="flex items-center gap-1.5">
                      <Icon className={`w-3.5 h-3.5 ${nodeTypeColors[type]}`} />
                      <span className="text-zinc-500 capitalize">{type.replace('_', ' ')}</span>
                    </div>
                  ))}
                </div>
              </div>

              {(scanPath || simulateMutation.data) && activeActions.length > 0 && (
                <EvolutionTimeline actions={activeActions} />
              )}
            </div>

            {/* Right Panel */}
            <div className="space-y-4">
              {/* Load from Scan */}
              <div className="brs-card">
                <h3 className="text-sm font-semibold text-zinc-200 mb-4 flex items-center gap-2">
                  <Search className="w-4 h-4 text-cyan-400" />
                  Load from Scan
                </h3>
                
                <div className="space-y-3">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={scanIdInput}
                      onChange={(e) => setScanIdInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleScanSearch()}
                      placeholder="Enter scan ID..."
                      className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm font-mono"
                    />
                    <button
                      onClick={handleScanSearch}
                      disabled={!scanIdInput.trim() || scanPathLoading}
                      className="px-3 py-2 bg-zinc-700 hover:bg-zinc-600 disabled:opacity-50 rounded transition-colors"
                    >
                      {scanPathLoading ? (
                        <RefreshCw className="w-4 h-4 animate-spin" />
                      ) : (
                        <Search className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                  
                  {scanPathError && (
                    <div className="text-xs text-red-400 bg-red-500/10 px-3 py-2 rounded">
                      {scanPathError}
                    </div>
                  )}
                  
                  {scanPath && (
                    <div className="bg-cyan-500/10 border border-cyan-500/30 rounded p-3">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <History className="w-4 h-4 text-cyan-400" />
                          <span className="text-sm font-medium text-cyan-400">
                            Scan {scanPath.scan_id}
                          </span>
                        </div>
                        <button
                          onClick={clearLoadedScan}
                          className="text-xs text-zinc-500 hover:text-zinc-300"
                        >
                          Clear
                        </button>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div>
                          <span className="text-zinc-500">Context:</span>
                          <span className="ml-1 text-zinc-300">{scanPath.initial_context}</span>
                        </div>
                        <div>
                          <span className="text-zinc-500">Actions:</span>
                          <span className="ml-1 text-zinc-300">{scanPath.statistics.total_actions}</span>
                        </div>
                      </div>
                      
                      <a
                        href={`/scan/${scanPath.scan_id}`}
                        className="mt-2 flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
                      >
                        <ExternalLink className="w-3 h-3" />
                        View scan details
                      </a>
                    </div>
                  )}
                </div>
              </div>
              
              {/* Simulation */}
              <div className="brs-card">
                <h3 className="text-sm font-semibold text-zinc-200 mb-4 flex items-center gap-2">
                  <Play className="w-4 h-4 text-cyan-400" />
                  Simulate Strategy
                </h3>

                <div className="space-y-3">
                  <div>
                    <label className="text-xs text-zinc-500 block mb-1">Context</label>
                    <select
                      value={simulationContext}
                      onChange={(e) => setSimulationContext(e.target.value)}
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm"
                    >
                      {contexts?.contexts.map((ctx) => (
                        <option key={ctx.id} value={ctx.id}>
                          {ctx.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="waf-detected"
                      checked={simulationWaf}
                      onChange={(e) => setSimulationWaf(e.target.checked)}
                      className="rounded border-zinc-700"
                    />
                    <label htmlFor="waf-detected" className="text-sm text-zinc-400">
                      WAF Detected
                    </label>
                  </div>

                  {simulationWaf && (
                    <div>
                      <label className="text-xs text-zinc-500 block mb-1">WAF Name</label>
                      <input
                        type="text"
                        value={simulationWafName}
                        onChange={(e) => setSimulationWafName(e.target.value)}
                        placeholder="e.g., Cloudflare"
                        className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm"
                      />
                    </div>
                  )}

                  <button
                    onClick={() => simulateMutation.mutate()}
                    disabled={simulateMutation.isPending}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-black font-medium rounded transition-colors"
                  >
                    {simulateMutation.isPending ? (
                      <RefreshCw className="w-4 h-4 animate-spin" />
                    ) : (
                      <Play className="w-4 h-4" />
                    )}
                    Run Simulation
                  </button>
                </div>
              </div>

              {/* Node Details */}
              <div className="brs-card">
                <h3 className="text-sm font-semibold text-zinc-200 mb-3 flex items-center gap-2">
                  <Eye className="w-4 h-4 text-zinc-400" />
                  Node Details
                </h3>
                <NodeExplanation node={selectedNodeData} />
              </div>

              {/* Encodings */}
              <div className="brs-card">
                <h3 className="text-sm font-semibold text-zinc-200 mb-3 flex items-center gap-2">
                  <Code className="w-4 h-4 text-purple-400" />
                  Encodings
                </h3>
                <div className="space-y-2">
                  {encodings?.encodings.map((enc) => (
                    <div key={enc.id} className="text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-zinc-300">{enc.name}</span>
                        <code className="text-purple-400 font-mono text-[10px]">
                          {enc.example}
                        </code>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'strategies' && (
          <div className="grid grid-cols-3 gap-6">
            <div className="col-span-2">
              <div className="brs-card">
                <h2 className="text-lg font-semibold text-zinc-200 mb-4 flex items-center gap-2">
                  <Edit3 className="w-5 h-5 text-cyan-400" />
                  Custom Strategies
                </h2>
                <StrategyList 
                  onSelect={setSelectedStrategy}
                  selectedId={selectedStrategy?.id}
                />
              </div>
            </div>
            <div className="space-y-4">
              {selectedStrategy && (
                <div className="brs-card">
                  <h3 className="text-sm font-semibold text-zinc-200 mb-3">Selected Strategy</h3>
                  <div className="space-y-2 text-sm">
                    <div>
                      <span className="text-zinc-500">Name:</span>
                      <span className="ml-2 text-zinc-200">{selectedStrategy.name}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500">Version:</span>
                      <span className="ml-2 text-zinc-200">{selectedStrategy.version}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500">Uses:</span>
                      <span className="ml-2 text-zinc-200">{selectedStrategy.total_uses}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500">Success Rate:</span>
                      <span className={`ml-2 ${selectedStrategy.success_rate > 0.5 ? 'text-green-400' : 'text-zinc-400'}`}>
                        {(selectedStrategy.success_rate * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                </div>
              )}
              
              <div className="brs-card bg-cyan-500/5 border-cyan-500/20">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-cyan-400 mt-0.5" />
                  <div className="text-xs text-zinc-400">
                    <p className="mb-2">
                      Create custom strategies or clone existing ones.
                    </p>
                    <p>
                      Export strategies as JSON for sharing or backup.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'ab-tests' && (
          <div className="grid grid-cols-3 gap-6">
            <div className="col-span-2">
              <div className="brs-card">
                <h2 className="text-lg font-semibold text-zinc-200 mb-4 flex items-center gap-2">
                  <FlaskConical className="w-5 h-5 text-cyan-400" />
                  A/B Testing
                </h2>
                <ABTestPanel />
              </div>
            </div>
            <div className="space-y-4">
              <div className="brs-card bg-cyan-500/5 border-cyan-500/20">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-cyan-400 mt-0.5" />
                  <div className="text-xs text-zinc-400">
                    <p className="mb-2">
                      <strong className="text-cyan-400">A/B Testing</strong> allows you to compare 
                      two strategies side by side.
                    </p>
                    <p className="mb-2">
                      Each strategy will be used for the specified number of scans, 
                      and the winner is determined by vulnerability detection rate.
                    </p>
                    <p>
                      Start a test, then run scans normally - the system will 
                      automatically alternate between strategies.
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="brs-card">
                <h3 className="text-sm font-semibold text-zinc-200 mb-3 flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-purple-400" />
                  Metrics Compared
                </h3>
                <ul className="text-xs text-zinc-400 space-y-1">
                  <li>• Vulnerabilities found</li>
                  <li>• Success rate (scans with findings)</li>
                  <li>• Average scan duration</li>
                  <li>• Payload efficiency</li>
                </ul>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

export default Strategy;
