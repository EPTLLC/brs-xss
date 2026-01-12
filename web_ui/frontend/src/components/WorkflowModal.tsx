import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { 
  X, 
  ShoppingCart, 
  FileText, 
  Code, 
  Server, 
  Search, 
  Settings,
  Play,
  ChevronRight
} from 'lucide-react';
import { api } from '../api/client';

interface WorkflowStep {
  type: string;
  context?: string;
  target?: string;
  mode?: string;
  depth?: number;
  blind?: boolean;
  format?: string;
}

interface Workflow {
  id: string;
  name: string;
  description: string | null;
  category: string | null;
  is_preset: boolean;
  steps: WorkflowStep[];
  settings: Record<string, any> | null;
  tags: string[];
  use_count: number;
}

interface WorkflowModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelect: (workflow: Workflow) => void;
}

const categoryIcons: Record<string, typeof ShoppingCart> = {
  ecommerce: ShoppingCart,
  blog: FileText,
  spa: Code,
  api: Server,
  recon: Search,
  custom: Settings,
};

const categoryColors: Record<string, string> = {
  ecommerce: 'text-emerald-400',
  blog: 'text-blue-400',
  spa: 'text-purple-400',
  api: 'text-orange-400',
  recon: 'text-cyan-400',
  custom: 'text-zinc-400',
};

export const WorkflowModal: React.FC<WorkflowModalProps> = ({
  isOpen,
  onClose,
  onSelect,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedWorkflow, setSelectedWorkflow] = useState<Workflow | null>(null);

  const { data: workflows, isLoading } = useQuery<Workflow[]>({
    queryKey: ['workflows', selectedCategory],
    queryFn: () => {
      const params = selectedCategory ? `?category=${selectedCategory}` : '';
      return api.get(`/api/workflows${params}`).then(res => res.data);
    },
    enabled: isOpen,
  });

  const { data: categories } = useQuery<{ categories: { id: string; name: string }[] }>({
    queryKey: ['workflow-categories'],
    queryFn: () => api.get('/api/workflows/categories').then(res => res.data),
    enabled: isOpen,
  });

  useEffect(() => {
    if (!isOpen) {
      setSelectedCategory(null);
      setSelectedWorkflow(null);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSelect = (workflow: Workflow) => {
    // Mark as used
    api.post(`/api/workflows/${workflow.id}/use`).catch(() => {});
    onSelect(workflow);
    onClose();
  };

  const getStepDescription = (step: WorkflowStep): string => {
    switch (step.type) {
      case 'crawl':
        return `Crawl ${step.target || 'all'} (depth: ${step.depth || 2})`;
      case 'scan':
        return `Scan ${step.context || 'all'} [${step.mode || 'standard'}]${step.blind ? ' + Blind' : ''}`;
      case 'report':
        return `Generate ${step.format || 'PDF'} report`;
      default:
        return step.type;
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl w-full max-w-4xl max-h-[80vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-zinc-100">Scan Workflows</h2>
            <p className="text-sm text-zinc-500">Select a predefined workflow or create your own</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-zinc-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-zinc-400" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-hidden flex">
          {/* Categories Sidebar */}
          <div className="w-48 border-r border-zinc-800 p-4 space-y-1">
            <button
              onClick={() => setSelectedCategory(null)}
              className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                selectedCategory === null
                  ? 'bg-cyan-500/20 text-cyan-400'
                  : 'text-zinc-400 hover:bg-zinc-800'
              }`}
            >
              All Workflows
            </button>
            {categories?.categories.map((cat) => {
              const Icon = categoryIcons[cat.id] || Settings;
              return (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCategory(cat.id)}
                  className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-2 ${
                    selectedCategory === cat.id
                      ? 'bg-cyan-500/20 text-cyan-400'
                      : 'text-zinc-400 hover:bg-zinc-800'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${categoryColors[cat.id] || ''}`} />
                  {cat.name}
                </button>
              );
            })}
          </div>

          {/* Workflows List */}
          <div className="flex-1 overflow-y-auto p-4">
            {isLoading ? (
              <div className="flex items-center justify-center h-full">
                <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full" />
              </div>
            ) : workflows?.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-zinc-500">
                <Settings className="w-12 h-12 mb-3 opacity-50" />
                <p>No workflows found</p>
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-3">
                {workflows?.map((workflow) => {
                  const Icon = categoryIcons[workflow.category || 'custom'] || Settings;
                  const isSelected = selectedWorkflow?.id === workflow.id;
                  
                  return (
                    <div
                      key={workflow.id}
                      onClick={() => setSelectedWorkflow(workflow)}
                      className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                        isSelected
                          ? 'border-cyan-500 bg-cyan-500/10'
                          : 'border-zinc-800 bg-zinc-800/50 hover:border-zinc-700'
                      }`}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Icon className={`w-5 h-5 ${categoryColors[workflow.category || 'custom']}`} />
                          <span className="font-medium text-zinc-200">{workflow.name}</span>
                        </div>
                        {workflow.is_preset && (
                          <span className="text-[10px] px-1.5 py-0.5 bg-cyan-500/20 text-cyan-400 rounded">
                            PRESET
                          </span>
                        )}
                      </div>
                      
                      {workflow.description && (
                        <p className="text-xs text-zinc-500 mb-3 line-clamp-2">
                          {workflow.description}
                        </p>
                      )}

                      {/* Steps Preview */}
                      <div className="space-y-1">
                        {workflow.steps.slice(0, 3).map((step, i) => (
                          <div key={i} className="flex items-center gap-1 text-xs text-zinc-400">
                            <ChevronRight className="w-3 h-3 text-zinc-600" />
                            {getStepDescription(step)}
                          </div>
                        ))}
                        {workflow.steps.length > 3 && (
                          <div className="text-xs text-zinc-600">
                            +{workflow.steps.length - 3} more steps
                          </div>
                        )}
                      </div>

                      {/* Tags */}
                      {workflow.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-3">
                          {workflow.tags.slice(0, 4).map((tag, i) => (
                            <span
                              key={i}
                              className="text-[10px] px-1.5 py-0.5 bg-zinc-800 text-zinc-500 rounded"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Usage Stats */}
                      {workflow.use_count > 0 && (
                        <div className="mt-2 text-[10px] text-zinc-600">
                          Used {workflow.use_count} time{workflow.use_count !== 1 ? 's' : ''}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-zinc-800 flex items-center justify-between">
          <div className="text-sm text-zinc-500">
            {selectedWorkflow ? (
              <span className="text-cyan-400">
                Selected: {selectedWorkflow.name}
              </span>
            ) : (
              'Select a workflow to apply'
            )}
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={() => selectedWorkflow && handleSelect(selectedWorkflow)}
              disabled={!selectedWorkflow}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:bg-zinc-700 disabled:text-zinc-500 text-black font-medium rounded-lg transition-colors"
            >
              <Play className="w-4 h-4" />
              Apply Workflow
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WorkflowModal;
