/**
 * Project: BRS-XSS Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 */

import { create } from 'zustand'
import type { ScanProgress, VulnerabilityInfo } from '../types'

interface ScanState {
  // Active scans progress
  activeScans: Record<string, ScanProgress>
  
  // Real-time vulnerabilities
  liveVulnerabilities: Record<string, VulnerabilityInfo[]>
  
  // Actions
  updateProgress: (progress: ScanProgress) => void
  addVulnerability: (scanId: string, vuln: VulnerabilityInfo) => void
  clearScan: (scanId: string) => void
  clearAll: () => void
}

export const useScanStore = create<ScanState>((set) => ({
  activeScans: {},
  liveVulnerabilities: {},
  
  updateProgress: (progress) => set((state) => ({
    activeScans: {
      ...state.activeScans,
      [progress.scan_id]: progress
    }
  })),
  
  addVulnerability: (scanId, vuln) => set((state) => ({
    liveVulnerabilities: {
      ...state.liveVulnerabilities,
      [scanId]: [...(state.liveVulnerabilities[scanId] || []), vuln]
    }
  })),
  
  clearScan: (scanId) => set((state) => {
    const { [scanId]: _, ...activeScans } = state.activeScans
    const { [scanId]: __, ...liveVulnerabilities } = state.liveVulnerabilities
    return { activeScans, liveVulnerabilities }
  }),
  
  clearAll: () => set({ activeScans: {}, liveVulnerabilities: {} })
}))

