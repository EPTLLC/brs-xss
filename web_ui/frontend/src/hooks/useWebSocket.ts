/**
 * Project: BRS-XSS Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 */

import { useCallback, useRef, useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useScanStore } from '../store/scanStore'
import type { WSMessage, ScanProgress, VulnerabilityInfo } from '../types'

const DEFAULT_RECONNECT_MS = 3000
const PING_INTERVAL_MS = 30000

function getDefaultWsUrl(): string {
  if (typeof window === 'undefined') return 'ws://localhost:8000/ws'
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const hostname = window.location.hostname
  // In dev mode, frontend is on 5173 but backend is on 8000
  // In production, both are on the same port (proxied)
  const port = window.location.port === '5173' ? '8000' : window.location.port
  return `${proto}://${hostname}:${port}/ws`
}

const WS_URL = import.meta.env.VITE_WS_URL || getDefaultWsUrl()

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<number>()
  const pingIntervalRef = useRef<number>()
  const shouldReconnectRef = useRef(true)
  const { updateProgress, addVulnerability } = useScanStore()
  const queryClient = useQueryClient()

  const connect = useCallback(() => {
    shouldReconnectRef.current = true
    if (
      wsRef.current?.readyState === WebSocket.OPEN ||
      wsRef.current?.readyState === WebSocket.CONNECTING
    ) {
      return
    }

    try {
      wsRef.current = new WebSocket(WS_URL)

      wsRef.current.onopen = () => {
        console.log('WebSocket connected')
        if (reconnectTimeoutRef.current) {
          clearTimeout(reconnectTimeoutRef.current)
        }
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current)
        }
        pingIntervalRef.current = window.setInterval(() => {
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify({ type: 'ping' }))
          }
        }, PING_INTERVAL_MS)
      }

      wsRef.current.onmessage = (event) => {
        try {
          const message: WSMessage = JSON.parse(event.data)
          
          switch (message.type) {
            case 'progress': {
              const progress = message.data as ScanProgress
              updateProgress(progress)
              
              // Invalidate scan query when status changes to completed/failed
              if (progress.status === 'completed' || progress.status === 'failed') {
                queryClient.invalidateQueries({ queryKey: ['scan', progress.scan_id] })
                queryClient.invalidateQueries({ queryKey: ['scans'] })
                queryClient.invalidateQueries({ queryKey: ['dashboard'] })
              }
              break
            }
            case 'vulnerability':
              if (message.scan_id) {
                addVulnerability(message.scan_id, message.data as VulnerabilityInfo)
                // Invalidate scan query to refresh vulnerability count
                queryClient.invalidateQueries({ queryKey: ['scan', message.scan_id] })
              }
              break
            case 'pong':
              // Connection alive
              break
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message', e)
        }
      }

      wsRef.current.onclose = () => {
        console.log('WebSocket disconnected, reconnecting...')
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current)
        }
        if (!shouldReconnectRef.current) return
        reconnectTimeoutRef.current = window.setTimeout(connect, DEFAULT_RECONNECT_MS)
      }

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error)
      }
    } catch (e) {
      console.error('Failed to connect WebSocket:', e)
      if (!shouldReconnectRef.current) return
      reconnectTimeoutRef.current = window.setTimeout(connect, DEFAULT_RECONNECT_MS)
    }
  }, [updateProgress, addVulnerability, queryClient])

  const disconnect = useCallback(() => {
    shouldReconnectRef.current = false
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
    }
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current)
    }
    wsRef.current?.close()
    wsRef.current = null
  }, [])

  useEffect(() => {
    return () => disconnect()
  }, [disconnect])

  return { connect, disconnect }
}

