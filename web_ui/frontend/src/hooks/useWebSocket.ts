/**
 * Project: BRS-XSS Web UI
 * Company: EasyProTech LLC (www.easypro.tech)
 */

import { useCallback, useRef, useEffect } from 'react'
import { useScanStore } from '../store/scanStore'
import type { WSMessage, ScanProgress, VulnerabilityInfo } from '../types'

const DEFAULT_RECONNECT_MS = 3000
const PING_INTERVAL_MS = 30000

function getDefaultWsUrl(): string {
  if (typeof window === 'undefined') return 'ws://localhost/ws'
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${window.location.host}/ws`
}

const WS_URL = import.meta.env.VITE_WS_URL || getDefaultWsUrl()

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<number>()
  const pingIntervalRef = useRef<number>()
  const shouldReconnectRef = useRef(true)
  const { updateProgress, addVulnerability } = useScanStore()

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
            case 'progress':
              updateProgress(message.data as ScanProgress)
              break
            case 'vulnerability':
              if (message.scan_id) {
                addVulnerability(message.scan_id, message.data as VulnerabilityInfo)
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
  }, [updateProgress, addVulnerability])

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

