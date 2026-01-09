import net from 'node:net'
import stream from 'node:stream'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

type Destroyable = {
  destroySoon?: () => void
  destroy: () => void
  end: () => void
  writableEnded?: boolean
  destroyed?: boolean
}

const attachDestroySoon = (proto: Destroyable | undefined) => {
  if (!proto || typeof proto.destroySoon === 'function') {
    return
  }
  proto.destroySoon = function destroySoonShim(this: Destroyable) {
    if (!this.writableEnded) {
      this.end()
    }
    if (!this.destroyed) {
      this.destroy()
    }
  }
}

attachDestroySoon(net.Socket?.prototype as Destroyable | undefined)
attachDestroySoon(stream.Duplex?.prototype as Destroyable | undefined)

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
})

