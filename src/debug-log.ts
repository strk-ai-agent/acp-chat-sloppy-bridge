import fs from "fs"
import path from "path"

export interface DebugLoggerOptions {
  enabled: boolean
  filePath: string
  onError?: (error: unknown) => void
}

/**
 * Create a best-effort append-only debug logger.
 * Debug logging must never interrupt normal bridge processing.
 */
export function createDebugLogger(options: DebugLoggerOptions): (message: string) => void {
  let ready = false
  let disabled = !options.enabled
  let errorReported = false

  const reportError = (error: unknown) => {
    if (errorReported) return
    errorReported = true
    options.onError?.(error)
  }

  return (message: string) => {
    if (disabled) return
    try {
      if (!ready) {
        fs.mkdirSync(path.dirname(options.filePath), { recursive: true, mode: 0o700 })
        ready = true
      }
      const timestamp = new Date().toISOString()
      const descriptor = fs.openSync(options.filePath, "a", 0o600)
      try {
        fs.fchmodSync(descriptor, 0o600)
        fs.writeSync(descriptor, `[${timestamp}] ${message}\n`, undefined, "utf8")
      } finally {
        fs.closeSync(descriptor)
      }
    } catch (error) {
      disabled = true
      reportError(error)
    }
  }
}
