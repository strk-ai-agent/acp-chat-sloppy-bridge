#!/usr/bin/env bun
/**
 * Web Connector for OpenCode Chat Bridge
 *
 * Serves an embeddable chat widget and a WebSocket endpoint.
 * The widget works in two modes:
 *   - "widget"   : floating bubble + popup panel (default)
 *   - "embedded"  : fills a container div, no bubble
 *
 * Usage:
 *   bun connectors/web.ts
 *
 * Embed (widget mode):
 *   <script src="http://your-server:3420/widget.js"></script>
 *
 * Embed (flat / embedded mode):
 *   <div id="chat" style="height:600px"></div>
 *   <script>window.OpenCodeWidget={mode:"embedded",container:"#chat"}</script>
 *   <script src="http://your-server:3420/widget.js"></script>
 *
 * Standalone full-page chat:
 *   http://your-server:3420/chat
 *
 * Environment variables:
 *   WEB_PORT            - Server port (default: 3420)
 *   WEB_HOST            - Bind address (default: 0.0.0.0)
 *   WEB_ALLOWED_ORIGINS - Comma-separated origins for CORS (default: *)
 *   WEB_TRIGGER         - Trigger prefix override (default: from config)
 */

import { readFileSync, existsSync } from "fs"
import { networkInterfaces } from "os"
import { join } from "path"
import type { Server, ServerWebSocket } from "bun"
import {
  ACPClient,
  getConfig,
  BaseConnector,
  type BaseSession,
  ToolActivityController,
  shouldShowToolOutput,
  sanitizeServerPaths,
  extractImagePaths,
  removeImageMarkers,
  stripThinkBlocks,
  extractDocPaths,
  removeDocMarkers,
} from "../src"
import { diagnoseEmptyResponse } from "../src/acp-response-diagnostics"
import { validateWebPromptImages, type WebPromptImage } from "../src/web-image-input"

// =============================================================================
// Configuration
// =============================================================================

const config = getConfig()
const webCfg = config.web || {} as any
const WEB_PORT = parseInt(process.env.WEB_PORT || String(webCfg.port || 3420), 10)
const WEB_HOST = process.env.WEB_HOST || webCfg.host || "0.0.0.0"
const ALLOWED_ORIGINS = process.env.WEB_ALLOWED_ORIGINS
  ? process.env.WEB_ALLOWED_ORIGINS.split(",").map((s) => s.trim())
  : (webCfg.allowedOrigins || ["*"])
const TRIGGER = process.env.WEB_TRIGGER || config.trigger
const BOT_NAME = config.botName || "OpenCode"
const WEB_ATTACHMENTS = config.web.attachments
const SESSION_RETENTION_DAYS = parseInt(
  process.env.SESSION_RETENTION_DAYS || "7",
  10,
)
const RATE_LIMIT_SECONDS = 2
const MAX_WEB_TEXT_CHARS = 100_000

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
}

function inlineJson(value: unknown): string {
  return JSON.stringify(value).replaceAll("<", "\\u003c")
}

/**
 * Detect a reachable LAN IP so logs/snippets show something
 * useful instead of localhost.
 */
function getLanIP(): string {
  const nets = networkInterfaces()
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === "IPv4" && !net.internal) return net.address
    }
  }
  return "127.0.0.1"
}

/** Public base URL shown in logs and example snippets. */
const WEB_PUBLIC_URL =
  process.env.WEB_PUBLIC_URL ||
  webCfg.publicUrl ||
  `http://${WEB_HOST === "0.0.0.0" ? getLanIP() : WEB_HOST}:${WEB_PORT}`

// =============================================================================
// Types
// =============================================================================

interface WebSession extends BaseSession {}

interface WSData {
  clientId: string
}

// =============================================================================
// WebConnector
// =============================================================================

export class WebConnector extends BaseConnector<WebSession> {
  private server: Server | null = null
  private wsClients = new Map<string, ServerWebSocket<WSData>>()
  private widgetSource = ""
  private faviconSource = ""

  constructor() {
    super({
      connector: "web",
      trigger: TRIGGER,
      botName: BOT_NAME,
      rateLimitSeconds: RATE_LIMIT_SECONDS,
      sessionRetentionDays: SESSION_RETENTION_DAYS,
    })
  }

  // ---------------------------------------------------------------------------
  // BaseConnector abstract implementations
  // ---------------------------------------------------------------------------

  async start(): Promise<void> {
    this.logStartup()
    await this.cleanupSessions()

    // Load pure state helpers and the safe renderer before the widget runtime.
    const statePath = join(import.meta.dir, "web-widget-state.js")
    const rendererPath = join(import.meta.dir, "web-message-renderer.js")
    const widgetPath = join(import.meta.dir, "web-widget.js")
    const faviconPath = join(import.meta.dir, "favicon.svg")
    if (
      !existsSync(statePath) || !existsSync(rendererPath) ||
      !existsSync(widgetPath) || !existsSync(faviconPath)
    ) {
      console.error(`Error: Widget source files not found in ${import.meta.dir}`)
      process.exit(1)
    }
    const serverWidgetConfig = `window.OpenCodeWidgetServerConfig = ${inlineJson({
      title: BOT_NAME,
      attachments: WEB_ATTACHMENTS,
    })};`
    this.widgetSource = [
      serverWidgetConfig,
      ...[statePath, rendererPath, widgetPath]
        .map((filePath) => readFileSync(filePath, "utf-8")),
    ].join("\n")
    this.faviconSource = readFileSync(faviconPath, "utf-8")

    const connector = this
    this.server = Bun.serve<WSData>({
      port: WEB_PORT,
      hostname: WEB_HOST,

      fetch(req, server) {
        return connector.handleHttp(req, server)
      },

      websocket: {
        maxPayloadLength: WEB_ATTACHMENTS.enabled
          ? Math.ceil(WEB_ATTACHMENTS.maxFileBytes * 4 / 3) * WEB_ATTACHMENTS.maxFilesPerMessage + 128 * 1024
          : 1024 * 1024,
        open(ws) {
          connector.onWsOpen(ws)
        },
        message(ws, msg) {
          connector.onWsMessage(
            ws,
            typeof msg === "string" ? msg : msg.toString(),
          )
        },
        close(ws) {
          connector.onWsClose(ws)
        },
      },
    })

    this.log(`Server running on ${WEB_PUBLIC_URL}`)
    this.log(`Full page:  ${WEB_PUBLIC_URL}/chat`)
    this.log(`Test page:  ${WEB_PUBLIC_URL}/test`)
    this.log(
      `Embed:  <script src="${WEB_PUBLIC_URL}/widget.js"><\/script>`,
    )
    const originsInfo = ALLOWED_ORIGINS.includes("*") ? "any origin" : ALLOWED_ORIGINS.join(", ")
    this.log(`Security:  origins=${originsInfo}`)
    this.startSessionExpiryLoop()
  }

  async stop(): Promise<void> {
    this.log("Stopping...")
    await this.disconnectAllSessions()
    this.wsClients.clear()
    if (this.server) this.server.stop()
    this.log("Stopped.")
  }

  async sendMessage(clientId: string, text: string): Promise<void> {
    this.wsSend(clientId, { type: "response", text })
  }

  // ---------------------------------------------------------------------------
  // HTTP
  // ---------------------------------------------------------------------------

  private handleHttp(
    req: Request,
    server: Server,
  ): Response | undefined {
    const url = new URL(req.url)
    const cors = this.corsHeaders(req)

    // Preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors })
    }

    // WebSocket upgrade
    if (url.pathname === "/ws") {
      // -- Origin check --
      const origin = req.headers.get("origin")
      if (
        !ALLOWED_ORIGINS.includes("*") &&
        origin &&
        !ALLOWED_ORIGINS.includes(origin)
      ) {
        this.log(`[WS] Rejected origin: ${origin}`)
        return new Response("Origin not allowed", { status: 403, headers: cors })
      }


      const clientId =
        url.searchParams.get("clientId") || crypto.randomUUID()
      const ok = server.upgrade(req, { data: { clientId } })
      if (ok) return undefined
      return new Response("WebSocket upgrade failed", { status: 400 })
    }

    // Favicon
    if (url.pathname === "/favicon.svg") {
      return new Response(this.faviconSource, {
        headers: {
          "Content-Type": "image/svg+xml; charset=utf-8",
          "Cache-Control": "public, max-age=86400",
          ...cors,
        },
      })
    }

    // Widget JS
    if (url.pathname === "/widget.js") {
      return new Response(this.widgetSource, {

        headers: {
          "Content-Type": "application/javascript; charset=utf-8",
          "Cache-Control": "no-cache",
          ...cors,
        },
      })
    }

    // Health
    if (url.pathname === "/" || url.pathname === "/health") {
      return Response.json(
        {
          status: "ok",
          connector: "web",
          sessions: this.sessionManager.sessions.size,
          clients: this.wsClients.size,
        },
        { headers: cors },
      )
    }

    // Standalone full-page chat
    if (url.pathname === "/chat") {
      return new Response(this.fullPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      })
    }

    // Test page
    if (url.pathname === "/test") {
      return new Response(this.testPage("widget"), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      })
    }
    if (url.pathname === "/test-embedded") {
      return new Response(this.testPage("embedded"), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      })
    }

    return new Response("Not found", { status: 404, headers: cors })
  }

  private corsHeaders(req: Request): Record<string, string> {
    const origin = req.headers.get("origin") || "*"
    const allowed =
      ALLOWED_ORIGINS.includes("*") || ALLOWED_ORIGINS.includes(origin)
    return {
      "Access-Control-Allow-Origin": allowed ? origin : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    }
  }

  // ---------------------------------------------------------------------------
  // WebSocket handlers
  // ---------------------------------------------------------------------------

  private onWsOpen(ws: ServerWebSocket<WSData>): void {
    const { clientId } = ws.data
    this.wsClients.set(clientId, ws)

    let state: "resumed" | "new" | "backend-unavailable" = "new"
    try {
      if (
        this.sessionManager.has(clientId) ||
        this.hasPersistedACPSession(clientId)
      ) {
        state = "resumed"
      }
    } catch (err) {
      state = "backend-unavailable"
      this.logError(`[WS] Failed to inspect persisted session ${clientId}:`, err)
    }

    const hasSession = state === "resumed"
    this.log(`[WS] Connected: ${clientId.slice(0, 12)}... (${state})`)
    this.wsSend(clientId, { type: "connected", clientId, hasSession, state })
  }

  private async onWsMessage(
    ws: ServerWebSocket<WSData>,
    raw: string,
  ): Promise<void> {
    const { clientId } = ws.data

    let msg: any
    try {
      msg = JSON.parse(raw)
    } catch {
      this.wsSend(clientId, { type: "error", message: "Invalid JSON" })
      return
    }

    if (msg.type !== "message" || typeof msg.text !== "string") return
    const text = msg.text.trim()
    if (text.length > MAX_WEB_TEXT_CHARS) {
      this.wsSend(clientId, { type: "error", message: "Message text is too long." })
      return
    }
    if (!text && (msg.images === undefined || (Array.isArray(msg.images) && msg.images.length === 0))) {
      return
    }
    // Apply per-client throttling before decoding potentially large base64 payloads.
    if (!this.checkRateLimit(clientId)) {
      this.wsSend(clientId, {
        type: "error",
        message: "Please wait a moment before sending again.",
      })
      return
    }
    let images: WebPromptImage[]
    try {
      images = validateWebPromptImages(msg.images, WEB_ATTACHMENTS)
    } catch (err) {
      this.wsSend(clientId, {
        type: "error",
        message: err instanceof Error ? err.message : "Invalid image attachment.",
      })
      return
    }
    if (!text && images.length === 0) return

    await this.stopMirrorForUserActivity(clientId, text, async (resp) => {
      this.wsSend(clientId, { type: "response", text: resp })
    })

    // Commands
    if (text.startsWith("/")) {
      if (images.length > 0) {
        this.wsSend(clientId, {
          type: "error",
          message: "Image attachments cannot be sent with commands.",
        })
        return
      }
      const session = this.sessionManager.get(clientId)
      const cmds = session?.client.availableCommands || []
      const normalizedCommand = text.toLowerCase()
      await this.handleCommand(
        clientId,
        text,
        async (resp) => this.wsSend(clientId, { type: "response", text: resp }),
        {
          openCodeCommands: cmds,
          forwardToOpenCode: async (cmd) => this.processQuery(clientId, cmd),
        },
      )
      if (normalizedCommand === "/clear" || normalizedCommand === "/reset") {
        this.wsSend(clientId, { type: "session_state", state: "cleared" })
      }
      return
    }

    await this.processQuery(
      clientId,
      text || "Please analyze the attached image.",
      images,
    )
  }

  private onWsClose(ws: ServerWebSocket<WSData>): void {
    const { clientId } = ws.data
    // A replacement connection may already own this client ID.
    if (this.wsClients.get(clientId) === ws) this.wsClients.delete(clientId)
    this.log(`[WS] Disconnected: ${clientId.slice(0, 12)}...`)
  }

  // ---------------------------------------------------------------------------
  // Query processing
  // ---------------------------------------------------------------------------

  private async processQuery(
    clientId: string,
    query: string,
    promptImages: WebPromptImage[] = [],
  ): Promise<void> {
    const t0 = Date.now()

    if (this.isQueryActive(clientId)) {
      this.wsSend(clientId, {
        type: "error",
        message: "Please wait for the current request to finish.",
      })
      return
    }

    let activeClient: ACPClient | null = null
    const queryHandle = this.markQueryActive(clientId, () => activeClient?.cancel())
    const createSession = (client: ACPClient) => ({ ...this.createBaseSession(client) }) as WebSession
    let initialSession: WebSession | null
    try {
      initialSession = await this.getOrCreateSession(clientId, createSession)
    } catch (err) {
      this.logError(`[FAIL] ${clientId.slice(0, 8)}... creating session:`, err)
      this.wsSend(clientId, { type: "error", message: "Could not connect to AI service." })
      this.wsSend(clientId, { type: "done" })
      this.markQueryDone(clientId, queryHandle)
      return
    }

    if (!initialSession) {
      this.wsSend(clientId, {
        type: "error",
        message: "Could not connect to AI service.",
      })
      this.markQueryDone(clientId, queryHandle)
      return
    }

    const runAttempt = async (session: WebSession) => {
      const client = session.client
      activeClient = client
      let buf = ""
      let toolResultsBuf = ""
      let tools = 0
      let hadToolActivity = false
      let responseImages = 0
      let chunks = 0
      let activitySequence = 0
      const toolActivity = new ToolActivityController(config.toolMessages, {
        create: async (message) => {
          const activityId = `${clientId}-${Date.now()}-${++activitySequence}`
          this.wsSend(clientId, { type: "activity", activityId, message })
          return activityId
        },
        update: async (activityId, message) => {
          this.wsSend(clientId, { type: "activity_update", activityId, message })
        },
      }, {
        sendEvent: async (message) => { this.wsSend(clientId, { type: "activity", message }) },
        onToolStart: () => {
          hadToolActivity = true
          tools++
        },
      })

      const onChunk = (text: string) => {
        chunks++
        buf += text
        this.wsSend(clientId, { type: "chunk", text })
      }

      const onImage = (img: any) => {
        responseImages++
        const size = img.data ? img.data.length : 0
        this.log(`[IMG] Base64 image received: ${img.mimeType || "unknown"} (${size} chars)`)
        this.wsSend(clientId, {
          type: "image",
          data: img.data,
          mimeType: img.mimeType || "image/png",
          alt: img.alt,
        })
      }

      const onUpdate = (update: any) => {
        if (update.type === "tool_result" && update.toolResult) {
          hadToolActivity = true
          toolResultsBuf += JSON.stringify(update.toolResult)

          const toolName = update.toolName || ""
          if (shouldShowToolOutput(toolName, config.toolMessages)) {
            const maxLen = 2000
            const result = update.toolResult.length > maxLen
              ? update.toolResult.slice(0, maxLen) + "\n... (truncated)"
              : update.toolResult
            const trimmed = result.trim()
            if (trimmed) {
              this.wsSend(clientId, { type: "tool_result", tool: toolName, text: trimmed })
            }
          }
        }

        if (update.type === "tool_output_delta" && update.partialOutput) {
          hadToolActivity = true
          const toolName = update.toolName || ""
          if (shouldShowToolOutput(toolName, config.toolMessages)) {
            const output = update.partialOutput.trim()
            if (output) {
              this.wsSend(clientId, { type: "tool_output", tool: toolName, text: output })
            }
          }
        }
      }

      const onPermission = (event: { permission: string; path: string | null; message: string }) => {
        hadToolActivity = true
        this.log(`[PERMISSION] Rejected: ${event.permission}${event.path ? ` (${event.path})` : ""}`)
        this.wsSend(clientId, { type: "permission_denied", message: event.message })
      }

      client.on("chunk", onChunk)
      client.on("activity", toolActivity.handleActivity)
      client.on("tool_activity", toolActivity.handleRevision)
      client.on("image", onImage)
      client.on("update", onUpdate)
      client.on("permission_rejected", onPermission)

      const queryTimeoutMs = 5 * 60 * 1000
      let queryTimeout: ReturnType<typeof setTimeout> | null = null
      const timeoutPromise = new Promise<never>((_, reject) => {
        queryTimeout = setTimeout(() => {
          client.cancel()
          reject(new Error("Request timed out"))
        }, queryTimeoutMs)
      })

      let acpResponse = ""
      let error: unknown = null
      try {
        acpResponse = await Promise.race([
          client.prompt(query, { images: promptImages }),
          timeoutPromise,
        ])
      } catch (err) {
        error = err
      } finally {
        if (queryTimeout) clearTimeout(queryTimeout)
        await toolActivity.flush()
        client.off("chunk", onChunk)
        client.off("activity", toolActivity.handleActivity)
        client.off("tool_activity", toolActivity.handleRevision)
        client.off("image", onImage)
        client.off("update", onUpdate)
        client.off("permission_rejected", onPermission)
      }

      return {
        acpResponse,
        buf,
        toolResultsBuf,
        tools,
        hadToolActivity,
        images: responseImages,
        chunks,
        error,
      }
    }

    const cleanAttempt = (attempt: Awaited<ReturnType<typeof runAttempt>>) =>
      sanitizeServerPaths(removeDocMarkers(removeImageMarkers(stripThinkBlocks(attempt.buf))))

    const sessionLabel = (session: WebSession) =>
      session.client.currentSessionId?.slice(0, 8) || "unknown"

    const hasNoUsefulOutput = (attempt: Awaited<ReturnType<typeof runAttempt>>) =>
      !attempt.hadToolActivity && attempt.images === 0 && attempt.chunks === 0 &&
      attempt.buf.length === 0 && attempt.acpResponse.length === 0 &&
      attempt.toolResultsBuf.length === 0

    const logAttemptFailure = (
      attemptNumber: number,
      attempt: Awaited<ReturnType<typeof runAttempt>>,
      diagnostic: ReturnType<typeof diagnoseEmptyResponse>,
    ) => {
      if (attempt.error) {
        const detail = attempt.error instanceof Error ? attempt.error.message : String(attempt.error)
        this.log(
          `[ACP] Failed attempt=${attemptNumber} error=${detail} chunks=${attempt.chunks} ` +
          `bridgeChars=${attempt.buf.length} tools=${attempt.tools} ` +
          `toolActivity=${attempt.hadToolActivity} images=${attempt.images} [${clientId}]`,
        )
        return
      }
      if (diagnostic) {
        this.log(
          `[ACP] Empty response attempt=${attemptNumber} source=${diagnostic.source} ` +
          `acpChars=${diagnostic.acpChars} bridgeChars=${diagnostic.bridgeChars} ` +
          `cleanChars=${diagnostic.cleanChars} chunks=${attempt.chunks} tools=${attempt.tools} ` +
          `toolActivity=${attempt.hadToolActivity} images=${attempt.images} [${clientId}]`,
        )
      }
    }

    try {
      let session = initialSession
      session.messageCount++
      session.lastActivity = new Date()
      session.inputChars += query.length

      let attempt = await runAttempt(session)
      let clean = cleanAttempt(attempt)
      let diagnostic = attempt.error
        ? null
        : diagnoseEmptyResponse(attempt.acpResponse, attempt.buf, clean)

      if (diagnostic?.source === "bridge-capture-lost") {
        this.log(
          `[ACP] Captured response recovery attempt=1 acpChars=${diagnostic.acpChars} ` +
          `bridgeChars=${diagnostic.bridgeChars} [${clientId}]`,
        )
        attempt.buf = attempt.acpResponse
        clean = cleanAttempt(attempt)
        diagnostic = diagnoseEmptyResponse(attempt.acpResponse, attempt.buf, clean)
        if (!diagnostic) this.wsSend(clientId, { type: "chunk", text: attempt.acpResponse })
      }

      let retried = false
      let failed = Boolean(attempt.error) || Boolean(diagnostic && attempt.images === 0)
      if (failed) {
        logAttemptFailure(1, attempt, diagnostic)
        const safeToRetry = !attempt.hadToolActivity && attempt.images === 0 &&
          attempt.buf.length === 0

        if (safeToRetry) {
          const previousSession = sessionLabel(session)
          this.log(
            `[ACP] Retrying once with a fresh client/session oldSession=${previousSession} [${clientId}]`,
          )
          const retrySession = await this.recreateACPSession(clientId, createSession)
          retried = true
          if (!retrySession) throw new Error("Failed to create a fresh ACP session for retry")
          session = retrySession
          this.log(
            `[ACP] Retry session created newSession=${sessionLabel(session)} [${clientId}]`,
          )
          session.messageCount++
          session.lastActivity = new Date()
          session.inputChars += query.length

          attempt = await runAttempt(session)
          clean = cleanAttempt(attempt)
          diagnostic = attempt.error
            ? null
            : diagnoseEmptyResponse(attempt.acpResponse, attempt.buf, clean)

          if (diagnostic?.source === "bridge-capture-lost") {
            this.log(
              `[ACP] Captured response recovery attempt=2 acpChars=${diagnostic.acpChars} ` +
              `bridgeChars=${diagnostic.bridgeChars} [${clientId}]`,
            )
            attempt.buf = attempt.acpResponse
            clean = cleanAttempt(attempt)
            diagnostic = diagnoseEmptyResponse(attempt.acpResponse, attempt.buf, clean)
            if (!diagnostic) this.wsSend(clientId, { type: "chunk", text: attempt.acpResponse })
          }

          failed = Boolean(attempt.error) || Boolean(diagnostic && attempt.images === 0)
          if (failed) logAttemptFailure(2, attempt, diagnostic)
        }
      }

      if (failed && retried && hasNoUsefulOutput(attempt)) {
        const failedSession = sessionLabel(session)
        this.log(
          `[ACP] Invalidating failed retry session=${failedSession} reason=no-useful-output [${clientId}]`,
        )
        await this.invalidateACPSession(clientId)
        this.wsSend(clientId, { type: "session_state", state: "stale-invalidated" })
        activeClient = null
      }

      if (failed) {
        const sec = ((Date.now() - t0) / 1000).toFixed(1)
        const reason = attempt.error ? "acp-error" : diagnostic?.source || "empty-response"
        this.log(`[FAIL] ${clientId.slice(0, 8)}... ${sec}s reason=${reason}`)
        this.wsSend(clientId, {
          type: "error",
          message: "The AI service completed without returning a usable response. Please try again.",
        })
        this.wsSend(clientId, { type: "done" })
        return
      }

      const allText = attempt.buf + "\n" + attempt.toolResultsBuf
      const markerImages = new Set([
        ...extractImagePaths(attempt.toolResultsBuf),
        ...extractImagePaths(attempt.buf),
      ])
      const pathRegex = /\/[\w.\-\/]+\.(?:png|jpe?g|gif|webp|svg|bmp)/gi
      const pathMatches = allText.match(pathRegex) || []
      const allImages = new Set([...markerImages, ...pathMatches])
      for (const imgPath of allImages) {
        const trimmed = imgPath.trim()
        if (existsSync(trimmed)) this.sendFileAsImage(clientId, trimmed)
      }

      const markerDocs = new Set([
        ...extractDocPaths(attempt.toolResultsBuf),
        ...extractDocPaths(attempt.buf),
      ])
      const docRegex = /\/[\w.\-\/]+\.(?:pdf|csv|txt|json|xml|html|md|zip|tar)/gi
      const docMatches = allText.match(docRegex) || []
      const allDocs = new Set([...markerDocs, ...docMatches])
      for (const docPath of allDocs) {
        const trimmed = docPath.trim()
        if (existsSync(trimmed)) this.sendFileAsDoc(clientId, trimmed)
      }

      session.outputChars += clean.length
      this.wsSend(clientId, { type: "done" })

      const sec = ((Date.now() - t0) / 1000).toFixed(1)
      const toolInfo = attempt.tools > 0
        ? `, ${attempt.tools} tool${attempt.tools > 1 ? "s" : ""}`
        : ""
      const imageInfo = attempt.images > 0
        ? `, ${attempt.images} image${attempt.images > 1 ? "s" : ""}`
        : ""
      this.log(
        `[DONE] ${clientId.slice(0, 8)}... ${sec}s (${clean.length} chars${toolInfo}${imageInfo})`,
      )
    } catch (err) {
      this.logError(`[FAIL] ${clientId.slice(0, 8)}...:`, err)
      this.wsSend(clientId, {
        type: "error",
        message: "Something went wrong processing your request.",
      })
      this.wsSend(clientId, { type: "done" })
    } finally {
      const session = this.sessionManager.get(clientId)
      if (session) session.lastActivity = new Date()
      this.markQueryDone(clientId, queryHandle)
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Read an image file from disk and send it to the client as base64.
   */
  private sendFileAsImage(clientId: string, filePath: string): void {
    try {
      if (!existsSync(filePath)) {
        this.logError(`[IMG] File not found: ${filePath}`)
        return
      }
      const data = readFileSync(filePath).toString("base64")
      const ext = filePath.split(".").pop()?.toLowerCase() || "png"
      const mimeMap: Record<string, string> = {
        png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg",
        gif: "image/gif", webp: "image/webp", svg: "image/svg+xml",
      }
      this.wsSend(clientId, {
        type: "image",
        data,
        mimeType: mimeMap[ext] || "image/png",
        alt: filePath.split("/").pop(),
      })
      this.log(`[IMG] Sent: ${filePath.split("/").pop()}`)
    } catch (err) {
      this.logError(`[IMG] Failed to read ${filePath}:`, err)
    }
  }

  /**
   * Read a document file from disk and send it to the client as a base64 download.
   */
  private sendFileAsDoc(clientId: string, filePath: string): void {
    try {
      if (!existsSync(filePath)) {
        this.logError(`[DOC] File not found: ${filePath}`)
        return
      }
      const data = readFileSync(filePath).toString("base64")
      const ext = filePath.split(".").pop()?.toLowerCase() || "bin"
      const mimeMap: Record<string, string> = {
        pdf: "application/pdf", txt: "text/plain", csv: "text/csv",
        json: "application/json", xml: "application/xml",
        html: "text/html", md: "text/markdown",
        zip: "application/zip", tar: "application/x-tar",
      }
      const fileName = filePath.split("/").pop() || "file"
      this.wsSend(clientId, {
        type: "file",
        data,
        mimeType: mimeMap[ext] || "application/octet-stream",
        fileName,
      })
      this.log(`[DOC] Sent: ${fileName}`)
    } catch (err) {
      this.logError(`[DOC] Failed to read ${filePath}:`, err)
    }
  }

  private wsSend(clientId: string, data: any): void {
    const ws = this.wsClients.get(clientId)
    if (!ws) return
    try {
      ws.send(JSON.stringify(data))
    } catch (err) {
      this.logError(`[WS] send failed (${clientId.slice(0, 8)}):`, err)
    }
  }

  private fullPage(): string {
    const title = escapeHtml(BOT_NAME)
    return `<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <title>${title} Chat</title>
  <style>
    * { box-sizing: border-box; }
    html, body { width: 100%; height: 100%; margin: 0; overflow: hidden; }
    #chat { width: 100%; height: 100vh; height: 100dvh; }
  </style>
</head><body>
  <div id="chat"></div>
  <script>window.OpenCodeWidget = { mode: "embedded", container: "#chat" }<\/script>
  <script src="/widget.js"><\/script>
</body></html>`
  }

  private testPage(mode: "widget" | "embedded"): string {
    // Actual widget loads via relative path (works from any IP).
    // Example snippets use the public URL so users can copy-paste.
    const pub = WEB_PUBLIC_URL
    const title = escapeHtml(BOT_NAME)

    if (mode === "embedded") {
      return `<!DOCTYPE html>
<html><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title} Chat - Embedded</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #f1f5f9; display: flex; flex-direction: column; height: 100vh; }
    header { padding: 16px 24px; background: white; border-bottom: 1px solid #e2e8f0; }
    header h1 { font-size: 18px; color: #1e293b; }
    header p  { font-size: 13px; color: #64748b; margin-top: 4px; }
    #chat { flex: 1; margin: 24px; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  </style>
</head><body>
  <header>
    <h1>${title} Chat - Embedded Mode</h1>
    <p>The chat fills the container below.
       <a href="/test">Switch to widget mode</a></p>
  </header>
  <div id="chat"></div>
  <script>window.OpenCodeWidget = { mode: "embedded", container: "#chat" }<\/script>
  <script src="/widget.js"><\/script>
</body></html>`
    }

    return `<!DOCTYPE html>
<html><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title} Chat - Widget</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 720px; margin: 60px auto; padding: 0 20px; color: #1e293b; }
    h1 { margin-bottom: 8px; }
    p { color: #475569; line-height: 1.6; }
    pre { background: #f1f5f9; padding: 14px 18px; border-radius: 8px; overflow-x: auto; margin: 16px 0; font-size: 14px; }
    a { color: #2563eb; }
  </style>
</head><body>
  <h1>${title} Chat Bridge - Web Widget</h1>
  <p>The chat widget is in the bottom-right corner. Click the bubble to open it.</p>
  <p><a href="/test-embedded">Switch to embedded mode</a></p>
  <h2>Widget snippet</h2>
  <pre>\&lt;script src="${pub}/widget.js"\&gt;\&lt;/script\&gt;</pre>
  <h2>Embedded snippet</h2>
  <pre>\&lt;div id="chat" style="height:600px"\&gt;\&lt;/div\&gt;
\&lt;script\&gt;window.OpenCodeWidget={mode:"embedded",container:"#chat"}\&lt;/script\&gt;
\&lt;script src="${pub}/widget.js"\&gt;\&lt;/script\&gt;</pre>
  <script src="/widget.js"><\/script>
</body></html>`
  }
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  const connector = new WebConnector()

  const shutdown = async () => {
    await connector.stop()
    process.exit(0)
  }
  process.on("SIGINT", shutdown)
  process.on("SIGTERM", shutdown)

  await connector.start()
}

if (import.meta.main) {
  main().catch((err) => {
    console.error("Fatal error:", err)
    process.exit(1)
  })
}
