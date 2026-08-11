#!/usr/bin/env bun
/**
 * IRC Connector for OpenCode Chat Bridge
 *
 * Bridges IRC channels to OpenCode via ACP protocol.
 *
 * Implementation: thin raw-TCP client with IRCv3 capability negotiation
 * and SASL PLAIN authentication. No new npm dependency. Per-line framing
 * is RFC 1459 (CRLF-terminated, 512-byte hard limit). Encoding is UTF-8.
 *
 * Trust model — copied from vjt/claude-ircbot, adapted to the bridge's
 * existing per-channel session + rate-limit + dedupe infrastructure.
 *
 *   1. Nick must appear in `irc.allowedUsers` (format: "<nick> <host_glob>").
 *   2. The `host` from the source prefix must match the fnmatch glob for
 *      that nick. Defends against nick spoofing on networks that issue cloaks.
 *   3. The nick must be registered+identified to services (verified via
 *      IRCv3 WHOIS: 307 RPL_WHOISREGNICK on Bahamut, 330 RPL_WHOISACCOUNT
 *      on charybdis/solanum). Cached, reset on PART/QUIT/NICK.
 *
 * All three must hold for a PRIVMSG to be treated as a command; otherwise
 * the message is still emitted but tagged `UNTRUSTED` so the agent can
 * see it without acting on it. Private messages (QUERY) from unlisted nicks
 * are dropped at the transport layer before they reach the agent context.
 *
 * Usage:
 *   bun connectors/irc.ts
 *
 * Environment variables:
 *   IRC_HOST, IRC_PORT, IRC_TLS, IRC_NICK, IRC_USERNAME, IRC_REALNAME,
 *   IRC_PASSWORD (SASL), IRC_NICKSERV_PASSWORD,
 *   IRC_TRIGGER (defaults to config.trigger),
 *   IRC_ALLOWED_USERS (csv of "<nick> <glob>" pairs).
 */

import fs from "fs"
import * as net from "net"
import * as tls from "tls"
import { ACPClient } from "../src"
import {
  BaseConnector,
  type BaseSession,
  parseCsvList,
  ToolActivityController,
  shouldShowToolOutput,
  extractImagePaths,
  removeImageMarkers,
  sanitizeServerPaths,
  stripThinkBlocks,
} from "../src"
import { getConfig } from "../src/config"

// =============================================================================
// Configuration
// =============================================================================

const config = getConfig()
const IRC_HOST = process.env.IRC_HOST || config.irc.host
const IRC_PORT = parseInt(process.env.IRC_PORT || String(config.irc.port), 10)
const IRC_TLS = (process.env.IRC_TLS ?? String(config.irc.tls)) !== "false"
const IRC_NICK = process.env.IRC_NICK || config.irc.nick
const IRC_USERNAME = process.env.IRC_USERNAME || config.irc.username || IRC_NICK
const IRC_REALNAME = process.env.IRC_REALNAME || config.irc.realname
const IRC_PASSWORD = process.env.IRC_PASSWORD || config.irc.password
const IRC_NICKSERV_PASSWORD = process.env.IRC_NICKSERV_PASSWORD || config.irc.nickservPassword
const TRIGGER = process.env.IRC_TRIGGER || config.trigger
const BOT_NAME = config.botName
const SESSION_RETENTION_DAYS = parseInt(process.env.SESSION_RETENTION_DAYS || "7", 10)
const RATE_LIMIT_SECONDS = config.rateLimitSeconds
const RESPOND_TO_MENTIONS = config.irc.respondToMentions
const MAX_LINE_BYTES = config.irc.maxLineBytes
const ENV_ALLOWED_USERS = parseCsvList(process.env.IRC_ALLOWED_USERS)
const ENV_IGNORE_USERS = parseCsvList(process.env.IRC_IGNORE_USERS)
const ALLOWED_USERS = ENV_ALLOWED_USERS.length > 0
  ? ENV_ALLOWED_USERS
  : config.irc.allowedUsers
const IGNORE_USERS = ENV_IGNORE_USERS.length > 0
  ? ENV_IGNORE_USERS
  : config.irc.ignoreUsers
const CHANNELS = config.irc.channels

// IRC services nicks (always allowed to send us messages, never trigger commands).
const SERVICE_NICKS = new Set([
  "nickserv", "chanserv", "memoserv", "operserv", "hostserv",
  "botserv", "helpserv", "statserv",
])

// =============================================================================
// Trust model (pure helpers, exported for testing)
// =============================================================================

/** A single trust rule: nick lower-cased + a fnmatch host glob. */
export interface TrustRule {
  nick: string
  hostGlob: string
}

/**
 * Parse a trust entry list into TrustRule objects.
 * Accepts either an array of "<nick> <glob>" strings or an empty array.
 * Lines starting with `#` and blank lines are ignored when separated by `\n`.
 */
export function parseTrustRules(input: string[]): TrustRule[] {
  const rules: TrustRule[] = []
  for (const raw of input) {
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith("#")) continue
      const parts = trimmed.split(/\s+/, 2)
      if (parts.length === 2 && parts[0] && parts[1]) {
        rules.push({ nick: parts[0].toLowerCase(), hostGlob: parts[1] })
      }
    }
  }
  return rules
}

/** fnmatch-style match for a single rule. Returns true if `host` matches the glob. */
export function hostMatchesRule(host: string, rule: TrustRule): boolean {
  // Inline fnmatch to avoid pulling the npm "fnmatch" package: translate `*`
  // and `?` into a tiny regex anchored at both ends. Brace/bracket syntax is
  // not supported (trust entries should stay simple).
  const pattern = "^" + rule.hostGlob
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".") + "$"
  return new RegExp(pattern, "i").test(host)
}

/**
 * True iff `nick` appears as a listed rule (case-insensitive).
 */
export function isTrustListed(nick: string, rules: TrustRule[]): boolean {
  const lower = nick.toLowerCase()
  return rules.some((r) => r.nick === lower)
}

/**
 * True iff `host` matches at least one rule for `nick`.
 */
export function hostMatches(nick: string, host: string, rules: TrustRule[]): boolean {
  const lower = nick.toLowerCase()
  return rules.some((r) => r.nick === lower && hostMatchesRule(host, r))
}

// =============================================================================
// IRC line framing (pure helpers, exported for testing)
// =============================================================================

/**
 * Parsed IRC protocol line.
 * RFC 1459 line: `[:prefix] COMMAND [params] [:trailing]`
 * Prefix is `nick!user@host` for user messages, `server` for server numerics.
 */
export interface IRCLine {
  /** Source prefix without the leading colon, or empty if none. */
  prefix: string
  /** Lower-cased command or numeric as a string (e.g. "privmsg", "001"). */
  command: string
  /** Space-separated parameters before the trailing param. */
  params: string[]
  /** Trailing parameter (after the lone `:`), or empty. */
  trailing: string
  /** `nick!user@host` portion of the prefix if it parses as one. */
  sourceNick: string
  sourceUser: string
  sourceHost: string
}

/**
 * Parse one CRLF-stripped IRC protocol line into structured fields.
 * Returns null for empty input or lines that don't match the grammar.
 */
export function parseIRCLine(raw: string): IRCLine | null {
  const line = raw.replace(/\r$/, "")
  if (!line) return null

  let rest = line
  let prefix = ""
  if (rest.startsWith(":")) {
    const sp = rest.indexOf(" ")
    if (sp < 0) return null
    prefix = rest.slice(1, sp)
    rest = rest.slice(sp + 1)
  }

  const trailingIdx = rest.indexOf(" :")
  let trailing = ""
  let head = rest
  if (trailingIdx >= 0) {
    head = rest.slice(0, trailingIdx)
    trailing = rest.slice(trailingIdx + 2)
  }
  const tokens = head.split(" ").filter((t) => t.length > 0)
  if (tokens.length === 0) return null

  const command = tokens[0].toLowerCase()
  const params = tokens.slice(1)

  let sourceNick = ""
  let sourceUser = ""
  let sourceHost = ""
  if (prefix) {
    const bangIdx = prefix.indexOf("!")
    const atIdx = prefix.indexOf("@")
    if (bangIdx >= 0 && atIdx > bangIdx) {
      sourceNick = prefix.slice(0, bangIdx)
      sourceUser = prefix.slice(bangIdx + 1, atIdx)
      sourceHost = prefix.slice(atIdx + 1)
    } else {
      sourceNick = prefix
    }
  }

  return { prefix, command, params, trailing, sourceNick, sourceUser, sourceHost }
}

/**
 * Resolve the channel/nick target a PRIVMSG was directed at.
 */
export interface IRCMessageTarget {
  /** True if this is a channel message, false if it is a private message. */
  isChannel: boolean
  /** Channel name (e.g. "#opencode") for channel messages, or our peer's nick for DMs. */
  target: string
  /** Normalized session key (channel name for channels; "pm:<nick>" for DMs). */
  sessionId: string
}

export function resolveTarget(params: string[], trailing: string, ourNick: string): IRCMessageTarget | null {
  if (params.length === 0) return null
  const target = params[0]
  if (!target) return null
  const isChannel = target.startsWith("#") || target.startsWith("&") || target.startsWith("+") || target.startsWith("!")
  if (isChannel) {
    return { isChannel: true, target, sessionId: target.toLowerCase() }
  }
  // Private message: target should equal our nick; use sender as session key.
  const peer = trailing // unused, but keeps linter quiet
  void peer
  return { isChannel: false, target, sessionId: `pm:${target.toLowerCase()}` }
}

/**
 * Decide whether a message body should be treated as a command for the bot.
 * Returns the stripped query (without the trigger prefix or nick address) or
 * null if no trigger matched.
 *
 * Rules:
 *  - In channels: trigger prefix, or "<nick>: ..." / "<nick>, ..." when
 *    respondToMentions is enabled.
 *  - In private messages (DM): always trigger, no prefix required (private
 *    message is itself the act of addressing the bot).
 */
export interface TriggerMatch {
  /** True if this message is a command addressed to us. */
  triggered: boolean
  /** Original body if not triggered, otherwise the body with the trigger removed. */
  query: string
  /** Why the message did or did not trigger. */
  reason:
    | "channel-trigger-prefix"
    | "channel-nick-address"
    | "channel-nick-address-no-respond"
    | "dm"
    | "channel-no-trigger"
    | "empty"
  /** True if the message looked like a nick-addressed message but respondToMentions is off. */
  nickAddressedButIgnored: boolean
}

export function matchTrigger(input: {
  body: string
  isChannel: boolean
  ourNick: string
  trigger: string
  respondToMentions: boolean
}): TriggerMatch {
  const body = input.body.trim()
  if (!body) {
    return { triggered: false, query: "", reason: "empty", nickAddressedButIgnored: false }
  }

  // DM: always trigger.
  if (!input.isChannel) {
    return { triggered: true, query: body, reason: "dm", nickAddressedButIgnored: false }
  }

  // Trigger prefix.
  const trigger = input.trigger
  if (trigger && body.toLowerCase().startsWith(trigger.toLowerCase() + " ")) {
    return {
      triggered: true,
      query: body.slice(trigger.length + 1).trimStart(),
      reason: "channel-trigger-prefix",
      nickAddressedButIgnored: false,
    }
  }

  // Nick address.
  const nick = input.ourNick
  const nickPatterns = [`${nick}: `, `${nick}, `]
  for (const pattern of nickPatterns) {
    if (body.startsWith(pattern)) {
      if (!input.respondToMentions) {
        return {
          triggered: false,
          query: body,
          reason: "channel-nick-address-no-respond",
          nickAddressedButIgnored: true,
        }
      }
      return {
        triggered: true,
        query: body.slice(pattern.length).trimStart(),
        reason: "channel-nick-address",
        nickAddressedButIgnored: false,
      }
    }
    // Case-insensitive variant.
    if (body.toLowerCase().startsWith(pattern.toLowerCase())) {
      if (!input.respondToMentions) {
        return {
          triggered: false,
          query: body,
          reason: "channel-nick-address-no-respond",
          nickAddressedButIgnored: true,
        }
      }
      return {
        triggered: true,
        query: body.slice(pattern.length).trimStart(),
        reason: "channel-nick-address",
        nickAddressedButIgnored: false,
      }
    }
  }

  return { triggered: false, query: body, reason: "channel-no-trigger", nickAddressedButIgnored: false }
}

/**
 * Wrap a body into one or more PRIVMSG lines that fit `maxBytes`. Mirrors the
 * vjt/claude-ircbot split_say: cut at the last space before the limit, never
 * strip leading whitespace; hard-split a single oversized word on a UTF-8
 * boundary.
 */
export function splitMessage(body: string, maxBytes: number): string[] {
  const out: string[] = []
  let buf = ""
  let bufBytes = 0

  for (const ch of body) {
    const chBytes = Buffer.byteLength(ch, "utf8")
    if (bufBytes + chBytes > maxBytes) {
      if (buf) out.push(buf)
      buf = ch
      bufBytes = chBytes
    } else {
      buf += ch
      bufBytes += chBytes
    }
  }
  if (buf) out.push(buf)
  return out.length > 0 ? out : [""]
}

// =============================================================================
// Session Type
// =============================================================================

interface ChannelSession extends BaseSession {}

// =============================================================================
// IRC Connector
// =============================================================================

export class IRCConnector extends BaseConnector<ChannelSession> {
  private socket: net.Socket | tls.TLSSocket | null = null
  private receiveBuffer = ""
  private registered = false
  private currentNick: string
  private trustRules: TrustRule[]
  private verified = new Set<string>()
  private whoisPending = new Set<string>()
  private reconnectAttempts = 0
  private maxReconnectAttempts = 10
  private reconnectDelayMs = 3000
  private joinedChannels = new Set<string>()
  private stopped = false
  private ghostMode = false
  private ghostTempNick: string | null = null

  constructor() {
    super({
      connector: "irc",
      trigger: TRIGGER,
      botName: BOT_NAME,
      rateLimitSeconds: RATE_LIMIT_SECONDS,
      sessionRetentionDays: SESSION_RETENTION_DAYS,
      allowedUsers: ALLOWED_USERS,
    })
    this.currentNick = IRC_NICK
    this.trustRules = parseTrustRules(ALLOWED_USERS)
    if (this.trustRules.length === 0) {
      console.warn("[IRC] Warning: allowedUsers is empty. All commands will be rejected as UNTRUSTED until trust rules are configured.")
    }
  }

  // ---------------------------------------------------------------------------
  // Abstract method implementations
  // ---------------------------------------------------------------------------

  async start(): Promise<void> {
    if (!IRC_HOST) {
      console.error("Error: IRC_HOST not set (or config.irc.host)")
      process.exit(1)
    }
    if (!IRC_NICK) {
      console.error("Error: IRC_NICK not set (or config.irc.nick)")
      process.exit(1)
    }
    this.stopped = false
    this.logStartup()
    console.log(`  Server: ${IRC_HOST}:${IRC_PORT} (TLS: ${IRC_TLS ? "on" : "off"})`)
    console.log(`  Nick: ${IRC_NICK}`)
    console.log(`  Channels: ${CHANNELS.length === 0 ? "(none)" : CHANNELS.join(", ")}`)
    console.log(`  Trust rules: ${this.trustRules.length}`)
    console.log(`  Responds to: trigger "${TRIGGER}"${RESPOND_TO_MENTIONS ? " + nick address" : ""}`)

    await this.cleanupSessions()
    await this.connect()
    this.startSessionExpiryLoop()
  }

  async stop(): Promise<void> {
    this.stopped = true
    this.log("Stopping...")
    if (this.socket) {
      try {
        this.sendRaw("QUIT :OpenCode Chat Bridge shutting down")
      } catch {}
      this.socket.destroy()
      this.socket = null
    }
    await this.disconnectAllSessions()
    this.log("Stopped.")
  }

  async sendMessage(target: string, text: string): Promise<void> {
    for (const chunk of splitMessage(text, MAX_LINE_BYTES)) {
      this.sendRaw(`PRIVMSG ${target} :${chunk}`)
    }
  }

  // ---------------------------------------------------------------------------
  // Connection / reconnect
  // ---------------------------------------------------------------------------

  private async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.log(`Connecting to ${IRC_HOST}:${IRC_PORT}...`)
      const raw = net.createConnection({ host: IRC_HOST, port: IRC_PORT })

      this.receiveBuffer = ""
      this.registered = false
      this.verified.clear()
      this.whoisPending.clear()
      this.joinedChannels.clear()
      this.ghostMode = false
      this.ghostTempNick = null

      const finalizeConnect = (sock: net.Socket | tls.TLSSocket) => {
        this.socket = sock
        // TCP keepalive so we detect a silently dropped line before the server's
        // next PING timeout (usually a couple of minutes).
        sock.setKeepAlive(true, 60)
        sock.on("data", (chunk: Buffer) => {
          this.receiveBuffer += chunk.toString("utf8")
          let nlIdx: number
          while ((nlIdx = this.receiveBuffer.indexOf("\n")) >= 0) {
            const line = this.receiveBuffer.slice(0, nlIdx)
            this.receiveBuffer = this.receiveBuffer.slice(nlIdx + 1)
            this.handleLine(line)
          }
        })
        sock.on("error", (err) => {
          this.logError("Socket error:", err)
        })
        sock.on("close", () => {
          this.log("Socket closed")
          this.socket = null
          if (!this.stopped) this.scheduleReconnect()
        })
      }

      const sendRegistration = () => {
        // IRCv3 capability negotiation. We request what's useful and accept the
        // server's reply; capabilities we don't request are silently dropped.
        const requestedCaps = [
          "sasl",           // SASL authentication
          "account-notify", // push notifications when a nick becomes identified
          "extended-join",  // account name in JOIN
          "multi-prefix",   // correct multi-prefix in NAMES replies
          "server-time",    // @time tag on messages (unused for now, but cheap)
        ]
        this.sendRaw(`CAP REQ :${requestedCaps.join(" ")}`)
        this.sendRaw(`NICK ${IRC_NICK}`)
        this.sendRaw(`USER ${IRC_USERNAME} 0 * :${IRC_REALNAME}`)
      }

      raw.once("error", (err) => {
        this.logError("TCP socket error:", err)
      })

      raw.once("connect", () => {
        this.log("TCP connected")
        if (IRC_TLS) {
          // The TLS upgrade requires an already-connected socket. Defer the
          // wrap to here so the underlying TCP handshake has completed.
          const tlsSock = tls.connect({
            socket: raw,
            servername: IRC_HOST,
            rejectUnauthorized: true,
          })
          tlsSock.once("secureConnect", () => {
            this.log("TLS handshake complete")
            finalizeConnect(tlsSock)
            sendRegistration()
            resolve()
          })
          tlsSock.once("error", (err) => {
            this.logError("TLS error:", err)
          })
        } else {
          finalizeConnect(raw)
          sendRegistration()
          resolve()
        }
      })

      // 30s connect timeout
      setTimeout(() => {
        if (!this.registered) {
          reject(new Error("IRC connection timeout"))
        }
      }, 30_000).unref()
    })
  }

  private scheduleReconnect(): void {
    if (this.stopped) return
    this.reconnectAttempts++
    if (this.reconnectAttempts > this.maxReconnectAttempts) {
      this.logError(`Giving up after ${this.maxReconnectAttempts} reconnect attempts`)
      process.exit(1)
    }
    const delay = this.reconnectDelayMs * Math.pow(2, Math.min(this.reconnectAttempts - 1, 6))
    const jitter = Math.random() * 1000
    const total = Math.min(delay + jitter, 60_000)
    this.log(`Reconnect attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${Math.round(total)}ms`)
    setTimeout(() => {
      this.connect().catch((err) => this.logError("Reconnect failed:", err))
    }, total)
  }

  private sendRaw(line: string): void {
    if (!this.socket) return
    // IRC lines are CRLF-terminated and 512-byte capped on the wire.
    const capped = line.length > 510 ? line.slice(0, 510) : line
    try {
      this.socket.write(capped + "\r\n")
    } catch (err) {
      this.logError("Send failed:", err)
    }
  }

  // ---------------------------------------------------------------------------
  // Inbound line handling
  // ---------------------------------------------------------------------------

  private handleLine(rawLine: string): void {
    const parsed = parseIRCLine(rawLine)
    if (!parsed) return

    // PING/PONG
    if (parsed.command === "ping") {
      this.sendRaw(`PONG :${parsed.trailing || parsed.params.join(" ")}`)
      return
    }

    // CAP negotiation
    if (parsed.command === "cap") {
      const subCmd = (parsed.params[1] || "").toLowerCase()
      if (subCmd === "ack") {
        // Server confirmed our requested capabilities; the actual auth step
        // happens via SASL on the next round trip, handled when we hit 001.
      }
      return
    }

    // SASL: server expects our credentials.
    if (parsed.command === "authenticate") {
      if (parsed.params[0] === "*") {
        // Server sent "AUTHENTICATE *" as a continuation prompt. We only
        // support PLAIN, which fits in one frame.
        if (!IRC_PASSWORD) {
          this.sendRaw("AUTHENTICATE *")
          this.sendRaw("CAP END")
          return
        }
        const auth = `\0${IRC_USERNAME}\0${IRC_PASSWORD}`
        this.sendRaw(`AUTHENTICATE ${Buffer.from(auth, "utf8").toString("base64")}`)
      }
      return
    }

    // Numeric replies
    switch (parsed.command) {
      case "001":
        this.registered = true
        this.reconnectAttempts = 0
        this.currentNick = IRC_NICK
        this.log(`Registered as ${parsed.params[0]}`)
        // Start NickServ IDENTIFY if configured (and SASL didn't run).
        if (IRC_NICKSERV_PASSWORD && !IRC_PASSWORD) {
          this.sendRaw(`PRIVMSG NickServ :IDENTIFY ${IRC_NICKSERV_PASSWORD}`)
        }
        // End capability negotiation: this is the IRCv3 handshake terminator.
        this.sendRaw("CAP END")
        // Kick off WHOIS for every trust-listed nick so verified-cache is hot.
        for (const r of this.trustRules) {
          this.whoisPending.add(r.nick)
          this.sendRaw(`WHOIS ${r.nick}`)
        }
        // Join configured channels.
        for (const ch of CHANNELS) {
          this.sendRaw(`JOIN ${ch}`)
        }
        return

      case "433":
      case "432":
      case "437":
        // Nick in use / restricted. Try a temp nick so we can GHOST and reclaim.
        if (!this.registered) {
          const temp = `${IRC_NICK}-${Math.floor(Math.random() * 900 + 100)}`
          this.ghostTempNick = temp
          this.ghostMode = true
          this.sendRaw(`NICK ${temp}`)
          this.log(`Nick in use, using temp ${temp} for ghost-recovery`)
        }
        return

      case "307":
        // RPL_WHOISREGNICK (Bahamut): user is identified to services.
        if (parsed.params.length >= 2) {
          const target = parsed.params[1].toLowerCase()
          this.verified.add(target)
          this.whoisPending.delete(target)
        }
        return

      case "330":
        // RPL_WHOISACCOUNT (charybdis/solanum/Libera): user is logged in as <account>.
        if (parsed.params.length >= 2) {
          const target = parsed.params[1].toLowerCase()
          this.verified.add(target)
          this.whoisPending.delete(target)
        }
        return

      case "318":
        // RPL_ENDOFWHOIS: if still pending after this, the nick is not registered.
        if (parsed.params.length >= 2) {
          const target = parsed.params[1].toLowerCase()
          if (this.whoisPending.delete(target) && !this.verified.has(target)) {
            this.log(`[TRUST] ${parsed.params[1]} is not registered to services`)
          }
        }
        return

      case "376":
      case "422":
        // End of MOTD / no MOTD. Join channels now if 001 already triggered
        // a JOIN. Some servers issue 001 before the channel list is finalised;
        // we send JOIN in 001 so this is mostly belt-and-suspenders.
        return

      case "464":
        this.logError(`AUTH ERROR (464): ${parsed.trailing}`)
        return
      case "465":
        this.logError(`BANNED (465): ${parsed.trailing}`)
        return

      case "sasl":
        // "903 SASL authentication successful" / "904 SASL authentication failed"
        if (parsed.params[1] === "903") {
          this.log("SASL authentication successful")
        } else if (parsed.params[1] === "904" || parsed.params[1] === "905") {
          this.logError(`SASL failed: ${parsed.trailing}`)
        }
        return
    }

    // NICK change (our own or a peer's)
    if (parsed.command === "nick") {
      const newNick = parsed.trailing || parsed.params[0] || ""
      if (parsed.sourceNick.toLowerCase() === this.currentNick.toLowerCase()) {
        this.currentNick = newNick
        this.log(`We are now known as ${newNick}`)
        if (this.ghostMode && newNick.toLowerCase() === IRC_NICK.toLowerCase()) {
          // We just reclaimed our real nick after a ghost cycle. Now identify.
          this.ghostMode = false
          this.ghostTempNick = null
          if (IRC_NICKSERV_PASSWORD && !IRC_PASSWORD) {
            this.sendRaw(`PRIVMSG NickServ :IDENTIFY ${IRC_NICKSERV_PASSWORD}`)
          }
        }
      } else {
        // Peer changed nick — invalidate cached verification.
        this.invalidateTrust(parsed.sourceNick, "nick-change")
      }
      return
    }

    // JOIN: track channels and detect our own join for post-connect setup.
    if (parsed.command === "join") {
      const channel = parsed.params[0] || parsed.trailing
      if (parsed.sourceNick.toLowerCase() === this.currentNick.toLowerCase()) {
        this.joinedChannels.add(channel.toLowerCase())
      }
      return
    }

    if (parsed.command === "part" || parsed.command === "quit") {
      if (parsed.sourceNick.toLowerCase() !== this.currentNick.toLowerCase()) {
        this.invalidateTrust(parsed.sourceNick, parsed.command)
      }
      return
    }

    if (parsed.command === "kick") {
      // params: #chan target
      if (parsed.params.length >= 2) {
        const chan = parsed.params[0]
        const target = parsed.params[1]
        if (target.toLowerCase() === this.currentNick.toLowerCase()) {
          this.log(`Kicked from ${chan} by ${parsed.sourceNick}: ${parsed.trailing}`)
          this.joinedChannels.delete(chan.toLowerCase())
        }
      }
      return
    }

    // CTCP (":\x01VERSION\x01" etc.) - just acknowledge for now.
    if (parsed.command === "privmsg" || parsed.command === "notice") {
      const body = parsed.trailing
      if (body.startsWith("\x01") && body.endsWith("\x01")) {
        const ctcp = body.slice(1, -1).toUpperCase()
        if (ctcp.startsWith("VERSION")) {
          this.sendRaw(`NOTICE ${parsed.sourceNick} :\x01VERSION OpenCode Chat Bridge IRC connector\x01`)
        } else if (ctcp.startsWith("PING")) {
          this.sendRaw(`NOTICE ${parsed.sourceNick} :\x01PING ${parsed.params.slice(1).join(" ")}\x01`)
        }
        // CTCP queries never trigger commands.
        return
      }

      // Skip our own outgoing messages mirrored back as NOTICE from services.
      if (parsed.sourceNick.toLowerCase() === this.currentNick.toLowerCase()) return

      // Handle NickServ identify confirmation notices.
      if (parsed.sourceNick.toLowerCase() === "nickserv" && parsed.command === "notice") {
        const low = body.toLowerCase()
        if (/(identified|recognized|accepted)/i.test(low)) {
          this.log("NickServ IDENTIFY acknowledged")
        }
        return
      }

      // Only PRIVMSG is actionable; NOTICE is just informational.
      if (parsed.command !== "privmsg") return

      this.handlePrivmsg(parsed)
      return
    }
  }

  private invalidateTrust(nick: string, reason: string): void {
    const lower = nick.toLowerCase()
    if (this.verified.delete(lower) || this.whoisPending.delete(lower)) {
      this.log(`[TRUST] Cache invalidated for ${nick}: ${reason}`)
    }
  }

  // ---------------------------------------------------------------------------
  // Trust check (sync three-factor)
  // ---------------------------------------------------------------------------

  /**
   * Returns {trusted, reason, needWhois}. Trust requires all three factors;
   * when the nick is listed and the host matches but the services check is
   * still pending, we fire a WHOIS and report not-trusted (pending).
   */
  private trustCheck(nick: string, host: string): { trusted: boolean; reason: string; needWhois: boolean } {
    if (!isTrustListed(nick, this.trustRules)) {
      return { trusted: false, reason: "not-listed", needWhois: false }
    }
    if (!hostMatches(nick, host, this.trustRules)) {
      return { trusted: false, reason: "host-mismatch", needWhois: false }
    }
    if (!this.verified.has(nick.toLowerCase())) {
      const lower = nick.toLowerCase()
      if (!this.whoisPending.has(lower)) {
        this.whoisPending.add(lower)
        this.sendRaw(`WHOIS ${nick}`)
      }
      return { trusted: false, reason: "pending-whois", needWhois: true }
    }
    return { trusted: true, reason: "ok", needWhois: false }
  }

  // ---------------------------------------------------------------------------
  // PRIVMSG dispatch
  // ---------------------------------------------------------------------------

  private async handlePrivmsg(parsed: IRCLine): Promise<void> {
    const body = parsed.trailing
    const sender = parsed.sourceNick
    const host = parsed.sourceHost

    if (IGNORE_USERS.map((n) => n.toLowerCase()).includes(sender.toLowerCase())) {
      return
    }
    if (SERVICE_NICKS.has(sender.toLowerCase())) return

    const targetInfo = resolveTarget(parsed.params, body, this.currentNick)
    if (!targetInfo) return

    // Hard DM block: private messages from unlisted nicks are dropped before
    // they reach the agent context. Listed nicks get through but tagged
    // UNTRUSTED until the WHOIS round-trip confirms services.
    if (!targetInfo.isChannel && !isTrustListed(sender, this.trustRules)) {
      this.log(`[DM_BLOCKED] from ${sender} (${host}) LEN=${body.length}`)
      return
    }

    const trust = this.trustCheck(sender, host)

    const triggerMatch = matchTrigger({
      body,
      isChannel: targetInfo.isChannel,
      ourNick: this.currentNick,
      trigger: TRIGGER,
      respondToMentions: RESPOND_TO_MENTIONS,
    })

    if (!triggerMatch.triggered) {
      // Even untriggered messages get logged so the agent can see channel
      // context if it wants to; just not acted on.
      this.log(`[MSG] ${trust.trusted ? "TRUSTED" : "UNTRUSTED"} FROM=${sender} HOST=${host} TO=${targetInfo.target} BODY=${body.slice(0, 200)}`)
      if (isTrustListed(sender, this.trustRules) && !trust.trusted) {
        this.log(`[TRUST_DENIED] ${sender} (${host}) reason=${trust.reason}`)
      }
      return
    }

    if (this.isDuplicateEvent(`${targetInfo.sessionId}:${parsed.trailing}:${sender}`)) {
      return
    }

    this.log(`[MSG] ${trust.trusted ? "TRUSTED" : "UNTRUSTED"} FROM=${sender} HOST=${host} TO=${targetInfo.target} BODY=${body.slice(0, 200)}`)
    if (isTrustListed(sender, this.trustRules) && !trust.trusted) {
      this.log(`[TRUST_DENIED] ${sender} (${host}) reason=${trust.reason}`)
    }

    const query = triggerMatch.query
    const id = targetInfo.sessionId
    const sendFn = async (text: string) => {
        await this.sendMessage(targetInfo.target, text)
      }

    await this.stopMirrorForUserActivity(id, query, sendFn)

    if (query.startsWith("/")) {
      await this.handleCommand(id, query, sendFn)
      return
    }

    if (!this.checkRateLimit(sender)) {
      await sendFn("Please wait a few seconds before sending another message.")
      return
    }

    await this.processQuery(targetInfo.target, id, sender, query, trust.trusted)
  }

  private async processQuery(
    target: string,
    id: string,
    sender: string,
    query: string,
    trusted: boolean,
  ): Promise<void> {
    const startTime = Date.now()

    if (this.isQueryActive(id)) {
      await this.sendMessage(target, "A request is already running in this thread. Wait for it to finish.")
      return
    }
    this.markQueryActive(id)

    const session = await this.getOrCreateSession(id, (client) => this.createSession(client))
    if (!session) {
      await this.sendMessage(target, "Sorry, I couldn't connect to the AI service.")
      return
    }

    session.messageCount++
    session.lastActivity = new Date()
    session.inputChars += query.length

    const client = session.client
    let responseBuffer = ""
    let toolResultsBuffer = ""
    let toolCallCount = 0
    const sentToolOutputs = new Set<string>()

    const toolActivity = new ToolActivityController(config.toolMessages, {
      create: async (text) => {
        await this.sendMessage(target, `> ${text}`)
        return null // IRC has no message-edit primitive, so we always create new.
      },
      update: async () => {
        throw new Error("IRC cannot edit existing messages")
      },
      onError: (error) => this.logError("Failed to update tool activity:", error),
    }, {
      sendEvent: async (activityMessage) => {
        await this.sendMessage(target, `> ${activityMessage}`)
      },
      onToolStart: () => { toolCallCount++ },
    })

    const chunkHandler = (text: string) => { responseBuffer += text }

    const updateHandler = async (update: any) => {
      if (update.type === "tool_result" && update.toolResult) {
        toolResultsBuffer += update.toolResult
        const toolName = update.toolName || ""
        if (!shouldShowToolOutput(toolName, config.toolMessages)) return
        const result = update.toolResult.length > MAX_LINE_BYTES
          ? update.toolResult.slice(0, MAX_LINE_BYTES) + "\n... (truncated)"
          : update.toolResult
        const output = result.trim()
        const key = output.slice(0, 100)
        if (output && !sentToolOutputs.has(key)) {
          sentToolOutputs.add(key)
          await this.sendMessage(target, output)
        }
      }
      if (update.type === "tool_output_delta" && update.partialOutput) {
        const toolName = update.toolName || ""
        if (!shouldShowToolOutput(toolName, config.toolMessages)) return
        const output = update.partialOutput.trim()
        const key = output.slice(0, 100)
        if (output && !sentToolOutputs.has(key)) {
          sentToolOutputs.add(key)
          await this.sendMessage(target, output)
        }
      }
    }

    const permissionHandler = async (event: { permission: string; path: string | null; message: string }) => {
      this.log(`[PERMISSION] Rejected: ${event.permission}${event.path ? ` (${event.path})` : ""}`)
      await this.sendMessage(target, `> ${event.message}`)
    }

    client.on("activity", toolActivity.handleActivity)
    client.on("tool_activity", toolActivity.handleRevision)
    client.on("chunk", chunkHandler)
    client.on("update", updateHandler)
    client.on("permission_rejected", permissionHandler)

    try {
      await client.prompt(query)

      // Forward images from tool results (upload as text; IRC has no inline image).
      const toolPaths = extractImagePaths(toolResultsBuffer)
      for (const imagePath of toolPaths) {
        if (fs.existsSync(imagePath)) {
          this.log(`Image at ${imagePath} (cannot attach on IRC; surfacing path)`)
          await this.sendMessage(target, `[image: ${imagePath}]`)
        }
      }
      const responsePaths = extractImagePaths(responseBuffer)
      for (const imagePath of responsePaths) {
        if (toolPaths.includes(imagePath)) continue
        if (fs.existsSync(imagePath)) {
          await this.sendMessage(target, `[image: ${imagePath}]`)
        }
      }

      const cleanResponse = sanitizeServerPaths(stripThinkBlocks(removeImageMarkers(responseBuffer)))
      if (cleanResponse) {
        session.outputChars += cleanResponse.length
        await this.sendMessage(target, cleanResponse)
      }
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1)
      const outChars = cleanResponse ? cleanResponse.length : 0
      const tools = toolCallCount > 0 ? `, ${toolCallCount} tool${toolCallCount === 1 ? "" : "s"}` : ""
      const trustTag = trusted ? "" : " (UNTRUSTED sender)"
      this.log(`[DONE] ${elapsed}s (${outChars} chars${tools}) from=${sender}${trustTag}`)
    } catch (err) {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1)
      this.logError(`[FAIL] ${elapsed}s from=${sender}:`, err)
      await this.sendMessage(target, this.userErrorMessage("Sorry, something went wrong processing your request.", err))
    } finally {
      await toolActivity.flush()
      client.off("activity", toolActivity.handleActivity)
      client.off("tool_activity", toolActivity.handleRevision)
      client.off("chunk", chunkHandler)
      client.off("update", updateHandler)
      client.off("permission_rejected", permissionHandler)
      if (session) session.lastActivity = new Date()
      this.markQueryDone(id)
    }
  }

  private createSession(client: ACPClient): ChannelSession {
    return { ...this.createBaseSession(client) }
  }
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  const connector = new IRCConnector()

  process.on("SIGINT", async () => {
    await connector.stop()
    process.exit(0)
  })
  process.on("SIGTERM", async () => {
    await connector.stop()
    process.exit(0)
  })

  await connector.start()
}

// Only invoke main() when run directly. Imports (e.g. unit tests) skip it.
if (import.meta.main) {
  main().catch((err) => {
    console.error("Fatal error:", err)
    process.exit(1)
  })
}