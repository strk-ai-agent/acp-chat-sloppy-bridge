/**
 * Unit tests for IRC connector helpers
 *
 * Tests the pure functions exported from connectors/irc.ts:
 *  - parseIRCLine           : RFC 1459 line framing
 *  - resolveTarget          : channel vs DM session key derivation
 *  - matchTrigger           : trigger prefix / nick-address / DM detection
 *  - parseTrustRules        : trust file parsing
 *  - isTrustListed          : trust file membership
 *  - hostMatches / hostMatchesRule : fnmatch-style host glob
 *  - splitMessage           : byte-aware message chunking
 */

import { describe, test, expect } from "bun:test"
import {
  parseIRCLine,
  resolveTarget,
  matchTrigger,
  parseTrustRules,
  isTrustListed,
  hostMatchesRule,
  hostMatches,
  splitMessage,
} from "../../connectors/irc"

// =============================================================================
// parseIRCLine
// =============================================================================

describe("parseIRCLine", () => {
  test("parses a PRIVMSG with prefix, params and trailing", () => {
    const parsed = parseIRCLine(":alice!~a@*.libera.chat PRIVMSG #opencode :hello world")
    expect(parsed).not.toBeNull()
    expect(parsed!.command).toBe("privmsg")
    expect(parsed!.prefix).toBe("alice!~a@*.libera.chat")
    expect(parsed!.sourceNick).toBe("alice")
    expect(parsed!.sourceUser).toBe("~a")
    expect(parsed!.sourceHost).toBe("*.libera.chat")
    expect(parsed!.params).toEqual(["#opencode"])
    expect(parsed!.trailing).toBe("hello world")
  })

  test("parses a server numeric without source nick", () => {
    const parsed = parseIRCLine(":irc.example.org 001 opencode-bot :Welcome to the network")
    expect(parsed!.command).toBe("001")
    expect(parsed!.sourceNick).toBe("irc.example.org")
    expect(parsed!.sourceUser).toBe("")
    expect(parsed!.sourceHost).toBe("")
    expect(parsed!.params).toEqual(["opencode-bot"])
    expect(parsed!.trailing).toBe("Welcome to the network")
  })

  test("parses a multi-param numeric", () => {
    const parsed = parseIRCLine(":srv 307 mybot alice :has identified for this nick")
    expect(parsed!.command).toBe("307")
    expect(parsed!.params).toEqual(["mybot", "alice"])
    expect(parsed!.trailing).toBe("has identified for this nick")
  })

  test("strips trailing CR", () => {
    const parsed = parseIRCLine(":a!b@c PRIVMSG #x :hi\r")
    expect(parsed!.trailing).toBe("hi")
  })

  test("returns null on empty input", () => {
    expect(parseIRCLine("")).toBeNull()
    expect(parseIRCLine("\r")).toBeNull()
  })

  test("returns null on garbage without command token", () => {
    expect(parseIRCLine(":just-a-prefix")).toBeNull()
  })

  test("handles command without prefix or trailing", () => {
    const parsed = parseIRCLine("PING :server.example.org")
    expect(parsed!.command).toBe("ping")
    expect(parsed!.prefix).toBe("")
    expect(parsed!.trailing).toBe("server.example.org")
  })

  test("handles empty trailing param", () => {
    const parsed = parseIRCLine(":alice!a@b PRIVMSG #x :")
    expect(parsed!.trailing).toBe("")
  })
})

// =============================================================================
// resolveTarget
// =============================================================================

describe("resolveTarget", () => {
  test("classifies #channel as channel and lower-cases session id", () => {
    const t = resolveTarget(["#OpenCode"], "hi", "opencode-bot")
    expect(t).not.toBeNull()
    expect(t!.isChannel).toBe(true)
    expect(t!.target).toBe("#OpenCode")
    expect(t!.sessionId).toBe("#opencode")
  })

  test("classifies & local-channel as channel", () => {
    const t = resolveTarget(["&local"], "hi", "bot")
    expect(t!.isChannel).toBe(true)
  })

  test("treats plain nick as a DM and uses pm:<nick> session key", () => {
    const t = resolveTarget(["opencode-bot"], "hi", "opencode-bot")
    expect(t!.isChannel).toBe(false)
    expect(t!.sessionId).toBe("pm:opencode-bot")
  })

  test("returns null when no target param", () => {
    expect(resolveTarget([], "hi", "bot")).toBeNull()
  })
})

// =============================================================================
// matchTrigger
// =============================================================================

describe("matchTrigger", () => {
  const base = { ourNick: "opencode-bot", trigger: "!oc", respondToMentions: true }

  test("DM always triggers", () => {
    const m = matchTrigger({ body: "hello there", isChannel: false, ...base })
    expect(m.triggered).toBe(true)
    expect(m.query).toBe("hello there")
    expect(m.reason).toBe("dm")
  })

  test("channel trigger prefix strips the prefix", () => {
    const m = matchTrigger({ body: "!oc what time is it", isChannel: true, ...base })
    expect(m.triggered).toBe(true)
    expect(m.query).toBe("what time is it")
    expect(m.reason).toBe("channel-trigger-prefix")
  })

  test("channel trigger prefix is case-insensitive", () => {
    const m = matchTrigger({ body: "!OC ping", isChannel: true, ...base })
    expect(m.triggered).toBe(true)
    expect(m.query).toBe("ping")
  })

  test("channel nick-address with colon triggers when respondToMentions is on", () => {
    const m = matchTrigger({ body: "opencode-bot: ping", isChannel: true, ...base })
    expect(m.triggered).toBe(true)
    expect(m.query).toBe("ping")
    expect(m.reason).toBe("channel-nick-address")
  })

  test("channel nick-address with comma triggers when respondToMentions is on", () => {
    const m = matchTrigger({ body: "opencode-bot, ping", isChannel: true, ...base })
    expect(m.triggered).toBe(true)
    expect(m.query).toBe("ping")
  })

  test("channel nick-address is ignored when respondToMentions is off", () => {
    const m = matchTrigger({
      body: "opencode-bot: ping",
      isChannel: true,
      ...base,
      respondToMentions: false,
    })
    expect(m.triggered).toBe(false)
    expect(m.nickAddressedButIgnored).toBe(true)
    expect(m.reason).toBe("channel-nick-address-no-respond")
  })

  test("untriggered channel message is left as-is", () => {
    const m = matchTrigger({ body: "general banter", isChannel: true, ...base })
    expect(m.triggered).toBe(false)
    expect(m.query).toBe("general banter")
    expect(m.reason).toBe("channel-no-trigger")
  })

  test("empty body does not trigger", () => {
    const m = matchTrigger({ body: "", isChannel: true, ...base })
    expect(m.triggered).toBe(false)
    expect(m.reason).toBe("empty")
  })

  test("body with only the trigger (no payload) does not trigger", () => {
    const m = matchTrigger({ body: "!oc", isChannel: true, ...base })
    expect(m.triggered).toBe(false)
    expect(m.reason).toBe("channel-no-trigger")
  })
})

// =============================================================================
// parseTrustRules
// =============================================================================

describe("parseTrustRules", () => {
  test("parses simple entries", () => {
    const rules = parseTrustRules(["alice *.libera.chat", "bob *.ofte.net"])
    expect(rules).toEqual([
      { nick: "alice", hostGlob: "*.libera.chat" },
      { nick: "bob", hostGlob: "*.ofte.net" },
    ])
  })

  test("ignores blank lines and comments", () => {
    const rules = parseTrustRules([
      "",
      "# a comment",
      "alice *.libera.chat",
      "   ",
    ])
    expect(rules).toHaveLength(1)
    expect(rules[0].nick).toBe("alice")
  })

  test("supports newline-joined entries (one big string)", () => {
    const rules = parseTrustRules(["alice *.libera.chat\nbob *.ofte.net\n"])
    expect(rules).toHaveLength(2)
  })

  test("ignores malformed entries (missing host glob)", () => {
    const rules = parseTrustRules(["alice-only", "bob *.ofte.net"])
    expect(rules).toHaveLength(1)
    expect(rules[0].nick).toBe("bob")
  })

  test("lower-cases nick entries", () => {
    const rules = parseTrustRules(["Alice *.libera.chat"])
    expect(rules[0].nick).toBe("alice")
  })
})

// =============================================================================
// isTrustListed / hostMatches / hostMatchesRule
// =============================================================================

describe("isTrustListed", () => {
  const rules = parseTrustRules(["alice *.libera.chat"])

  test("matches listed nick case-insensitively", () => {
    expect(isTrustListed("alice", rules)).toBe(true)
    expect(isTrustListed("Alice", rules)).toBe(true)
    expect(isTrustListed("ALICE", rules)).toBe(true)
  })

  test("returns false for unlisted nicks", () => {
    expect(isTrustListed("bob", rules)).toBe(false)
  })
})

describe("hostMatchesRule", () => {
  const rule = { nick: "alice", hostGlob: "*.libera.chat" }

  test("matches a wildcard glob", () => {
    expect(hostMatchesRule("user/libera/staff/libera.chat", rule)).toBe(false) // missing wildcard match
    expect(hostMatchesRule("frob.li.irc.libera.chat", rule)).toBe(true)
  })

  test("supports literal hosts without wildcards", () => {
    const r = { nick: "bob", hostGlob: "fixed.host.example" }
    expect(hostMatchesRule("fixed.host.example", r)).toBe(true)
    expect(hostMatchesRule("not.fixed.host.example", r)).toBe(false)
  })

  test("matches single-char ? wildcard", () => {
    const r = { nick: "x", hostGlob: "host?.example" }
    expect(hostMatchesRule("host1.example", r)).toBe(true)
    expect(hostMatchesRule("host12.example", r)).toBe(false)
  })

  test("escapes regex metacharacters", () => {
    const r = { nick: "x", hostGlob: "a.b.example" }
    // dot must not match arbitrary chars
    expect(hostMatchesRule("aXb.example", r)).toBe(false)
    expect(hostMatchesRule("a.b.example", r)).toBe(true)
  })
})

describe("hostMatches", () => {
  const rules = parseTrustRules(["alice *.libera.chat"])

  test("matches when nick is listed and host matches its glob", () => {
    expect(hostMatches("alice", "frob.li.irc.libera.chat", rules)).toBe(true)
  })

  test("rejects when host does not match", () => {
    expect(hostMatches("alice", "attacker.example.org", rules)).toBe(false)
  })

  test("rejects when nick is not listed", () => {
    expect(hostMatches("bob", "frob.li.irc.libera.chat", rules)).toBe(false)
  })
})

// =============================================================================
// splitMessage
// =============================================================================

describe("splitMessage", () => {
  test("returns single chunk when body fits", () => {
    expect(splitMessage("hello", 400)).toEqual(["hello"])
  })

  test("splits at byte boundary when body exceeds limit", () => {
    const body = "a".repeat(500)
    const chunks = splitMessage(body, 100)
    expect(chunks.length).toBeGreaterThan(1)
    for (const chunk of chunks) {
      expect(Buffer.byteLength(chunk, "utf8")).toBeLessThanOrEqual(100)
    }
    expect(chunks.join("")).toBe(body)
  })

  test("preserves multibyte UTF-8 characters (no splitting mid-codepoint)", () => {
    // Each emoji is 4 bytes in UTF-8.
    const body = "😀".repeat(50) // 200 bytes total
    const chunks = splitMessage(body, 50) // forces split
    for (const chunk of chunks) {
      expect(Buffer.byteLength(chunk, "utf8")).toBeLessThanOrEqual(50)
      // round-tripping must produce the same string
      expect(Buffer.from(chunk, "utf8").toString("utf8")).toBe(chunk)
    }
  })

  test("returns empty-chunk fallback for empty input", () => {
    expect(splitMessage("", 400)).toEqual([""])
  })
})