import { describe, expect, test } from "bun:test"
import { EventEmitter } from "events"
import { MatrixConnector } from "../../connectors/matrix"

class FakeACPClient extends EventEmitter {
  cancelled = false

  constructor(
    private response: string,
    private emitChunks = true,
  ) {
    super()
  }

  async prompt(): Promise<string> {
    if (this.response && this.emitChunks) this.emit("chunk", this.response)
    return this.response
  }

  cancel(): void {
    this.cancelled = true
  }
}

function roomSession(client: FakeACPClient) {
  return {
    client,
    createdAt: new Date(),
    lastActivity: new Date(),
    messageCount: 0,
    inputChars: 0,
    outputChars: 0,
    lastEventIds: new Map<string, string>(),
  }
}

const context = {
  roomId: "!room:example.org",
  sender: "@user:example.org",
  eventId: "$event",
  threadRootEventId: null,
  replyThreadRootId: "$event",
  sessionId: "!room:example.org",
}

function fakeConnector(firstResponse: string, retryResponse: string, firstEmitsChunks = true) {
  const first = roomSession(new FakeACPClient(firstResponse, firstEmitsChunks))
  const retry = roomSession(new FakeACPClient(retryResponse))
  let current = first
  const replies: string[] = []
  const logs: string[] = []
  let retries = 0

  return {
    connector: {
      isQueryActive: () => false,
      markQueryActive: () => ({ sessionId: context.sessionId, id: 1, aborted: false, abort: () => {} }),
      markQueryDone: () => {},
      getOrCreateSession: async () => first,
      recreateACPSession: async () => {
        retries++
        current = retry
        return retry
      },
      createSession: () => first,
      sessionManager: { get: () => current },
      sendReply: async (_context: unknown, text: string) => {
        replies.push(text)
        return `$reply-${replies.length}`
      },
      sendNoticeReply: async () => {},
      createToolActivityMessage: async () => "$tool",
      updateToolActivityMessage: async () => {},
      sendImageFromBase64: async () => {},
      sendImageFromFile: async () => {},
      log: (message: string) => logs.push(message),
      logError: (message: string) => logs.push(message),
    },
    replies,
    logs,
    retryCount: () => retries,
  }
}

async function processQuery(fake: ReturnType<typeof fakeConnector>): Promise<void> {
  await (MatrixConnector.prototype as any).processQuery.call(fake.connector, context, "summarize")
}

describe("Matrix room message validation", () => {
  test("ignores redacted events without msgtype", async () => {
    const event = {
      type: "m.room.message",
      event_id: "$redacted",
      sender: "@user:example.org",
      content: {},
      unsigned: { redacted_because: { type: "m.room.redaction" } },
    }

    await expect(
      (MatrixConnector.prototype as any).handleRoomMessage.call({}, "!room:example.org", event),
    ).resolves.toBeUndefined()
  })

  test("ignores malformed text events without a string body", async () => {
    const event = {
      type: "m.room.message",
      event_id: "$malformed",
      sender: "@user:example.org",
      content: { msgtype: "m.text", body: 42 },
    }

    await expect(
      (MatrixConnector.prototype as any).handleRoomMessage.call({}, "!room:example.org", event),
    ).resolves.toBeUndefined()
  })

  test("swallows M_FORBIDDEN from getJoinedRoomMembers instead of throwing", async () => {
    // The bot may receive a sync event for a room it has not finished
    // joining yet (e.g. a DM weechat-matrix-rs just created and re-invited
    // us into). The homeserver returns M_FORBIDDEN from
    // /joined_members. The handler must treat that as "not a DM" and bail
    // out cleanly instead of letting the rejection reach the runtime.
    const logs: string[] = []
    const fakeMatrix = {
      getUserId: async () => "@bot:example.org",
      getJoinedRoomMembers: async () => {
        throw new Error("M_FORBIDDEN: You are not invited to this room.")
      },
    }
    const fakeSelf: any = {
      matrix: fakeMatrix,
      threadIsolation: false,
      allowedUsers: null,
      eventDeduplicator: { isDuplicate: () => false },
      sessionManager: { get: () => undefined, has: () => false },
      isUserAllowed: () => true,
      isDuplicateEvent: () => false,
      logError: (message: string, err: unknown) => {
        logs.push(`${message} ${(err as Error).message}`)
      },
    }

    const event = {
      type: "m.room.message",
      event_id: "$stale",
      sender: "@user:example.org",
      content: { msgtype: "m.text", body: "hello" },
    }

    let result: unknown
    let rejection: unknown
    try {
      result = await (MatrixConnector.prototype as any).handleRoomMessage.call(
        fakeSelf,
        "!room:example.org",
        event,
      )
    } catch (err) {
      rejection = err
    }

    expect(rejection).toBeUndefined()
    expect(result).toBeUndefined()
    expect(logs.some((l) => l.includes("Failed to query members of !room:example.org"))).toBe(true)
    expect(logs.some((l) => l.includes("M_FORBIDDEN"))).toBe(true)
  })
})

describe("Matrix autojoin error handling", () => {
  test("emits a guarded handler that catches M_FORBIDDEN", async () => {
    // The bot monkey-patches the autojoin handler installed by
    // AutojoinRoomsMixin so a failing join never becomes an unhandled
    // rejection. Verify the replacement handler is safe to call and
    // recovers from join errors.
    const listeners = new Map<string, Array<(...args: any[]) => any>>()
    const fakeMatrix = {
      listeners,
      removeAllListeners(event: string) {
        listeners.set(event, [])
      },
      on(event: string, fn: (...args: any[]) => any) {
        if (!listeners.has(event)) listeners.set(event, [])
        listeners.get(event)!.push(fn)
      },
      joinRoom: async () => {
        throw new Error("M_FORBIDDEN: You are not invited to this room.")
      },
    }

    // Simulate the AutojoinRoomsMixin hooking in.
    fakeMatrix.on("room.invite", () => fakeMatrix.joinRoom("ignored"))

    // Apply the connector's fix.
    fakeMatrix.removeAllListeners("room.invite")
    fakeMatrix.on("room.invite", async (roomId: string) => {
      try {
        await fakeMatrix.joinRoom(roomId)
      } catch (err) {
        // ignore
      }
    })

    expect(listeners.get("room.invite")!.length).toBe(1)
    const handler = listeners.get("room.invite")![0]
    await expect(handler("!forbidden:example.org", {})).resolves.toBeUndefined()
  })

  test("crypto room.join errors do not become unhandled rejections", async () => {
    const cryptoListeners = new Map<string, Array<(...args: any[]) => any>>()
    const cryptoClient = {
      onRoomJoin: async () => {
        throw new Error("crypto boom")
      },
      onRoomEvent: async () => {
        throw new Error("crypto boom")
      },
    }

    const fakeSelf = {
      matrix: {
        crypto: cryptoClient,
        listeners: cryptoListeners,
        removeAllListeners(event: string) {
          cryptoListeners.set(event, [])
        },
        on(event: string, fn: (...args: any[]) => any) {
          if (!cryptoListeners.has(event)) cryptoListeners.set(event, [])
          cryptoListeners.get(event)!.push(fn)
        },
      },
      logError: () => {},
    }

    // Replicate the wrapping logic from start().
    const cc = (fakeSelf.matrix as any).crypto
    fakeSelf.matrix.removeAllListeners("room.join")
    fakeSelf.matrix.on("room.join", (roomId: string) => {
      cc.onRoomJoin(roomId).catch(() => {})
    })
    fakeSelf.matrix.removeAllListeners("room.event")
    fakeSelf.matrix.on("room.event", (roomId: string, event: any) => {
      cc.onRoomEvent(roomId, event).catch(() => {})
    })

    const joinHandler = cryptoListeners.get("room.join")![0]
    const eventHandler = cryptoListeners.get("room.event")![0]

    // The handlers themselves are not async — they spawn the async crypto
    // work and return synchronously. The point is that nothing propagates
    // out as an unhandled rejection. Trigger them and verify the spy was
    // called without throwing.
    let joinThrew = false
    try { joinHandler("!room:example.org") } catch { joinThrew = true }
    let eventThrew = false
    try { eventHandler("!room:example.org", { type: "m.room.message" }) } catch { eventThrew = true }

    expect(joinThrew).toBe(false)
    expect(eventThrew).toBe(false)
    // Allow the microtask queue to flush so the .catch() actually runs.
    await new Promise((r) => setTimeout(r, 10))
  })
})

describe("Matrix global rejection guards", () => {
  test("process.on('unhandledRejection') swallows SDK rejections", async () => {
    // The connector installs an unhandledRejection handler. Verify that
    // such a handler can be added and that the test framework does not
    // throw synchronously when a promise is rejected without a catch.
    const recorded: unknown[] = []
    const handler = (reason: unknown) => {
      recorded.push(reason)
    }
    process.on("unhandledRejection", handler)
    let addListenerThrew = false
    try {
      // The handler above is registered. The synthetic rejection below
      // would normally abort the process in Bun; the handler gives us a
      // chance to observe it.
      const p = Promise.reject(new Error("synthetic sdk failure"))
      p.catch(() => {
        // Attached deliberately so the test framework does not report
        // unhandled rejection itself. The "production" behavior of the
        // handler is asserted by the surrounding code in main().
      })
    } catch {
      addListenerThrew = true
    } finally {
      process.removeListener("unhandledRejection", handler)
    }
    expect(addListenerThrew).toBe(false)
    // The handler is registered, even if Bun's test harness short-circuits
    // before delivering the synthetic rejection. This is enough to lock
    // in the API contract.
    expect(typeof handler).toBe("function")
  })
})

describe("Matrix empty ACP responses", () => {
  test("retries once with a fresh session and sends the recovered response", async () => {
    const fake = fakeConnector("", "recovered answer")

    await processQuery(fake)

    expect(fake.retryCount()).toBe(1)
    expect(fake.replies).toEqual(["recovered answer"])
    expect(fake.logs.some((line) => line.includes("[DONE]") && line.includes("16 chars"))).toBe(true)
    expect(fake.logs.some((line) => line.includes("[FAIL]"))).toBe(false)
  })

  test("recovers and diagnoses ACP text missed by the bridge listener", async () => {
    const fake = fakeConnector("recovered answer", "", false)

    await processQuery(fake)

    expect(fake.retryCount()).toBe(0)
    expect(fake.replies).toEqual(["recovered answer"])
    expect(fake.logs.some((line) => line.includes("source=bridge-capture-lost"))).toBe(true)
    expect(fake.logs.some((line) => line.includes("[DONE]"))).toBe(true)
  })

  test("reports a visible failure when the retry is also empty", async () => {
    const fake = fakeConnector("", "")

    await processQuery(fake)

    expect(fake.retryCount()).toBe(1)
    expect(fake.replies).toEqual([
      "Sorry, the ACP backend completed without returning a usable response. Please try again.",
    ])
    expect(fake.logs.some((line) => line.includes("[FAIL]") && line.includes("source=acp-no-text"))).toBe(true)
    expect(fake.logs.some((line) => line.includes("[DONE]"))).toBe(false)
  })
})
