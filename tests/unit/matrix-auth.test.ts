import { afterEach, describe, expect, test } from "bun:test"
import fs from "fs"
import os from "os"
import path from "path"
import {
  isMatrixAuthenticationError,
  resolveMatrixAccessToken,
  writePrivateFileAtomically,
  type MatrixAccessTokenDependencies,
} from "../../connectors/matrix-auth"

const temporaryDirectories: string[] = []

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

function dependencies(overrides: Partial<MatrixAccessTokenDependencies> = {}) {
  const calls = {
    validated: [] as string[],
    logins: 0,
    saved: [] as string[],
    logs: [] as string[],
  }
  const value: MatrixAccessTokenDependencies = {
    validateToken: async (token) => {
      calls.validated.push(token)
      return { userId: "@bot:example.org" }
    },
    loginWithPassword: async () => {
      calls.logins++
      return "new-token"
    },
    saveToken: (token) => { calls.saved.push(token) },
    log: (message) => { calls.logs.push(message) },
    ...overrides,
  }
  return { calls, value }
}

const baseOptions = {
  explicitToken: "",
  savedToken: "saved-token",
  passwordConfigured: true,
  expectedUserId: "@bot:example.org",
}

describe("Matrix access token resolution", () => {
  test("uses an explicit token without validating or replacing it", async () => {
    const deps = dependencies()
    const token = await resolveMatrixAccessToken({
      ...baseOptions,
      explicitToken: "explicit-token",
    }, deps.value)

    expect(token).toBe("explicit-token")
    expect(deps.calls.validated).toEqual([])
    expect(deps.calls.logins).toBe(0)
    expect(deps.calls.saved).toEqual([])
  })

  test("validates and reuses a saved token for the configured user", async () => {
    const deps = dependencies()
    const token = await resolveMatrixAccessToken(baseOptions, deps.value)

    expect(token).toBe("saved-token")
    expect(deps.calls.validated).toEqual(["saved-token"])
    expect(deps.calls.logins).toBe(0)
    expect(deps.calls.saved).toEqual([])
  })

  test("replaces a saved token rejected with M_UNKNOWN_TOKEN", async () => {
    const deps = dependencies({
      validateToken: async () => {
        throw { errcode: "M_UNKNOWN_TOKEN" }
      },
    })
    const token = await resolveMatrixAccessToken(baseOptions, deps.value)

    expect(token).toBe("new-token")
    expect(deps.calls.logins).toBe(1)
    expect(deps.calls.saved).toEqual(["new-token"])
  })

  test("replaces a saved token rejected with nested M_MISSING_TOKEN", async () => {
    const deps = dependencies({
      validateToken: async () => {
        throw { body: { errcode: "M_MISSING_TOKEN" } }
      },
    })
    const token = await resolveMatrixAccessToken(baseOptions, deps.value)

    expect(token).toBe("new-token")
    expect(deps.calls.logins).toBe(1)
    expect(deps.calls.saved).toEqual(["new-token"])
  })

  test("does not replace a token after a network or homeserver failure", async () => {
    const networkError = new Error("connection refused")
    const deps = dependencies({
      validateToken: async () => { throw networkError },
    })

    await expect(resolveMatrixAccessToken(baseOptions, deps.value)).rejects.toBe(networkError)
    expect(deps.calls.logins).toBe(0)
    expect(deps.calls.saved).toEqual([])
  })

  test("replaces a valid token belonging to a different user", async () => {
    const deps = dependencies({
      validateToken: async () => ({ userId: "@other:example.org" }),
    })
    const token = await resolveMatrixAccessToken(baseOptions, deps.value)

    expect(token).toBe("new-token")
    expect(deps.calls.logins).toBe(1)
    expect(deps.calls.saved).toEqual(["new-token"])
  })

  test("does not replace an invalid token without a configured password", async () => {
    const deps = dependencies({
      validateToken: async () => { throw { body: { errcode: "M_UNKNOWN_TOKEN" } } },
    })
    const token = await resolveMatrixAccessToken({
      ...baseOptions,
      passwordConfigured: false,
    }, deps.value)

    expect(token).toBeNull()
    expect(deps.calls.logins).toBe(0)
    expect(deps.calls.saved).toEqual([])
  })

  test("does not save anything when password login fails", async () => {
    const deps = dependencies({
      loginWithPassword: async () => null,
    })
    const token = await resolveMatrixAccessToken({
      ...baseOptions,
      savedToken: "",
    }, deps.value)

    expect(token).toBeNull()
    expect(deps.calls.saved).toEqual([])
  })
})

describe("Matrix token persistence", () => {
  test("atomically writes owner-only token files and replaces existing content", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "matrix-token-test-"))
    temporaryDirectories.push(directory)
    const tokenPath = path.join(directory, "access_token")

    writePrivateFileAtomically(tokenPath, "first-token")
    expect(fs.readFileSync(tokenPath, "utf-8")).toBe("first-token")
    expect(fs.statSync(tokenPath).mode & 0o777).toBe(0o600)

    writePrivateFileAtomically(tokenPath, "second-token")
    expect(fs.readFileSync(tokenPath, "utf-8")).toBe("second-token")
    expect(fs.readdirSync(directory)).toEqual(["access_token"])
  })
})

describe("Matrix authentication error classification", () => {
  test("recognizes only Matrix token authentication errors", () => {
    expect(isMatrixAuthenticationError({ errcode: "M_UNKNOWN_TOKEN" })).toBe(true)
    expect(isMatrixAuthenticationError({ body: { errcode: "M_MISSING_TOKEN" } })).toBe(true)
    expect(isMatrixAuthenticationError({ errcode: "M_FORBIDDEN" })).toBe(false)
    expect(isMatrixAuthenticationError(new Error("M_UNKNOWN_TOKEN"))).toBe(false)
  })
})
