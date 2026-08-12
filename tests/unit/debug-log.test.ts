import { afterEach, describe, expect, test } from "bun:test"
import fs from "fs"
import os from "os"
import path from "path"
import { createDebugLogger } from "../../src/debug-log"

const temporaryDirectories: string[] = []

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

function temporaryPath(): { directory: string; logPath: string } {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bridge-debug-test-"))
  temporaryDirectories.push(directory)
  return { directory, logPath: path.join(directory, "missing", "logs", "bridge-debug.log") }
}

describe("debug logger", () => {
  test("creates missing parent directories and appends messages", () => {
    const { logPath } = temporaryPath()
    const logger = createDebugLogger({ enabled: true, filePath: logPath })

    logger("first message")
    logger("second message")

    const content = fs.readFileSync(logPath, "utf8")
    expect(content).toContain("first message\n")
    expect(content).toContain("second message\n")
    expect(content.split("\n").filter(Boolean)).toHaveLength(2)
    expect(fs.statSync(logPath).mode & 0o777).toBe(0o600)
  })

  test("tightens permissions on an existing debug log", () => {
    const { logPath } = temporaryPath()
    fs.mkdirSync(path.dirname(logPath), { recursive: true })
    fs.writeFileSync(logPath, "existing\n", { mode: 0o644 })
    fs.chmodSync(logPath, 0o644)
    const logger = createDebugLogger({ enabled: true, filePath: logPath })

    logger("new message")

    expect(fs.statSync(logPath).mode & 0o777).toBe(0o600)
    expect(fs.readFileSync(logPath, "utf8")).toContain("existing\n")
  })

  test("does not touch the filesystem when disabled", () => {
    const { logPath } = temporaryPath()
    const logger = createDebugLogger({ enabled: false, filePath: logPath })

    logger("ignored")

    expect(fs.existsSync(logPath)).toBe(false)
  })

  test("reports a write failure once and never throws into bridge processing", () => {
    const { directory } = temporaryPath()
    const invalidLogPath = path.join(directory, "not-a-directory", "bridge-debug.log")
    fs.writeFileSync(path.dirname(invalidLogPath), "blocking file")
    const errors: unknown[] = []
    const logger = createDebugLogger({
      enabled: true,
      filePath: invalidLogPath,
      onError: (error) => errors.push(error),
    })

    expect(() => logger("first failure")).not.toThrow()
    expect(() => logger("ignored after failure")).not.toThrow()
    expect(errors).toHaveLength(1)
  })
})
