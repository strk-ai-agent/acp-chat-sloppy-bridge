import fs from "fs"
import { randomUUID } from "crypto"

export interface MatrixTokenValidation {
  userId: string
}

export interface MatrixAccessTokenOptions {
  explicitToken: string
  savedToken: string
  passwordConfigured: boolean
  expectedUserId: string
}

export interface MatrixAccessTokenDependencies {
  validateToken: (token: string) => Promise<MatrixTokenValidation>
  loginWithPassword: () => Promise<string | null>
  saveToken: (token: string) => void
  log: (message: string) => void
}

export function writePrivateFileAtomically(filePath: string, content: string): void {
  const temporaryPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`
  try {
    fs.writeFileSync(temporaryPath, content, { mode: 0o600, flag: "wx" })
    fs.renameSync(temporaryPath, filePath)
  } catch (error) {
    try { fs.unlinkSync(temporaryPath) } catch {}
    throw error
  }
}

export function matrixErrorCode(error: unknown): string {
  if (!error || typeof error !== "object") return ""
  const candidate = error as {
    errcode?: unknown
    body?: { errcode?: unknown }
  }
  if (typeof candidate.errcode === "string") return candidate.errcode
  return typeof candidate.body?.errcode === "string" ? candidate.body.errcode : ""
}

export function isMatrixAuthenticationError(error: unknown): boolean {
  const code = matrixErrorCode(error)
  return code === "M_UNKNOWN_TOKEN" || code === "M_MISSING_TOKEN"
}

export async function resolveMatrixAccessToken(
  options: MatrixAccessTokenOptions,
  dependencies: MatrixAccessTokenDependencies,
): Promise<string | null> {
  if (options.explicitToken) {
    dependencies.log("Using access token from config/env")
    return options.explicitToken
  }

  if (options.savedToken) {
    try {
      const validation = await dependencies.validateToken(options.savedToken)
      if (!options.expectedUserId || validation.userId === options.expectedUserId) {
        dependencies.log("Using validated saved access token")
        return options.savedToken
      }
      dependencies.log(
        `Saved access token belongs to ${validation.userId}, not ${options.expectedUserId}; logging in again`,
      )
    } catch (error) {
      if (!isMatrixAuthenticationError(error)) throw error
      dependencies.log("Saved access token is no longer valid; logging in again")
    }
  }

  if (!options.passwordConfigured) return null
  const token = await dependencies.loginWithPassword()
  if (!token) return null
  dependencies.saveToken(token)
  return token
}
