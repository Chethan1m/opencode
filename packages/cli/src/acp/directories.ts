import { basename, dirname, isAbsolute, join } from "node:path"
import { isDeepStrictEqual } from "node:util"
import type { OpenCodeClient, PermissionRule, SessionInfo } from "@opencode/client/promise"
import { FSUtil } from "@opencode/util/fs-util"
import { Effect } from "effect"
import { ACPError } from "./error"
import { ACPPromise } from "./promise"

/**
 * Resolves additional workspace roots the way session cwd is resolved, dropping duplicates and cwd itself.
 * Glob characters are rejected because permission resources would treat them as wildcards.
 */
export const parse = Effect.fnUntraced(function* (cwd: string, directories: readonly string[] = []) {
  const invalid = directories.find((directory) => !isAbsolute(directory) || /[*?]/.test(directory))
  if (invalid !== undefined) return yield* new ACPError.InvalidAdditionalDirectoryError({ directory: invalid })
  const root = FSUtil.resolve(cwd)
  return [...new Set(directories.map((directory) => FSUtil.resolve(directory)))].filter(
    (directory) => directory !== root,
  )
})

/** Grants each directory subtree the access tools already have inside the session directory. */
export function rules(directories: readonly string[]): PermissionRule[] {
  return directories.map((directory) => ({
    action: "external_directory",
    resource: join(directory, "**"),
    effect: "allow",
  }))
}

/** The additional directories granted by ACP-owned rules, in request order. */
export function list(permissions: readonly PermissionRule[] = []) {
  return permissions.filter(owned).map((rule) => dirname(rule.resource))
}

/** Replaces the session's ACP-owned rules with grants for exactly these directories. */
export const activate = Effect.fnUntraced(function* (
  client: OpenCodeClient,
  session: SessionInfo,
  directories: readonly string[],
) {
  const current = session.permissions ?? []
  // ACP rules lead so the session's other rules keep precedence for the same paths.
  const permissions = [...rules(directories), ...current.filter((rule) => !owned(rule))]
  if (isDeepStrictEqual(permissions, current)) return
  yield* ACPPromise.promise(() => client.session.update({ sessionID: session.id, permissions }))
})

// ACP writes `<dir>/**` while opencode's own grants use `<dir>/*`, so the suffix marks the rules ACP owns.
function owned(rule: PermissionRule) {
  return rule.action === "external_directory" && rule.effect === "allow" && basename(rule.resource) === "**"
}

export * as ACPDirectories from "./directories"
