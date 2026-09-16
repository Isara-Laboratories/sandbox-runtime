import * as fs from 'node:fs'
import * as path from 'node:path'
import type { FilesystemConfig } from './sandbox-config.js'
import { parseGlob } from './apparmor-patterns.js'
import { normalizePathForSandbox } from './sandbox-utils.js'

export type RepositoryProtection = NonNullable<
  FilesystemConfig['repositoryProtection']
>
export const REPOSITORY_PROTECTION_MARKER = '# srt-repository-protection-v1'

export const within = (candidate: string, root: string): boolean =>
  candidate === root || candidate.startsWith(root === '/' ? '/' : root + '/')

/** Scope paths are canonical literal names, not aliases or policy expressions. */
function scopePath(raw: string, allowMissing = false): string {
  parseGlob(raw)
  if (
    !path.isAbsolute(raw) ||
    /[*?]/.test(raw) ||
    path.resolve(raw) !== raw ||
    raw === '/' ||
    /^\/(dev|proc|sys)(\/|$)/.test(raw)
  )
    throw new Error(
      `repositoryProtection requires canonical absolute directory paths: ${raw}`,
    )
  let candidate = raw
  if (allowMissing && !fs.existsSync(candidate))
    candidate = path.dirname(candidate)
  if (
    !fs.statSync(candidate).isDirectory() ||
    fs.realpathSync(candidate) !== candidate
  )
    throw new Error(
      `repositoryProtection path is not a canonical directory: ${raw}`,
    )
  // existsSync follows symlinks, including dangling ones: lstat checks the leaf too.
  try {
    if (fs.lstatSync(raw).isSymbolicLink())
      throw new Error(`repositoryProtection cannot use a symlink: ${raw}`)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT' || !allowMissing)
      throw error
  }
  return raw
}

/** Pure validation used by both profile generation and mount construction. */
export function resolveRepositoryProtection(
  value: RepositoryProtection,
): RepositoryProtection {
  if (
    !value.roots.length ||
    value.roots.length > 8 ||
    value.worktreeRoots.length > 8 ||
    value.gitDirectories.length > 8
  )
    throw new Error('repositoryProtection exceeds scope limits')
  const roots = [...new Set(value.roots.map(p => scopePath(p)))].sort()
  const gitDirectories = [
    ...new Set(value.gitDirectories.map(p => scopePath(p))),
  ].sort()
  const worktreeRoots = [
    ...new Set(value.worktreeRoots.map(p => scopePath(p, true))),
  ].sort()
  for (const scratch of worktreeRoots) {
    if (
      !roots.includes(path.dirname(scratch)) ||
      /^(\.git|\.claude|\.pi|\.codex|\.vscode|\.idea)$/i.test(
        path.basename(scratch),
      )
    )
      throw new Error(
        `worktreeRoots must be separate direct children of protected roots: ${scratch}`,
      )
    if (
      roots.includes(scratch) ||
      gitDirectories.some(git => within(scratch, git) || within(git, scratch))
    )
      throw new Error(
        `worktreeRoots must not overlap shared Git metadata: ${scratch}`,
      )
  }
  return { roots, worktreeRoots, gitDirectories }
}

/**
 * Rebuild the complete mount plan parent-first. Simply appending barriers could
 * erase narrower write grants; retaining the old allowWrite order could hide a
 * barrier with a later ancestor bind (notably repositories under /tmp).
 * Boundaries are mounts even when backed by the same filesystem: rename returns
 * EXDEV across them, and moving/replacing a boundary itself returns EBUSY.
 */
export function repositoryFilesystemArgs(
  value: RepositoryProtection,
  allowWrite: string[],
): string[] {
  const scope = resolveRepositoryProtection(value)
  const writes = [...new Set(allowWrite.map(normalizePathForSandbox))].filter(
    p => {
      if (/[*?[\]]/.test(p))
        throw new Error(
          `repositoryProtection requires literal allowWrite: ${p}`,
        )
      if (/^\/(dev|proc|sys)(\/|$)/.test(p)) return false
      // An explicit grant for an absent reserved worktree root must survive
      // filtering so it can be created below; other absent grants stay ignored.
      if (!fs.existsSync(p)) return scope.worktreeRoots.includes(p)
      if (fs.realpathSync(p) !== p)
        throw new Error(
          `repositoryProtection cannot mount a writable alias: ${p}`,
        )
      return true
    },
  )
  const writable = (p: string) => writes.some(root => within(p, root))
  for (const scratch of scope.worktreeRoots) {
    if (!fs.existsSync(scratch) && writable(scratch))
      fs.mkdirSync(scratch, { mode: 0o700 })
  }
  // Revalidate after mkdir; never accept a replaced or newly introduced symlink.
  resolveRepositoryProtection(scope)
  const paths = [
    ...new Set([
      ...writes,
      ...scope.roots,
      ...scope.gitDirectories,
      ...scope.worktreeRoots.filter(p => fs.existsSync(p)),
    ]),
  ].sort(
    (a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b),
  )
  const args = ['--ro-bind', '/', '/']
  for (const p of paths) args.push(writable(p) ? '--bind' : '--ro-bind', p, p)
  return args
}
