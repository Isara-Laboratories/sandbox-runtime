import { createHash } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { homedir } from 'node:os'
import type { FilesystemConfig } from './sandbox-config.js'
import { getDangerousDirectories, getDangerousFiles } from './sandbox-utils.js'
import {
  complementBasename,
  complementTree,
  intersect,
  matchesAny,
  parseGlob,
  render,
  subtract,
  unique,
  type Pattern,
} from './apparmor-patterns.js'

export interface AppArmorPolicy {
  name: string
  policy: string
  /** True when the compiled read denies cover this concrete in-sandbox path. */
  deniesRead: (concretePath: string) => boolean
}
const hasGlob = (s: string) => /[*?]/.test(s)

/**
 * Fixed in-sandbox location of `filesystem.secretFiles` (Linux AppArmor mode).
 * Aliases are `<index>-<basename>` so that basename-selector denies such as
 * `.env` do not match them; the launcher still verifies this against the policy.
 */
export const APPARMOR_SECRETS_DIR = '/dev/srt/secrets'
export const secretAliasPath = (index: number, file: string): string =>
  `${APPARMOR_SECRETS_DIR}/${index}-${path.basename(file)}`

/** Resolve only the finite static prefix, never walk a directory tree. */
function normalize(raw: string): string {
  parseGlob(raw) // Validate before interpreting or resolving any paths.
  // `**/name` selectors apply system-wide (stricter than the legacy
  // project-local expansion) so the profile does not depend on the launch
  // directory. Other relative paths still resolve against cwd.
  const expanded =
    raw === '~'
      ? homedir()
      : raw.startsWith('~/')
        ? homedir() + raw.slice(1)
        : raw === '**' || raw.startsWith('**/')
          ? '/' + raw
          : raw
  let absolute = path.resolve(expanded).replace(/\/\*\*$/, '') || '/'
  // /dev and /proc are replaced by bwrap. Resolving /dev/stdout on the host
  // would make the policy (and its hash!) depend on the launcher's open FDs.
  if (/^\/(dev|proc|sys)(\/|$)/.test(absolute)) return absolute
  const prefix = absolute.split(/[*?]/)[0]!
  let candidate = hasGlob(absolute)
    ? path.dirname(prefix.endsWith('/') ? prefix + '_' : prefix)
    : absolute
  const suffix: string[] = []
  while (true) {
    try {
      const canonical = fs.realpathSync(candidate)
      const resolvedPrefix = path.join(canonical, ...suffix.reverse())
      absolute =
        resolvedPrefix +
        absolute.slice(
          hasGlob(absolute)
            ? path.dirname(prefix.endsWith('/') ? prefix + '_' : prefix).length
            : absolute.length,
        )
      break
    } catch (error) {
      if (
        !['ENOENT', 'ENOTDIR'].includes(
          (error as NodeJS.ErrnoException).code ?? '',
        )
      )
        throw error
      if (candidate === '/') throw error
      suffix.push(path.basename(candidate))
      candidate = path.dirname(candidate)
    }
  }
  return absolute.replace(/\/$/, '') || '/'
}

const tree = (p: string): Pattern[] =>
  p === '/' ? parseGlob('/**') : [...parseGlob(p), ...parseGlob(p + '/**')]
const quote = (s: string) => `"${s}"`

function basenameSelector(
  p: string,
): { root: string; name: string } | undefined {
  const marker = p.indexOf('/**/')
  if (
    marker < 0 ||
    hasGlob(p.slice(0, marker)) ||
    p.slice(marker + 4).includes('/')
  )
    return undefined
  return { root: p.slice(0, marker), name: p.slice(marker + 4) }
}

/**
 * Compile a bounded, documented subset of SRT policy to an enforcing profile.
 * AppArmor denies cannot be re-allowed. Subtract read exceptions before emitting
 * deny rules, instead of relying on misleading rule order.
 *
 * Conservative differences: denied-read objects are also immutable; a template
 * glob does not reopen a child inside a denied directory. A literal allowRead
 * can reopen such a child. Bracket globs/non-ASCII paths and complex read-exception
 * expressions are rejected, not silently dropped. See the backend README.
 */
export function compileAppArmorFilesystem(
  config: FilesystemConfig,
): AppArmorPolicy {
  if (
    [
      ...config.denyRead,
      ...(config.allowRead ?? []),
      ...config.allowWrite,
      ...config.denyWrite,
    ].length > 512
  ) {
    throw new Error('AppArmor policy exceeds safe entry limit')
  }
  const allowRead = [...new Set((config.allowRead ?? []).map(normalize))]
  const literalExceptions = allowRead.filter(p => !hasGlob(p))
  const globExceptions = allowRead.filter(hasGlob)
  for (const exception of globExceptions) {
    const selector = basenameSelector(exception)
    if (!selector)
      throw new Error(
        `AppArmor allowRead glob must be a recursive basename selector: ${exception}`,
      )
    complementBasename(selector.name) // reject unsupported shapes even if currently disjoint
  }
  const rules = new Set<string>()
  const add = (patterns: Pattern[], perms: string, deny = false) => {
    for (const p of unique(patterns)) {
      // AARE collapses literal // before compiling. Intersection can produce
      // impossible normalized paths containing //; emitting those would turn
      // an empty branch into a broader rule and destroy read exceptions.
      if (
        p.some(
          (a, i) =>
            !a.excluded &&
            a.chars === '/' &&
            !p[i - 1]?.excluded &&
            p[i - 1]?.chars === '/',
        )
      )
        continue
      rules.add(`  ${deny ? 'deny ' : ''}${quote(render(p))} ${perms},`)
    }
  }
  // The profile carries only the repository-independent rules: every deny,
  // every read exception and the mandatory protections. Writable roots are
  // per-launch bubblewrap mounts (read-only root plus read-write binds), so
  // the same loaded profile serves every repository. No change_profile,
  // mount, capability, ptrace-to-peer, or policy-management permissions.
  rules.add('  network,')
  rules.add('  signal,')
  rules.add('  ptrace (readby, tracedby),')
  rules.add('  "/" r,')
  rules.add('  "/**" rwklix,')

  const foldCase = (patterns: Pattern[]): Pattern[] =>
    patterns.map(pattern =>
      pattern.map(atom =>
        !atom.excluded && /^[a-zA-Z]$/.test(atom.chars)
          ? {
              ...atom,
              chars: atom.chars.toUpperCase() + atom.chars.toLowerCase(),
            }
          : atom,
      ),
    )
  const protectAncestors = (p: string, insensitive = false) => {
    const ancestorPattern = (s: string) =>
      insensitive ? foldCase(parseGlob(s)) : parseGlob(s)
    // Protect literal ancestors against renaming an entire policy root away.
    const staticPart = p.split(/[*?]/)[0]!
    let parent = path.dirname(
      staticPart.endsWith('/') ? staticPart + '_' : staticPart,
    )
    while (parent !== '/') {
      add(ancestorPattern(parent + '/'), 'w', true)
      parent = path.dirname(parent)
    }
    // Protect named ancestors after ** (e.g. .git above .git/hooks). Do not
    // protect a bare ** directory: that would prohibit creating any directory.
    let globParent = path.dirname(p)
    while (hasGlob(globParent) && !globParent.endsWith('/**')) {
      add(ancestorPattern(globParent + '/'), 'w', true)
      globParent = path.dirname(globParent)
    }
  }

  const deniedRead: Pattern[] = []
  for (const p of [...new Set(config.denyRead.map(normalize))]) {
    let denied: Pattern[]
    const selector = basenameSelector(p)
    if (selector && globExceptions.length) {
      let names = parseGlob(selector.name)
      let exceptions = globExceptions
        .map(basenameSelector)
        .filter(e => e?.root === selector.root)
        .map(e => e!.name)
      // Under .env.*, these are redundant with the two standard example rules.
      if (
        selector.name === '.env.*' &&
        exceptions.includes('.env.example') &&
        exceptions.includes('.env.*.example')
      ) {
        exceptions = exceptions.filter(
          e => e !== '*.env.example' && e !== '.envrc',
        )
      }
      for (const exception of exceptions) {
        if (
          !names.some(n =>
            parseGlob(exception).some(e => intersect(n, e).length),
          )
        )
          continue
        names = subtract(names, complementBasename(exception))
      }
      const roots = parseGlob(selector.root + '/**/')
      const direct = roots.flatMap(root =>
        names.map(name => [...root, ...name]),
      )
      denied = [
        ...direct,
        ...direct.map(pattern => [...pattern, ...parseGlob('/**')[0]!]),
      ]
    } else {
      if (hasGlob(p) && globExceptions.length)
        throw new Error(
          `Unsupported AppArmor denyRead/allowRead glob combination: ${p}`,
        )
      denied = tree(p)
    }
    for (const exception of literalExceptions) {
      // A regular-file exception intersects only its own path; subtree
      // semantics for directories/absent paths. (Stat-dependent, but stable
      // for the fixed files Isara names; per-launch secrets use secretFiles.)
      let isFile = false
      try {
        isFile = fs.statSync(exception).isFile()
      } catch {
        /* absent paths retain subtree semantics */
      }
      const allowed = isFile ? parseGlob(exception) : tree(exception)
      denied = unique(
        denied.flatMap(d =>
          allowed.some(e => intersect(d, e).length)
            ? subtract([d], complementTree(exception))
            : [d],
        ),
      )
    }
    add(denied, 'rwmx', true)
    deniedRead.push(...denied)
    if (denied.length) protectAncestors(p)
  }

  // Mandatory denies are name rules, not a cwd/depth-limited scan. Include
  // future files and nested repositories at every depth.
  const mandatory = [
    ...getDangerousFiles(config.allowGitConfig).map(p => '/**/' + p),
    ...getDangerousDirectories().map(p => '/**/' + p),
    '/**/.git/hooks',
    ...(config.allowGitConfig ? [] : ['/**/.git/config']),
  ]
  for (const p of config.denyWrite.map(normalize)) {
    add(tree(p), 'wkl', true)
    protectAncestors(p)
  }
  for (const p of mandatory) {
    // Preserve the legacy mandatory scanner's case-insensitive --iglob rules.
    add(foldCase(tree(p)), 'wkl', true)
    protectAncestors(p, true)
  }
  // These remain inaccessible even for an explicit allowWrite ['/']. They
  // prevent remount/profile/ptrace escapes; user namespaces cannot write maps.
  rules.add('  deny "/proc/**" wkl,')
  rules.add('  deny "/sys/**" wkl,')
  rules.add('  deny "/proc/*/mem" rw,')
  // attach_disconnected: bwrap supplies a fresh /dev, so inherited terminal
  // descriptors have no path inside the sandbox. Without the flag, fstat(0)
  // fails with EACCES and Node aborts at startup. Attached names still go
  // through the deny rules above.
  const body = [...rules].sort().join('\n')
  const flags = 'flags=(attach_disconnected,mediate_deleted)'
  // Hash the header too: a flag change must never reuse a stale loaded profile.
  const name =
    'srt-fs-v2-' +
    createHash('sha256')
      .update(flags + '\n' + body)
      .digest('hex')
  return {
    name,
    deniesRead: concretePath => matchesAny(deniedRead, concretePath),
    policy: `# Generated by srt; load as root after review. Do not use complain mode.\nprofile ${name} ${flags} {\n${body}\n}\n`,
  }
}

/** The guard executes before the user's shell (including its startup files). */
export function appArmorCommand(profile: string, command: string): string[] {
  const guard =
    'IFS= read -r actual < /proc/self/attr/current; [ "$actual" = "$1 (enforce)" ] || { echo "srt: AppArmor enforcement verification failed" >&2; exit 126; }; shift; exec "$@"'
  return [
    '/usr/bin/aa-exec',
    '-p',
    profile,
    '--',
    '/usr/bin/env',
    '-u',
    'BASH_ENV',
    '-u',
    'ENV',
    '/bin/bash',
    '--noprofile',
    '--norc',
    '-c',
    guard,
    'srt-apparmor-guard',
    profile,
    '/bin/bash',
    '-c',
    command,
  ]
}
