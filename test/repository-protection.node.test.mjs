import { test } from 'node:test'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { compileAppArmorFilesystem } from '../dist/sandbox/apparmor.js'
import {
  resolveRepositoryProtection,
  repositoryFilesystemArgs,
} from '../dist/sandbox/repository-protection.js'
import { FilesystemConfigSchema } from '../dist/sandbox/sandbox-config.js'

function fixture(t) {
  const base = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), 'srt-repo-unit-')),
  )
  t.after(() => fs.rmSync(base, { recursive: true, force: true }))
  const root = path.join(base, 'repo')
  fs.mkdirSync(path.join(root, '.git'), { recursive: true })
  const scope = {
    roots: [root],
    worktreeRoots: [root + '/.worktrees'],
    gitDirectories: [root + '/.git'],
  }
  const config = {
    allowGitConfig: true,
    allowRead: [],
    denyRead: ['**/.env'],
    allowWrite: [base],
    denyWrite: [],
    repositoryProtection: scope,
  }
  return { base, root, scope, config }
}

test('CLI requirement rejects missing scope or the wrong backend before a workload', t => {
  const { base, root, config } = fixture(t)
  const settings = base + '/settings.json'
  const marker = base + '/must-not-run'
  for (const filesystem of [
    { ...config, repositoryProtection: undefined, linuxBackend: 'apparmor' },
    { ...config, linuxBackend: 'bubblewrap' },
  ]) {
    fs.writeFileSync(
      settings,
      JSON.stringify({
        network: {
          allowedDomains: [],
          deniedDomains: [],
          allowAllDomains: true,
        },
        filesystem,
      }),
    )
    const result = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL('../dist/cli.js', import.meta.url)),
        '--require-repository-protection',
        '--settings',
        settings,
        '--',
        'touch',
        marker,
      ],
      { cwd: root, encoding: 'utf8', timeout: 10000 },
    )
    assert.equal(result.error, undefined)
    assert.notEqual(result.status, 0)
    assert.match(
      result.stderr,
      /requires an AppArmor repositoryProtection policy/,
    )
    assert.equal(fs.existsSync(marker), false)
  }
})

test('protected config is scoped; scratch config is writable and explicit denies remain global', t => {
  const { base, root, config } = fixture(t)
  const policy = compileAppArmorFilesystem(config)
  assert.match(policy.policy, /# srt-repository-protection-v1\n/)
  for (const name of [
    '.claude/settings.json',
    '.claude/hooks/setup.sh',
    '.pi/extensions/tool.ts',
    '.codex/config.toml',
    '.mcp.json',
    '.git/config',
    '.git/config.worktree',
    '.git/commondir',
    '.git/gitdir',
    '.git/hooks/pre-commit',
    '.vscode/settings.json',
    '.bashrc',
  ]) {
    assert.equal(policy.deniesWrite(root + '/' + name), true, name)
    assert.equal(policy.deniesWrite(root + '/subproject/' + name), true, name)
    assert.equal(
      policy.deniesWrite(root + '/.worktrees/new/' + name),
      false,
      name,
    )
    assert.equal(policy.deniesWrite(base + '/scratch/' + name), false, name)
  }
  assert.equal(policy.deniesWrite(root + '/.CLAUDE/settings.json'), true)
  assert.equal(
    policy.deniesWrite(root + '/.worktrees-elsewhere/.claude/settings.json'),
    true,
  )
  assert.equal(
    policy.deniesWrite(root + '/.git'),
    true,
    'linked launch marker cannot be replaced',
  )
  assert.equal(
    policy.deniesWrite(root + '/.git/'),
    true,
    'metadata directory cannot be renamed',
  )
  assert.equal(policy.deniesWrite(root + '/.git/objects/example'), false)
  assert.equal(policy.deniesWrite(root + '/.git/worktrees/new/HEAD'), false)
  assert.equal(policy.deniesWrite(root + '/ordinary.py'), false)
  assert.equal(
    policy.deniesWrite(root + '/'),
    true,
    'cannot relocate the original root',
  )
  assert.equal(
    policy.deniesWrite(root + '/.worktrees/'),
    true,
    'cannot relocate the exempt boundary',
  )
  assert.equal(policy.deniesRead(root + '/.worktrees/new/.env'), true)
  assert.equal(policy.deniesWrite(root + '/.worktrees/new/.env'), true)
  const explicit = compileAppArmorFilesystem({
    ...config,
    denyWrite: ['**/.mcp.json'],
  })
  assert.equal(explicit.deniesWrite(root + '/.worktrees/new/.mcp.json'), true)
  assert.equal(
    fs.existsSync(root + '/.worktrees'),
    false,
    'compilation has no filesystem mutations',
  )
})

test('launching in a linked checkout protects it even inside another root exemption', t => {
  const { root, scope, config } = fixture(t)
  const linked = root + '/.worktrees/linked'
  const gitDir = root + '/.git/worktrees/linked'
  fs.mkdirSync(linked, { recursive: true })
  fs.mkdirSync(gitDir, { recursive: true })
  scope.roots.push(linked)
  scope.worktreeRoots.push(linked + '/.worktrees')
  scope.gitDirectories.push(gitDir)
  const policy = compileAppArmorFilesystem(config)
  assert.equal(policy.deniesWrite(linked + '/.claude/settings.json'), true)
  assert.equal(policy.deniesWrite(linked + '/.git'), true)
  for (const name of ['config.worktree', 'commondir', 'gitdir'])
    assert.equal(policy.deniesWrite(gitDir + '/' + name), true)
  assert.equal(policy.deniesWrite(gitDir + '/index'), false)
  assert.equal(
    policy.deniesWrite(linked + '/.worktrees/new/.claude/settings.json'),
    false,
  )
  assert.equal(
    policy.deniesWrite(root + '/.worktrees/another/.claude/settings.json'),
    false,
  )
})

test('profile hashes include repository scope but not per-launch writable roots', t => {
  const { base, root, config } = fixture(t)
  const first = compileAppArmorFilesystem(config)
  assert.equal(
    compileAppArmorFilesystem({ ...config, allowWrite: [] }).name,
    first.name,
  )
  const other = base + '/other'
  fs.mkdirSync(other)
  const changed = {
    roots: [other],
    worktreeRoots: [other + '/.worktrees'],
    gitDirectories: [root + '/.git'],
  }
  assert.notEqual(
    compileAppArmorFilesystem({ ...config, repositoryProtection: changed })
      .name,
    first.name,
  )
})

test('mount plan is parent-first, preserves narrower write grants, and creates reserved boundaries', t => {
  const { base, root, scope } = fixture(t)
  const args = repositoryFilesystemArgs(scope, [root, base])
  const mounts = []
  for (let i = 0; i < args.length; i += 3) mounts.push(args.slice(i, i + 3))
  assert.ok(
    mounts.findIndex(m => m[1] === base) < mounts.findIndex(m => m[1] === root),
  )
  assert.ok(
    mounts.some(m => m[0] === '--bind' && m[1] === root + '/.worktrees'),
  )
  const sub = root + '/src'
  fs.mkdirSync(sub)
  const restricted = repositoryFilesystemArgs(scope, [sub])
  assert.deepEqual(
    restricted.slice(
      restricted.indexOf(root) - 1,
      restricted.indexOf(root) + 2,
    ),
    ['--ro-bind', root, root],
  )
  assert.ok(restricted.includes(sub))
})

test('an explicit write grant can create only the reserved worktree area', t => {
  const { root, scope } = fixture(t)
  const scratch = root + '/.worktrees'
  const args = repositoryFilesystemArgs(scope, [scratch])
  assert.equal(fs.statSync(scratch).isDirectory(), true)
  assert.deepEqual(args.slice(args.indexOf(root) - 1, args.indexOf(root) + 2), [
    '--ro-bind',
    root,
    root,
  ])
  assert.deepEqual(
    args.slice(args.indexOf(scratch) - 1, args.indexOf(scratch) + 2),
    ['--bind', scratch, scratch],
  )
})

test('absent worktree storage is not created outside writable roots', t => {
  const { root, scope } = fixture(t)
  repositoryFilesystemArgs(scope, [])
  assert.equal(fs.existsSync(root + '/.worktrees'), false)
})

test('invalid, alias, and overlapping boundaries fail closed', t => {
  const { base, root, scope } = fixture(t)
  for (const bad of ['/', '/proc', root + '/..', root + '/*', 'relative'])
    assert.throws(() => resolveRepositoryProtection({ ...scope, roots: [bad] }))
  for (const bad of [
    root,
    root + '/.claude',
    root + '/.git',
    base + '/other',
    root + '/missing/deep',
  ])
    assert.throws(() =>
      resolveRepositoryProtection({ ...scope, worktreeRoots: [bad] }),
    )
  fs.symlinkSync(base, root + '/alias', 'dir')
  assert.throws(
    () => repositoryFilesystemArgs(scope, [root + '/alias']),
    /writable alias/,
  )
  fs.symlinkSync(root, root + '/.worktrees', 'dir')
  assert.throws(() => resolveRepositoryProtection(scope), /canonical|symlink/)
  fs.unlinkSync(root + '/.worktrees')
  fs.symlinkSync(base + '/missing', root + '/.worktrees', 'dir')
  assert.throws(() => resolveRepositoryProtection(scope), /symlink/)
  assert.equal(
    FilesystemConfigSchema.safeParse({
      denyRead: [],
      allowWrite: [],
      denyWrite: [],
      repositoryProtection: { roots: [root], typo: [] },
    }).success,
    false,
  )
})
