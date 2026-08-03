import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import {
  mkdirSync,
  writeFileSync,
  rmSync,
  existsSync,
  realpathSync,
  chmodSync,
  readFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  expandGlobPattern,
  expandGlobPatterns,
  globToRegex,
} from '../../src/sandbox/sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'
import { spawnSync } from 'node:child_process'

/**
 * Helper to get the real path of a file/dir (resolves symlinks like /var -> /private/var on macOS)
 */
function realPath(p: string): string {
  try {
    return realpathSync(p)
  } catch {
    return p
  }
}

// ============================================================================
// Tests for expandGlobPattern()
// ============================================================================

describe('expandGlobPattern', () => {
  // Use raw path for creation, real path for assertions
  const RAW_BASE_DIR = join(tmpdir(), 'glob-expand-test-' + Date.now())
  const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')
  let TEST_DIR: string

  beforeAll(() => {
    // Create test directory structure:
    // testdir/
    //   token.env
    //   secrets.env
    //   readme.txt
    //   config.json
    //   subdir/
    //     nested.env
    //     deep.txt
    //     deeper/
    //       bottom.env
    mkdirSync(join(RAW_TEST_DIR, 'subdir', 'deeper'), { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'token.env'), 'TOKEN=secret')
    writeFileSync(join(RAW_TEST_DIR, 'secrets.env'), 'SECRET=value')
    writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'readme content')
    writeFileSync(join(RAW_TEST_DIR, 'config.json'), '{}')
    writeFileSync(join(RAW_TEST_DIR, 'subdir', 'nested.env'), 'NESTED=secret')
    writeFileSync(join(RAW_TEST_DIR, 'subdir', 'deep.txt'), 'deep content')
    writeFileSync(
      join(RAW_TEST_DIR, 'subdir', 'deeper', 'bottom.env'),
      'BOTTOM=secret',
    )

    // Resolve real path after creation (handles /var -> /private/var on macOS)
    TEST_DIR = realPath(RAW_TEST_DIR)
  })

  afterAll(() => {
    if (existsSync(RAW_BASE_DIR)) {
      rmSync(RAW_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('should expand *.env to match only .env files in the directory', () => {
    const pattern = join(RAW_TEST_DIR, '*.env')
    const results = expandGlobPattern(pattern)

    // Should match token.env and secrets.env but NOT nested ones
    expect(results).toContain(join(TEST_DIR, 'token.env'))
    expect(results).toContain(join(TEST_DIR, 'secrets.env'))
    expect(results).not.toContain(join(TEST_DIR, 'readme.txt'))
    expect(results).not.toContain(join(TEST_DIR, 'config.json'))
    expect(results).not.toContain(join(TEST_DIR, 'subdir', 'nested.env'))
    expect(results.length).toBe(2)
  })

  it('should expand **/*.env to match .env files recursively', () => {
    const pattern = join(RAW_TEST_DIR, '**/*.env')
    const results = expandGlobPattern(pattern)

    // Should match all .env files recursively
    expect(results).toContain(join(TEST_DIR, 'token.env'))
    expect(results).toContain(join(TEST_DIR, 'secrets.env'))
    expect(results).toContain(join(TEST_DIR, 'subdir', 'nested.env'))
    expect(results).toContain(join(TEST_DIR, 'subdir', 'deeper', 'bottom.env'))
    expect(results).not.toContain(join(TEST_DIR, 'readme.txt'))
    expect(results.length).toBe(4)
  })

  it('should expand ** to match all files recursively', () => {
    const pattern = join(RAW_TEST_DIR, '**')
    const results = expandGlobPattern(pattern)

    // Should match all files and directories
    expect(results.length).toBeGreaterThan(0)
    expect(results).toContain(join(TEST_DIR, 'token.env'))
    expect(results).toContain(join(TEST_DIR, 'readme.txt'))
    expect(results).toContain(join(TEST_DIR, 'subdir', 'nested.env'))
    expect(results).toContain(join(TEST_DIR, 'subdir', 'deeper', 'bottom.env'))
  })

  it('should return empty array for non-existent base directory', () => {
    const pattern = '/nonexistent/path/*.env'
    const results = expandGlobPattern(pattern)
    expect(results).toEqual([])
  })

  it('should return empty array when no files match the pattern', () => {
    const pattern = join(RAW_TEST_DIR, '*.xyz')
    const results = expandGlobPattern(pattern)
    expect(results).toEqual([])
  })

  it('should match directories as well as files', () => {
    const pattern = join(RAW_TEST_DIR, '*')
    const results = expandGlobPattern(pattern)

    // Should include both files and directories (subdir)
    expect(results).toContain(join(TEST_DIR, 'token.env'))
    expect(results).toContain(join(TEST_DIR, 'subdir'))
    expect(results).toContain(join(TEST_DIR, 'readme.txt'))
  })

  it('should handle ? wildcard', () => {
    const pattern = join(RAW_TEST_DIR, '*.tx?')
    const results = expandGlobPattern(pattern)

    expect(results).toContain(join(TEST_DIR, 'readme.txt'))
    expect(results).not.toContain(join(TEST_DIR, 'token.env'))
  })

  it('should match with partial name glob', () => {
    const pattern = join(RAW_TEST_DIR, 'secret*.env')
    const results = expandGlobPattern(pattern)

    expect(results).toContain(join(TEST_DIR, 'secrets.env'))
    expect(results).not.toContain(join(TEST_DIR, 'token.env'))
  })
})

describe('expandGlobPatterns', () => {
  const RAW_BASE_DIR = join(tmpdir(), 'glob-expand-batch-test-' + Date.now())
  const FIRST_DIR = join(RAW_BASE_DIR, 'first tree')
  const SECOND_DIR = join(RAW_BASE_DIR, 'second-tree')
  let REAL_FIRST_DIR: string
  let REAL_SECOND_DIR: string

  beforeAll(() => {
    mkdirSync(join(FIRST_DIR, 'nested'), { recursive: true })
    mkdirSync(SECOND_DIR, { recursive: true })
    writeFileSync(join(FIRST_DIR, '.env'), 'SECRET=value')
    writeFileSync(join(FIRST_DIR, '.env.example'), 'SAFE=value')
    writeFileSync(join(FIRST_DIR, 'nested', '.env.local'), 'LOCAL=value')
    writeFileSync(join(FIRST_DIR, 'nested', '.env.local.example'), 'SAFE=value')
    writeFileSync(join(FIRST_DIR, 'nested', 'line\nbreak.env'), 'ODD=value')
    writeFileSync(join(FIRST_DIR, 'nested', 'choicea.env'), 'CHOICE=value')
    writeFileSync(join(SECOND_DIR, 'other.env'), 'OTHER=value')
    REAL_FIRST_DIR = realPath(FIRST_DIR)
    REAL_SECOND_DIR = realPath(SECOND_DIR)
  })

  afterAll(() => {
    rmSync(RAW_BASE_DIR, { recursive: true, force: true })
  })

  it('resolves patterns with shared and distinct roots in one batch', () => {
    const recursiveEnv = join(FIRST_DIR, '**/.env*')
    const examples = join(FIRST_DIR, '**/.env.*.example')
    const otherTree = join(SECOND_DIR, '*.env')

    const results = expandGlobPatterns([recursiveEnv, examples, otherTree])

    expect(results.get(recursiveEnv)).toEqual(
      expect.arrayContaining([
        join(REAL_FIRST_DIR, '.env'),
        join(REAL_FIRST_DIR, '.env.example'),
        join(REAL_FIRST_DIR, 'nested', '.env.local'),
        join(REAL_FIRST_DIR, 'nested', '.env.local.example'),
      ]),
    )
    expect(results.get(examples)).toEqual([
      join(REAL_FIRST_DIR, 'nested', '.env.local.example'),
    ])
    expect(results.get(otherTree)).toEqual([join(REAL_SECOND_DIR, 'other.env')])
  })

  it('preserves spaces and newlines in matched paths', () => {
    const pattern = join(FIRST_DIR, '**/*.env')
    const results = expandGlobPatterns([pattern])

    expect(results.get(pattern)).toContain(
      join(REAL_FIRST_DIR, 'nested', 'line\nbreak.env'),
    )
  })

  it('preserves exact matching when native name filtering is unsafe', () => {
    const pattern = join(FIRST_DIR, '**/choice[ab].env')
    const results = expandGlobPatterns([pattern, pattern])

    expect(results.get(pattern)).toEqual([
      join(REAL_FIRST_DIR, 'nested', 'choicea.env'),
    ])
  })

  it('invokes find once for the entire batch', () => {
    const wrapperDir = join(RAW_BASE_DIR, 'find-wrapper')
    const invocationLog = join(RAW_BASE_DIR, 'find-invocations')
    const realFind = spawnSync('which', ['find'], {
      encoding: 'utf8',
    }).stdout.trim()
    mkdirSync(wrapperDir, { recursive: true })
    writeFileSync(
      join(wrapperDir, 'find'),
      `#!/bin/sh\nprintf x >> "$FIND_INVOCATION_LOG"\nexec "${realFind}" "$@"\n`,
    )
    chmodSync(join(wrapperDir, 'find'), 0o755)

    const patterns = [
      join(FIRST_DIR, '**/.env'),
      join(FIRST_DIR, '**/.env.*'),
      join(FIRST_DIR, '**/.env*.example'),
      join(SECOND_DIR, '*.env'),
    ]
    const modulePath = join(process.cwd(), 'src/sandbox/sandbox-utils.ts')
    const child = spawnSync(
      process.execPath,
      [
        '-e',
        `import { expandGlobPatterns } from ${JSON.stringify(modulePath)}; expandGlobPatterns(${JSON.stringify(patterns)})`,
      ],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: `${wrapperDir}:${process.env.PATH ?? ''}`,
          FIND_INVOCATION_LOG: invocationLog,
        },
      },
    )

    expect(child.stderr).toBe('')
    expect(child.status).toBe(0)
    expect(readFileSync(invocationLog, 'utf8')).toBe('x')
  })
})

// ============================================================================
// Tests for globToRegex() after move to sandbox-utils.ts
// ============================================================================

describe('globToRegex (shared)', () => {
  it('should convert simple wildcard', () => {
    const regex = globToRegex('/tmp/test/*.env')
    expect(new RegExp(regex).test('/tmp/test/token.env')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/secrets.env')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/readme.txt')).toBe(false)
    // * should not match across /
    expect(new RegExp(regex).test('/tmp/test/sub/token.env')).toBe(false)
  })

  it('should convert globstar pattern', () => {
    const regex = globToRegex('/tmp/test/**/*.env')
    expect(new RegExp(regex).test('/tmp/test/token.env')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/sub/token.env')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/sub/deep/token.env')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/readme.txt')).toBe(false)
  })

  it('should convert ? wildcard', () => {
    const regex = globToRegex('/tmp/test/file?.txt')
    expect(new RegExp(regex).test('/tmp/test/file1.txt')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/fileA.txt')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/file12.txt')).toBe(false)
    // ? should not match /
    expect(new RegExp(regex).test('/tmp/test/file/.txt')).toBe(false)
  })

  it('should handle ** without trailing slash', () => {
    const regex = globToRegex('/tmp/test/**')
    expect(new RegExp(regex).test('/tmp/test/anything')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/sub/deep/file.txt')).toBe(true)
  })
})

// ============================================================================
// Tests for getFsReadConfig with glob expansion on Linux
// ============================================================================

describe.if(isLinux)('getFsReadConfig with glob patterns on Linux', () => {
  const RAW_BASE_DIR = join(tmpdir(), 'fsread-glob-test-' + Date.now())
  const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')

  beforeAll(() => {
    mkdirSync(RAW_TEST_DIR, { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'SECRET=value')
    writeFileSync(join(RAW_TEST_DIR, 'token.env'), 'TOKEN=value')
    writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'readme')
  })

  afterAll(() => {
    if (existsSync(RAW_BASE_DIR)) {
      rmSync(RAW_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('should expand glob denyRead patterns to concrete paths on Linux', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, '*.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const readConfig = SandboxManager.getFsReadConfig()
    const realTestDir = realPath(RAW_TEST_DIR)

    // Should contain the expanded concrete paths, not the glob pattern
    expect(readConfig.denyOnly).toContain(join(realTestDir, 'secret.env'))
    expect(readConfig.denyOnly).toContain(join(realTestDir, 'token.env'))
    // Should NOT contain the original glob pattern
    const hasGlob = readConfig.denyOnly.some((p: string) => p.includes('*'))
    expect(hasGlob).toBe(false)
    // Should NOT contain non-matching files
    expect(readConfig.denyOnly).not.toContain(join(realTestDir, 'readme.txt'))

    await SandboxManager.reset()
  })

  it('should batch denyRead and allowRead patterns while preserving both', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )
    const allowedPath = join(RAW_TEST_DIR, 'allowed.env')
    writeFileSync(allowedPath, 'SAFE=value')

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, '*.env')],
        allowRead: [join(RAW_TEST_DIR, 'allowed.*')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const readConfig = SandboxManager.getFsReadConfig()
    const realAllowedPath = realPath(allowedPath)
    expect(readConfig.denyOnly).toContain(realAllowedPath)
    expect(readConfig.allowWithinDeny).toEqual([realAllowedPath])

    await SandboxManager.reset()
  })

  it('should pass non-glob paths through unchanged on Linux', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, 'secret.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const readConfig = SandboxManager.getFsReadConfig()

    // Literal path should pass through (after normalization)
    expect(readConfig.denyOnly.length).toBe(1)
    expect(readConfig.denyOnly[0]).toContain('secret.env')

    await SandboxManager.reset()
  })

  it('should handle trailing /** by stripping suffix (existing behavior)', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )
    const realTestDir = realPath(RAW_TEST_DIR)

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [RAW_TEST_DIR + '/**'],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const readConfig = SandboxManager.getFsReadConfig()

    // /** suffix is stripped, leaving the directory path
    // This is the existing behavior - bubblewrap uses tmpfs over the directory
    expect(readConfig.denyOnly.length).toBe(1)
    expect(readConfig.denyOnly[0]).toBe(realTestDir)

    await SandboxManager.reset()
  })
})

describe.if(isLinux)('getFsWriteConfig with glob patterns on Linux', () => {
  const RAW_BASE_DIR = join(tmpdir(), 'fswrite-glob-test-' + Date.now())
  const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')

  beforeAll(() => {
    mkdirSync(RAW_TEST_DIR, { recursive: true })
    mkdirSync(join(RAW_TEST_DIR, 'writable-one'), { recursive: true })
    mkdirSync(join(RAW_TEST_DIR, 'writable-two'), { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'SECRET=value')
    writeFileSync(join(RAW_TEST_DIR, 'token.env'), 'TOKEN=value')
    writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'readme')
  })

  afterAll(() => {
    rmSync(RAW_BASE_DIR, { recursive: true, force: true })
  })

  it('expands glob denyWrite patterns to concrete paths on Linux', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [RAW_TEST_DIR],
        denyWrite: [join(RAW_TEST_DIR, '*.env')],
      },
    })

    const writeConfig = SandboxManager.getFsWriteConfig()
    const realTestDir = realPath(RAW_TEST_DIR)

    expect(writeConfig.denyWithinAllow).toContain(
      join(realTestDir, 'secret.env'),
    )
    expect(writeConfig.denyWithinAllow).toContain(
      join(realTestDir, 'token.env'),
    )
    expect(writeConfig.denyWithinAllow).not.toContain(
      join(realTestDir, 'readme.txt'),
    )
    expect(writeConfig.denyWithinAllow.some(path => path.includes('*'))).toBe(
      false,
    )

    await SandboxManager.reset()
  })

  it('expands glob allowWrite patterns to concrete paths on Linux', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [join(RAW_TEST_DIR, 'writable-*')],
        denyWrite: [],
      },
    })

    const writeConfig = SandboxManager.getFsWriteConfig()
    const realTestDir = realPath(RAW_TEST_DIR)

    expect(writeConfig.allowOnly).toContain(join(realTestDir, 'writable-one'))
    expect(writeConfig.allowOnly).toContain(join(realTestDir, 'writable-two'))
    expect(writeConfig.allowOnly).not.toContain(join(realTestDir, 'readme.txt'))
    expect(writeConfig.allowOnly.some(path => path.includes('*'))).toBe(false)

    await SandboxManager.reset()
  })
})

// ============================================================================
// Tests for getLinuxGlobPatternWarnings
// ============================================================================

describe.if(isLinux)('getLinuxGlobPatternWarnings after fix', () => {
  it('should NOT warn about denyRead globs on Linux (they are now expanded)', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: ['/tmp/test/*.env'],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const warnings = SandboxManager.getLinuxGlobPatternWarnings()

    // denyRead globs should no longer produce warnings since they are expanded
    expect(warnings).not.toContain('/tmp/test/*.env')
    expect(warnings.length).toBe(0)

    await SandboxManager.reset()
  })

  it('should not warn about expanded write globs on Linux', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: ['/tmp/test/*.log'],
        denyWrite: ['/tmp/test/secret_*'],
      },
    })

    const warnings = SandboxManager.getLinuxGlobPatternWarnings()

    expect(warnings).toEqual([])

    await SandboxManager.reset()
  })
})

describe.if(isLinux)(
  'allowWrite with glob patterns - Linux integration',
  () => {
    const RAW_BASE_DIR = join(tmpdir(), 'glob-allow-write-integ-' + Date.now())
    const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')
    const ALLOWED_FILE = join(RAW_TEST_DIR, 'allowed.writable')
    const BLOCKED_FILE = join(RAW_TEST_DIR, 'blocked.txt')

    beforeAll(() => {
      mkdirSync(RAW_TEST_DIR, { recursive: true })
      writeFileSync(ALLOWED_FILE, 'ALLOWED_DATA')
      writeFileSync(BLOCKED_FILE, 'BLOCKED_DATA')
    })

    afterAll(() => {
      rmSync(RAW_BASE_DIR, { recursive: true, force: true })
    })

    it('allows writes to existing paths that match allowWrite globs', async () => {
      const { SandboxManager } = await import(
        '../../src/sandbox/sandbox-manager.js'
      )

      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: {
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [join(RAW_TEST_DIR, '*.writable')],
          denyWrite: [],
        },
      })

      const command = await SandboxManager.wrapWithSandbox(
        `printf CHANGED > ${ALLOWED_FILE}`,
      )
      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(readFileSync(ALLOWED_FILE, 'utf8')).toBe('CHANGED')

      await SandboxManager.reset()
    })

    it('keeps non-matching paths read-only', async () => {
      const { SandboxManager } = await import(
        '../../src/sandbox/sandbox-manager.js'
      )

      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: {
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [join(RAW_TEST_DIR, '*.writable')],
          denyWrite: [],
        },
      })

      const command = await SandboxManager.wrapWithSandbox(
        `printf CHANGED > ${BLOCKED_FILE}`,
      )
      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).not.toBe(0)
      expect(readFileSync(BLOCKED_FILE, 'utf8')).toBe('BLOCKED_DATA')

      await SandboxManager.reset()
    })
  },
)

describe.if(isLinux)('denyWrite with glob patterns - Linux integration', () => {
  const RAW_BASE_DIR = join(tmpdir(), 'glob-deny-write-integ-' + Date.now())
  const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')
  let TEST_DIR: string

  beforeAll(() => {
    mkdirSync(RAW_TEST_DIR, { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'SECRET_DATA')
    writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'PUBLIC_DATA')
    TEST_DIR = realPath(RAW_TEST_DIR)
  })

  afterAll(() => {
    rmSync(RAW_BASE_DIR, { recursive: true, force: true })
  })

  it('blocks writes to existing files that match a denyWrite glob', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [RAW_TEST_DIR],
        denyWrite: [join(RAW_TEST_DIR, '*.env')],
      },
    })

    const command = await SandboxManager.wrapWithSandbox(
      `printf CHANGED > ${join(TEST_DIR, 'secret.env')}`,
    )
    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    expect(result.status).not.toBe(0)
    expect(readFileSync(join(TEST_DIR, 'secret.env'), 'utf8')).toBe(
      'SECRET_DATA',
    )

    await SandboxManager.reset()
  })

  it('allows writes to files that do not match the denyWrite glob', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [RAW_TEST_DIR],
        denyWrite: [join(RAW_TEST_DIR, '*.env')],
      },
    })

    const command = await SandboxManager.wrapWithSandbox(
      `printf CHANGED > ${join(TEST_DIR, 'readme.txt')}`,
    )
    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(readFileSync(join(TEST_DIR, 'readme.txt'), 'utf8')).toBe('CHANGED')

    await SandboxManager.reset()
  })
})

// ============================================================================
// Integration test: denyRead with glob patterns on Linux via sandbox
// ============================================================================

describe.if(isLinux)('denyRead with glob patterns - Linux integration', () => {
  const RAW_BASE_DIR = join(tmpdir(), 'glob-deny-integ-' + Date.now())
  const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')
  let TEST_DIR: string

  beforeAll(() => {
    mkdirSync(RAW_TEST_DIR, { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'SECRET_DATA')
    writeFileSync(join(RAW_TEST_DIR, 'token.env'), 'TOKEN_DATA')
    writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'PUBLIC_DATA')
    TEST_DIR = realPath(RAW_TEST_DIR)
  })

  afterAll(() => {
    if (existsSync(RAW_BASE_DIR)) {
      rmSync(RAW_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('should block reading files matching *.env glob pattern via sandbox', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, '*.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    // Try reading a .env file - should fail
    const command = await SandboxManager.wrapWithSandbox(
      `cat ${join(TEST_DIR, 'secret.env')}`,
    )

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // The file should be blocked (bound to /dev/null, so empty output or error)
    expect(result.stdout).not.toContain('SECRET_DATA')

    await SandboxManager.reset()
  })

  it('should allow reading files NOT matching glob pattern via sandbox', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, '*.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    // Try reading a .txt file - should succeed
    const command = await SandboxManager.wrapWithSandbox(
      `cat ${join(TEST_DIR, 'readme.txt')}`,
    )

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout).toContain('PUBLIC_DATA')

    await SandboxManager.reset()
  })

  it('should block reading with literal path (regression test)', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, 'secret.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const command = await SandboxManager.wrapWithSandbox(
      `cat ${join(TEST_DIR, 'secret.env')}`,
    )

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // Should be blocked
    expect(result.stdout).not.toContain('SECRET_DATA')

    await SandboxManager.reset()
  })

  it('should block reading with ** recursive glob via sandbox', async () => {
    // Create a nested file
    mkdirSync(join(RAW_TEST_DIR, 'nested'), { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'nested', 'deep.env'), 'DEEP_SECRET')
    const nestedPath = realPath(join(RAW_TEST_DIR, 'nested', 'deep.env'))

    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, '**/*.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    // Try reading nested .env file
    const command = await SandboxManager.wrapWithSandbox(`cat ${nestedPath}`)

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    expect(result.stdout).not.toContain('DEEP_SECRET')

    await SandboxManager.reset()
  })
})

// ============================================================================
// Tests for wrapWithSandbox with glob denyRead via customConfig
// ============================================================================

describe.if(isLinux)('wrapWithSandbox with glob denyRead customConfig', () => {
  const RAW_BASE_DIR = join(tmpdir(), 'wrap-sandbox-glob-test-' + Date.now())
  const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')
  let TEST_DIR: string

  beforeAll(() => {
    mkdirSync(RAW_TEST_DIR, { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'CUSTOM_SECRET')
    writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'CUSTOM_PUBLIC')
    TEST_DIR = realPath(RAW_TEST_DIR)
  })

  afterAll(() => {
    if (existsSync(RAW_BASE_DIR)) {
      rmSync(RAW_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('should expand glob denyRead in customConfig on Linux', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    // Use customConfig with glob denyRead
    const command = await SandboxManager.wrapWithSandbox(
      `cat ${join(TEST_DIR, 'secret.env')}`,
      undefined,
      {
        filesystem: {
          denyRead: [join(RAW_TEST_DIR, '*.env')],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
      },
    )

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // Should be blocked
    expect(result.stdout).not.toContain('CUSTOM_SECRET')

    await SandboxManager.reset()
  })
})
