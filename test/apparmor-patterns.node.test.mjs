import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  complementBasename,
  complementTree,
  intersect,
  parseGlob,
  subtract,
} from '../dist/sandbox/apparmor-patterns.js'
import { compileAppArmorFilesystem } from '../dist/sandbox/apparmor.js'

function matches(p, s, i = 0, j = 0, memo = new Map()) {
  const id = `${i},${j}`
  if (memo.has(id)) return memo.get(id)
  if (i === p.length) return j === s.length
  const a = p[i],
    consumes =
      j < s.length &&
      (a.excluded ? !a.chars.includes(s[j]) : a.chars.includes(s[j]))
  const result =
    (a.star && matches(p, s, i + 1, j, memo)) ||
    (consumes && matches(p, s, a.star ? i : i + 1, j + 1, memo)) ||
    false
  memo.set(id, result)
  return result
}
const accepts = (patterns, s) => patterns.some(p => matches(p, s))
function words(alphabet, depth) {
  let level = [''],
    result = ['']
  for (let i = 0; i < depth; i++) {
    level = level.flatMap(p => [...alphabet].map(c => p + c))
    result.push(...level)
  }
  return result
}
const corpus = words('ab./', 4)

test('glob intersection agrees with independent membership, including globstar and empty matches', () => {
  const patterns = [
    'a*',
    '*b',
    'a*b',
    '**/a',
    '/**/a*',
    '?a*',
    '*',
    '**',
    'a/b',
    '',
    'a?b',
  ]
  for (const x of patterns)
    for (const y of patterns) {
      const a = parseGlob(x),
        b = parseGlob(y),
        product = a.flatMap(p => b.flatMap(q => intersect(p, q)))
      for (const s of corpus)
        assert.equal(
          accepts(product, s),
          accepts(a, s) && accepts(b, s),
          `${x} intersect ${y}: ${s}`,
        )
    }
})

test('basename complement handles literal, prefix, suffix, and overlapping prefix/suffix', () => {
  for (const glob of ['a', 'ab', 'a*', '*ab', 'a*b', 'ab*ab', '*', '']) {
    const complement = complementBasename(glob)
    for (const s of words('ab.', 5))
      assert.equal(
        accepts(complement, s),
        !accepts(parseGlob(glob), s),
        `${glob}: ${s}`,
      )
  }
})

test('literal subtree subtraction distinguishes siblings and exact paths', () => {
  const c = complementTree('/a/b')
  for (const s of [
    ...corpus,
    '/a/b',
    '/a/b/',
    '/a/b/file',
    '/a/bb',
    '/a',
    '/a/c',
  ]) {
    assert.equal(accepts(c, s), !(s === '/a/b' || s.startsWith('/a/b/')), s)
  }
})

test('dotenv template exceptions are subtracted rather than re-allowed after deny', () => {
  let denied = parseGlob('.env.*')
  const exceptions = ['.env.example', '.env.example.*', '.env.*.example']
  for (const e of exceptions) denied = subtract(denied, complementBasename(e))
  const examples = [
    '.env.example',
    '.env.example.local',
    '.env.local.example',
    '.env..example',
    '.env.example.example',
  ]
  const secrets = [
    '.env.local',
    '.env.production',
    '.env.examplex',
    '.env.example.local.secret',
    '.env.local.example.secret',
    '.env.examp',
    '.env.',
    '.env.fooexample',
  ]
  // .env.example.* is intentionally a template according to Isara's policy.
  secrets.splice(secrets.indexOf('.env.example.local.secret'), 1)
  for (const s of examples) assert.equal(accepts(denied, s), false, s)
  for (const s of secrets) assert.equal(accepts(denied, s), true, s)
})

test('compiler is deterministic, does not omit mandatory rules, and rejects unsupported syntax', () => {
  const config = {
    // /usr is never a symlink (macOS resolves /tmp to /private/tmp).
    denyRead: ['/usr/srt-test-secret'],
    allowRead: [],
    allowWrite: ['/tmp/project'],
    denyWrite: [],
  }
  const text = ({ name, policy }) => ({ name, policy })
  const a = text(compileAppArmorFilesystem(config)),
    b = text(compileAppArmorFilesystem(config))
  assert.deepEqual(a, b)
  assert.match(a.name, /^srt-fs-v2-[0-9a-f]{64}$/)
  // Writable roots are per-launch mounts; secret files use a fixed alias dir.
  // Neither may influence the profile, or every repository needs a new load.
  for (const variant of [
    { allowWrite: ['/home/someone/other-repo', '/tmp'] },
    { allowWrite: [] },
    { secretFiles: ['/home/someone/other-repo/.env'] },
  ]) {
    assert.deepEqual(
      text(compileAppArmorFilesystem({ ...config, ...variant })),
      a,
    )
  }
  assert.notDeepEqual(
    text(
      compileAppArmorFilesystem({
        ...config,
        denyRead: ['/usr/srt-test-other'],
      }),
    ),
    a,
  )
  const compiled = compileAppArmorFilesystem(config)
  assert.equal(compiled.deniesRead('/usr/srt-test-secret/key'), true)
  assert.equal(compiled.deniesRead('/dev/srt/secrets/0-.env'), false)
  assert.equal(
    compileAppArmorFilesystem({ ...config, denyRead: ['**/.env'] }).deniesRead(
      '/dev/srt/secrets/0-.env',
    ),
    false,
  )
  assert.equal(
    compileAppArmorFilesystem({ ...config, denyRead: ['/dev/**'] }).deniesRead(
      '/dev/srt/secrets/0-.env',
    ),
    true,
  )
  assert.ok(!a.policy.includes('/tmp/project'))
  // Recursive selectors are system-wide, independent of the launch directory.
  const selectors = compileAppArmorFilesystem({
    ...config,
    denyRead: ['**/.env'],
    denyWrite: ['**/.env.local'],
  })
  assert.ok(selectors.policy.includes('  deny "/**/.env" rwmx,'))
  assert.ok(selectors.policy.includes('  deny "/**/.env.local" wkl,'))
  assert.ok(!selectors.policy.includes(process.cwd() + '/**/.env'))
  assert.ok(a.policy.includes('  "/**" rwklix,'))
  assert.ok(a.policy.includes('  deny "/usr/srt-test-secret/**" rwmx,'))
  assert.ok(a.policy.includes('[Gg][Ii][Tt]/[Hh][Oo][Oo][Kk][Ss]'))
  assert.match(a.policy, /flags=\(attach_disconnected,mediate_deleted\)/)
  assert.doesNotMatch(a.policy, /\bmount,|\bcapability,|\bchange_profile/)
  assert.throws(() => parseGlob('/' + '**/'.repeat(14)), /complexity limit/)
  assert.throws(() => parseGlob('/' + 'a'.repeat(4096)), /length limit/)
  assert.throws(
    () =>
      compileAppArmorFilesystem({
        ...config,
        denyRead: Array(513).fill('/tmp/secret'),
      }),
    /entry limit/,
  )
  for (const bad of ['a[bc]', 'x\n}', 'x" rw,', '@{HOME}', '\\x', 'café']) {
    assert.throws(() =>
      compileAppArmorFilesystem({ ...config, denyRead: [bad] }),
    )
  }
})
