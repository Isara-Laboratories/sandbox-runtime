/** Bounded glob algebra. No filesystem enumeration and no raw AppArmor syntax. */
export type Atom = { excluded: boolean; chars: string; star?: boolean }
export type Pattern = Atom[]
const LIMIT = 4096
const literal = (c: string): Atom => ({ excluded: false, chars: c })
const any = (slash: boolean, star = false): Atom => ({
  excluded: true,
  chars: slash ? '' : '/',
  star,
})
const key = (p: Pattern) => JSON.stringify(p)

export function unique(patterns: Pattern[]): Pattern[] {
  const normalized = patterns.map(p =>
    p.reduce<Pattern>((out, atom) => {
      const last = out[out.length - 1]
      if (last?.star && atom.star && last.excluded && atom.excluded) {
        out[out.length - 1] = any(last.chars === '' || atom.chars === '', true)
      } else out.push(atom)
      return out
    }, []),
  )
  const result = [...new Map(normalized.map(p => [key(p), p])).values()]
  if (result.length > LIMIT)
    throw new Error('AppArmor pattern expansion exceeds safe complexity limit')
  return result
}

/** Deliberately reject bracket syntax, escaping and policy-language injection. */
export function parseGlob(value: string): Pattern[] {
  if (value.length > 4096)
    throw new Error('AppArmor path exceeds safe length limit')
  if (
    [...value].some(
      c =>
        c.charCodeAt(0) < 32 ||
        c.charCodeAt(0) >= 127 ||
        '\\[]{}"@'.includes(c),
    )
  ) {
    throw new Error(
      `Unsupported AppArmor path syntax: ${JSON.stringify(value)}`,
    )
  }
  let out: Pattern[] = [[]]
  for (let i = 0; i < value.length; i++) {
    const c = value[i]!
    if (c === '*' && value[i + 1] === '*') {
      if (value[i + 2] === '*')
        throw new Error('AppArmor does not support runs of three or more stars')
      i++
      if (value[i + 1] === '/') {
        if (out.length * 2 > LIMIT)
          throw new Error('AppArmor glob exceeds safe complexity limit')
        out = out.flatMap(p => [p, [...p, any(true, true), literal('/')]])
        i++
      } else out = out.map(p => [...p, any(true, true)])
    } else
      out = out.map(p => [
        ...p,
        c === '*' ? any(false, true) : c === '?' ? any(false) : literal(c),
      ])
  }
  return unique(out)
}

function common(a: Atom, b: Atom): Atom | undefined {
  const aa = new Set(a.chars),
    bb = new Set(b.chars)
  if (a.excluded && b.excluded)
    return {
      excluded: true,
      chars: [...new Set([...aa, ...bb])].sort().join(''),
    }
  const chars = a.excluded
    ? [...bb].filter(c => !aa.has(c))
    : b.excluded
      ? [...aa].filter(c => !bb.has(c))
      : [...aa].filter(c => bb.has(c))
  return chars.length
    ? { excluded: false, chars: chars.sort().join('') }
    : undefined
}

/** Product of two monotone glob NFAs. The only cycles are wildcard self loops. */
export function intersect(a: Pattern, b: Pattern): Pattern[] {
  const memo = new Map<string, Pattern[]>()
  const visit = (i: number, j: number): Pattern[] => {
    const id = `${i},${j}`
    if (memo.has(id)) return memo.get(id)!
    if (i === a.length && j === b.length) return [[]]
    const x = a[i],
      y = b[j]
    const out: Pattern[] = []
    if (x?.star) out.push(...visit(i + 1, j))
    if (y?.star) out.push(...visit(i, j + 1))
    if (x && y) {
      const c = common(x, y)
      if (c) {
        if (x.star && y.star) {
          const loop = { ...c, star: true }
          const result = unique(out.map(p => [loop, ...p]))
          memo.set(id, result)
          return result
        }
        out.push(
          ...visit(i + (x.star ? 0 : 1), j + (y.star ? 0 : 1)).map(p => [
            c,
            ...p,
          ]),
        )
      }
    }
    const result = unique(out)
    memo.set(id, result)
    return result
  }
  return visit(0, 0)
}

const letters = (s: string): Pattern => Array.from(s, literal)
const notLetter = (s: string, slash: boolean): Atom => ({
  excluded: true,
  chars: [...new Set([...(slash ? [] : ['/']), s])].sort().join(''),
})

/** Complement of a basename with at most one star: prefix*suffix or a literal. */
export function complementBasename(glob: string): Pattern[] {
  if ([...glob].some(c => '?[]{}\\/'.includes(c)) || glob.split('*').length > 2)
    throw new Error(`Unsupported AppArmor read exception: ${glob}`)
  const parts = glob.split('*')
  if (parts.length === 1) {
    const s = parts[0]!
    return [
      ...Array.from({ length: s.length }, (_, i) => letters(s.slice(0, i))),
      ...Array.from(s, (c, i) => [
        ...letters(s.slice(0, i)),
        notLetter(c, false),
        any(false, true),
      ]),
      [...letters(s), any(false), any(false, true)],
    ]
  }
  const [prefix, suffix] = parts as [string, string]
  return [
    ...Array.from({ length: prefix.length }, (_, i) =>
      letters(prefix.slice(0, i)),
    ),
    ...Array.from(prefix, (c, i) => [
      ...letters(prefix.slice(0, i)),
      notLetter(c, false),
      any(false, true),
    ]),
    // Consume the prefix before complementing the suffix. These branches are
    // disjoint from the prefix-mismatch branches, avoiding exponential overlap.
    ...Array.from({ length: suffix.length }, (_, i) => [
      ...letters(prefix),
      ...Array.from({ length: i }, () => any(false)),
    ]),
    ...Array.from(suffix, (c, i) => [
      ...letters(prefix),
      any(false, true),
      notLetter(c, false),
      ...letters(suffix.slice(i + 1)),
    ]),
  ]
}

/** Everything except one literal path and its descendants. */
export function complementTree(path: string): Pattern[] {
  if (/[*?]/.test(path))
    throw new Error('Expected a literal AppArmor read exception')
  const prefix = path.replace(/\/$/, '') + '/'
  return [
    ...Array.from({ length: prefix.length }, (_, i) =>
      letters(prefix.slice(0, i)),
    ).filter(p => p.length !== prefix.length - 1),
    ...Array.from(prefix, (c, i) => [
      ...letters(prefix.slice(0, i)),
      notLetter(c, true),
      any(true, true),
    ]),
  ]
}

export function subtract(
  patterns: Pattern[],
  complement: Pattern[],
): Pattern[] {
  let result: Pattern[] = []
  for (const p of patterns)
    for (const c of complement) {
      result.push(...intersect(p, c))
      if (result.length > LIMIT) result = unique(result)
    }
  return unique(result)
}

function escapeLiteral(c: string): string {
  return '\\*?[]{}"^@'.includes(c) ? `\\${c}` : c
}

export function render(pattern: Pattern): string {
  return pattern
    .map(a => {
      if (a.star) {
        if (a.excluded && a.chars === '') return '**'
        if (a.excluded && a.chars === '/') return '*'
        throw new Error('Unrepresentable AppArmor wildcard intersection')
      }
      if (!a.excluded && a.chars.length === 1) return escapeLiteral(a.chars)
      if (a.excluded && a.chars === '') return '[^\\000]'
      if (a.excluded && a.chars === '/') return '?'
      const chars = [...a.chars]
        .map(c => (/[\\\]\-^]/.test(c) ? `\\${c}` : c))
        .join('')
      return `[${a.excluded ? '^' : ''}${chars}]`
    })
    .join('')
}

/** Exact-match test of one concrete path against patterns (memoized backtracking). */
export function matchesAny(patterns: Pattern[], s: string): boolean {
  const matches = (
    p: Pattern,
    i: number,
    j: number,
    memo: Map<string, boolean>,
  ): boolean => {
    const id = `${i},${j}`
    const known = memo.get(id)
    if (known !== undefined) return known
    if (i === p.length) return j === s.length
    const a = p[i]!
    const consumes =
      j < s.length &&
      (a.excluded ? !a.chars.includes(s[j]!) : a.chars.includes(s[j]!))
    const result =
      (a.star === true && matches(p, i + 1, j, memo)) ||
      (consumes && matches(p, a.star ? i : i + 1, j + 1, memo)) ||
      false
    memo.set(id, result)
    return result
  }
  return patterns.some(p => matches(p, 0, 0, new Map()))
}
