import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdirSync, rmSync } from 'node:fs'
import { createServer, type Server } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import { isLinux } from '../helpers/platform.js'

const WORK_DIR = join(tmpdir(), `srt-unix-allowlist-${process.pid}`)
const ALLOWED_SOCKET = join(WORK_DIR, 'sxd.sock')
const DENIED_SOCKET = join(WORK_DIR, 'docker.sock')
const hostSupportsUnixSockets =
  spawnSync('python3', ['-c', 'import socket; socket.socket(socket.AF_UNIX)'], {
    encoding: 'utf8',
  }).status === 0

let applySeccomp: string
let allowedServer: Server | undefined
let deniedServer: Server | undefined
let tcpServer: Server
let tcpPort: number

function listen(server: Server, target: string | number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(target, () => {
      server.off('error', reject)
      resolve()
    })
  })
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close(error => {
      if (error) {
        reject(error)
      } else {
        resolve()
      }
    })
  })
}

function runWithAllowlist(args: string[]) {
  return spawnSync(
    applySeccomp,
    ['--allow-unix-socket', ALLOWED_SOCKET, '--', ...args],
    {
      encoding: 'utf8',
      timeout: 10000,
    },
  )
}

function connectTo(path: string) {
  return runWithAllowlist([
    'python3',
    '-c',
    [
      'import socket, sys',
      'sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
      'sock.connect(sys.argv[1])',
    ].join('\n'),
    path,
  ])
}

describe.if(isLinux)('Linux Unix socket allowlist', () => {
  beforeAll(async () => {
    const resolved = getApplySeccompBinaryPath()
    expect(resolved).toBeTruthy()
    applySeccomp = resolved!

    mkdirSync(WORK_DIR, { recursive: true })
    tcpServer = createServer(socket => socket.destroy())
    await listen(tcpServer, 0)
    const address = tcpServer.address()
    if (address === null || typeof address === 'string') {
      throw new Error('TCP test server did not expose a port')
    }
    tcpPort = address.port

    if (hostSupportsUnixSockets) {
      allowedServer = createServer(socket => socket.destroy())
      deniedServer = createServer(socket => socket.destroy())
      await listen(allowedServer, ALLOWED_SOCKET)
      await listen(deniedServer, DENIED_SOCKET)
    }
  })

  afterAll(async () => {
    const servers = [allowedServer, deniedServer, tcpServer].filter(
      (server): server is Server => server !== undefined,
    )
    await Promise.all(servers.map(close))
    rmSync(WORK_DIR, { recursive: true, force: true })
  })

  it.if(hostSupportsUnixSockets)(
    'connects to the exact allowed Unix stream socket',
    () => {
      const result = connectTo(ALLOWED_SOCKET)
      expect(result.status).toBe(0)
    },
  )

  it.if(hostSupportsUnixSockets)(
    'blocks an adjacent Docker-like Unix socket',
    () => {
      const result = connectTo(DENIED_SOCKET)
      expect(result.status).not.toBe(0)
      expect(result.stderr.toLowerCase()).toMatch(
        /permission denied|operation not permitted/,
      )
    },
  )

  it('blocks relative and abstract Unix socket addresses', () => {
    const relative = connectTo('relative.sock')
    expect(relative.status).not.toBe(0)
    expect(relative.stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )

    const abstract = runWithAllowlist([
      'python3',
      '-c',
      [
        'import socket',
        'sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
        "sock.connect('\\0srt-denied')",
      ].join('\n'),
    ])
    expect(abstract.status).not.toBe(0)
    expect(abstract.stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )
  })

  it('keeps Unix datagram sockets blocked', () => {
    const result = runWithAllowlist([
      'python3',
      '-c',
      'import socket; socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)',
    ])
    expect(result.status).not.toBe(0)
    expect(result.stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )
  })

  it('rejects non-absolute policy paths before executing the command', () => {
    const result = spawnSync(
      applySeccomp,
      ['--allow-unix-socket', 'relative.sock', '--', 'true'],
      { encoding: 'utf8', timeout: 10000 },
    )
    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('must be absolute')
  })

  it('keeps io_uring blocked in allowlist mode', () => {
    const result = runWithAllowlist([
      'python3',
      '-c',
      [
        'import ctypes',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'params = (ctypes.c_byte * 256)()',
        'fd = libc.syscall(425, 4, params)',
        'error = ctypes.get_errno()',
        'print(f"fd={fd} errno={error}")',
        'raise SystemExit(0 if fd == -1 and error == 1 else 1)',
      ].join('\n'),
    ])
    expect(result.status).toBe(0)
    expect(result.stdout).toMatch(/fd=-1 errno=1\b/)
  })

  it('preserves non-Unix connect behavior', () => {
    const result = runWithAllowlist([
      'python3',
      '-c',
      [
        'import socket, sys',
        'sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)',
        "sock.connect(('127.0.0.1', int(sys.argv[1])))",
      ].join('\n'),
      String(tcpPort),
    ])
    expect(result.status).toBe(0)
  })

  it('duplicates descriptors from a non-leader thread', () => {
    const result = runWithAllowlist([
      'python3',
      '-c',
      [
        'import socket, sys, threading',
        'errors = []',
        'def connect():',
        '    try:',
        '        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)',
        "        sock.connect(('127.0.0.1', int(sys.argv[1])))",
        '    except Exception as error:',
        '        errors.append(error)',
        'thread = threading.Thread(target=connect)',
        'thread.start()',
        'thread.join()',
        'raise SystemExit(1 if errors else 0)',
      ].join('\n'),
      String(tcpPort),
    ])
    expect(result.status).toBe(0)
  })
})
