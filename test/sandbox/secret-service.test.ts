import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import shellquote from 'shell-quote'
import { compileAppArmorFilesystem } from '../../src/sandbox/apparmor.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  resolveSessionBusSocket,
  secretServiceDenyWrite,
  SECRET_SERVICE_APPARMOR_RULES,
  sessionBusAddress,
  verifySecretServiceMediation,
} from '../../src/sandbox/secret-service.js'
import { isLinux } from '../helpers/platform.js'

const WORK_DIR = join(tmpdir(), `srt-secret-service-${process.pid}`)
const BUS_SOCKET = join(WORK_DIR, 'bus')
const REGULAR_FILE = join(WORK_DIR, 'not-a-socket')
let server: Server | undefined

/** The rejection error (or undefined), avoiding non-thenable bun matchers. */
const rejection = (promise: Promise<unknown>): Promise<unknown> =>
  promise.then(
    () => undefined,
    (error: unknown) => error,
  )

const filesystem = {
  denyRead: [],
  allowWrite: [WORK_DIR],
  denyWrite: [],
}

describe('Secret Service D-Bus policy', () => {
  beforeAll(async () => {
    mkdirSync(WORK_DIR, { recursive: true })
    writeFileSync(REGULAR_FILE, '')
    server = createServer(socket => socket.destroy())
    await new Promise<void>((resolve, reject) => {
      server!.once('error', reject)
      server!.listen(BUS_SOCKET, () => resolve())
    })
  })

  afterAll(async () => {
    await new Promise<void>(resolve => server?.close(() => resolve()))
    rmSync(WORK_DIR, { recursive: true, force: true })
  })

  describe('resolveSessionBusSocket', () => {
    it('parses unix:path= addresses with extra keys, escapes and fallbacks', () => {
      expect(
        resolveSessionBusSocket({
          DBUS_SESSION_BUS_ADDRESS: `unix:path=${BUS_SOCKET},guid=0123abcd;tcp:host=localhost`,
        }),
      ).toBe(BUS_SOCKET)
      expect(
        resolveSessionBusSocket({
          DBUS_SESSION_BUS_ADDRESS: `unix:path=${BUS_SOCKET.replace(/\//g, '%2f')}`,
        }),
      ).toBe(BUS_SOCKET)
    })

    it('falls back to XDG_RUNTIME_DIR/bus without an address', () => {
      expect(resolveSessionBusSocket({ XDG_RUNTIME_DIR: WORK_DIR })).toBe(
        BUS_SOCKET,
      )
    })

    it('rejects addresses the exact-path socket policy cannot allow', () => {
      for (const address of [
        'unix:abstract=/tmp/dbus-xyz',
        'unix:tmpdir=/tmp',
        'tcp:host=localhost,port=1234',
      ]) {
        expect(() =>
          resolveSessionBusSocket({ DBUS_SESSION_BUS_ADDRESS: address }),
        ).toThrow(/unix:path=/)
      }
      expect(() =>
        resolveSessionBusSocket({
          DBUS_SESSION_BUS_ADDRESS: 'unix:path=relative/bus',
        }),
      ).toThrow(/absolute/)
    })

    it('rejects missing paths and non-sockets', () => {
      expect(() =>
        resolveSessionBusSocket({ XDG_RUNTIME_DIR: join(WORK_DIR, 'nope') }),
      ).toThrow(/not found/)
      expect(() =>
        resolveSessionBusSocket({
          DBUS_SESSION_BUS_ADDRESS: `unix:path=${REGULAR_FILE}`,
        }),
      ).toThrow(/not a Unix socket/)
    })
  })

  it('escapes bus addresses per the D-Bus address syntax', () => {
    expect(sessionBusAddress('/run/user/1000/bus')).toBe(
      'unix:path=/run/user/1000/bus',
    )
    expect(sessionBusAddress('/tmp/a b,c;d=e')).toBe(
      'unix:path=/tmp/a%20b%2cc%3bd%3de',
    )
  })

  it('write-denies D-Bus service and systemd unit directories', () => {
    const paths = secretServiceDenyWrite(
      { XDG_RUNTIME_DIR: '/run/user/1000', XDG_DATA_HOME: '/data' },
      1000,
    )
    expect(paths).toEqual(
      expect.arrayContaining([
        '/run/user/1000/dbus-1',
        '/run/user/1000/systemd',
        '~/.local/share/dbus-1',
        '~/.local/share/systemd',
        '/data/dbus-1',
        '~/.config/systemd',
      ]),
    )
    expect(new Set(paths).size).toBe(paths.length)
  })

  describe('AppArmor profile', () => {
    const plain = compileAppArmorFilesystem(filesystem)
    const withSecretService = compileAppArmorFilesystem(filesystem, {
      secretService: true,
    })

    it('adds D-Bus rules only when requested, under a distinct profile name', () => {
      expect(plain.policy).not.toContain('dbus')
      expect(plain.name).not.toBe(withSecretService.name)
      for (const rule of SECRET_SERVICE_APPARMOR_RULES) {
        expect(withSecretService.policy).toContain(rule)
      }
    })

    it('allows only the strict bus-driver set and Secret Service interfaces', () => {
      const allowed = withSecretService.policy
        .split('\n')
        .filter(line => /^\s*dbus /.test(line) || /^\s*dbus \(/.test(line))
      const text = allowed.join('\n')
      for (const forbidden of [
        'BecomeMonitor',
        'UpdateActivationEnvironment',
        'RequestName',
        'org.freedesktop.DBus.*',
        'eavesdrop',
        'bind',
      ]) {
        expect(text).not.toContain(forbidden)
      }
      expect(text).toContain('path=/org/freedesktop/secrets{,/**}')
    })

    it('write-denies service definitions even under a writable home', () => {
      const broad = compileAppArmorFilesystem(
        { ...filesystem, allowWrite: ['~'] },
        { secretService: true },
      )
      expect(
        broad.deniesWrite('/run/user/1000/dbus-1/services/x.service'),
      ).toBe(process.getuid?.() === 1000)
      expect(
        broad.deniesWrite(
          `${process.env.HOME}/.local/share/dbus-1/services/x.service`,
        ),
      ).toBe(true)
      expect(
        broad.deniesWrite(`${process.env.HOME}/.config/systemd/user/x.service`),
      ).toBe(true)
      expect(plain.deniesWrite(`${process.env.HOME}/.config/systemd/x`)).toBe(
        false,
      )
    })
  })

  describe.if(isLinux)('Linux wrapper', () => {
    it('exports the verified bus address and refuses without AppArmor', async () => {
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        appArmorProfile: 'srt-test-profile',
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: [WORK_DIR], denyWithinAllow: [] },
        allowUnixSockets: [BUS_SOCKET],
        secretServiceSocket: BUS_SOCKET,
      })
      expect(wrapped).toContain(
        `--setenv DBUS_SESSION_BUS_ADDRESS ${shellquote.quote([`unix:path=${BUS_SOCKET}`])}`,
      )
      expect(wrapped).toContain(`--allow-unix-socket ${BUS_SOCKET}`)

      expect(
        String(
          await rejection(
            wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              writeConfig: { allowOnly: [WORK_DIR], denyWithinAllow: [] },
              secretServiceSocket: BUS_SOCKET,
            }),
          ),
        ),
      ).toMatch(/AppArmor/)
    })

    it('passes --deny-kernel-keyring and rejects allowAllUnixSockets', async () => {
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: [WORK_DIR], denyWithinAllow: [] },
        seccompConfig: { denyKernelKeyring: true },
      })
      expect(wrapped).toContain('--deny-kernel-keyring --')

      expect(
        String(
          await rejection(
            wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              writeConfig: { allowOnly: [WORK_DIR], denyWithinAllow: [] },
              allowAllUnixSockets: true,
              seccompConfig: { denyKernelKeyring: true },
            }),
          ),
        ),
      ).toMatch(/allowAllUnixSockets/)
    })

    it('refuses the bubblewrap backend in the manager', async () => {
      expect(
        String(
          await rejection(
            SandboxManager.wrapWithSandbox('true', undefined, {
              network: {
                allowedDomains: [],
                deniedDomains: [],
                allowSecretService: true,
              },
              filesystem: { ...filesystem, linuxBackend: 'bubblewrap' },
            }),
          ),
        ),
      ).toMatch(/requires the Linux AppArmor backend/)
    })

    it('fails closed when mediation cannot be verified', () => {
      expect(() =>
        verifySecretServiceMediation(
          'srt-profile-that-is-not-loaded',
          BUS_SOCKET,
        ),
      ).toThrow(/could not verify AppArmor D-Bus mediation/)
    })
  })
})
