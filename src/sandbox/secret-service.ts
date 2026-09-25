import { spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as path from 'node:path'

/**
 * Linux AppArmor only: the D-Bus session bus is exposed to the workload so it
 * can use the freedesktop Secret Service API (gnome-keyring, KeePassXC, ...),
 * and AppArmor D-Bus mediation confines it to exactly that API.
 *
 * The session bus is otherwise a sandbox escape: `systemd --user` can start
 * arbitrary units, `UpdateActivationEnvironment` injects environment variables
 * (for example LD_PRELOAD) into services the bus activates later,
 * `BecomeMonitor` eavesdrops on every other client (including their secrets),
 * and `RequestName` impersonates services. None of those are granted here.
 *
 * The Secret Service API has no per-client access control: the workload can
 * read every item in every unlocked collection. Callers opt into that.
 */
const BUS_DRIVER_METHODS = [
  'Hello',
  'AddMatch',
  'RemoveMatch',
  'GetNameOwner',
  'NameHasOwner',
  // Read-only name discovery; keyring-rs checks that the provider is present.
  'ListNames',
  // libsecret activates the provider first. The bus daemon does NOT restrict
  // which activatable name is started, and AppArmor cannot inspect the
  // argument: any installed service can be started (and then not talked to).
  // Activated services run their configured command with the bus's
  // activation environment, which the workload cannot change
  // (UpdateActivationEnvironment is denied). Writing new service or unit
  // files would turn this into an escape, see SECRET_SERVICE_DENY_WRITE.
  'StartServiceByName',
]

const SECRET_SERVICE_INTERFACES = [
  'org.freedesktop.Secret.Service',
  'org.freedesktop.Secret.Collection',
  'org.freedesktop.Secret.Item',
  'org.freedesktop.Secret.Session',
  'org.freedesktop.Secret.Prompt',
  'org.freedesktop.DBus.Properties',
  'org.freedesktop.DBus.Introspectable',
]

/**
 * AppArmor rules appended to the filesystem profile. Once a profile is loaded
 * with D-Bus mediation, anything not allowed here is denied by the bus daemon.
 *
 * - Bus driver calls: the `dbus-session-strict` abstraction's set plus
 *   ListNames.
 * - Secret Service: modeled on snapd's `password-manager-service` interface.
 *   Clients such as libsecret address the provider by its unique connection
 *   name, so the peer is matched by label, not by well-known name. Paths and
 *   interfaces are what restrict the peer to a Secret Service provider.
 *   Unlike snapd, `org.freedesktop.DBus.*` is not allowed: the bus daemon is
 *   also an unconfined peer and ignores the object path for most of its own
 *   methods, so a wildcard would reopen bus-driver calls via these paths.
 * - Deny rules take precedence. They remove destructive collection-wide calls
 *   (deleting or locking a whole collection, re-pointing the default alias,
 *   creating collections, which needs an interactive prompt). Item-level
 *   create/read/update/delete stays available.
 */
export const SECRET_SERVICE_APPARMOR_RULES: readonly string[] = [
  `  dbus send bus=session path=/org/freedesktop/DBus interface=org.freedesktop.DBus member={${BUS_DRIVER_METHODS.join(',')}} peer=(name=org.freedesktop.DBus),`,
  '  dbus receive bus=session path=/org/freedesktop/DBus interface=org.freedesktop.DBus peer=(name=org.freedesktop.DBus),',
  `  dbus (send, receive) bus=session path=/org/freedesktop/secrets{,/**} interface={${SECRET_SERVICE_INTERFACES.join(',')}} peer=(label=unconfined),`,
  '  deny dbus send bus=session path=/org/freedesktop/secrets{,/**} interface=org.freedesktop.Secret.Collection member=Delete,',
  '  deny dbus send bus=session path=/org/freedesktop/secrets interface=org.freedesktop.Secret.Service member={CreateCollection,Lock,SetAlias},',
]

/**
 * D-Bus service files and systemd user units define what StartServiceByName
 * runs, outside the sandbox. Writing them must stay impossible no matter what
 * the caller's allowWrite contains, so they become AppArmor write denies.
 * System directories (XDG_DATA_DIRS, /etc) are not writable by the user.
 */
export function secretServiceDenyWrite(
  env: NodeJS.ProcessEnv = process.env,
  uid: number | undefined = process.getuid?.(),
): string[] {
  const runtimeDirs = [
    ...(uid !== undefined ? [`/run/user/${uid}`] : []),
    ...(env.XDG_RUNTIME_DIR ? [env.XDG_RUNTIME_DIR] : []),
  ]
  const dataDirs = [
    '~/.local/share',
    ...(env.XDG_DATA_HOME ? [env.XDG_DATA_HOME] : []),
  ]
  const configDirs = [
    '~/.config',
    ...(env.XDG_CONFIG_HOME ? [env.XDG_CONFIG_HOME] : []),
  ]
  return [
    ...new Set([
      ...runtimeDirs.flatMap(d => [`${d}/dbus-1`, `${d}/systemd`]),
      ...dataDirs.flatMap(d => [`${d}/dbus-1`, `${d}/systemd`]),
      ...configDirs.map(d => `${d}/systemd`),
    ]),
  ]
}

function unescapeAddressValue(value: string): string {
  return value.replace(/%([0-9a-fA-F]{2})/g, (_, hex: string) =>
    String.fromCharCode(parseInt(hex, 16)),
  )
}

/** D-Bus address value escaping: bytes outside [-0-9A-Za-z_/.\*] become %XX. */
function escapeAddressValue(value: string): string {
  return Array.from(Buffer.from(value, 'utf8'), byte => {
    const c = String.fromCharCode(byte)
    return /[-0-9A-Za-z_/.\\*]/.test(c)
      ? c
      : '%' + byte.toString(16).padStart(2, '0')
  }).join('')
}

/**
 * Resolve the filesystem path of the session bus socket.
 *
 * Only `unix:path=` addresses can be allowed by the exact-path Unix socket
 * policy. Without DBUS_SESSION_BUS_ADDRESS (the launcher may scrub the
 * environment), fall back to the systemd user bus locations.
 */
export function resolveSessionBusSocket(
  env: NodeJS.ProcessEnv = process.env,
  uid: number | undefined = process.getuid?.(),
): string {
  let socketPath: string | undefined
  const address = env.DBUS_SESSION_BUS_ADDRESS
  if (address) {
    const first = address.split(';')[0]!
    const colon = first.indexOf(':')
    const transport = colon < 0 ? first : first.slice(0, colon)
    const params = new Map(
      (colon < 0 ? '' : first.slice(colon + 1))
        .split(',')
        .filter(Boolean)
        .map(pair => {
          const eq = pair.indexOf('=')
          return [
            eq < 0 ? pair : pair.slice(0, eq),
            unescapeAddressValue(eq < 0 ? '' : pair.slice(eq + 1)),
          ] as const
        }),
    )
    if (transport !== 'unix' || !params.has('path')) {
      throw new Error(
        `network.allowSecretService requires a unix:path= session bus address, got: ${address}`,
      )
    }
    socketPath = params.get('path')
  } else if (env.XDG_RUNTIME_DIR) {
    socketPath = path.join(env.XDG_RUNTIME_DIR, 'bus')
  } else if (uid !== undefined) {
    socketPath = `/run/user/${uid}/bus`
  }
  if (!socketPath || !path.isAbsolute(socketPath)) {
    throw new Error(
      'network.allowSecretService could not determine an absolute session bus socket path',
    )
  }
  let stat: fs.Stats
  try {
    stat = fs.statSync(socketPath)
  } catch (error) {
    throw new Error(
      `network.allowSecretService: session bus socket not found at ${socketPath}: ${(error as Error).message}`,
    )
  }
  if (!stat.isSocket()) {
    throw new Error(
      `network.allowSecretService: ${socketPath} is not a Unix socket`,
    )
  }
  return socketPath
}

export function sessionBusAddress(socketPath: string): string {
  return `unix:path=${escapeAddressValue(socketPath)}`
}

const verifiedMediation = new Set<string>()

/**
 * Fail closed unless the bus daemon enforces AppArmor D-Bus rules for this
 * profile. Without mediation (a bus daemon built without AppArmor support,
 * `<apparmor mode="disabled"/>`, or a parser feature set without D-Bus), the
 * rules above are inert and the socket would expose the entire session bus.
 *
 * The probe confines `dbus-send` to the loaded profile and calls a bus method
 * the profile does not allow. Only an AppArmor AccessDenied passes.
 */
export function verifySecretServiceMediation(
  profile: string,
  socketPath: string,
): void {
  const key = `${profile}\0${socketPath}`
  if (verifiedMediation.has(key)) return
  const result = spawnSync(
    '/usr/bin/aa-exec',
    [
      '-p',
      profile,
      '--',
      'dbus-send',
      `--bus=${sessionBusAddress(socketPath)}`,
      '--print-reply',
      '--reply-timeout=5000',
      '--dest=org.freedesktop.DBus',
      '/org/freedesktop/DBus',
      // Harmless and never allowed by SECRET_SERVICE_APPARMOR_RULES.
      'org.freedesktop.DBus.GetId',
    ],
    { encoding: 'utf8', timeout: 10_000, env: { PATH: process.env.PATH } },
  )
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`
  if (
    result.error ||
    result.status === 0 ||
    !output.includes('org.freedesktop.DBus.Error.AccessDenied') ||
    !output.includes('AppArmor')
  ) {
    const reason = result.error
      ? result.error.message
      : result.status === 0
        ? 'the session bus did not enforce the AppArmor D-Bus rules'
        : output.trim().slice(0, 300) || `exit status ${result.status}`
    throw new Error(
      `network.allowSecretService refused: could not verify AppArmor D-Bus mediation for ${profile} (${reason})`,
    )
  }
  verifiedMediation.add(key)
}
