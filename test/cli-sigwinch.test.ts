import { describe, expect, test } from 'bun:test'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import { checkLinuxDependencies } from '../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from './helpers/platform.js'

const cliPath = join(process.cwd(), 'src', 'cli.ts')

describe.if(isLinux)('CLI terminal resize forwarding', () => {
  test('forwards SIGWINCH into the bubblewrap process tree', async () => {
    expect(checkLinuxDependencies().errors).toEqual([])

    const child = spawn(
      'bun',
      [
        'run',
        cliPath,
        '-c',
        "trap 'echo GOT_SIGWINCH; exit 0' WINCH; echo READY; while :; do sleep 1; done",
      ],
      {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          HOME: '/tmp/cli-sigwinch-test-nonexistent',
        },
      },
    )

    expect(child.pid).toBeDefined()
    const exitPromise = new Promise<number | null>(resolve => {
      child.once('exit', code => resolve(code))
    })

    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', chunk => {
      stdout += chunk
    })
    child.stderr.on('data', chunk => {
      stderr += chunk
    })

    try {
      await waitFor(() => stdout.includes('READY'))
      process.kill(child.pid!, 'SIGWINCH')
      await waitFor(() => stdout.includes('GOT_SIGWINCH'))

      expect(await exitPromise).toBe(0)
    } finally {
      if (child.exitCode === null) child.kill('SIGKILL')
    }

    expect(stderr).toBe('')
  }, 15_000)
})

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 10_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() >= deadline) {
      throw new Error('Timed out waiting for sandboxed command output')
    }
    await Bun.sleep(20)
  }
}
