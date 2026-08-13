import { readFileSync } from 'node:fs'

/**
 * Return a Linux process and all of its descendants in parent-before-child order.
 *
 * Reading /proc rather than relying on process groups is intentional: bubblewrap's
 * --new-session creates a separate session, and nested sandbox helpers may create
 * additional PID namespaces. The host-side /proc tree can still see every
 * descendant by its host PID.
 */
export function getLinuxProcessTree(rootPid: number): number[] {
  const processTree: number[] = []
  const pending = [rootPid]
  const seen = new Set<number>()

  while (pending.length > 0) {
    const pid = pending.pop()!
    if (seen.has(pid)) continue

    seen.add(pid)
    processTree.push(pid)

    try {
      const children = readFileSync(`/proc/${pid}/task/${pid}/children`, 'utf8')
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .map(Number)
        .filter(Number.isSafeInteger)

      pending.push(...children)
    } catch {
      // Processes can exit while the tree is being inspected. Keep the partial
      // tree so remaining live descendants still receive the signal.
    }
  }

  return processTree
}

/**
 * Forward a signal to a Linux process tree, deepest descendants first.
 *
 * SIGWINCH normally comes from the controlling terminal. A bubblewrap sandbox
 * created with --new-session has no controlling terminal, so interactive
 * workloads otherwise retain stale terminal dimensions after a resize.
 */
export function signalLinuxProcessTree(
  rootPid: number,
  signal: NodeJS.Signals,
): void {
  const processTree = getLinuxProcessTree(rootPid)

  for (const pid of processTree.reverse()) {
    try {
      process.kill(pid, signal)
    } catch {
      // A process may have exited between tree discovery and signal delivery.
    }
  }
}
