import { whichSync } from './which.js'

const FD_COMMAND_NAMES = ['fdfind', 'fd'] as const

/** Resolve the parallel filesystem scanner used for Linux glob expansion. */
export function findFdCommand(): string | null {
  for (const command of FD_COMMAND_NAMES) {
    const resolved = whichSync(command)
    if (resolved !== null) {
      return resolved
    }
  }
  return null
}
