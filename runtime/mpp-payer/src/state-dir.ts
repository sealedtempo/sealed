import { closeSync, constants, fchmodSync, fstatSync, mkdirSync, openSync } from 'node:fs'

/**
 * Makes the payer's state directory private to this process's user (mode 0700) before any
 * state is written: the day's debits, the channel journal and the stored session channel.
 *
 * The composer's `envexec private` already does this for the composed payer service. This is
 * defense in depth for every other way the payer runs (the image alone, STATE_DIR moved, a mount
 * that arrives 0755). Same rules as envexec's privateDir: the directory is created 0700 if it is
 * missing, opened without following a symlink, and must belong to euid; anything else throws, so
 * the payer never starts with state another user could read or that it could not write.
 */
export function privateStateDir(dir: string, euid: number | undefined = process.geteuid?.()): void {
  let fd: number
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    fd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
  } catch (error) {
    throw new Error(`STATE_DIR ${dir}: ${(error as Error).message} (it must be a directory, not a symlink)`)
  }
  try {
    const st = fstatSync(fd)
    if (euid !== undefined && st.uid !== euid) throw new Error(`STATE_DIR ${dir} is owned by uid ${st.uid}, not by this process's uid ${euid}`)
    if ((st.mode & 0o7777) !== 0o700) fchmodSync(fd, 0o700)
  } finally {
    closeSync(fd)
  }
}
